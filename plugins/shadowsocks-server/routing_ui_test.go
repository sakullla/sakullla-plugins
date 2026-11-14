package shadowsocksserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// datasetRuntimeFake extends the managed fake with a dataset.control endpoint
// and per-source version digests, so refresh tests can watch the host prepared
// version change underneath the plugin. It also emulates the
// dataset.source-register, dataset.catalog, and delete-source operations used
// by the remote ruleset panel.
type datasetRuntimeFake struct {
	*managedRuntimeFake
	datasetMu    sync.Mutex
	digests      map[string]string
	nextDigests  map[string]string
	denyManage   bool
	refreshErr   error
	deleteErr    error
	perSourceErr map[string]error
	unavailable  map[string]bool
	fetchedAt    map[string]string
	controls     []pluginsdk.DatasetControlRequest
	denyRegister bool
	registerErr  error
	registers    []pluginsdk.DatasetSourceRegisterRequest
}

func (fake *datasetRuntimeFake) Call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	fake.datasetMu.Lock()
	defer fake.datasetMu.Unlock()
	switch call.Operation {
	case pluginsdk.HostRuntimeDatasetSourceRegister:
		var request pluginsdk.DatasetSourceRegisterRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		fake.registers = append(fake.registers, request)
		if fake.denyRegister {
			return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "dataset.source-register denied"}
		}
		if fake.registerErr != nil {
			return fake.registerErr
		}
		digest := fake.digests[request.Source.ID]
		if digest == "" {
			digest = datasetDigest("a")
			if fake.digests == nil {
				fake.digests = map[string]string{}
			}
			fake.digests[request.Source.ID] = digest
		}
		version := fakeDatasetVersion(request.Source.ID, digest, request.Source.URL, request.Source.Format)
		return copyHostResult(pluginsdk.DatasetSourceRegisterResponse{SourceID: request.Source.ID, Version: version}, target)
	case pluginsdk.HostRuntimeDatasetCatalog:
		var request pluginsdk.DatasetCatalogRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		if fake.denyManage {
			return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "dataset.manage denied"}
		}
		response := pluginsdk.DatasetCatalogResponse{SourceID: request.SourceID}
		if digest := fake.digests[request.SourceID]; digest != "" && !fake.unavailable[request.SourceID] {
			version := fakeDatasetVersion(request.SourceID, digest, "", pluginsdk.DatasetFormatGeoSite)
			if fetched := fake.fetchedAt[request.SourceID]; fetched != "" {
				version.FetchedAt = fetched
			}
			response.Versions = []pluginsdk.DatasetVersion{version}
		}
		return copyHostResult(response, target)
	case pluginsdk.HostRuntimeDatasetControl:
		var request pluginsdk.DatasetControlRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			return err
		}
		fake.controls = append(fake.controls, request)
		if fake.denyManage {
			return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "dataset.manage denied"}
		}
		if err, ok := fake.perSourceErr[request.SourceID]; ok {
			return err
		}
		if request.Action == pluginsdk.DatasetControlDeleteSource {
			if fake.deleteErr != nil {
				return fake.deleteErr
			}
			delete(fake.digests, request.SourceID)
			if fake.unavailable == nil {
				fake.unavailable = map[string]bool{}
			}
			fake.unavailable[request.SourceID] = true
			return copyHostResult(pluginsdk.DatasetControlResponse{OperationID: call.OperationID, SourceID: request.SourceID}, target)
		}
		if fake.refreshErr != nil {
			return fake.refreshErr
		}
		if next, ok := fake.nextDigests[request.SourceID]; ok && request.Action == pluginsdk.DatasetControlRefresh {
			if fake.digests == nil {
				fake.digests = map[string]string{}
			}
			fake.digests[request.SourceID] = next
		}
		return copyHostResult(pluginsdk.DatasetControlResponse{OperationID: call.OperationID, SourceID: request.SourceID}, target)
	default:
		return nil
	}
}

func fakeDatasetVersion(sourceID, digest, sourceURL string, format pluginsdk.DatasetFormat) pluginsdk.DatasetVersion {
	return pluginsdk.DatasetVersion{
		SourceID:            sourceID,
		Digest:              digest,
		SourceURL:           sourceURL,
		Revision:            "rev-1",
		FetchedAt:           "2026-11-14T02:03:04Z",
		RawDigest:           datasetDigest("b"),
		IndexDigest:         datasetDigest("c"),
		Format:              format,
		SemanticVersion:     "v1",
		ClassificationCount: 1,
		EntryCount:          1,
		IndexBytes:          1,
		Coverage:            pluginsdk.DatasetAddressCoverage{IPv4: pluginsdk.DatasetFamilyComplete, IPv6: pluginsdk.DatasetFamilyComplete},
	}
}

func (fake *datasetRuntimeFake) ResolveDataset(_ context.Context, request pluginsdk.DatasetResolveRequest) (pluginsdk.DatasetReference, error) {
	fake.datasetMu.Lock()
	defer fake.datasetMu.Unlock()
	if fake.unavailable[request.SourceID] {
		return pluginsdk.DatasetReference{}, ErrRouteDatasetUnavailable
	}
	digest := fake.digests[request.SourceID]
	if digest == "" {
		digest = "sha256:" + strings.Repeat("a", 64)
	}
	return pluginsdk.DatasetReference{Handle: strings.Repeat("d", 43), InstanceID: "instance-a", Generation: "generation-a", SourceID: request.SourceID, VersionDigest: digest}, nil
}

func datasetDigest(suffix string) string {
	return "sha256:" + strings.Repeat(suffix, 64)
}

func routingRefreshFixture(t *testing.T) (*Controller, *datasetRuntimeFake, *uiListenHost) {
	t.Helper()
	fake := &datasetRuntimeFake{managedRuntimeFake: &managedRuntimeFake{}}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: &uiMemoryListenState{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm"}`); response.Code != 200 {
		t.Fatalf("listen=%d %s", response.Code, response.Body.String())
	}
	rules := `{"rules":[{"id":"cn-direct","source_id":"geosite","classification":{"name":"cn","kind":"domain"},"action":"direct"}],"default_action":"direct"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	return controller, fake, host
}

func (fake *datasetRuntimeFake) refreshCalls() int {
	fake.datasetMu.Lock()
	defer fake.datasetMu.Unlock()
	return len(fake.controls)
}

func TestRoutingRefreshAppliesNewHostPreparedVersion(t *testing.T) {
	controller, fake, host := routingRefreshFixture(t)
	fake.digests = map[string]string{"geosite": datasetDigest("a")}
	fake.nextDigests = map[string]string{"geosite": datasetDigest("b")}
	host.mu.Lock()
	appliesBefore := len(host.apply)
	host.mu.Unlock()

	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if response.Code != 200 {
		t.Fatalf("refresh=%d %s", response.Code, response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if payload.Refresh == nil || payload.Refresh.Mode != "host-refresh" {
		t.Fatalf("refresh=%s", response.Body.String())
	}
	if len(payload.Refresh.Sources) != 1 || payload.Refresh.Sources[0].Status != "updated" ||
		payload.Refresh.Sources[0].BeforeDigest != datasetDigest("a") || payload.Refresh.Sources[0].AfterDigest != datasetDigest("b") {
		t.Fatalf("sources=%+v", payload.Refresh.Sources)
	}
	if len(payload.Refresh.Nodes) != 1 || payload.Refresh.Nodes[0].AgentID != "agent-1" || !payload.Refresh.Nodes[0].RoutingApplied || payload.Refresh.Nodes[0].RoutingError != "" {
		t.Fatalf("nodes=%+v", payload.Refresh.Nodes)
	}
	if fake.refreshCalls() != 1 || fake.controls[0].Action != pluginsdk.DatasetControlRefresh || fake.controls[0].SourceID != "geosite" {
		t.Fatalf("controls=%+v", fake.controls)
	}
	host.mu.Lock()
	applied := len(host.apply)
	host.mu.Unlock()
	if applied != appliesBefore+1 {
		t.Fatalf("re-apply count=%d want=%d", applied, appliesBefore+1)
	}
	get := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-1", ""))
	if len(get.RouteSources) != 1 || get.RouteSources[0].VersionDigest != datasetDigest("b") {
		t.Fatalf("route sources=%+v", get.RouteSources)
	}
}

func TestRoutingRefreshReportsAlreadyLatest(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	fake.digests = map[string]string{"geosite": datasetDigest("a")}
	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if response.Code != 200 {
		t.Fatalf("refresh=%d %s", response.Code, response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if payload.Refresh == nil || len(payload.Refresh.Sources) != 1 || payload.Refresh.Sources[0].Status != "latest" ||
		payload.Refresh.Sources[0].AfterDigest != payload.Refresh.Sources[0].BeforeDigest {
		t.Fatalf("sources=%s", response.Body.String())
	}
	if fake.refreshCalls() != 1 {
		t.Fatalf("refresh calls=%d", fake.refreshCalls())
	}
}

func TestRoutingRefreshControlFailureKeepsOldVersionWithoutReapply(t *testing.T) {
	controller, fake, host := routingRefreshFixture(t)
	fake.digests = map[string]string{"geosite": datasetDigest("a")}
	fake.refreshErr = &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "refresh transport failed"}
	host.mu.Lock()
	appliesBefore := len(host.apply)
	host.mu.Unlock()

	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if response.Code == 200 || !strings.Contains(response.Body.String(), "数据集刷新失败") {
		t.Fatalf("failed refresh=%d %s", response.Code, response.Body.String())
	}
	host.mu.Lock()
	applied := len(host.apply)
	host.mu.Unlock()
	if applied != appliesBefore {
		t.Fatalf("failed refresh re-applied %d times", applied-appliesBefore)
	}
	get := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-1", ""))
	if len(get.RouteSources) != 1 || get.RouteSources[0].VersionDigest != datasetDigest("a") {
		t.Fatalf("route sources=%+v", get.RouteSources)
	}
	fake.refreshErr = nil
	fake.nextDigests = map[string]string{"geosite": datasetDigest("b")}
	retried := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if retried.Code != 200 {
		t.Fatalf("retry=%d %s", retried.Code, retried.Body.String())
	}
	payload := decodeListenAPI(t, retried)
	if len(payload.Refresh.Sources) != 1 || payload.Refresh.Sources[0].Status != "updated" {
		t.Fatalf("retry sources=%+v", payload.Refresh.Sources)
	}
}

func TestRoutingRefreshDegradesToReapplyWithoutDatasetManage(t *testing.T) {
	controller, fake, host := routingRefreshFixture(t)
	fake.denyManage = true
	host.mu.Lock()
	appliesBefore := len(host.apply)
	host.mu.Unlock()

	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if response.Code != 200 {
		t.Fatalf("degraded refresh=%d %s", response.Code, response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if payload.Refresh == nil || payload.Refresh.Mode != "reapply-only" || !strings.Contains(payload.Refresh.Message, "dataset.manage") {
		t.Fatalf("degraded refresh=%s", response.Body.String())
	}
	if len(payload.Refresh.Sources) != 1 || payload.Refresh.Sources[0].Status != "skipped" {
		t.Fatalf("degraded sources=%+v", payload.Refresh.Sources)
	}
	if len(payload.Refresh.Nodes) != 1 || !payload.Refresh.Nodes[0].RoutingApplied {
		t.Fatalf("degraded nodes=%+v", payload.Refresh.Nodes)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.apply) != appliesBefore+1 {
		t.Fatalf("degraded re-apply count=%d want=%d", len(host.apply), appliesBefore+1)
	}
}

func TestRoutingRefreshKeepsEarlierSessionSnapshots(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	fake.digests = map[string]string{"geosite": datasetDigest("a")}
	oldSnapshot, err := prepareRouteSnapshot(t.Context(), controller.directory().Routing, fake)
	if err != nil {
		t.Fatal(err)
	}
	fake.nextDigests = map[string]string{"geosite": datasetDigest("b")}
	if response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`); response.Code != 200 {
		t.Fatalf("refresh=%d %s", response.Code, response.Body.String())
	}
	newSnapshot, err := prepareRouteSnapshot(t.Context(), controller.directory().Routing, fake)
	if err != nil {
		t.Fatal(err)
	}
	if oldSnapshot.references["geosite"].VersionDigest != datasetDigest("a") {
		t.Fatalf("existing session snapshot moved=%+v", oldSnapshot.references)
	}
	if newSnapshot.references["geosite"].VersionDigest != datasetDigest("b") {
		t.Fatalf("new snapshot=%+v", newSnapshot.references)
	}
}

func TestRoutingRefreshUnknownSourceRejected(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{"source_id":"ghost"}`)
	if response.Code != 400 {
		t.Fatalf("unknown source=%d %s", response.Code, response.Body.String())
	}
	if fake.refreshCalls() != 0 {
		t.Fatalf("unknown source issued %d refresh calls", fake.refreshCalls())
	}
	if response := uiJSON(t, controller, "GET", "/api/routing/refresh", ""); response.Code != 405 {
		t.Fatalf("get refresh=%d", response.Code)
	}
	if response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{"source_id":`); response.Code != 400 {
		t.Fatalf("bad body=%d %s", response.Code, response.Body.String())
	}
}

func TestRoutingRefreshPerSourcePartialFailure(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	rules := `{"rules":[{"id":"cn-direct","source_id":"geosite","classification":{"name":"cn","kind":"domain"},"action":"direct"},{"id":"cn-ip","source_id":"geoip","classification":{"name":"cn","kind":"country"},"action":"direct"}],"default_action":"direct"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	fake.digests = map[string]string{"geosite": datasetDigest("a"), "geoip": datasetDigest("c")}
	fake.nextDigests = map[string]string{"geosite": datasetDigest("b")}
	fake.perSourceErr = map[string]error{"geoip": errors.New("single source refresh failed")}
	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{}`)
	if response.Code != 200 {
		t.Fatalf("partial refresh=%d %s", response.Code, response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if payload.Refresh == nil {
		t.Fatalf("partial refresh body=%s", response.Body.String())
	}
	statusBySource := map[string]datasetRefreshSource{}
	for _, source := range payload.Refresh.Sources {
		statusBySource[source.SourceID] = source
	}
	if statusBySource["geosite"].Status != "updated" || statusBySource["geoip"].Status != "error" {
		t.Fatalf("partial sources=%+v", payload.Refresh.Sources)
	}
}

// importExportFixture mirrors upstreamTestFixture but exposes the managed fake
// so import tests can observe secret mints and revocations.
func importExportFixture(t *testing.T) (*Controller, *managedRuntimeFake) {
	t.Helper()
	fake := &managedRuntimeFake{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: &uiMemoryListenState{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller, fake
}

func exportRoutingDoc(t *testing.T, controller *Controller) routingExportDocument {
	t.Helper()
	response := uiJSON(t, controller, "GET", "/api/routing/export", "")
	if response.Code != 200 {
		t.Fatalf("export=%d %s", response.Code, response.Body.String())
	}
	var document routingExportDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("export json=%s err=%v", response.Body.String(), err)
	}
	return document
}

func importRequest(document routingExportDocument, passwords map[string]string) routingImportRequest {
	request := routingImportRequest{Version: document.Version, Rules: document.Rules, DefaultAction: document.DefaultAction, DefaultUpstreamID: document.DefaultUpstreamID}
	for _, upstream := range document.Upstreams {
		request.Upstreams = append(request.Upstreams, upstreamImportEntry{
			ID: upstream.ID, Host: upstream.Host, Port: upstream.Port, Method: upstream.Method,
			Enabled: upstream.Enabled, TCP: upstream.TCP, UDP: upstream.UDP, Password: passwords[upstream.ID],
		})
	}
	return request
}

func postRoutingImport(t *testing.T, controller *Controller, request any) int {
	t.Helper()
	response := uiJSON(t, controller, "POST", "/api/routing/import", marshalTestJSON(t, request))
	return response.Code
}

func marshalTestJSON(t *testing.T, value any) string {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func TestRoutingExportOmitsSecretFields(t *testing.T) {
	controller, _ := importExportFixture(t)
	created := uiJSON(t, controller, "POST", "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-export-secret","tcp":true,"udp":true}`)
	if created.Code != 200 {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	upstream := decodeListenAPI(t, created).Routing.Upstreams[0]
	rules := `{"rules":[{"id":"ai","source_id":"geosite","classification":{"name":"category-ai","kind":"domain"},"action":"upstream","upstream_id":"edge"}],"default_action":"upstream","default_upstream_id":"edge"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}

	response := uiJSON(t, controller, "GET", "/api/routing/export", "")
	if response.Code != 200 {
		t.Fatalf("export=%d %s", response.Code, response.Body.String())
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, ".json") {
		t.Fatalf("export disposition=%q", disposition)
	}
	body := response.Body.String()
	for _, forbidden := range []string{"secret_ref", "secret_version", "password", "edge-export-secret", upstream.SecretRef, upstream.SecretVersion} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("export leaked %q: %s", forbidden, body)
		}
	}
	document := exportRoutingDoc(t, controller)
	if document.Version != routingExportVersion || document.DefaultAction != "upstream" || document.DefaultUpstreamID != "edge" || len(document.Rules) != 1 || len(document.Upstreams) != 1 {
		t.Fatalf("export document=%+v", document)
	}
	entry := document.Upstreams[0]
	if entry.ID != "edge" || entry.Host != "203.0.113.10" || entry.Port != 8388 || entry.Method != "aes-256-gcm" || !entry.Enabled || !entry.TCP || !entry.UDP {
		t.Fatalf("export upstream=%+v", entry)
	}
	if response := uiJSON(t, controller, "POST", "/api/routing/export", `{}`); response.Code != 405 {
		t.Fatalf("export post=%d", response.Code)
	}
	if response := uiJSON(t, controller, "GET", "/api/routing/import", ""); response.Code != 405 {
		t.Fatalf("import get=%d", response.Code)
	}
}

func TestRoutingImportExportRoundTripAcrossInstances(t *testing.T) {
	source, _ := importExportFixture(t)
	passwords := map[string]string{"edge": "edge-roundtrip-secret", "backup": "MDEyMzQ1Njc4OWFiY2RlZg=="}
	for _, body := range []string{
		`{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-roundtrip-secret","tcp":true,"udp":true}`,
		`{"id":"backup","host":"198.51.100.20","port":8389,"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg==","tcp":true,"udp":false}`,
	} {
		if response := uiJSON(t, source, "POST", "/api/upstreams", body); response.Code != 200 {
			t.Fatalf("create=%d %s", response.Code, response.Body.String())
		}
	}
	rules := `{"rules":[{"id":"ai","source_id":"geosite","classification":{"name":"category-ai","kind":"domain"},"action":"upstream","upstream_id":"edge"},{"id":"cn","source_id":"geoip","classification":{"name":"cn","kind":"country"},"action":"direct"}],"default_action":"upstream","default_upstream_id":"backup"}`
	if response := uiJSON(t, source, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	document := exportRoutingDoc(t, source)

	target, targetFake := importExportFixture(t)
	if code := postRoutingImport(t, target, importRequest(document, passwords)); code != 200 {
		t.Fatalf("import=%d", code)
	}
	reexported := exportRoutingDoc(t, target)
	if !reflect.DeepEqual(document, reexported) {
		t.Fatalf("round trip mismatch:\nsource=%+v\ntarget=%+v", document, reexported)
	}
	routing := decodeListenAPI(t, uiJSON(t, target, "GET", "/api/routing", "")).Routing
	if routing == nil || len(routing.Upstreams) != 2 {
		t.Fatalf("target routing=%+v", routing)
	}
	// Secrets were re-minted on the target instance through the scoped-secret
	// path; nothing references the source instance's opaque IDs.
	sourceSecrets := map[string]bool{}
	for _, upstream := range decodeListenAPI(t, uiJSON(t, source, "GET", "/api/routing", "")).Routing.Upstreams {
		sourceSecrets[upstream.SecretRef] = true
	}
	for _, upstream := range routing.Upstreams {
		if upstream.SecretRef == "" || upstream.SecretVersion == "" {
			t.Fatalf("target upstream missing secret ref=%+v", upstream)
		}
		if sourceSecrets[upstream.SecretRef] {
			t.Fatalf("target reused source secret ref=%+v", upstream)
		}
	}
	if targetFake.createCalls != 2 || targetFake.revokes != 0 {
		t.Fatalf("target secrets creates=%d revokes=%d", targetFake.createCalls, targetFake.revokes)
	}
}

func TestRoutingImportRejectsMalformedAndTamperedFiles(t *testing.T) {
	controller, fake := importExportFixture(t)
	if response := uiJSON(t, controller, "POST", "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-tamper-secret","tcp":true,"udp":true}`); response.Code != 200 {
		t.Fatalf("create=%d %s", response.Code, response.Body.String())
	}
	before := exportRoutingDoc(t, controller)
	creates, revokes := fake.createCalls, fake.revokes

	cases := []struct {
		name string
		body string
		want int
	}{
		{"not json", `{`, 400},
		{"wrong version", `{"version":2,"rules":[],"default_action":"direct","upstreams":[]}`, 400},
		{"unknown field", `{"version":1,"rules":[],"default_action":"direct","upstreams":[],"bogus":true}`, 400},
		{"rule references missing upstream", `{"version":1,"rules":[{"id":"r1","source_id":"geosite","classification":{"name":"category-ai","kind":"domain"},"action":"upstream","upstream_id":"ghost"}],"default_action":"direct","upstreams":[]}`, 409},
		{"default upstream missing", `{"version":1,"rules":[],"default_action":"upstream","default_upstream_id":"ghost","upstreams":[]}`, 409},
		{"unsupported method", `{"version":1,"rules":[],"default_action":"direct","upstreams":[{"id":"x","host":"203.0.113.9","port":8388,"method":"rc4-md5","password":"p","tcp":true,"udp":false}]}`, 400},
		{"invalid upstream port", `{"version":1,"rules":[],"default_action":"direct","upstreams":[{"id":"x","host":"203.0.113.9","port":0,"method":"aes-256-gcm","password":"p","tcp":true,"udp":false}]}`, 400},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			if response := uiJSON(t, controller, "POST", "/api/routing/import", testcase.body); response.Code != testcase.want {
				t.Fatalf("import=%d want=%d %s", response.Code, testcase.want, response.Body.String())
			}
		})
	}
	// A duplicate upstream id is rejected after the first entry already minted
	// a secret; the minted reference must be rolled back with the attempt.
	duplicate := `{"version":1,"rules":[],"default_action":"direct","upstreams":[` +
		`{"id":"fresh","host":"203.0.113.9","port":8388,"method":"aes-256-gcm","password":"fresh-secret","tcp":true,"udp":false},` +
		`{"id":"fresh","host":"203.0.113.9","port":8389,"method":"aes-256-gcm","password":"fresh-secret","tcp":true,"udp":false}]}`
	if response := uiJSON(t, controller, "POST", "/api/routing/import", duplicate); response.Code != 400 {
		t.Fatalf("duplicate import=%d", response.Code)
	}
	if fake.createCalls-creates != fake.revokes-revokes {
		t.Fatalf("rejected imports leaked secrets: creates=%d revokes=%d", fake.createCalls-creates, fake.revokes-revokes)
	}
	if after := exportRoutingDoc(t, controller); !reflect.DeepEqual(before, after) {
		t.Fatalf("routing changed after rejected imports:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestRoutingImportReusesSameIDCredential(t *testing.T) {
	controller, fake := importExportFixture(t)
	for _, body := range []string{
		`{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-reuse-secret","tcp":true,"udp":true}`,
		`{"id":"retire","host":"203.0.113.11","port":8389,"method":"aes-256-gcm","password":"retire-secret","tcp":true,"udp":false}`,
	} {
		if response := uiJSON(t, controller, "POST", "/api/upstreams", body); response.Code != 200 {
			t.Fatalf("create=%d %s", response.Code, response.Body.String())
		}
	}
	routing := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing", "")).Routing
	refs := map[string]Upstream{}
	for _, upstream := range routing.Upstreams {
		refs[upstream.ID] = upstream
	}
	document := exportRoutingDoc(t, controller)

	// Reuse validates the stored material against the imported method: a
	// legacy password cannot serve a 2022 upstream, so the file is rejected
	// with a readable per-upstream error before anything is minted.
	incompatible := routingImportRequest{Version: document.Version, Rules: document.Rules, DefaultAction: document.DefaultAction, Upstreams: []upstreamImportEntry{
		{ID: "edge", Host: "203.0.113.10", Port: 8388, Method: "2022-blake3-aes-128-gcm", Enabled: true, TCP: true, UDP: true},
	}}
	response := uiJSON(t, controller, "POST", "/api/routing/import", marshalTestJSON(t, incompatible))
	if response.Code != 400 || !strings.Contains(response.Body.String(), "edge") {
		t.Fatalf("incompatible reuse=%d %s", response.Code, response.Body.String())
	}
	if fake.createCalls != 2 || fake.revokes != 0 {
		t.Fatalf("rejected reuse minted or revoked secrets: creates=%d revokes=%d", fake.createCalls, fake.revokes)
	}

	// "edge" reuses its stored credential, "retire" is dropped, "remote" is
	// minted fresh. The retired secret is revoked only after a successful
	// commit.
	request := routingImportRequest{Version: document.Version, Rules: document.Rules, DefaultAction: document.DefaultAction, Upstreams: []upstreamImportEntry{
		{ID: "edge", Host: "203.0.113.10", Port: 8388, Method: "aes-256-gcm", Enabled: true, TCP: true, UDP: true},
		{ID: "remote", Host: "198.51.100.30", Port: 8390, Method: "aes-256-gcm", Password: "remote-secret", Enabled: true, TCP: true, UDP: true},
	}}
	if code := postRoutingImport(t, controller, request); code != 200 {
		t.Fatalf("import=%d", code)
	}
	after := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing", "")).Routing
	if len(after.Upstreams) != 2 {
		t.Fatalf("imported upstreams=%+v", after.Upstreams)
	}
	var edge, remote Upstream
	for _, upstream := range after.Upstreams {
		switch upstream.ID {
		case "edge":
			edge = upstream
		case "remote":
			remote = upstream
		}
	}
	if edge.SecretRef != refs["edge"].SecretRef || edge.SecretVersion != refs["edge"].SecretVersion {
		t.Fatalf("edge credential not reused: %+v", edge)
	}
	if remote.SecretRef == "" || remote.SecretRef == refs["edge"].SecretRef || remote.SecretRef == refs["retire"].SecretRef {
		t.Fatalf("remote credential=%+v", remote)
	}
	if fake.createCalls != 3 || fake.revokes != 1 {
		t.Fatalf("import secrets creates=%d revokes=%d", fake.createCalls, fake.revokes)
	}
}

func TestRoutingImportMissingCredentialIsAtomic(t *testing.T) {
	controller, fake := importExportFixture(t)
	if response := uiJSON(t, controller, "POST", "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-atomic-secret","tcp":true,"udp":true}`); response.Code != 200 {
		t.Fatalf("create=%d %s", response.Code, response.Body.String())
	}
	before := exportRoutingDoc(t, controller)
	request := routingImportRequest{Version: before.Version, Rules: before.Rules, DefaultAction: before.DefaultAction, Upstreams: []upstreamImportEntry{
		{ID: "fresh", Host: "203.0.113.9", Port: 8388, Method: "aes-256-gcm", Password: "fresh-secret", Enabled: true, TCP: true, UDP: true},
		{ID: "edge", Host: "203.0.113.10", Port: 8388, Method: "aes-256-gcm", Enabled: true, TCP: true, UDP: true},
		{ID: "ghost", Host: "198.51.100.40", Port: 8391, Method: "aes-256-gcm", Enabled: true, TCP: true, UDP: true},
	}}
	response := uiJSON(t, controller, "POST", "/api/routing/import", marshalTestJSON(t, request))
	if response.Code != 400 {
		t.Fatalf("import=%d %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "ghost") {
		t.Fatalf("missing credential error=%s", body)
	}
	// "fresh" minted a secret before "ghost" was found; the whole attempt is
	// rolled back and the stored configuration keeps only "edge".
	if fake.createCalls != 2 || fake.revokes != 1 {
		t.Fatalf("atomic rollback creates=%d revokes=%d", fake.createCalls, fake.revokes)
	}
	if after := exportRoutingDoc(t, controller); !reflect.DeepEqual(before, after) {
		t.Fatalf("routing changed after rejected import:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestRoutingImportEnforcesConfiguredLimits(t *testing.T) {
	controller, fake := importExportFixture(t)
	upstreams := make([]upstreamImportEntry, 0, MaxUpstreams+1)
	for index := 0; index < MaxUpstreams+1; index++ {
		upstreams = append(upstreams, upstreamImportEntry{ID: fmt.Sprintf("u%02d", index), Host: "203.0.113.9", Port: 8388, Method: "aes-256-gcm", Password: "p", Enabled: true, TCP: true})
	}
	request := routingImportRequest{Version: routingExportVersion, DefaultAction: "direct", Rules: []RouteRule{}, Upstreams: upstreams}
	if code := postRoutingImport(t, controller, request); code != 400 {
		t.Fatalf("upstream limit import=%d", code)
	}
	rules := make([]RouteRule, 0, MaxRouteRules+1)
	for index := 0; index < MaxRouteRules+1; index++ {
		rules = append(rules, RouteRule{ID: fmt.Sprintf("r%d", index), SourceID: "geosite", Classification: pluginsdk.DatasetClassification{Name: "n", Kind: pluginsdk.DatasetClassificationDomain}, Action: "direct"})
	}
	request = routingImportRequest{Version: routingExportVersion, DefaultAction: "direct", Rules: rules, Upstreams: []upstreamImportEntry{}}
	if code := postRoutingImport(t, controller, request); code != 400 {
		t.Fatalf("rule limit import=%d", code)
	}
	if fake.createCalls != 0 || fake.revokes != 0 {
		t.Fatalf("limit rejection touched secrets: creates=%d revokes=%d", fake.createCalls, fake.revokes)
	}
	if document := exportRoutingDoc(t, controller); len(document.Upstreams) != 0 || len(document.Rules) != 0 {
		t.Fatalf("routing changed after limit rejection=%+v", document)
	}
}

func rollingSourceBody(sourceID string) string {
	return fmt.Sprintf(`{"source_id":%q,"url":"https://datasets.example.com/geosite.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/geosite.sha256","refresh_interval_seconds":86400}`, sourceID)
}

func TestDatasetSourceRegisterSuccess(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	state := controller.listenState.(*uiMemoryListenState)

	response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules"))
	if response.Code != 200 {
		t.Fatalf("register=%d %s", response.Code, response.Body.String())
	}
	if len(fake.registers) != 1 {
		t.Fatalf("host register calls=%d", len(fake.registers))
	}
	registered := fake.registers[0]
	if registered.Source.ID != "remote-rules" || registered.Source.URL != "https://datasets.example.com/geosite.dat" ||
		registered.Source.Format != pluginsdk.DatasetFormatGeoSite || registered.Source.RefreshIntervalSeconds != 86400 ||
		registered.Retrieval.Mode != pluginsdk.DatasetRetrievalRollingSHA256 ||
		registered.Retrieval.ChecksumURL != "https://datasets.example.com/geosite.sha256" {
		t.Fatalf("register request=%+v", registered)
	}
	payload := decodeListenAPI(t, response)
	if len(payload.RemoteSources) != 1 || payload.RemoteSources[0].SourceID != "remote-rules" {
		t.Fatalf("remote sources=%+v", payload.RemoteSources)
	}
	view := payload.RemoteSources[0]
	if view.VersionDigest == "" || view.Error != "" || view.FetchedAt == "" || view.Referenced {
		t.Fatalf("registered view=%+v", view)
	}
	if len(state.sources) != 1 || state.sources[0].Source.ID != "remote-rules" {
		t.Fatalf("persisted sources=%+v", state.sources)
	}
	// The registered source is listed again on the routing read path, so the
	// rule dialog can offer it as a source option.
	get := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing", ""))
	if len(get.RemoteSources) != 1 || get.RemoteSources[0].SourceID != "remote-rules" {
		t.Fatalf("routing remote sources=%+v", get.RemoteSources)
	}
	if response := uiJSON(t, controller, "GET", "/api/dataset-sources", ""); response.Code != 200 {
		t.Fatalf("list=%d %s", response.Code, response.Body.String())
	} else if views := decodeListenAPI(t, response).RemoteSources; len(views) != 1 || views[0].Mode != "rolling-sha256" {
		t.Fatalf("listed sources=%+v", views)
	}
	// A rule can reference the registered source exactly like geosite/geoip.
	rules := `{"rules":[{"id":"remote-cn","source_id":"remote-rules","classification":{"name":"cn","kind":"domain"},"action":"direct"}],"default_action":"direct"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	if referenced := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/dataset-sources", "")).RemoteSources; len(referenced) != 1 || !referenced[0].Referenced {
		t.Fatalf("referenced view=%+v", referenced)
	}
}

func TestDatasetSourceRegisterRejectsInvalidInput(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	cases := []struct {
		name string
		body string
	}{
		{"http url", `{"source_id":"bad","url":"http://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"credential url", `{"source_id":"bad","url":"https://user:pass@datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"fragment url", `{"source_id":"bad","url":"https://datasets.example.com/x.dat#frag","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"bad id", `{"source_id":"BAD ID","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		// A "/" in the id would split the {id}/delete route segment and make
		// the source unremovable; ":" is excluded for the same URL-safety set.
		{"slash id", `{"source_id":"bad/id","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"colon id", `{"source_id":"bad:id","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"bad format", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"yaml","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"bad mode", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"latest","checksum_url":"https://datasets.example.com/x.sha256"}`},
		{"rolling missing checksum", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256"}`},
		{"pinned missing digest", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"pinned","revision":"v1"}`},
		{"pinned bad digest", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"pinned","revision":"v1","expected_digest":"deadbeef"}`},
		{"bad interval", `{"source_id":"bad","url":"https://datasets.example.com/x.dat","format":"geosite","mode":"rolling-sha256","checksum_url":"https://datasets.example.com/x.sha256","refresh_interval_seconds":60}`},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			response := uiJSON(t, controller, "POST", "/api/dataset-sources", testcase.body)
			if response.Code != 400 {
				t.Fatalf("invalid register=%d %s", response.Code, response.Body.String())
			}
			if message := decodeListenAPI(t, response).Error; message == "" || message == "请求无效" {
				t.Fatalf("invalid register error=%q", message)
			}
		})
	}
	if len(fake.registers) != 0 {
		t.Fatalf("invalid input reached host register=%+v", fake.registers)
	}
	if views := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/dataset-sources", "")).RemoteSources; len(views) != 0 {
		t.Fatalf("rejected input created sources=%+v", views)
	}
}

func TestDatasetSourceRegisterDeniedIsHonest(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	fake.denyRegister = true
	response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules"))
	if response.Code != 403 {
		t.Fatalf("denied register=%d %s", response.Code, response.Body.String())
	}
	if message := decodeListenAPI(t, response).Error; !strings.Contains(message, "dataset.source-register") {
		t.Fatalf("denied error=%q", message)
	}
	if views := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/dataset-sources", "")).RemoteSources; len(views) != 0 {
		t.Fatalf("denied register created sources=%+v", views)
	}
	fake.denyRegister = false
	fake.registerErr = &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "fetch failed"}
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules")); response.Code != 400 {
		t.Fatalf("failed register=%d %s", response.Code, response.Body.String())
	}
	if views := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/dataset-sources", "")).RemoteSources; len(views) != 0 {
		t.Fatalf("failed register created sources=%+v", views)
	}
}

func TestDatasetSourceManualRefreshAndDelete(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules")); response.Code != 200 {
		t.Fatalf("register=%d %s", response.Code, response.Body.String())
	}
	fake.digests = map[string]string{"remote-rules": datasetDigest("e")}
	fake.nextDigests = map[string]string{"remote-rules": datasetDigest("f")}
	// Manual refresh reuses the routing refresh channel even while no rule
	// references the source yet.
	response := uiJSON(t, controller, "POST", "/api/routing/refresh", `{"source_id":"remote-rules"}`)
	if response.Code != 200 {
		t.Fatalf("refresh=%d %s", response.Code, response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if len(payload.Refresh.Sources) != 1 || payload.Refresh.Sources[0].Status != "updated" ||
		payload.Refresh.Sources[0].BeforeDigest != datasetDigest("e") || payload.Refresh.Sources[0].AfterDigest != datasetDigest("f") {
		t.Fatalf("refresh sources=%+v", payload.Refresh.Sources)
	}
	if len(fake.controls) != 1 || fake.controls[0].Action != pluginsdk.DatasetControlRefresh || fake.controls[0].SourceID != "remote-rules" {
		t.Fatalf("controls=%+v", fake.controls)
	}
	// Removing the source issues delete-source and drops the registry record.
	response = uiJSON(t, controller, "POST", "/api/dataset-sources/remote-rules/delete", `{}`)
	if response.Code != 200 {
		t.Fatalf("delete=%d %s", response.Code, response.Body.String())
	}
	if views := decodeListenAPI(t, response).RemoteSources; len(views) != 0 {
		t.Fatalf("post-delete sources=%+v", views)
	}
	if len(fake.controls) != 2 || fake.controls[1].Action != pluginsdk.DatasetControlDeleteSource || fake.controls[1].SourceID != "remote-rules" {
		t.Fatalf("controls=%+v", fake.controls)
	}
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources/remote-rules/delete", `{}`); response.Code != 400 {
		t.Fatalf("second delete=%d %s", response.Code, response.Body.String())
	}
}

func TestDatasetSourceDeleteLeavesRulesFailClosed(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules")); response.Code != 200 {
		t.Fatalf("register=%d %s", response.Code, response.Body.String())
	}
	rules := `{"rules":[{"id":"remote-cn","source_id":"remote-rules","classification":{"name":"cn","kind":"domain"},"action":"direct"},{"id":"cn-direct","source_id":"geosite","classification":{"name":"cn","kind":"domain"},"action":"direct"}],"default_action":"direct"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources/remote-rules/delete", `{}`); response.Code != 200 {
		t.Fatalf("delete=%d %s", response.Code, response.Body.String())
	}
	get := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-1", ""))
	failureByRule := map[string]string{}
	for _, status := range get.RouteStatus {
		failureByRule[status.RuleID] = status.Failure
	}
	if failureByRule["remote-cn"] != "dataset-unavailable" {
		t.Fatalf("referenced rule after delete=%+v", get.RouteStatus)
	}
	if failureByRule["cn-direct"] != "" {
		t.Fatalf("unrelated rule affected=%+v", get.RouteStatus)
	}
	// The routing snapshot itself fails closed while resolving the missing
	// source instead of silently rebinding to another dataset.
	if _, err := prepareRouteSnapshot(t.Context(), controller.directory().Routing, fake); err == nil {
		t.Fatal("route snapshot resolved a removed source")
	}
}

func TestDatasetSourceDeleteDeniedKeepsRegistry(t *testing.T) {
	controller, fake, _ := routingRefreshFixture(t)
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources", rollingSourceBody("remote-rules")); response.Code != 200 {
		t.Fatalf("register=%d %s", response.Code, response.Body.String())
	}
	fake.denyManage = true
	response := uiJSON(t, controller, "POST", "/api/dataset-sources/remote-rules/delete", `{}`)
	if response.Code != 403 {
		t.Fatalf("denied delete=%d %s", response.Code, response.Body.String())
	}
	fake.denyManage = false
	fake.deleteErr = errors.New("source still referenced")
	if response := uiJSON(t, controller, "POST", "/api/dataset-sources/remote-rules/delete", `{}`); response.Code != 400 {
		t.Fatalf("failed delete=%d %s", response.Code, response.Body.String())
	}
	if views := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/dataset-sources", "")).RemoteSources; len(views) != 1 {
		t.Fatalf("failed delete dropped registry=%+v", views)
	}
}
