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
// version change underneath the plugin.
type datasetRuntimeFake struct {
	*managedRuntimeFake
	datasetMu    sync.Mutex
	digests      map[string]string
	nextDigests  map[string]string
	denyManage   bool
	refreshErr   error
	perSourceErr map[string]error
	controls     []pluginsdk.DatasetControlRequest
}

func (fake *datasetRuntimeFake) Call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	if call.Operation != pluginsdk.HostRuntimeDatasetControl {
		return nil
	}
	var request pluginsdk.DatasetControlRequest
	if err := json.Unmarshal(call.Payload, &request); err != nil {
		return err
	}
	fake.datasetMu.Lock()
	defer fake.datasetMu.Unlock()
	fake.controls = append(fake.controls, request)
	if fake.denyManage {
		return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "dataset.manage denied"}
	}
	if err, ok := fake.perSourceErr[request.SourceID]; ok {
		return err
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
}

func (fake *datasetRuntimeFake) ResolveDataset(_ context.Context, request pluginsdk.DatasetResolveRequest) (pluginsdk.DatasetReference, error) {
	fake.datasetMu.Lock()
	defer fake.datasetMu.Unlock()
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
