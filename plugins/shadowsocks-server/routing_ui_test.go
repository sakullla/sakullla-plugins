package shadowsocksserver

import (
	"context"
	"encoding/json"
	"errors"
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
