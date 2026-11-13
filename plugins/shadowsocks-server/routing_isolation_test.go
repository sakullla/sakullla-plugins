package shadowsocksserver

import (
	"context"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type isolatedRoutingHost struct {
	nodes   map[string]*uiListenHost
	offline string
}

func (h *isolatedRoutingHost) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	req := decodePluginCallRequestFromCall(call)
	if req.AgentID == h.offline {
		return ErrExecutionUnavailable
	}
	node := h.nodes[req.AgentID]
	if node == nil {
		return ErrAgentOffline
	}
	return node.Call(ctx, call, target)
}

func TestRoutingSaveIsolatesOfflineNodeAndReconcilesUnchangedPorts(t *testing.T) {
	state := &uiMemoryListenState{}
	controller := startManagedListenController(t, &uiListenHost{online: true}, state)
	defer controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"})
	host := &isolatedRoutingHost{nodes: map[string]*uiListenHost{"agent-a": {online: true}, "agent-b": {online: true}}}
	controller.listenHost = newHostCapabilityRuntime(host)
	for _, id := range []string{"agent-a", "agent-b"} {
		response := uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"`+id+`","method":"aes-256-gcm"}`)
		if response.Code != 200 {
			t.Fatalf("create %s: %s", id, response.Body.String())
		}
	}
	host.offline = "agent-b"
	desired := RoutingConfiguration{DefaultAction: RouteReject}
	if err := controller.replaceRouting(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if state.routing.effectiveDefault() != RouteReject || controller.directory().Routing.effectiveDefault() != RouteReject {
		t.Fatal("offline node rolled back durable routing")
	}
	if got := host.nodes["agent-a"].apply; len(got) != 2 || got[len(got)-1].Routing.effectiveDefault() != RouteReject {
		t.Fatalf("healthy node applies=%+v", got)
	}
	if len(host.nodes["agent-b"].apply) != 1 {
		t.Fatal("unavailable node unexpectedly applied")
	}
	pending := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-b", ""))
	if pending.RoutingApplied == nil || *pending.RoutingApplied || pending.RoutingError == "" {
		t.Fatal("saved routing was reported as applied to offline node")
	}
	host.offline = ""
	controller.reconcileAgentListens(t.Context(), "agent-b")
	if got := host.nodes["agent-b"].apply; len(got) != 2 || got[1].Routing.effectiveDefault() != RouteReject {
		t.Fatalf("recovered node did not receive changed routing on existing port: %+v", got)
	}
	controller.reconcileAgentListens(t.Context(), "agent-b")
	if len(host.nodes["agent-b"].apply) != 2 {
		t.Fatal("matching routing was unnecessarily reapplied")
	}
	applied := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-b", ""))
	if applied.RoutingApplied == nil || !*applied.RoutingApplied || applied.RoutingError != "" {
		t.Fatal("recovered routing did not report applied status")
	}
}

func TestRoutingDiagnosticsKeepAppliedNodeDatasetEvidence(t *testing.T) {
	desired := RoutingConfiguration{DefaultAction: RouteDirect, Rules: []RouteRule{{ID: "ai", SourceID: "geosite", Classification: pluginsdk.DatasetClassification{Name: "category-ai-!cn", Kind: pluginsdk.DatasetClassificationDomain}, Action: RouteReject}}}
	host := &uiListenHost{online: true, routingDigest: routingDigest(desired), routes: []RouteStatus{{RuleID: "ai", SourceID: "geosite", VersionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: RouteReject}}}
	controller := newUITestController(t, host, NodeAddresses{})
	if err := controller.replaceRouting(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	payload := decodeListenAPI(t, uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-a", ""))
	if len(payload.RouteSources) != 1 || payload.RouteSources[0].Error != "" || payload.RouteSources[0].VersionDigest == "" || len(payload.RouteStatus) != 1 || payload.RouteStatus[0].Failure != "" {
		t.Fatalf("control-face resolution hid applied node evidence: %+v", payload)
	}
}

type failingRouteBatch struct{ routeDatasetFake }

func (d *failingRouteBatch) QueryDatasets(ctx context.Context, r pluginsdk.DatasetQueryRequest) (pluginsdk.DatasetQueryResponse, error) {
	if len(r.Classifications) > 1 || r.Classifications[0].Name == "category-ai" {
		return pluginsdk.DatasetQueryResponse{Status: pluginsdk.DatasetQueryMissingClassification}, nil
	}
	return d.routeDatasetFake.QueryDatasets(ctx, r)
}

func TestRouteBatchFailurePreservesFirstMatch(t *testing.T) {
	d := &failingRouteBatch{routeDatasetFake{matches: map[string]bool{"category-ai-cn": true}}}
	snapshot, err := prepareRouteSnapshot(t.Context(), routeFixture(), d)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := snapshot.decide(t.Context(), "tcp", "example.com:443")
	if err != nil || decision.RuleID != "first-direct" {
		t.Fatalf("later missing classification changed first match: %+v %v", decision, err)
	}
	d.matches["category-ai-cn"] = false
	if _, err := snapshot.decide(t.Context(), "tcp", "example.com:443"); err != ErrRouteDatasetUnavailable {
		t.Fatalf("missing classification did not fail closed: %v", err)
	}
}
