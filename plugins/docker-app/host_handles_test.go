package dockerapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type hostCallFunc func(context.Context, pluginsdk.HostRuntimeCall, any) error

func (function hostCallFunc) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	return function(ctx, call, target)
}

func TestHostCapabilityRuntimeConsumesGenericAgentHandles(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallEngineName:
			return copyHostResult(map[string]any{
				"agent_id": "agent-1", "online": true,
				"engine": map[string]any{"installed": true, "version": "27.1.1"},
			}, target)
		case pluginCallComposeName:
			payload := decodePluginCallInner(t, request)
			if payload["action"] == "logs" {
				return copyHostResult(map[string]any{"logs": "listening on :80\n"}, target)
			}
			return copyHostResult(map[string]any{"accepted": true}, target)
		default:
			t.Fatalf("unexpected plugin.call name %q", request.Name)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)

	report, err := runtime.Report(context.Background(), "agent-1")
	if err != nil || !report.Online || !report.Installed || report.Version != "27.1.1" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if !ProjectEngine(ObservationFromReport(report)).Ready {
		t.Fatal("generic engine report did not project ready")
	}

	app := App{ID: "media", AgentID: "agent-1", Compose: "services:\n  web:\n    image: nginx:1.27\n", WorkDir: "/apps/media"}
	if err := runtime.ApplyApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Restart(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	logs, err := runtime.ReadLogs(context.Background(), app, "web")
	if err != nil || logs != "listening on :80\n" {
		t.Fatalf("logs=%q err=%v", logs, err)
	}
	if err := runtime.RemoveApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 7 {
		t.Fatalf("host calls = %d", len(calls))
	}
	assertNoNamedAgentHostOps(t, calls)
	engine := decodePluginCallRequest(t, calls[0])
	if engine.Name != pluginCallEngineName || engine.AgentID != "agent-1" || !strings.Contains(string(engine.Payload), `"agent_id":"agent-1"`) {
		t.Fatalf("engine call = %#v", calls[0])
	}
	apply := decodePluginCallInner(t, decodePluginCallRequest(t, calls[1]))
	if calls[1].Operation != pluginsdk.HostRuntimePluginCall || apply["action"] != "apply" || apply["agent_id"] != "agent-1" || apply["app_id"] != "media" {
		t.Fatalf("compose apply call = %#v payload=%#v", calls[1], apply)
	}
	for _, call := range calls[2:6] {
		payload := decodePluginCallInner(t, decodePluginCallRequest(t, call))
		if _, ok := payload["compose"]; ok {
			t.Fatalf("lifecycle call restaged compose: %#v", payload)
		}
	}
	remove := decodePluginCallInner(t, decodePluginCallRequest(t, calls[6]))
	if remove["action"] != "remove" || remove["compose"] == nil {
		t.Fatalf("remove omitted compose restage: %#v", remove)
	}
	for index, call := range calls[1:] {
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallComposeName {
			t.Fatalf("compose call %d = %#v", index, call)
		}
		payload := decodePluginCallInner(t, request)
		if payload["agent_id"] != "agent-1" || payload["app_id"] != "media" {
			t.Fatalf("compose call %d omitted agent routing: %#v", index, payload)
		}
	}
	for _, marker := range []string{"docker.socket", "docker.sock", "unix://", "container.compose"} {
		for _, call := range calls {
			if call.Operation == marker {
				t.Fatalf("generic handle leaked local Docker target: %#v", call)
			}
		}
	}
}

func TestHostCapabilityRuntimePersistsAppsThroughHostState(t *testing.T) {
	stored := map[string]json.RawMessage{}
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		var payload struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(call.Payload, &payload); err != nil {
			return err
		}
		if payload.Key != pluginAppsStateKey && payload.Key != pluginRuntimeStateKey {
			t.Fatalf("state key=%q", payload.Key)
		}
		switch call.Operation {
		case "state.put":
			stored[payload.Key] = append(json.RawMessage(nil), payload.Value...)
			return copyHostResult(map[string]any{"stored": true}, target)
		case "state.get":
			return copyHostResult(map[string]any{"found": true, "value": stored[payload.Key]}, target)
		default:
			t.Fatalf("state operation=%q", call.Operation)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)
	want := []App{{ID: "hubproxy", AgentID: "agent-1", Generation: "generation-1", Compose: "services:\n  hubproxy:\n    image: registry.example.test/hubproxy:latest\n"}}
	if err := runtime.StoreApps(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, found, err := runtime.LoadApps(context.Background())
	if err != nil || !found || len(got) != 1 || got[0].ID != want[0].ID || got[0].AgentID != want[0].AgentID {
		t.Fatalf("LoadApps()=(%#v,%t,%v)", got, found, err)
	}
	if err := runtime.StoreRuntime(context.Background(), map[string]bool{"hubproxy": false}); err != nil {
		t.Fatal(err)
	}
	runtimeState, found, err := runtime.LoadRuntime(context.Background())
	if err != nil || !found || runtimeState["hubproxy"] {
		t.Fatalf("LoadRuntime()=(%#v,%t,%v)", runtimeState, found, err)
	}
	if len(calls) != 4 || calls[0].Operation != "state.put" || calls[1].Operation != "state.get" || calls[2].Operation != "state.put" || calls[3].Operation != "state.get" {
		t.Fatalf("state calls=%#v", calls)
	}
}

func TestHostCapabilityRuntimePersistsDeploymentStoreThroughHostState(t *testing.T) {
	t.Parallel()
	stored := map[string]json.RawMessage{}
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		var payload struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(call.Payload, &payload); err != nil {
			return err
		}
		if payload.Key != pluginDeploymentsStateKey {
			t.Fatalf("state key=%q", payload.Key)
		}
		switch call.Operation {
		case "state.put":
			stored[payload.Key] = append(json.RawMessage(nil), payload.Value...)
			return copyHostResult(map[string]any{"stored": true}, target)
		case "state.get":
			value, found := stored[payload.Key]
			return copyHostResult(map[string]any{"found": found, "value": value}, target)
		default:
			t.Fatalf("state operation=%q", call.Operation)
			return nil
		}
	})
	store := newPersistedDeploymentStore(newHostCapabilityRuntime(client))
	ctx := context.Background()
	seed := Deployment{
		AppID: "media", AgentID: "agent-1", Image: "nginx:latest", Generation: "generation-1",
		Phase: PhaseActive, ImageDigest: "sha256:current", AvailableDigest: "sha256:latest",
		History: []DeploymentRevision{{Image: "nginx:latest", ImageDigest: "sha256:prior"}},
	}
	leased, err := store.AcquireLease(ctx, "media", 0, seed, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	active := leased.Value
	active.Lease, active.LeaseUntil = "", time.Time{}
	if _, err := store.CompareAndSwap(ctx, "media", leased.Version, leased.Value.FencingToken, active); err != nil {
		t.Fatal(err)
	}
	reloaded := newPersistedDeploymentStore(newHostCapabilityRuntime(client))
	got, ok, err := reloaded.Load(ctx, "media")
	if err != nil || !ok || got.Value.ImageDigest != "sha256:current" || got.Value.AvailableDigest != "sha256:latest" || len(got.Value.History) != 1 || got.Value.History[0].ImageDigest != "sha256:prior" {
		t.Fatalf("reloaded deployment=%#v ok=%v err=%v", got, ok, err)
	}
	if err := reloaded.DeleteCAS(ctx, "media", got.Version, got.Value.FencingToken); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Load(ctx, "media"); err != nil || ok {
		t.Fatalf("deleted deployment still present ok=%v err=%v", ok, err)
	}
	if _, err := store.AcquireLease(ctx, "media", 0, seed, time.Now().Add(time.Second)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("deleted deployment reseed err=%v", err)
	}
	if len(calls) == 0 {
		t.Fatal("deployment store did not use host state.get/put")
	}
	for _, call := range calls {
		if call.Operation != "state.get" && call.Operation != "state.put" {
			t.Fatalf("unexpected host operation %q", call.Operation)
		}
	}
}

func TestHostCapabilityRuntimeFailClosedWithoutClientOrOnLocalSocket(t *testing.T) {
	t.Parallel()
	if runtime := newHostCapabilityRuntime(nil); runtime != nil {
		t.Fatal("nil host client still constructed a runtime")
	}
	if _, err := (*hostCapabilityRuntime)(nil).Report(context.Background(), "agent-1"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime report err=%v", err)
	}
	if err := (*hostCapabilityRuntime)(nil).ApplyApp(context.Background(), App{ID: "media", AgentID: "agent-1"}); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime apply err=%v", err)
	}
	if err := (*hostCapabilityRuntime)(nil).Files(context.Background(), App{ID: "media", AgentID: "agent-1"}, map[string]any{"action": "list"}, nil); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime files err=%v", err)
	}

	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		if call.Operation != pluginsdk.HostRuntimePluginCall {
			t.Fatalf("unexpected host operation %q", call.Operation)
		}
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallEngineName:
			return copyHostResult(map[string]any{
				"kind": "docker.socket", "id": "local", "path": "/var/run/docker.sock",
			}, target)
		default:
			return copyHostResult(map[string]any{"socket": "/var/run/docker.sock"}, target)
		}
	})
	runtime := newHostCapabilityRuntime(client)
	if _, err := runtime.Report(context.Background(), "agent-1"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("local docker.socket report err=%v", err)
	}
	if err := runtime.ApplyApp(context.Background(), App{ID: "media", AgentID: "agent-1", Compose: "services:\n  web:\n    image: nginx:1.27\n"}); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("local docker.socket apply err=%v", err)
	}

	denied := hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "unsupported"}
	})
	unavailable := newHostCapabilityRuntime(denied)
	if _, err := unavailable.Report(context.Background(), "agent-1"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unsupported engine handle err=%v", err)
	}
	if err := unavailable.Start(context.Background(), App{ID: "media", AgentID: "agent-1"}); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unsupported compose handle err=%v", err)
	}
}

func TestHostCapabilityRuntimeForwardsFilesThroughPluginCall(t *testing.T) {
	t.Parallel()
	var request pluginsdk.PluginCallRequest
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		if call.Operation != pluginsdk.HostRuntimePluginCall {
			t.Fatalf("unexpected host operation %q", call.Operation)
		}
		request = decodePluginCallRequest(t, call)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	var result map[string]any
	if err := newHostCapabilityRuntime(client).files(context.Background(), map[string]any{
		"action": "write", "agent_id": "agent-1", "app_id": "media", "path": "config.yaml", "content": "listen: 80\n",
	}, &result); err != nil {
		t.Fatal(err)
	}
	if request.Name != pluginCallFilesName || request.AgentID != "agent-1" {
		t.Fatalf("plugin.call = %#v", request)
	}
	payload := decodePluginCallInner(t, request)
	if payload["action"] != "write" || payload["agent_id"] != "agent-1" || payload["app_id"] != "media" || payload["path"] != "config.yaml" || filesContentField(t, payload) != "listen: 80\n" {
		t.Fatalf("files handle payload = %#v", payload)
	}
	if result["accepted"] != true {
		t.Fatalf("files result=%#v", result)
	}
	if err := (*hostCapabilityRuntime)(nil).files(context.Background(), map[string]any{"agent_id": "agent-1"}, nil); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime files err=%v", err)
	}
}

func TestHostCapabilityRuntimeAcceptsFilesPathNameAndEntriesWithDockerSock(t *testing.T) {
	t.Parallel()
	var request pluginsdk.PluginCallRequest
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request = decodePluginCallRequest(t, call)
		return copyHostResult(map[string]any{
			"path": "data",
			"entries": []map[string]any{
				{"name": "docker.sock", "path": "data/docker.sock", "dir": false},
			},
		}, target)
	})
	var result map[string]any
	if err := newHostCapabilityRuntime(client).Files(context.Background(), App{ID: "media", AgentID: "agent-1"}, map[string]any{
		"action": "list", "path": "data/docker.sock",
	}, &result); err != nil {
		t.Fatal(err)
	}
	if request.Name != pluginCallFilesName {
		t.Fatalf("plugin.call = %#v", request)
	}
	payload := decodePluginCallInner(t, request)
	if payload["path"] != "data/docker.sock" {
		t.Fatalf("files path was stripped: %#v", payload)
	}
	entries, _ := result["entries"].([]any)
	if result["path"] != "data" || len(entries) != 1 {
		t.Fatalf("files list result=%#v", result)
	}
}

func TestHostCapabilityRuntimeSendsFilesContentWithoutTreatingItAsLocalEngine(t *testing.T) {
	t.Parallel()
	var request pluginsdk.PluginCallRequest
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request = decodePluginCallRequest(t, call)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	content := "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock\n"
	if err := newHostCapabilityRuntime(client).files(context.Background(), map[string]any{
		"action": "write", "agent_id": "agent-1", "app_id": "media", "path": "compose.snippet.yaml", "content": content,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if request.Name != pluginCallFilesName || request.AgentID != "agent-1" {
		t.Fatalf("plugin.call = %#v", request)
	}
	payload := decodePluginCallInner(t, request)
	if filesContentField(t, payload) != content {
		t.Fatalf("files content was stripped: %#v", payload)
	}
}

func TestHostCapabilityRuntimeSendsFilesThroughPluginCall(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallFilesName:
			return copyHostResult(map[string]any{"accepted": true, "path": "config.yaml"}, target)
		case pluginCallComposeName:
			return copyHostResult(map[string]any{"accepted": true}, target)
		default:
			t.Fatalf("unexpected plugin.call name %q", request.Name)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)
	app := App{
		ID: "media", AgentID: "agent-1", WorkDir: "/apps",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yaml:/app/config.yaml\n",
	}
	if err := runtime.ApplyApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := runtime.Files(context.Background(), app, map[string]any{
		"action": "write", "path": "config.yaml", "content": "listen: 80\n",
	}, &result); err != nil {
		t.Fatal(err)
	}
	if result["accepted"] != true {
		t.Fatalf("files result=%#v", result)
	}
	if len(calls) != 2 {
		t.Fatalf("host calls = %d", len(calls))
	}
	assertNoNamedAgentHostOps(t, calls)
	applyRequest := decodePluginCallRequest(t, calls[0])
	if calls[0].Operation != pluginsdk.HostRuntimePluginCall || applyRequest.Name != pluginCallComposeName || applyRequest.AgentID != "agent-1" {
		t.Fatalf("compose plugin.call = %#v", calls[0])
	}
	apply := decodePluginCallInner(t, applyRequest)
	if apply["action"] != "apply" || apply["workdir"] != app.WorkDir {
		t.Fatalf("compose apply payload = %#v", apply)
	}
	if calls[1].Operation != pluginsdk.HostRuntimePluginCall {
		t.Fatalf("files must use plugin.call envelope: %#v", calls[1])
	}
	request := decodePluginCallRequest(t, calls[1])
	if request.Name != pluginCallFilesName || request.AgentID != "agent-1" {
		t.Fatalf("files plugin.call = %#v", request)
	}
	payload := decodePluginCallInner(t, request)
	if payload["action"] != "write" || payload["agent_id"] != "agent-1" || payload["app_id"] != "media" || payload["path"] != "config.yaml" || payload["workdir"] != apply["workdir"] || filesContentField(t, payload) != "listen: 80\n" {
		t.Fatalf("files handle payload = %#v compose workdir=%#v", payload, apply["workdir"])
	}
	if err := runtime.Files(context.Background(), App{ID: "media"}, map[string]any{"action": "list"}, nil); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("files without agent_id err=%v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("empty agent_id dispatched files: %#v", calls)
	}
}

func TestHostCapabilityRuntimeSendsComposeVolumeBindWithoutTreatingItAsLocalEngine(t *testing.T) {
	t.Parallel()
	var request pluginsdk.PluginCallRequest
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request = decodePluginCallRequest(t, call)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	compose := "services:\n  dind:\n    image: docker:27\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
	if err := newHostCapabilityRuntime(client).ApplyApp(context.Background(), App{ID: "dind", AgentID: "agent-1", Compose: compose}); err != nil {
		t.Fatal(err)
	}
	if request.Name != pluginCallComposeName || request.AgentID != "agent-1" {
		t.Fatalf("plugin.call = %#v", request)
	}
	payload := decodePluginCallInner(t, request)
	if payload["action"] != "apply" || payload["agent_id"] != "agent-1" || payload["app_id"] != "dind" {
		t.Fatalf("compose handle payload = %#v", payload)
	}
	if !strings.Contains(payload["compose"].(string), "/var/run/docker.sock") {
		t.Fatalf("compose YAML was stripped: %#v", payload)
	}
}

func TestProductionRuntimeWiresGenericHostHandlesAndOmitsComposeGrant(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")

	config := productionControllerConfig()
	if config.UIEngineSource == nil {
		t.Fatal("production runtime still treats a zero UIEngine as the only observation path")
	}
	if _, isHost := config.UIEngineSource.(*hostCapabilityRuntime); isHost {
		t.Fatal("missing host runtime still bound a compose/engine handle")
	}
	if config.UIApply != nil || config.UIStart != nil || config.UIStop != nil || config.UIRestart != nil || config.UILogs != nil || config.UIFiles != nil || config.UIRemove != nil || config.UIDiskCleanup != nil {
		t.Fatal("missing host runtime still bound compose executors")
	}
	if config.UIHTTPRule != nil || config.UIHTTPRuleList != nil || config.UIHTTPBackendOffer != nil || config.UIImageObserver != nil || config.UIRolloutExecutor != nil || config.UIDeploymentState != nil {
		t.Fatal("missing host runtime still bound http/image/rollout handles")
	}
	if config.Admission == nil {
		t.Fatal("production admission must not require container.compose")
	}

	controller, err := NewController(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatalf("handshake without container.compose: %v", err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{
		Generation: "generation-1", Config: []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27\n","generation":"generation-1"}]}`),
	}); response.Error != nil {
		t.Fatalf("prepare without container.compose: %#v", response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatalf("activate without container.compose: %#v", response.Error)
	}
	report, err := controller.observeAgent(context.Background(), "agent-1")
	if err != nil || report.Online || report.Installed || ProjectEngine(ObservationFromReport(report)).Ready {
		t.Fatalf("missing host observation leaked readiness: %#v err=%v", report, err)
	}
	next, err := DeployComposeAppForAgent(context.Background(), nil, ComposeDeploySpec{
		AppID: "media", Generation: "generation-1", Compose: "services:\n  web:\n    image: nginx:1.27\n",
	}, AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"}, config.UIApply, AuditorFunc(func(AuditRecord) {}))
	if !errors.Is(err, ErrTypedHandlesUnavailable) || len(next) != 0 {
		t.Fatalf("missing compose handle err=%v apps=%#v", err, next)
	}
}

func TestProductionRuntimeBindsHostCapabilityWhenClientExists(t *testing.T) {
	t.Parallel()
	client := hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		t.Fatal("production bind must not call the host while constructing")
		return nil
	})
	config := bindHostCapabilityClient(ControllerConfig{}, func() (hostRuntimeCaller, error) {
		return client, nil
	})
	runtime, ok := config.UIEngineSource.(*hostCapabilityRuntime)
	if !ok || runtime == nil || runtime.client == nil {
		t.Fatalf("engine source = %#v", config.UIEngineSource)
	}
	if config.UIApply != runtime || config.UIStart != runtime || config.UIStop != runtime || config.UIRestart != runtime || config.UILogs != runtime || config.UIFiles != runtime || config.UIRemove != runtime || config.UIDiskCleanup != runtime {
		t.Fatal("compose executors were not bound to the generic host handle")
	}
	if config.UIHTTPRule != runtime || config.UIHTTPRuleList != runtime || config.UIHTTPRuleDelete != runtime || config.UIHTTPBackendOffer != runtime || config.UIImageObserver != runtime {
		t.Fatal("http.rule, catalog, and image observer were not bound to the generic host handle")
	}
	if rollout, ok := config.UIRolloutExecutor.(hostRolloutRuntime); !ok || rollout.runtime != runtime {
		t.Fatalf("rollout executor = %#v", config.UIRolloutExecutor)
	}
	store, ok := config.UIDeploymentState.(*persistedDeploymentStore)
	if !ok || store == nil || store.backend != runtime {
		t.Fatalf("deployment store = %#v", config.UIDeploymentState)
	}
}

func TestHostCapabilityRuntimeWiresHTTPImageAndRolloutHandles(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		switch call.Operation {
		case hostHTTPRuleOperation:
			var payload map[string]any
			if err := json.Unmarshal(call.Payload, &payload); err != nil {
				return err
			}
			if payload["action"] == "create" {
				if _, exists := payload["app_id"]; exists {
					t.Fatal("http.rule create must not send app_id")
				}
				return copyHostResult(map[string]any{
					"rule_ref": "rule-media-8080", "frontend_url": "https://app.example.com",
					"backend": "http://127.0.0.1:8080", "agent_id": "agent-1",
				}, target)
			}
			if payload["action"] == "list" {
				return copyHostResult(map[string]any{"rules": []map[string]any{{
					"rule_ref": "rule-media-8080", "frontend_url": "https://app.example.com",
					"backend": "http://127.0.0.1:8080", "enabled": true,
				}}}, target)
			}
			return copyHostResult(map[string]any{"accepted": true}, target)
		case hostHTTPBackendOfferOperation:
			return copyHostResult(map[string]any{"stored": true, "count": 1}, target)
		case pluginsdk.HostRuntimePluginCall:
			request := decodePluginCallRequest(t, call)
			switch request.Name {
			case pluginCallImageName:
				return copyHostResult(map[string]any{
					"current_digest": "sha256:current", "latest_digest": "sha256:latest",
				}, target)
			case pluginCallComposeName:
				payload := decodePluginCallInner(t, request)
				if payload["action"] == "start-instance" {
					return copyHostResult(map[string]any{"instance_id": "new"}, target)
				}
				return copyHostResult(map[string]any{"accepted": true}, target)
			default:
				t.Fatalf("unexpected plugin.call name %q", request.Name)
				return nil
			}
		default:
			t.Fatalf("unexpected host operation %q", call.Operation)
			return nil
		}
	})
	config := bindHostCapabilityClient(ControllerConfig{}, func() (hostRuntimeCaller, error) {
		return client, nil
	})
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:latest"}
	ruleContext := withHostOperationKey(context.Background(), "operation/ui-test")
	rule, err := config.UIHTTPRule.Create(ruleContext, HTTPRuleSpec{
		AppID: "media", AgentID: "agent-1", Domain: "https://app.example.com", Port: 8080,
	})
	if err != nil || rule.Backend != "http://127.0.0.1:8080" || rule.AgentID != "agent-1" || rule.Domain != "https://app.example.com" || rule.Port != 8080 {
		t.Fatalf("http rule=%#v err=%v", rule, err)
	}
	listed, err := config.UIHTTPRuleList.List(context.Background(), "agent-1")
	if err != nil || len(listed) != 1 || listed[0].Ref != "rule-media-8080" || listed[0].Port != 8080 || !listed[0].Enabled {
		t.Fatalf("http list=%#v err=%v", listed, err)
	}
	if err := config.UIHTTPBackendOffer.ReplaceHTTPBackendOffers(context.Background(), []HTTPBackendCatalogOffer{{
		ResourceID: "media", AgentID: "agent-1", Port: 8080, DisplayName: "media", Available: true,
	}}); err != nil {
		t.Fatal(err)
	}
	observed, err := config.UIImageObserver.ObserveImage(context.Background(), app)
	if err != nil || observed.CurrentDigest != "sha256:current" || observed.LatestDigest != "sha256:latest" {
		t.Fatalf("image observe=%#v err=%v", observed, err)
	}
	if err := config.UIRolloutExecutor.Pull(context.Background(), 1, app); err != nil {
		t.Fatal(err)
	}
	instance, err := config.UIRolloutExecutor.Start(context.Background(), 1, app)
	if err != nil || instance != "new" {
		t.Fatalf("rollout start instance=%q err=%v", instance, err)
	}
	if err := config.UIRolloutExecutor.Ready(context.Background(), 1, app, instance); err != nil {
		t.Fatal(err)
	}
	if err := config.UIRolloutExecutor.Drain(context.Background(), 1, app, "old"); err != nil {
		t.Fatal(err)
	}
	if err := config.UIRolloutExecutor.Remove(context.Background(), 1, app, "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := config.UIRolloutExecutor.Inspect(context.Background(), 1, app, "rule-media"); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 10 {
		t.Fatalf("host calls = %d", len(calls))
	}
	assertNoNamedAgentHostOps(t, calls)
	if calls[0].Operation != hostHTTPRuleOperation || calls[0].OperationID != "operation/ui-test" || !strings.Contains(string(calls[0].Payload), `"agent_id":"agent-1"`) {
		t.Fatalf("http.rule call = %#v", calls[0])
	}
	if calls[1].Operation != hostHTTPRuleOperation || !strings.Contains(string(calls[1].Payload), `"action":"list"`) {
		t.Fatalf("http.rule list call = %#v", calls[1])
	}
	if calls[2].Operation != hostHTTPBackendOfferOperation || !strings.Contains(string(calls[2].Payload), `"resource_id":"media"`) {
		t.Fatalf("http.backend-offer call = %#v", calls[2])
	}
	image := decodePluginCallRequest(t, calls[3])
	if calls[3].Operation != pluginsdk.HostRuntimePluginCall || image.Name != pluginCallImageName || image.AgentID != "agent-1" {
		t.Fatalf("image plugin.call = %#v", calls[3])
	}
	for index, call := range calls[4:] {
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallComposeName {
			t.Fatalf("rollout compose call %d = %#v", index, call)
		}
		payload := decodePluginCallInner(t, request)
		if payload["agent_id"] != "agent-1" || payload["app_id"] != "media" {
			t.Fatalf("rollout compose call %d omitted agent routing: %#v", index, payload)
		}
	}
	if err := config.UIRolloutExecutor.Ready(context.Background(), 1, App{ID: "media"}, "new"); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("ready without agent_id err=%v", err)
	}
}

func TestHostCapabilityRuntimeDeletesHTTPRuleByRef(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		if call.Operation != hostHTTPRuleOperation {
			t.Fatalf("unexpected host operation %q", call.Operation)
		}
		var payload map[string]any
		if err := json.Unmarshal(call.Payload, &payload); err != nil {
			return err
		}
		if payload["action"] != "delete" {
			t.Fatalf("payload=%#v", payload)
		}
		if _, exists := payload["domain"]; exists {
			t.Fatal("http.rule delete must not send domain")
		}
		if _, exists := payload["port"]; exists {
			t.Fatal("http.rule delete must not send port")
		}
		if payload["rule_ref"] != "rule-media-8080" || payload["agent_id"] != "agent-1" {
			t.Fatalf("payload=%#v", payload)
		}
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	config := bindHostCapabilityClient(ControllerConfig{}, func() (hostRuntimeCaller, error) {
		return client, nil
	})
	if err := config.UIHTTPRuleDelete.Delete(withHostOperationKey(context.Background(), "operation/ui-test"), "agent-1", "rule-media-8080"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].Operation != hostHTTPRuleOperation || calls[0].OperationID != "operation/ui-test" {
		t.Fatalf("http.rule delete call = %#v", calls)
	}
	if !strings.Contains(string(calls[0].Payload), `"action":"delete"`) || !strings.Contains(string(calls[0].Payload), `"rule_ref":"rule-media-8080"`) || !strings.Contains(string(calls[0].Payload), `"agent_id":"agent-1"`) {
		t.Fatalf("http.rule delete payload = %s", calls[0].Payload)
	}
	if err := config.UIHTTPRuleDelete.Delete(context.Background(), "", "rule-media-8080"); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("delete without agent_id err=%v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("empty agent_id dispatched http.rule: %#v", calls)
	}
}

func TestHostRolloutRuntimeSkipsHTTPRuleCutoverWithoutRuleRef(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, _ any) error {
		calls = append(calls, call)
		return nil
	})
	if err := (hostRolloutRuntime{}).Cutover(context.Background(), 1, "", "new"); err != nil {
		t.Fatalf("empty rule_ref without runtime err=%v", err)
	}
	rollout := hostRolloutRuntime{runtime: newHostCapabilityRuntime(client)}
	if err := rollout.Cutover(context.Background(), 1, "", "new"); err != nil {
		t.Fatal(err)
	}
	if err := rollout.Cutover(context.Background(), 1, "   ", "new"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("empty rule_ref dispatched http.rule: %#v", calls)
	}
	if err := rollout.Cutover(context.Background(), 1, "rule-media", "new"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].Operation != hostHTTPRuleOperation {
		t.Fatalf("cutover calls=%#v", calls)
	}
	if !strings.Contains(string(calls[0].Payload), `"rule_ref":"rule-media"`) || !strings.Contains(string(calls[0].Payload), `"action":"cutover"`) {
		t.Fatalf("cutover payload=%s", calls[0].Payload)
	}
}

func TestHostCapabilityRuntimeRemoveAppSendsImagesForReclaim(t *testing.T) {
	t.Parallel()
	var payload map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallComposeName {
			t.Fatalf("plugin.call = %#v", request)
		}
		payload = decodePluginCallInner(t, request)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:1.27", Compose: "services:\n  web:\n    image: nginx:1.27\n"}
	if err := newHostCapabilityRuntime(client).RemoveApp(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "remove" {
		t.Fatalf("payload=%#v", payload)
	}
	images, _ := payload["images"].([]any)
	if len(images) != 1 || images[0] != "nginx:1.27" {
		t.Fatalf("remove images=%#v", payload["images"])
	}
}

func TestHostRolloutRuntimeRemoveKeepsCurrentImages(t *testing.T) {
	t.Parallel()
	var payload map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		payload = decodePluginCallInner(t, request)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:1.28", Compose: "services:\n  web:\n    image: nginx:1.28\n"}
	if err := (hostRolloutRuntime{runtime: newHostCapabilityRuntime(client)}).Remove(context.Background(), 1, app, "old"); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "remove-instance" || payload["instance_id"] != "old" {
		t.Fatalf("payload=%#v", payload)
	}
	keep, _ := payload["keep_images"].([]any)
	if len(keep) != 1 || keep[0] != "nginx:1.28" {
		t.Fatalf("keep_images=%#v", payload["keep_images"])
	}
}

func TestHostRolloutRuntimePullAndStartSendCompose(t *testing.T) {
	t.Parallel()
	var payloads []map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		payload := decodePluginCallInner(t, request)
		payloads = append(payloads, payload)
		if payload["action"] == "start-instance" {
			return copyHostResult(map[string]any{"accepted": true, "instance_id": "new"}, target)
		}
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:latest@sha256:current", Compose: "services:\n  web:\n    image: nginx:latest@sha256:current\n"}
	rollout := hostRolloutRuntime{runtime: newHostCapabilityRuntime(client)}
	if err := rollout.Pull(context.Background(), 1, app); err != nil {
		t.Fatal(err)
	}
	instance, err := rollout.Start(context.Background(), 1, app)
	if err != nil || instance != "new" {
		t.Fatalf("start instance=%q err=%v", instance, err)
	}
	if len(payloads) != 2 {
		t.Fatalf("payloads=%#v", payloads)
	}
	if payloads[0]["action"] != "pull" || payloads[0]["compose"] != app.Compose || payloads[0]["image"] != app.Image {
		t.Fatalf("pull payload=%#v", payloads[0])
	}
	if payloads[1]["action"] != "start-instance" || payloads[1]["compose"] != app.Compose || payloads[1]["image"] != app.Image {
		t.Fatalf("start payload=%#v", payloads[1])
	}
}

func TestHostRolloutRuntimeDrainPassesKeepImagesForReclaim(t *testing.T) {
	t.Parallel()
	var payload map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		payload = decodePluginCallInner(t, request)
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:1.28", Compose: "services:\n  web:\n    image: nginx:1.28\n"}
	if err := (hostRolloutRuntime{runtime: newHostCapabilityRuntime(client)}).Drain(context.Background(), 1, app, "old"); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "drain" || payload["instance_id"] != "old" {
		t.Fatalf("payload=%#v", payload)
	}
	keep, _ := payload["keep_images"].([]any)
	if len(keep) != 1 || keep[0] != "nginx:1.28" {
		t.Fatalf("keep_images=%#v", payload["keep_images"])
	}
}

func TestHostCapabilityRuntimeDiskCleanupPreviewCancelAndPrune(t *testing.T) {
	t.Parallel()
	var payloads []map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallImageName {
			t.Fatalf("plugin.call = %#v", request)
		}
		payload := decodePluginCallInner(t, request)
		payloads = append(payloads, payload)
		action, _ := payload["action"].(string)
		confirm, _ := payload["confirm"].(bool)
		if action == "preview" {
			return copyHostResult(map[string]any{
				"accepted": true, "preview": true, "empty": false,
				"images": "untagged: nginx:old", "builder_cache": "Total: 4MB",
			}, target)
		}
		if action == "prune" && !confirm {
			return copyHostResult(map[string]any{"accepted": true, "unchanged": true, "empty": true}, target)
		}
		if action == "prune" && confirm {
			return copyHostResult(map[string]any{
				"accepted": true, "preview": false, "empty": false,
				"images": "Deleted Images:\nuntagged: nginx:old", "builder_cache": "Total: 4MB",
			}, target)
		}
		t.Fatalf("unexpected disk cleanup payload %#v", payload)
		return nil
	})
	runtime := newHostCapabilityRuntime(client)
	preview, err := runtime.PreviewDiskCleanup(context.Background(), "agent-1")
	if err != nil || !preview.Preview || preview.Empty || preview.Images == "" || preview.BuilderCache == "" {
		t.Fatalf("preview=%#v err=%v", preview, err)
	}
	canceled, err := runtime.ApplyDiskCleanup(context.Background(), "agent-1", false)
	if err != nil || !canceled.Unchanged || canceled.Preview {
		t.Fatalf("cancel=%#v err=%v", canceled, err)
	}
	applied, err := runtime.ApplyDiskCleanup(context.Background(), "agent-1", true)
	if err != nil || applied.Unchanged || applied.Empty || applied.Images == "" {
		t.Fatalf("confirm=%#v err=%v", applied, err)
	}
	if len(payloads) != 3 {
		t.Fatalf("payloads=%#v", payloads)
	}
	if payloads[0]["action"] != "preview" {
		t.Fatalf("preview payload=%#v", payloads[0])
	}
	if payloads[1]["action"] != "prune" || payloads[1]["confirm"] != false {
		t.Fatalf("cancel payload=%#v", payloads[1])
	}
	if payloads[2]["action"] != "prune" || payloads[2]["confirm"] != true {
		t.Fatalf("confirm payload=%#v", payloads[2])
	}
	if _, err := runtime.PreviewDiskCleanup(context.Background(), ""); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("missing agent err=%v", err)
	}
}

func decodePluginCallRequest(t *testing.T, call pluginsdk.HostRuntimeCall) pluginsdk.PluginCallRequest {
	t.Helper()
	if call.Operation != pluginsdk.HostRuntimePluginCall {
		t.Fatalf("host operation = %q want %q", call.Operation, pluginsdk.HostRuntimePluginCall)
	}
	var request pluginsdk.PluginCallRequest
	if err := json.Unmarshal(call.Payload, &request); err != nil {
		t.Fatalf("plugin.call envelope: %v payload=%s", err, call.Payload)
	}
	return request
}

func decodePluginCallInner(t *testing.T, request pluginsdk.PluginCallRequest) map[string]any {
	t.Helper()
	var payload map[string]any
	if len(request.Payload) == 0 {
		return payload
	}
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		t.Fatalf("plugin.call payload: %v", err)
	}
	return payload
}

func filesContentField(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, ok := payload["content"].(string)
	if !ok {
		t.Fatalf("content=%#v", payload["content"])
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("content base64: %v value=%q", err, raw)
	}
	return string(decoded)
}

func assertNoNamedAgentHostOps(t *testing.T, calls []pluginsdk.HostRuntimeCall) {
	t.Helper()
	for _, call := range calls {
		switch call.Operation {
		case "agent.engine.report", "agent.compose", "agent.image":
			t.Fatalf("production still emits %q: %#v", call.Operation, call)
		case pluginsdk.HostRuntimePluginCall, pluginsdk.HostRuntimeHTTPRule, hostHTTPBackendOfferOperation:
		default:
			t.Fatalf("unexpected host operation %q", call.Operation)
		}
	}
}

func copyHostResult(value, target any) error {
	if target == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}
