package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
		switch call.Operation {
		case hostAgentEngineOperation:
			return copyHostResult(map[string]any{
				"agent_id": "agent-1", "online": true,
				"engine": map[string]any{"installed": true, "version": "27.1.1"},
			}, target)
		case hostAgentComposeOperation:
			var payload map[string]any
			if err := json.Unmarshal(call.Payload, &payload); err != nil {
				return err
			}
			if payload["action"] == "logs" {
				return copyHostResult(map[string]any{"logs": "listening on :80\n"}, target)
			}
			return copyHostResult(map[string]any{"accepted": true}, target)
		default:
			t.Fatalf("unexpected host operation %q", call.Operation)
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
	if err := runtime.Start(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Restart(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	logs, err := runtime.ReadLogs(context.Background(), app.ID, "web")
	if err != nil || logs != "listening on :80\n" {
		t.Fatalf("logs=%q err=%v", logs, err)
	}
	if err := runtime.RemoveApp(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 7 {
		t.Fatalf("host calls = %d", len(calls))
	}
	if calls[0].Operation != hostAgentEngineOperation || !strings.Contains(string(calls[0].Payload), `"agent_id":"agent-1"`) {
		t.Fatalf("engine call = %#v", calls[0])
	}
	var apply map[string]any
	if err := json.Unmarshal(calls[1].Payload, &apply); err != nil {
		t.Fatal(err)
	}
	if calls[1].Operation != hostAgentComposeOperation || apply["action"] != "apply" || apply["agent_id"] != "agent-1" || apply["app_id"] != "media" {
		t.Fatalf("compose apply call = %#v payload=%#v", calls[1], apply)
	}
	for _, marker := range []string{"docker.socket", "docker.sock", "unix://", "container.compose"} {
		for _, call := range calls {
			if strings.Contains(strings.ToLower(string(call.Payload)), marker) || call.Operation == marker {
				t.Fatalf("generic handle leaked local Docker target: %#v", call)
			}
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

	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		switch call.Operation {
		case hostAgentEngineOperation:
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
	if err := unavailable.Start(context.Background(), "media"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unsupported compose handle err=%v", err)
	}
}

func TestHostCapabilityRuntimeSendsComposeVolumeBindWithoutTreatingItAsLocalEngine(t *testing.T) {
	t.Parallel()
	var payload map[string]any
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		if err := json.Unmarshal(call.Payload, &payload); err != nil {
			return err
		}
		return copyHostResult(map[string]any{"accepted": true}, target)
	})
	compose := "services:\n  dind:\n    image: docker:27\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
	if err := newHostCapabilityRuntime(client).ApplyApp(context.Background(), App{ID: "dind", AgentID: "agent-1", Compose: compose}); err != nil {
		t.Fatal(err)
	}
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
	if config.UIApply != nil || config.UIStart != nil || config.UIStop != nil || config.UIRestart != nil || config.UILogs != nil || config.UIRemove != nil {
		t.Fatal("missing host runtime still bound compose executors")
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
		GrantedScopes: []string{"http.rule", "ui.dynamic"}, Generation: "generation-1",
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
	if config.UIApply != runtime || config.UIStart != runtime || config.UIStop != runtime || config.UIRestart != runtime || config.UILogs != runtime || config.UIRemove != runtime {
		t.Fatal("compose executors were not bound to the generic host handle")
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
