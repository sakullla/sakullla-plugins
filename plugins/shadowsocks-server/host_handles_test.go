package shadowsocksserver

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

func TestHostListenRuntimeUsesPluginCall(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallListenReport:
			return copyHostResult(map[string]any{
				"agent_id": "agent-1", "online": true,
				"listens": []map[string]any{{"id": "listen-1", "port": 8388, "tcp": true, "udp": true}},
			}, target)
		case pluginCallListenApply:
			payload := decodePluginCallInner(t, request)
			if payload["agent_id"] != "agent-1" {
				t.Fatalf("apply payload=%#v", payload)
			}
			return copyHostResult(map[string]any{
				"accepted": true, "agent_id": "agent-1",
				"listens": []map[string]any{{"id": "listen-1", "port": 8388, "tcp": true, "udp": true}},
			}, target)
		case pluginCallListenStop:
			return copyHostResult(map[string]any{"accepted": true, "agent_id": "agent-1", "listens": []any{}}, target)
		default:
			t.Fatalf("unexpected plugin.call name %q", request.Name)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)

	report, err := runtime.Report(context.Background(), "agent-1")
	if err != nil || !report.Online || report.AgentID != "agent-1" || len(report.Listens) != 1 || report.Listens[0].Port != 8388 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if err := runtime.Apply(context.Background(), "agent-1", []ListenApplyItem{{
		ID: "listen-1", Port: 8388, Method: "aes-256-gcm",
		Users: []ListenApplyUser{{ID: "alice", Enabled: true, Password: "alice-password"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if !runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("successful apply did not mark listen live")
	}
	if err := runtime.Stop(context.Background(), "agent-1", []string{"listen-1"}); err != nil {
		t.Fatal(err)
	}
	if runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("stop left listen marked live")
	}

	if len(calls) != 3 {
		t.Fatalf("host calls = %d", len(calls))
	}
	for i, call := range calls {
		if call.Operation != pluginsdk.HostRuntimePluginCall {
			t.Fatalf("call %d operation=%q", i, call.Operation)
		}
	}
	apply := decodePluginCallRequest(t, calls[1])
	if apply.Name != pluginCallListenApply || apply.AgentID != "agent-1" || !strings.Contains(string(apply.Payload), `"agent_id":"agent-1"`) {
		t.Fatalf("apply call=%#v", apply)
	}
	inner := decodePluginCallInner(t, apply)
	if inner["agent_id"] != "agent-1" {
		t.Fatalf("apply inner=%#v", inner)
	}
}

func TestHostListenOfflineAgentIDDoesNotDispatch(t *testing.T) {
	t.Parallel()
	var calls int
	client := hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		calls++
		return nil
	})
	runtime := newHostCapabilityRuntime(client)
	listens := []ListenApplyItem{{ID: "listen-1", Port: 8388, Method: "aes-256-gcm"}}
	if _, err := runtime.Report(context.Background(), ""); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("report err=%v", err)
	}
	if err := runtime.Apply(context.Background(), "", listens); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("apply err=%v", err)
	}
	if err := runtime.Stop(context.Background(), "  ", nil); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("stop err=%v", err)
	}
	if calls != 0 {
		t.Fatalf("missing agent id dispatched plugin.call: %d", calls)
	}
	if runtime.HasLiveListen("", "listen-1") || runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("offline agent id marked a listen live")
	}
}

func TestHostListenApplyBindFailureDoesNotMarkLive(t *testing.T) {
	t.Parallel()
	var calls int
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, _ any) error {
		calls++
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallListenApply {
			t.Fatalf("unexpected name %q", request.Name)
		}
		return ErrListenBind
	})
	runtime := newHostCapabilityRuntime(client)
	if err := runtime.Apply(context.Background(), "agent-1", []ListenApplyItem{{
		ID: "listen-1", Port: 8388, Method: "aes-256-gcm",
	}}); !errors.Is(err, ErrListenBind) {
		t.Fatalf("apply err=%v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	if runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("bind failure still marked listen live")
	}
	if live := runtime.LiveListens("agent-1"); len(live) != 0 {
		t.Fatalf("live=%#v", live)
	}
}

func TestHostControllerOfflineAgentIDDoesNotApply(t *testing.T) {
	t.Parallel()
	var calls int
	client := hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		calls++
		return nil
	})
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ListenRuntime: newHostCapabilityRuntime(client),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplyListen(context.Background(), "", []ListenApplyItem{{ID: "listen-1", Port: 8388, Method: "aes-256-gcm"}}); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("apply err=%v", err)
	}
	if _, err := controller.ReportListen(context.Background(), ""); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("report err=%v", err)
	}
	if err := controller.StopListen(context.Background(), "", nil); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("stop err=%v", err)
	}
	if calls != 0 {
		t.Fatalf("controller dispatched plugin.call without agent id: %d", calls)
	}
}

func TestHostListenRuntimeFailClosedWithoutClient(t *testing.T) {
	t.Parallel()
	if runtime := newHostCapabilityRuntime(nil); runtime != nil {
		t.Fatal("nil host client still constructed a runtime")
	}
	if _, err := (*hostCapabilityRuntime)(nil).Report(context.Background(), "agent-1"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime report err=%v", err)
	}
	if err := (*hostCapabilityRuntime)(nil).Apply(context.Background(), "agent-1", nil); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime apply err=%v", err)
	}
}

func TestHostProductionRuntimeBindsPluginCallWithoutTypedListener(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")

	config := productionControllerConfig()
	if config.ListenRuntime != nil {
		t.Fatal("missing host runtime still bound plugin.call")
	}
	if config.Admission == nil {
		t.Fatal("production admission must not require typed Listener.Register")
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
		t.Fatal(err)
	}
	wire, err := json.Marshal(Configuration{Generation: "generation-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); result.Error != nil {
		t.Fatalf("prepare: %#v", result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatalf("activate without typed listener: %#v", result.Error)
	}
	if err := controller.Use(context.Background(), func(context.Context, *Service) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatalf("production activate published a typed Service: %v", err)
	}
}

func TestHostProductionBindsHostCapabilityWhenClientExists(t *testing.T) {
	t.Parallel()
	client := hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		t.Fatal("production bind must not call the host while constructing")
		return nil
	})
	config := bindHostCapabilityClient(ControllerConfig{}, func() (hostRuntimeCaller, error) {
		return client, nil
	})
	if config.ListenRuntime == nil || config.ListenRuntime.client == nil {
		t.Fatalf("listen runtime = %#v", config.ListenRuntime)
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
