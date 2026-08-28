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
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls++
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallListenApply:
			return ErrListenBind
		case pluginCallListenReport:
			return copyHostResult(map[string]any{"agent_id": "agent-1", "online": true, "listens": []any{}}, target)
		default:
			t.Fatalf("unexpected name %q", request.Name)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)
	if err := runtime.Apply(context.Background(), "agent-1", []ListenApplyItem{{
		ID: "listen-1", Port: 8388, Method: "aes-256-gcm",
	}}); !errors.Is(err, ErrListenBind) {
		t.Fatalf("apply err=%v", err)
	}
	if calls < 1 {
		t.Fatalf("calls=%d", calls)
	}
	if runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("bind failure still marked listen live")
	}
	if live := runtime.LiveListens("agent-1"); len(live) != 0 {
		t.Fatalf("live=%#v", live)
	}
}

func TestHostListenApplyErrorRefreshesLiveFromAgentReport(t *testing.T) {
	t.Parallel()
	applied := 0
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		switch request.Name {
		case pluginCallListenApply:
			applied++
			if applied == 1 {
				return copyHostResult(map[string]any{
					"accepted": true, "agent_id": "agent-1",
					"listens": []map[string]any{{"id": "listen-1", "port": 8388, "tcp": true, "udp": true}},
				}, target)
			}
			return ErrListenBind
		case pluginCallListenReport:
			return copyHostResult(map[string]any{"agent_id": "agent-1", "online": true, "listens": []any{}}, target)
		default:
			t.Fatalf("unexpected name %q", request.Name)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)
	if err := runtime.Apply(context.Background(), "agent-1", []ListenApplyItem{{
		ID: "listen-1", Port: 8388, Method: "aes-256-gcm",
	}}); err != nil {
		t.Fatal(err)
	}
	if !runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("successful apply did not mark listen live")
	}
	if err := runtime.Apply(context.Background(), "agent-1", []ListenApplyItem{{
		ID: "listen-1", Port: 8389, Method: "aes-256-gcm",
	}}); !errors.Is(err, ErrListenBind) {
		t.Fatalf("apply err=%v", err)
	}
	if runtime.HasLiveListen("agent-1", "listen-1") {
		t.Fatal("apply error left stale live listen")
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
	if config.ListenState == nil {
		t.Fatal("production bind omitted listen catalog state")
	}
}

func TestHostCapabilityRuntimePersistsListensThroughHostState(t *testing.T) {
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
		if payload.Key != pluginListensStateKey && payload.Key != pluginSecretsStateKey && payload.Key != pluginNodesStateKey {
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
	want := []ListenRule{{
		ID: "listen-1", AgentID: "agent-1", Port: 8388, Method: DefaultSS2022Method,
		ServerSecretRef: "secret/server/listen-1", ServerSecretVersion: "v1",
		Users: []User{{ID: "acct-1", Name: "alice", SecretRef: "secret/acct-1", SecretVersion: "v1", Enabled: true}},
	}}
	if err := runtime.StoreListens(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, found, err := runtime.LoadListens(context.Background())
	if err != nil || !found || len(got) != 1 || got[0].ID != want[0].ID || got[0].AgentID != want[0].AgentID || got[0].Port != want[0].Port {
		t.Fatalf("LoadListens()=(%#v,%t,%v)", got, found, err)
	}
	secrets := map[string]string{issuedSecretKey("secret/acct-1", "v1"): "user-psk"}
	if err := runtime.StoreSecrets(context.Background(), secrets); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := runtime.LoadSecrets(context.Background())
	if err != nil || !found || loaded[issuedSecretKey("secret/acct-1", "v1")] != "user-psk" {
		t.Fatalf("LoadSecrets()=(%#v,%t,%v)", loaded, found, err)
	}
	if len(calls) != 4 || calls[0].Operation != "state.put" || calls[1].Operation != "state.get" || calls[2].Operation != "state.put" || calls[3].Operation != "state.get" {
		t.Fatalf("state calls=%#v", calls)
	}
}

func TestHostListenShareUsesCatalogNodeWithoutPluginCallIdentity(t *testing.T) {
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		switch call.Operation {
		case pluginsdk.HostRuntimePluginCall:
			request := decodePluginCallRequest(t, call)
			if request.Name != pluginCallListenReport {
				t.Fatalf("unexpected plugin.call name %q", request.Name)
			}
			return copyHostResult(ListenReport{AgentID: request.AgentID, Online: true}, target)
		case pluginNodeAddressesOp:
			return copyHostResult(map[string]any{"ddns_domain": "catalog.example.com", "ipv4": "198.51.100.8"}, target)
		default:
			t.Fatalf("unexpected host operation %q", call.Operation)
			return nil
		}
	})
	runtime := newHostCapabilityRuntime(client)
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ListenRuntime: runtime,
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return RuntimeAdapters{}, nil
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(Configuration{Generation: "generation-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	node := controller.shareNode(context.Background(), "agent-1")
	if node.DDNS != "catalog.example.com" || node.IPv4 != "198.51.100.8" {
		t.Fatalf("share node=%#v", node)
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
