package shadowsocksserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

type reservation struct{}

func (reservation) Consume(context.Context, uint64) error { return nil }
func (reservation) Finish(context.Context) error          { return nil }
func (reservation) Abort(context.Context) error           { return nil }

type runtime struct {
	listened    atomic.Int32
	now         uint64
	secrets     map[string]string
	registerErr error
}

func (*runtime) Verify(context.Context, string, string, []byte) error { return nil }
func (r *runtime) Resolve(_ context.Context, ref, _ string) ([]byte, error) {
	if value, ok := r.secrets[ref]; ok {
		return []byte(value), nil
	}
	return []byte("fixture-password"), nil
}
func (*runtime) Reserve(context.Context, string, uint64, string) (ss.TrafficReservation, error) {
	return reservation{}, nil
}
func (r *runtime) Now(context.Context) (uint64, error) {
	if r.now != 0 {
		return r.now, nil
	}
	return 1, nil
}
func (*runtime) Admit(context.Context, string, []byte) error { return nil }
func (r *runtime) Register(context.Context, string, *ss.Service) error {
	r.listened.Add(1)
	return r.registerErr
}
func (*runtime) Rotate(context.Context, string, string, string, string) (*ss.SecretOnce, error) {
	return ss.NewSecretOnce("secret/new", "v2", []byte("one-time")), nil
}
func (*runtime) Audit(context.Context, ss.AuditRecord) error { return nil }
func (r *runtime) adapters() ss.RuntimeAdapters {
	return ss.RuntimeAdapters{Secrets: r, Traffic: r, Clock: r, Replay: r, Listener: r, Vault: r, Auditor: r}
}

func listenRules(method string, users []ss.User) []ss.ListenRule {
	if len(users) == 0 {
		return []ss.ListenRule{{ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: method}}
	}
	if ss.SS2022Method(method) {
		return []ss.ListenRule{{ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: method, Users: users}}
	}
	out := make([]ss.ListenRule, len(users))
	for i, user := range users {
		out[i] = ss.ListenRule{ID: "listener-" + user.ID, AgentID: "agent-1", Port: 8388 + i, Method: method, Users: []ss.User{user}}
	}
	return out
}

func config() ss.Configuration {
	return ss.Configuration{Generation: "generation-1", Listeners: listenRules("aes-256-gcm", []ss.User{{ID: "alice", SecretRef: "secret/alice", SecretVersion: "v1", Enabled: true}})}
}
func wire(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(config())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func grants() []string {
	return []string{"secret.use", "storage.read", "storage.write", "event.emit", "service.revocable-resource-handle", pluginsdk.PermissionNetworkFull}
}
func handshake(scopes []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: ss.PluginID, PluginVersion: ss.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: scopes, Generation: "generation-1"}
}

func TestShadowsocksRPCGenerationGrantsAndDefaultFailClosed(t *testing.T) {
	c, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Handshake(context.Background(), handshake(grants()[:len(grants())-1])); err == nil {
		t.Fatal("missing network.full grant accepted")
	}
	c, _ = ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if _, err = c.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if result := c.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire(t)}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := c.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error == nil {
		t.Fatal("default typed admission accepted")
	}
}
func TestShadowsocksRPCInjectedTCPUDPDrainAndRevoke(t *testing.T) {
	r := &runtime{}
	var aborts atomic.Int32
	c, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: ss.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, ss.Configuration) (ss.PreparedAdmission, error) {
		return ss.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (ss.RuntimeAdapters, error) { return r.adapters(), nil }, AbortFunc: func() { aborts.Add(1) }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if x := c.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire(t)}); x.Error != nil {
		t.Fatal(x.Error)
	}
	if x := c.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); x.Error != nil {
		t.Fatal(x.Error)
	}
	if r.listened.Load() != 1 {
		t.Fatalf("listener=%d", r.listened.Load())
	}
	if x := c.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); x.Error != nil {
		t.Fatal(x.Error)
	}
	if aborts.Load() != 1 {
		t.Fatalf("aborts=%d", aborts.Load())
	}
	if err := c.Use(context.Background(), func(context.Context, *ss.Service) error { return nil }); !errors.Is(err, ss.ErrRevoked) {
		t.Fatalf("post-stop=%v", err)
	}
}

func TestShadowsocksRPCPortConflictAbortsPreparedAdmissionAndDoesNotPublish(t *testing.T) {
	portConflict := errors.New("bind: address already in use: credential-must-not-leak")
	r := &runtime{registerErr: portConflict}
	var aborts atomic.Int32
	c, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: ss.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, ss.Configuration) (ss.PreparedAdmission, error) {
		return ss.PreparedAdmissionFuncs{
			CommitFunc: func(context.Context) (ss.RuntimeAdapters, error) { return r.adapters(), nil },
			AbortFunc:  func() { aborts.Add(1) },
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if result := c.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire(t)}); result.Error != nil {
		t.Fatal(result.Error)
	}
	result := c.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if result.Error == nil || strings.Contains(result.Error.Error(), "credential-must-not-leak") {
		t.Fatalf("unsafe conflict result=%#v", result)
	}
	if r.listened.Load() != 1 || aborts.Load() != 1 {
		t.Fatalf("listener attempts=%d aborts=%d", r.listened.Load(), aborts.Load())
	}
	if err = c.Use(context.Background(), func(context.Context, *ss.Service) error { return nil }); !errors.Is(err, ss.ErrRevoked) {
		t.Fatalf("conflicted service published: %v", err)
	}

	// A failed generation does not poison an independent generation/controller.
	goodRuntime := &runtime{}
	good, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: ss.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, ss.Configuration) (ss.PreparedAdmission, error) {
		return ss.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (ss.RuntimeAdapters, error) { return goodRuntime.adapters(), nil }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = good.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if response := good.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire(t)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := good.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if goodRuntime.listened.Load() != 1 {
		t.Fatalf("independent listener=%d", goodRuntime.listened.Load())
	}
}
func TestShadowsocksCanonicalRPCEntrypointAndSecretRedact(t *testing.T) {
	var output bytes.Buffer
	if err := ss.RunEntrypoint(context.Background(), []string{ss.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
	t.Setenv("NRE_PLUGIN_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("NRE_PLUGIN_HTTP_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_HTTP_COOKIE_FILE", "")
	err := ss.RunEntrypoint(context.Background(), nil, &output)
	if err == nil {
		t.Fatal("RunEntrypoint() unexpectedly succeeded without host endpoints")
	}
	if errors.Is(err, ss.ErrTypedHandlesUnavailable) {
		t.Fatalf("RunEntrypoint() returned the old startup sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("RunEntrypoint() error = %v, want canonical SDK endpoint validation", err)
	}
	c, _ := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	_, _ = c.Handshake(context.Background(), handshake(grants()))
	bad := append(wire(t)[:len(wire(t))-1], []byte(`,"password":"raw-secret"}`)...)
	result := c.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: bad})
	if result.Error == nil || strings.Contains(result.Error.Error(), "raw-secret") {
		t.Fatalf("unsafe result=%#v", result)
	}
}
