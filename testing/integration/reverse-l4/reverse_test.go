package reversel4_test

import (
	"context"
	"errors"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
	reversel4 "github.com/sakullla/sakullla-plugins/plugins/reverse-l4"
)

func TestReverseTCPUDPMappingOwner(t *testing.T) {
	store := reversel4.NewMappingStore()
	tcp := testMapping("tcp-map", reversel4.ProtocolTCP)
	udp := testMapping("udp-map", reversel4.ProtocolUDP)
	udp.ListenPort = 5353
	if err := store.Put(tcp); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(udp); err != nil {
		t.Fatal(err)
	}
	listed := store.List()
	if len(listed) != 2 || listed[0].ID != "tcp-map" || listed[1].ID != "udp-map" {
		t.Fatalf("mapping list = %#v", listed)
	}
	disabled, err := store.Disable(tcp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("mapping owner did not persist disabled state")
	}
	invalid := tcp
	invalid.BackendHost = "https://plugin-owned-dial.example/path"
	if err := store.Put(invalid); err == nil {
		t.Fatal("mapping accepted URL instead of a bounded backend host")
	}
}

func TestReverseReconnectRequiresMTLSSessionAndBoundedBackoff(t *testing.T) {
	backoff := testBackoff()
	session, err := reversel4.NewSession(testMapping("tcp-map", reversel4.ProtocolTCP), "generation-1", backoff)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10, 0)
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(false, now); !errors.Is(err, reversel4.ErrMTLSRequired) {
		t.Fatalf("non-mTLS authentication error = %v", err)
	}
	snapshot := session.Snapshot()
	if snapshot.State != reversel4.StateUnavailable || snapshot.Accepting || snapshot.LastFailure == "" {
		t.Fatalf("unavailable status = %#v", snapshot)
	}
	if err := session.Retry(now.Add(backoff.Minimum - time.Nanosecond)); !errors.Is(err, reversel4.ErrRetryNotReady) {
		t.Fatalf("early reconnect error = %v", err)
	}
	if err := session.BeginConnect(); !errors.Is(err, reversel4.ErrInvalidState) {
		t.Fatalf("direct connect bypassed reconnect schedule: %v", err)
	}
	if err := session.Retry(now.Add(backoff.Minimum)); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(false, now.Add(backoff.Minimum)); !errors.Is(err, reversel4.ErrMTLSRequired) {
		t.Fatalf("second non-mTLS authentication error = %v", err)
	}
	if got := session.Snapshot().ReconnectAt; !got.Equal(now.Add(backoff.Minimum + 2*backoff.Minimum)) {
		t.Fatalf("second reconnect at %s", got)
	}
	if delay := backoff.Delay(100); delay != backoff.Maximum {
		t.Fatalf("bounded backoff delay = %s, want %s", delay, backoff.Maximum)
	}
}

func TestReverseTCPUDPAuthenticatedAdmission(t *testing.T) {
	for _, protocol := range []reversel4.Protocol{reversel4.ProtocolTCP, reversel4.ProtocolUDP} {
		t.Run(string(protocol), func(t *testing.T) {
			session := authenticatedSession(t, testMapping(string(protocol)+"-map", protocol))
			flow, err := session.Admit("generation-1")
			if err != nil {
				t.Fatal(err)
			}
			flow.Close()
			if snapshot := session.Snapshot(); snapshot.State != reversel4.StateAuthenticated || snapshot.InFlight != 0 {
				t.Fatalf("authenticated %s state = %#v", protocol, snapshot)
			}
		})
	}
}

func TestReverseDisableDrainIsAdmissionFirst(t *testing.T) {
	session := authenticatedSession(t, testMapping("tcp-map", reversel4.ProtocolTCP))
	first, err := session.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	session.BeginDisable()
	if _, err := session.Admit("generation-1"); !errors.Is(err, reversel4.ErrAdmissionClosed) {
		t.Fatalf("admission during drain error = %v", err)
	}
	if snapshot := session.Snapshot(); snapshot.State != reversel4.StateDraining || snapshot.InFlight != 2 || snapshot.ReleaseRequired {
		t.Fatalf("initial drain state = %#v", snapshot)
	}
	first.Close()
	if snapshot := session.Snapshot(); snapshot.State != reversel4.StateDraining || snapshot.InFlight != 1 {
		t.Fatalf("partial drain state = %#v", snapshot)
	}
	second.Close()
	second.Close()
	if snapshot := session.Snapshot(); snapshot.State != reversel4.StateDisabled || snapshot.InFlight != 0 || !snapshot.ReleaseRequired {
		t.Fatalf("completed drain state = %#v", snapshot)
	}
	if err := session.AcknowledgeRelease(); err != nil {
		t.Fatal(err)
	}
	if session.Snapshot().ReleaseRequired {
		t.Fatal("release acknowledgement was not recorded")
	}
}

func TestReverseGrantAndGenerationFailClosed(t *testing.T) {
	lifecycle := newLifecycle(t, rpcplugin.HookFuncs{})
	request := handshakeRequest(nil)
	if _, err := lifecycle.Handshake(context.Background(), request); !runtimeCode(err, pluginsdk.ErrorPermissionDenied) {
		t.Fatalf("missing reverse-session grant error = %v", err)
	}

	var session *reversel4.Session
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		var err error
		session, err = reversel4.NewSession(testMapping("tcp-map", reversel4.ProtocolTCP), generation.ID(), testBackoff())
		return err
	}}
	lifecycle = newLifecycle(t, hooks)
	request = handshakeRequest([]string{"fixture.reverse-session"})
	if _, err := lifecycle.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(true, time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Admit("stale-generation"); !errors.Is(err, reversel4.ErrGenerationMismatch) {
		t.Fatalf("stale generation admission error = %v", err)
	}
	flow, err := session.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	session.Revoke()
	if _, err := session.Admit("generation-1"); !errors.Is(err, reversel4.ErrAdmissionClosed) {
		t.Fatalf("revoked admission error = %v", err)
	}
	flow.Close()
	if snapshot := session.Snapshot(); snapshot.State != reversel4.StateRevoked || !snapshot.ReleaseRequired {
		t.Fatalf("revoked drain state = %#v", snapshot)
	}
}

func TestReverseRuntimeFailsClosedWithoutTypedHandles(t *testing.T) {
	err := reversel4.AdmitRuntime(pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1,
		GrantedScopes: []string{
			"fixture.claims.typed-handles",
		},
	})
	if !errors.Is(err, reversel4.ErrTypedServiceHandlesUnavailable) {
		t.Fatalf("string-only capability gate error = %v", err)
	}
	var runtimeErr *pluginsdk.RuntimeError
	if err := reversel4.AdmitRuntime(pluginsdk.RPCHandshakeRequest{ABI: "nre:rpc/v2"}); !errors.As(err, &runtimeErr) || runtimeErr.Code != pluginsdk.ErrorIncompatibleABI {
		t.Fatalf("ABI gate error = %v", err)
	}
}

func authenticatedSession(t *testing.T, mapping reversel4.Mapping) *reversel4.Session {
	t.Helper()
	session, err := reversel4.NewSession(mapping, "generation-1", testBackoff())
	if err != nil {
		t.Fatal(err)
	}
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(true, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	return session
}

func testMapping(id string, protocol reversel4.Protocol) reversel4.Mapping {
	return reversel4.Mapping{
		ID: id, PrivateAgentID: "private-agent", PublicAgentID: "public-agent", Protocol: protocol,
		ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443, Enabled: true,
	}
}

func testBackoff() reversel4.Backoff {
	return reversel4.Backoff{Minimum: 100 * time.Millisecond, Maximum: 2 * time.Second, Factor: 2}
}

func newLifecycle(t *testing.T, hooks rpcplugin.Hooks) *rpcplugin.Lifecycle {
	t.Helper()
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: "reverse-l4", PluginVersion: "0.1.0", PackageDigest: "package", ArtifactDigest: "artifact",
		Capabilities: []string{"fixture.reverse-l4-model"}, RequiredGrants: []string{"fixture.reverse-session"},
		Timeouts: rpcplugin.Timeouts{Prepare: time.Second, Activate: time.Second, Stop: time.Second, Drain: time.Second},
	}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func handshakeRequest(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: "reverse-l4", PluginVersion: "0.1.0",
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1",
	}
}

func runtimeCode(err error, code pluginsdk.ErrorCode) bool {
	var runtimeErr *pluginsdk.RuntimeError
	return errors.As(err, &runtimeErr) && runtimeErr.Code == code
}
