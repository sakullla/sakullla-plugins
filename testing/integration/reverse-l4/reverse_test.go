package reversel4_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
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
	now := time.Unix(10, 0)
	clock := newFakeClock(now)
	session, err := reversel4.NewSession(testMapping("tcp-map", reversel4.ProtocolTCP), "generation-1", backoff, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(false); !errors.Is(err, reversel4.ErrMTLSRequired) {
		t.Fatalf("non-mTLS authentication error = %v", err)
	}
	snapshot := session.Snapshot()
	if snapshot.State != reversel4.StateUnavailable || snapshot.Accepting || snapshot.LastFailure == "" {
		t.Fatalf("unavailable status = %#v", snapshot)
	}
	clock.Advance(backoff.Minimum - time.Nanosecond)
	if err := session.Retry(); !errors.Is(err, reversel4.ErrRetryNotReady) {
		t.Fatalf("early reconnect error = %v", err)
	}
	if err := session.BeginConnect(); !errors.Is(err, reversel4.ErrInvalidState) {
		t.Fatalf("direct connect bypassed reconnect schedule: %v", err)
	}
	if err := session.Retry(); !errors.Is(err, reversel4.ErrRetryNotReady) {
		t.Fatalf("repeated early retry error = %v", err)
	}
	clock.Advance(time.Nanosecond)
	if err := session.Retry(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(false); !errors.Is(err, reversel4.ErrMTLSRequired) {
		t.Fatalf("second non-mTLS authentication error = %v", err)
	}
	if got := session.Snapshot().ReconnectAt; !got.Equal(now.Add(backoff.Minimum + 2*backoff.Minimum)) {
		t.Fatalf("second reconnect at %s", got)
	}
	if delay := backoff.Delay(100); delay != backoff.Maximum {
		t.Fatalf("bounded backoff delay = %s, want %s", delay, backoff.Maximum)
	}
}

func TestReverseDisconnectUsesHostClockInternally(t *testing.T) {
	start := time.Unix(100, 0)
	clock := newFakeClock(start)
	session, err := reversel4.NewSession(testMapping("tcp-map", reversel4.ProtocolTCP), "generation-1", testBackoff(), clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(true); err != nil {
		t.Fatal(err)
	}
	if observed := session.Snapshot().ObservedAt; !observed.Equal(start) {
		t.Fatalf("authenticate observed time = %s", observed)
	}
	clock.Advance(time.Second)
	if err := session.Disconnect("network unavailable"); err != nil {
		t.Fatal(err)
	}
	snapshot := session.Snapshot()
	want := start.Add(time.Second + testBackoff().Minimum)
	if !snapshot.ObservedAt.Equal(start.Add(time.Second)) || !snapshot.ReconnectAt.Equal(want) {
		t.Fatalf("host-clock disconnect snapshot = %#v want reconnect=%s", snapshot, want)
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

func TestReverseRevokeDrainTargetCannotBeDowngraded(t *testing.T) {
	for _, order := range []string{"disable-revoke", "revoke-disable"} {
		t.Run(order, func(t *testing.T) {
			session := authenticatedSession(t, testMapping("tcp-map", reversel4.ProtocolTCP))
			flow, err := session.Admit("generation-1")
			if err != nil {
				t.Fatal(err)
			}
			if order == "disable-revoke" {
				session.BeginDisable()
				session.Revoke()
			} else {
				session.Revoke()
				session.BeginDisable()
			}
			flow.Close()
			snapshot := session.Snapshot()
			if snapshot.State != reversel4.StateRevoked || !snapshot.ReleaseRequired {
				t.Fatalf("drain order %s = %#v", order, snapshot)
			}
			if err := session.AcknowledgeRelease(); err != nil {
				t.Fatal(err)
			}
			if session.Snapshot().ReleaseRequired {
				t.Fatal("release acknowledgement not recorded")
			}
		})
	}
}

func TestReverseFlowAliasesShareOneReleaseToken(t *testing.T) {
	session := authenticatedSession(t, testMapping("tcp-map", reversel4.ProtocolTCP))
	first, err := session.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	alias := *first
	session.BeginDisable()
	var wait sync.WaitGroup
	for _, flow := range []*reversel4.Flow{first, &alias, first, &alias} {
		wait.Add(1)
		go func(flow *reversel4.Flow) { defer wait.Done(); flow.Close() }(flow)
	}
	wait.Wait()
	if snapshot := session.Snapshot(); snapshot.InFlight != 1 || snapshot.State != reversel4.StateDraining {
		t.Fatalf("alias released another real flow: %#v", snapshot)
	}
	other.Close()
	if snapshot := session.Snapshot(); snapshot.InFlight != 0 || snapshot.State != reversel4.StateDisabled {
		t.Fatalf("final real flow did not finish drain: %#v", snapshot)
	}

	single := authenticatedSession(t, testMapping("udp-map", reversel4.ProtocolUDP))
	only, err := single.Admit("generation-1")
	if err != nil {
		t.Fatal(err)
	}
	onlyAlias := *only
	only.Close()
	onlyAlias.Close()
	if snapshot := single.Snapshot(); snapshot.InFlight != 0 {
		t.Fatalf("single aliased flow underflowed: %#v", snapshot)
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
		session, err = reversel4.NewSession(testMapping("tcp-map", reversel4.ProtocolTCP), generation.ID(), testBackoff(), newFakeClock(time.Unix(20, 0)))
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
	if err := session.Authenticate(true); err != nil {
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

func TestReverseControllerCanonicalRPCLifecycleFailsClosedAtTypedHandles(t *testing.T) {
	controller, err := reversel4.NewController(reversel4.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", Clock: newFakeClock(time.Unix(30, 0)), Backoff: testBackoff(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := handshakeRequest([]string{"reverse-session"})
	if response, err := controller.Handshake(context.Background(), request); err != nil || response.ABI != pluginsdk.RPCABIV1 {
		t.Fatalf("controller handshake response=%#v err=%v", response, err)
	}
	config := []byte(`{"mappings":[{"id":"tcp-map","private_agent_id":"private-agent","public_agent_id":"public-agent","protocol":"tcp","listen_port":8443,"backend_host":"127.0.0.1","backend_port":9443,"enabled":true}]}`)
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if mapping, exists := controller.Mapping("tcp-map"); !exists || !mapping.Enabled {
		t.Fatalf("prepared mapping = %#v exists=%v", mapping, exists)
	}
	if snapshot, exists := controller.Session("tcp-map"); !exists || snapshot.State != reversel4.StateDisconnected {
		t.Fatalf("prepared session = %#v exists=%v", snapshot, exists)
	}
	response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error == nil || response.Error.Code != pluginsdk.ErrorInternal {
		t.Fatalf("typed-handle gate response = %#v", response)
	}
	if snapshot, _ := controller.Session("tcp-map"); snapshot.State != reversel4.StateRevoked || !snapshot.ReleaseRequired {
		t.Fatalf("failed activation did not revoke model session: %#v", snapshot)
	}
}

func TestReverseEntrypointValidatesPublicRPCHandshakeOnly(t *testing.T) {
	var output bytes.Buffer
	if err := reversel4.RunEntrypoint(context.Background(), []string{reversel4.CIHandshakeFlag}, &output); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("RPC ABI output = %q", output.String())
	}
	if err := reversel4.RunEntrypoint(context.Background(), nil, &output); !errors.Is(err, reversel4.ErrTypedServiceHandlesUnavailable) {
		t.Fatalf("runtime entrypoint did not fail closed: %v", err)
	}
}

func authenticatedSession(t *testing.T, mapping reversel4.Mapping) *reversel4.Session {
	t.Helper()
	session, err := reversel4.NewSession(mapping, "generation-1", testBackoff(), newFakeClock(time.Unix(1, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.BeginConnect(); err != nil {
		t.Fatal(err)
	}
	if err := session.Authenticate(true); err != nil {
		t.Fatal(err)
	}
	return session
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
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
