package hostfixture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

const testSecret = "fixture-super-secret"

func TestSDKPolicyHostABI(t *testing.T) {
	host := &FakePolicyHost{
		ReadFieldFunc: func(_ context.Context, name string) ([]byte, error) { return []byte(name), nil },
		ReadBodyWindowFunc: func(_ context.Context, offset, length uint32) ([]byte, error) {
			return []byte(fmt.Sprintf("%d:%d", offset, length)), nil
		},
		StateGetFunc:  func(context.Context, string) ([]byte, bool, error) { return []byte("state"), true, nil },
		StatePutFunc:  func(context.Context, string, []byte) error { return nil },
		EmitEventFunc: func(context.Context, string, []byte) error { return nil },
		AddMetricFunc: func(context.Context, string, int64) error { return nil },
	}
	var public pluginsdk.PolicyHost = host
	value, err := public.ReadField(context.Background(), "request.method")
	if err != nil || string(value) != "request.method" {
		t.Fatalf("public PolicyHost call = %q, %v", value, err)
	}
}

func TestRPCSDKABIAndCapabilityHandshake(t *testing.T) {
	lifecycle := newLifecycle(t, rpcplugin.HookFuncs{}, nil)
	request := handshakeRequest()
	request.ABI = "nre:rpc/v2"
	if _, err := lifecycle.Handshake(context.Background(), request); !runtimeCode(err, pluginsdk.ErrorIncompatibleABI) {
		t.Fatalf("ABI mismatch error = %v", err)
	}

	lifecycle = newLifecycle(t, rpcplugin.HookFuncs{}, nil)
	response, err := lifecycle.Handshake(context.Background(), handshakeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.ABI != pluginsdk.RPCABIV1 || strings.Join(response.Capabilities, ",") != "fixture.status,resource.use" {
		t.Fatalf("unexpected handshake response: %#v", response)
	}
}

func TestGrantMissingAndImmutable(t *testing.T) {
	lifecycle := newLifecycle(t, rpcplugin.HookFuncs{}, nil)
	request := handshakeRequest()
	request.GrantedScopes = nil
	if _, err := lifecycle.Handshake(context.Background(), request); !runtimeCode(err, pluginsdk.ErrorPermissionDenied) {
		t.Fatalf("missing grant error = %v", err)
	}

	var observed []string
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		observed = generation.Grants().Scopes()
		return nil
	}}
	lifecycle = newLifecycle(t, hooks, nil)
	request = handshakeRequest()
	if _, err := lifecycle.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.GrantedScopes[0] = "mutated.after.handshake"
	// The public request slice cannot mutate the generation's immutable copy.
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if strings.Join(observed, ",") != "resource.read" {
		t.Fatalf("generation grants mutated through handshake request: %v", observed)
	}
}

func TestGenerationMismatchFailsClosed(t *testing.T) {
	lifecycle := newLifecycle(t, rpcplugin.HookFuncs{}, nil)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "stale-generation"})
	if response.Error == nil || response.Error.Code != pluginsdk.ErrorPermissionDenied {
		t.Fatalf("stale generation response = %#v", response)
	}
}

func TestRevokeGenerationOwnedHandle(t *testing.T) {
	var handle *rpcplugin.Handle[string]
	closed := 0
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		var err error
		handle, err = rpcplugin.BindHandle(generation, "resource", func(string) { closed++ })
		return err
	}}
	lifecycle := readyLifecycle(t, hooks, nil)
	if response := lifecycle.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if closed != 1 {
		t.Fatalf("handle close count = %d, want 1", closed)
	}
	if err := handle.Use(context.Background(), func(context.Context, string) error { return nil }); !errors.Is(err, rpcplugin.ErrRevoked) {
		t.Fatalf("stale handle use error = %v", err)
	}
}

func TestGenerationGracefulDrainRejectsNewAdmission(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		var err error
		handle, err = rpcplugin.BindHandle(generation, "resource", nil)
		return err
	}}
	lifecycle := readyLifecycle(t, hooks, nil)
	go func() {
		_ = handle.Use(context.Background(), func(context.Context, string) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	stopped := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		stopped <- lifecycle.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		err := handle.Use(context.Background(), func(context.Context, string) error { return nil })
		if errors.Is(err, rpcplugin.ErrDraining) || errors.Is(err, rpcplugin.ErrRevoked) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("generation continued admitting work during drain")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case response := <-stopped:
		t.Fatalf("Stop completed before in-flight call: %#v", response)
	default:
	}
	close(release)
	if response := <-stopped; response.Error != nil {
		t.Fatal(response.Error)
	}
}

func TestSecretNeverAppearsInStatusLogOrError(t *testing.T) {
	var recordsMu sync.Mutex
	var records []rpcplugin.Record
	sink := rpcplugin.LogSinkFunc(func(_ context.Context, record rpcplugin.Record) {
		recordsMu.Lock()
		records = append(records, record)
		recordsMu.Unlock()
	})
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(ctx context.Context, generation *rpcplugin.Generation, _ []byte) error {
		secret, err := generation.Secret("vault://fixture", []byte(testSecret))
		if err != nil {
			return err
		}
		if fmt.Sprint(secret) != "[REDACTED]" {
			return errors.New("secret formatter exposed material")
		}
		if err := secret.WithBytes(func(material []byte) error {
			if string(material) != testSecret {
				return errors.New("secret callback received wrong material")
			}
			return nil
		}); err != nil {
			return err
		}
		generation.Log(ctx, "info", "resolved "+testSecret, map[string]string{"token": testSecret})
		status := generation.Status("ready "+testSecret, map[string]string{"detail": testSecret})
		if strings.Contains(fmt.Sprint(status), testSecret) {
			return errors.New("status exposed secret")
		}
		return fmt.Errorf("upstream rejected %s", testSecret)
	}}
	lifecycle := newLifecycle(t, hooks, sink)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error == nil || strings.Contains(response.Error.Message, testSecret) {
		t.Fatalf("unsafe lifecycle error: %#v", response.Error)
	}
	status := lifecycle.Status("stopped "+testSecret, map[string]string{"detail": testSecret})
	if strings.Contains(fmt.Sprint(status), testSecret) {
		t.Fatalf("unsafe post-revoke status: %#v", status)
	}
	recordsMu.Lock()
	defer recordsMu.Unlock()
	if len(records) != 1 || strings.Contains(fmt.Sprint(records[0]), testSecret) {
		t.Fatalf("unsafe log records: %#v", records)
	}
}

func TestGenerationDeadlineBoundsPrepare(t *testing.T) {
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(ctx context.Context, _ *rpcplugin.Generation, _ []byte) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	lifecycle := newLifecycleWithTimeouts(t, hooks, nil, rpcplugin.Timeouts{
		Prepare: 10 * time.Millisecond, Activate: time.Second, Stop: time.Second, Drain: time.Second,
	})
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error == nil || response.Error.Code != pluginsdk.ErrorDeadlineExceeded {
		t.Fatalf("deadline response = %#v", response)
	}
}

func newLifecycle(t *testing.T, hooks rpcplugin.Hooks, sink rpcplugin.LogSink) *rpcplugin.Lifecycle {
	t.Helper()
	return newLifecycleWithTimeouts(t, hooks, sink, rpcplugin.Timeouts{
		Prepare: time.Second, Activate: time.Second, Stop: time.Second, Drain: time.Second,
	})
}

func newLifecycleWithTimeouts(t *testing.T, hooks rpcplugin.Hooks, sink rpcplugin.LogSink, timeouts rpcplugin.Timeouts) *rpcplugin.Lifecycle {
	t.Helper()
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: "fixture", PluginVersion: "1.0.0", PackageDigest: "package", ArtifactDigest: "artifact",
		Capabilities: []string{"resource.use", "fixture.status"}, RequiredGrants: []string{"resource.read"},
		Timeouts: timeouts, LogSink: sink,
	}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle
}

func handshakeRequest() pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: "fixture", PluginVersion: "1.0.0",
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: []string{"resource.read"},
		Generation: "generation-1",
	}
}

func readyLifecycle(t *testing.T, hooks rpcplugin.Hooks, sink rpcplugin.LogSink) *rpcplugin.Lifecycle {
	t.Helper()
	lifecycle := newLifecycle(t, hooks, sink)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return lifecycle
}

func runtimeCode(err error, code pluginsdk.ErrorCode) bool {
	var runtimeErr *pluginsdk.RuntimeError
	return errors.As(err, &runtimeErr) && runtimeErr.Code == code
}
