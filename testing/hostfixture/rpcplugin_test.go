package hostfixture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

func TestGrantRequiredForHandleCreation(t *testing.T) {
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		_, err := rpcplugin.BindHandle(generation, "resource.write", "resource", nil)
		return err
	}}
	lifecycle := newLifecycle(t, hooks, nil)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Success != nil || response.Error == nil || response.Error.Code != pluginsdk.ErrorPermissionDenied {
		t.Fatalf("missing handle grant response = %#v", response)
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
		handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", func(string) { closed++ })
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
		handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
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
		generation.Log(ctx, "level-"+testSecret, "resolved "+testSecret, map[string]string{
			"token-" + testSecret: testSecret,
			"token-[REDACTED]":    "collision-value",
		})
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
	if len(records[0].Fields) != 2 {
		t.Fatalf("redacted field-key collision lost data: %#v", records[0].Fields)
	}
	if records[0].Level != "level-[REDACTED]" {
		t.Fatalf("secret-bearing level was not redacted: %q", records[0].Level)
	}
	if _, ok := records[0].Fields["token-[REDACTED]"]; !ok {
		t.Fatalf("redacted field key is missing: %#v", records[0].Fields)
	}
	if _, ok := records[0].Fields["token-[REDACTED]#2"]; !ok {
		t.Fatalf("colliding redacted field key was not preserved: %#v", records[0].Fields)
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

func TestGenerationDeadlineRejectsLateNilPrepare(t *testing.T) {
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(ctx context.Context, generation *rpcplugin.Generation, _ []byte) error {
		var err error
		handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
		if err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}}
	lifecycle := newLifecycleWithShortPhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertDeadlineAndRevoked(t, response, handle)
}

func TestGenerationDeadlineRejectsLateNilActivate(t *testing.T) {
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		ActivateFunc: func(ctx context.Context, _ *rpcplugin.Generation) error {
			<-ctx.Done()
			return nil
		},
	}
	lifecycle := newLifecycleWithShortPhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	response := lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertDeadlineAndRevoked(t, response, handle)
}

func TestGenerationDeadlineRejectsLateNilStop(t *testing.T) {
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		StopFunc: func(ctx context.Context, _ *rpcplugin.Generation) error {
			<-ctx.Done()
			return nil
		},
	}
	lifecycle := newLifecycleWithShortPhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	response := lifecycle.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertDeadlineAndRevoked(t, response, handle)
}

func TestGenerationDeadlineBoundsNonCooperativePrepare(t *testing.T) {
	blocker := newNonCooperativeHook()
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
		var err error
		handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
		if err != nil {
			return err
		}
		return blocker.Wait()
	}}
	lifecycle := newLifecycleWithNonCooperativePhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	assertNonCooperativeHookIsolated(t, lifecycle, blocker, func() pluginsdk.LifecycleResponse {
		return lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}, func() *rpcplugin.Handle[string] { return handle })
}

func TestGenerationDeadlineBoundsNonCooperativeActivate(t *testing.T) {
	blocker := newNonCooperativeHook()
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		ActivateFunc: func(context.Context, *rpcplugin.Generation) error { return blocker.Wait() },
	}
	lifecycle := newLifecycleWithNonCooperativePhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	assertNonCooperativeHookIsolated(t, lifecycle, blocker, func() pluginsdk.LifecycleResponse {
		return lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}, func() *rpcplugin.Handle[string] { return handle })
}

func TestGenerationDeadlineBoundsNonCooperativeStop(t *testing.T) {
	blocker := newNonCooperativeHook()
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		StopFunc: func(context.Context, *rpcplugin.Generation) error { return blocker.Wait() },
	}
	lifecycle := newLifecycleWithNonCooperativePhase(t, hooks)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	assertNonCooperativeHookIsolated(t, lifecycle, blocker, func() pluginsdk.LifecycleResponse {
		return lifecycle.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}, func() *rpcplugin.Handle[string] { return handle })
}

func TestGenerationPreCanceledPrepareDoesNotInvokeHook(t *testing.T) {
	var calls atomic.Int32
	hooks := rpcplugin.HookFuncs{PrepareFunc: func(context.Context, *rpcplugin.Generation, []byte) error {
		calls.Add(1)
		return nil
	}}
	lifecycle := newLifecycle(t, hooks, nil)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := lifecycle.Prepare(ctx, pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertPreCanceledHookRejected(t, lifecycle, response, pluginsdk.ErrorUnavailable, calls.Load(), nil, func() pluginsdk.LifecycleResponse {
		return lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	})
}

func TestGenerationPreExpiredActivateDoesNotInvokeHook(t *testing.T) {
	var calls atomic.Int32
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		ActivateFunc: func(context.Context, *rpcplugin.Generation) error {
			calls.Add(1)
			return nil
		},
	}
	lifecycle := newLifecycle(t, hooks, nil)
	if _, err := lifecycle.Handshake(context.Background(), handshakeRequest()); err != nil {
		t.Fatal(err)
	}
	if response := lifecycle.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	response := lifecycle.Activate(ctx, pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertPreCanceledHookRejected(t, lifecycle, response, pluginsdk.ErrorDeadlineExceeded, calls.Load(), handle, func() pluginsdk.LifecycleResponse {
		return lifecycle.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	})
}

func TestGenerationPreCanceledStopDoesNotInvokeHook(t *testing.T) {
	var calls atomic.Int32
	var handle *rpcplugin.Handle[string]
	hooks := rpcplugin.HookFuncs{
		PrepareFunc: func(_ context.Context, generation *rpcplugin.Generation, _ []byte) error {
			var err error
			handle, err = rpcplugin.BindHandle(generation, "resource.read", "resource", nil)
			return err
		},
		StopFunc: func(context.Context, *rpcplugin.Generation) error {
			calls.Add(1)
			return nil
		},
	}
	lifecycle := readyLifecycle(t, hooks, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := lifecycle.Stop(ctx, pluginsdk.LifecycleRequest{Generation: "generation-1"})
	assertPreCanceledHookRejected(t, lifecycle, response, pluginsdk.ErrorUnavailable, calls.Load(), handle, func() pluginsdk.LifecycleResponse {
		return lifecycle.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	})
}

func assertPreCanceledHookRejected(
	t *testing.T,
	lifecycle *rpcplugin.Lifecycle,
	response pluginsdk.LifecycleResponse,
	expectedCode pluginsdk.ErrorCode,
	calls int32,
	handle *rpcplugin.Handle[string],
	retry func() pluginsdk.LifecycleResponse,
) {
	t.Helper()
	if calls != 0 {
		t.Fatalf("pre-canceled lifecycle invoked hook %d time(s)", calls)
	}
	if response.Success != nil || response.Error == nil || response.Error.Code != expectedCode {
		t.Fatalf("pre-canceled lifecycle response = %#v", response)
	}
	assertLifecycleStopped(t, lifecycle)
	if handle != nil {
		if err := handle.Use(context.Background(), func(context.Context, string) error { return nil }); !errors.Is(err, rpcplugin.ErrRevoked) {
			t.Fatalf("handle use after pre-canceled lifecycle error = %v", err)
		}
	}
	retryResponse := retry()
	if retryResponse.Success != nil || retryResponse.Error == nil || retryResponse.Error.Code != pluginsdk.ErrorInvalidArgument {
		t.Fatalf("terminal lifecycle accepted retry: %#v", retryResponse)
	}
}

type nonCooperativeHook struct {
	started chan struct{}
	release chan struct{}
	done    chan struct{}
}

func newNonCooperativeHook() *nonCooperativeHook {
	return &nonCooperativeHook{
		started: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Wait deliberately ignores the lifecycle context. release exists only to
// reap the test goroutine after proving that the lifecycle did not wait for it.
func (hook *nonCooperativeHook) Wait() error {
	close(hook.started)
	<-hook.release
	close(hook.done)
	return nil
}

func assertNonCooperativeHookIsolated(
	t *testing.T,
	lifecycle *rpcplugin.Lifecycle,
	hook *nonCooperativeHook,
	call func() pluginsdk.LifecycleResponse,
	handle func() *rpcplugin.Handle[string],
) {
	t.Helper()
	responses := make(chan pluginsdk.LifecycleResponse, 1)
	go func() { responses <- call() }()
	select {
	case <-hook.started:
	case response := <-responses:
		t.Fatalf("lifecycle returned before non-cooperative hook started: %#v", response)
	case <-time.After(time.Second):
		t.Fatal("non-cooperative hook did not start")
	}

	var response pluginsdk.LifecycleResponse
	select {
	case response = <-responses:
	case <-time.After(time.Second):
		close(hook.release)
		t.Fatal("lifecycle did not return at hook deadline")
	}
	assertDeadlineAndRevoked(t, response, handle())
	assertLifecycleStopped(t, lifecycle)
	retry := call()
	if retry.Success != nil || retry.Error == nil || retry.Error.Code != pluginsdk.ErrorInvalidArgument {
		t.Fatalf("terminal lifecycle accepted a retry: %#v", retry)
	}
	select {
	case <-hook.done:
		t.Fatal("non-cooperative hook unexpectedly returned before test release")
	default:
	}

	close(hook.release)
	select {
	case <-hook.done:
	case <-time.After(time.Second):
		t.Fatal("released late hook did not return")
	}
	// The late nil result has no state-commit authority.
	assertLifecycleStopped(t, lifecycle)
}

func assertLifecycleStopped(t *testing.T, lifecycle *rpcplugin.Lifecycle) {
	t.Helper()
	status := lifecycle.Status("fixture", nil)
	if phase := status.Fields["phase"]; phase != "stopped" {
		t.Fatalf("lifecycle phase after deadline = %q, want stopped", phase)
	}
}

func newLifecycleWithNonCooperativePhase(t *testing.T, hooks rpcplugin.Hooks) *rpcplugin.Lifecycle {
	t.Helper()
	return newLifecycleWithTimeouts(t, hooks, nil, rpcplugin.Timeouts{
		Prepare:  50 * time.Millisecond,
		Activate: 50 * time.Millisecond,
		Stop:     50 * time.Millisecond,
		Drain:    time.Second,
	})
}

func newLifecycleWithShortPhase(t *testing.T, hooks rpcplugin.Hooks) *rpcplugin.Lifecycle {
	t.Helper()
	return newLifecycleWithTimeouts(t, hooks, nil, rpcplugin.Timeouts{
		Prepare:  10 * time.Millisecond,
		Activate: 10 * time.Millisecond,
		Stop:     10 * time.Millisecond,
		Drain:    time.Second,
	})
}

func assertDeadlineAndRevoked(t *testing.T, response pluginsdk.LifecycleResponse, handle *rpcplugin.Handle[string]) {
	t.Helper()
	if response.Success != nil || response.Error == nil || response.Error.Code != pluginsdk.ErrorDeadlineExceeded {
		t.Fatalf("late-nil deadline response = %#v", response)
	}
	if handle == nil {
		t.Fatal("test hook did not create a generation handle")
	}
	if err := handle.Use(context.Background(), func(context.Context, string) error { return nil }); !errors.Is(err, rpcplugin.ErrRevoked) {
		t.Fatalf("handle use after deadline error = %v", err)
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
