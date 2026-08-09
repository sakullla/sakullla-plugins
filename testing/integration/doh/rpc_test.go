package doh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/doh"
)

func TestDoHRPCGenerationGrantsDefaultFailClosedAndEntrypoint(t *testing.T) {
	controller, err := doh.NewController(doh.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	missing := requiredRPCGrants()[1:]
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", missing)); err == nil {
		t.Fatal("missing audit grant accepted")
	}

	controller, err = doh.NewController(doh.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", requiredRPCGrants())); err != nil || response.ABI != pluginsdk.RPCABIV1 {
		t.Fatalf("handshake=%#v err=%v", response, err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationJSON(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error == nil {
		t.Fatal("default admission did not fail closed")
	}
	if _, err := controller.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "closed.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrRevoked) {
		t.Fatalf("default Serve err=%v", err)
	}

	var output bytes.Buffer
	if err := doh.RunEntrypoint(context.Background(), []string{doh.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint=%q err=%v", output.String(), err)
	}
	if err := doh.RunEntrypoint(context.Background(), nil, &output); !errors.Is(err, doh.ErrTypedHandlesUnavailable) {
		t.Fatalf("runtime entrypoint err=%v", err)
	}
}

func TestDoHRPCPreparedAdmissionServeStopRevokeAndCleanup(t *testing.T) {
	var commits, aborts, listenerCalls, resets atomic.Int32
	cache := &resetCache{Cache: doh.NewMemoryCache(8, 1<<20), resets: &resets}
	runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
	runtime.Listener = doh.ListenerFunc(func(_ context.Context, ref string, service *doh.Service) error {
		if ref != "listener/doh" || service == nil {
			t.Fatalf("listener ref=%q service=%v", ref, service)
		}
		listenerCalls.Add(1)
		return nil
	})
	controller, err := doh.NewController(doh.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: doh.TypedHandleAdmissionFunc(func(_ context.Context, request pluginsdk.RPCHandshakeRequest, configuration doh.Configuration) (doh.PreparedAdmission, error) {
			if request.Generation != configuration.Generation {
				t.Fatal("generation drift")
			}
			return doh.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (doh.RuntimeAdapters, error) { commits.Add(1); return runtime, nil }, AbortFunc: func() { aborts.Add(1) }}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", requiredRPCGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationJSON(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response, err := controller.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "rpc.example", 1), []byte("valid-token"))); err != nil || response.Status != "200" {
		t.Fatalf("Serve=%#v err=%v", response, err)
	}
	if commits.Load() != 1 || listenerCalls.Load() != 1 {
		t.Fatalf("commits=%d listener=%d", commits.Load(), listenerCalls.Load())
	}
	if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if aborts.Load() != 1 || resets.Load() != 1 {
		t.Fatalf("aborts=%d resets=%d", aborts.Load(), resets.Load())
	}
	if _, err := controller.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(2, "rpc.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrRevoked) {
		t.Fatalf("post-stop err=%v", err)
	}
}

func TestDoHRPCStopCancelsAndDrainsPublishedRequests(t *testing.T) {
	for _, stage := range []string{"policy", "cache", "resolver"} {
		t.Run(stage, func(t *testing.T) {
			started, canceled := make(chan struct{}), make(chan struct{})
			var startOnce, cancelOnce sync.Once
			block := func(ctx context.Context) error {
				startOnce.Do(func() { close(started) })
				<-ctx.Done()
				cancelOnce.Do(func() { close(canceled) })
				return ctx.Err()
			}
			cache := doh.Cache(doh.NewMemoryCache(8, 1<<20))
			if stage == "cache" {
				cache = &blockingGetCache{Cache: cache, block: block}
			}
			runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
			switch stage {
			case "policy":
				runtime.Policy = doh.IPPolicyEvaluatorFunc(func(ctx context.Context, _ string, _ doh.SourceIdentity) error { return block(ctx) })
			case "resolver":
				runtime.Resolver = doh.ResolverFunc(func(ctx context.Context, _ doh.ResolveRequest) ([]byte, error) { return nil, block(ctx) })
			}
			controller, published := activatedController(t, runtime, time.Second)
			serveResult := make(chan error, 1)
			go func() {
				_, err := published.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "drain.example", 1), []byte("valid-token")))
				serveResult <- err
			}()
			<-started
			stopResult := make(chan pluginsdk.LifecycleResponse, 1)
			go func() {
				stopResult <- controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
			}()
			<-canceled
			if _, err := published.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(2, "new.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrRevoked) {
				t.Fatalf("new request during drain err=%v", err)
			}
			if err := <-serveResult; !errors.Is(err, doh.ErrRevoked) && !errors.Is(err, context.Canceled) {
				t.Fatalf("drained request err=%v", err)
			}
			if response := <-stopResult; response.Error != nil {
				t.Fatalf("Stop=%#v", response)
			}
		})
	}
}

func TestDoHRPCStopOrdersLatePutBeforeResetAndRejectsResponse(t *testing.T) {
	cache := newBlockingPutCache()
	runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
	controller, published := activatedController(t, runtime, time.Second)
	serveResult := make(chan error, 1)
	go func() {
		_, err := published.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "put.example", 1), []byte("valid-token")))
		serveResult <- err
	}()
	<-cache.putStarted
	stopResult := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		stopResult <- controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	<-cache.putCanceled
	if _, err := published.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(2, "new.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrRevoked) {
		t.Fatalf("new request during drain err=%v", err)
	}
	close(cache.releasePut)
	if err := <-serveResult; !errors.Is(err, doh.ErrRevoked) && !errors.Is(err, context.Canceled) {
		t.Fatalf("late Put returned success err=%v", err)
	}
	if response := <-stopResult; response.Error != nil {
		t.Fatalf("Stop=%#v", response)
	}
	if events := cache.Events(); len(events) != 2 || events[0] != "put" || events[1] != "reset" {
		t.Fatalf("cleanup order=%v", events)
	}
}

func TestDoHRPCStopPropagatesRedactedCacheCleanupFailure(t *testing.T) {
	cache := &resetFailureCache{Cache: doh.NewMemoryCache(8, 1<<20)}
	runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
	controller, _ := activatedController(t, runtime, time.Second)
	response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	if response.Error == nil || response.Error.Message != doh.ErrCacheUnavailable.Error() || strings.Contains(response.Error.Message, "raw backend secret") {
		t.Fatalf("cleanup response=%#v", response)
	}
}

func TestDoHRPCTerminalSinkLateNilAfterStopNeverReturns200(t *testing.T) {
	for _, sink := range []string{"logger", "auditor"} {
		t.Run(sink, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			block := func() {
				once.Do(func() { close(started) })
				<-release
			}
			runtime := testRuntime(doh.NewMemoryCache(8, 1<<20), func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
			switch sink {
			case "logger":
				runtime.Logger = doh.QueryLoggerFunc(func(context.Context, doh.QueryLog) error { block(); return nil })
			case "auditor":
				runtime.Auditor = doh.AuditorFunc(func(_ context.Context, record doh.AuditRecord) error {
					if record.Outcome == "succeeded" {
						block()
					}
					return nil
				})
			}
			controller, published := activatedController(t, runtime, 20*time.Millisecond)
			type serveOutcome struct {
				response doh.HTTPResponse
				err      error
			}
			serveResult := make(chan serveOutcome, 1)
			go func() {
				response, err := published.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, sink+".example", 1), []byte("valid-token")))
				serveResult <- serveOutcome{response: response, err: err}
			}()
			<-started
			stopResult := make(chan pluginsdk.LifecycleResponse, 1)
			go func() {
				stopResult <- controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
			}()
			select {
			case response := <-stopResult:
				if response.Error == nil {
					t.Fatalf("non-cooperative %s allowed successful Stop", sink)
				}
			case <-time.After(time.Second):
				t.Fatalf("Stop blocked behind %s", sink)
			}
			close(release)
			select {
			case outcome := <-serveResult:
				if outcome.response.Status == "200" || outcome.err == nil {
					t.Fatalf("late %s outcome=%#v err=%v", sink, outcome.response, outcome.err)
				}
			case <-time.After(time.Second):
				t.Fatalf("request remained blocked after releasing %s", sink)
			}
		})
	}
}

func TestDoHRPCLateCommitDeadlineRevokesAndCannotPublish(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var lasting, aborts atomic.Int32
	controller, err := doh.NewController(doh.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond,
		Admission: doh.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, doh.Configuration) (doh.PreparedAdmission, error) {
			return doh.PreparedAdmissionFuncs{
				CommitFunc: func(context.Context) (doh.RuntimeAdapters, error) {
					lasting.Store(1)
					close(started)
					<-release
					return testRuntime(doh.NewMemoryCache(8, 1<<20), func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil }), nil
				},
				AbortFunc: func() { lasting.Store(0); aborts.Add(1) },
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", requiredRPCGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationJSON(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	result := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		result <- controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	<-started
	response := <-result
	if response.Error == nil || lasting.Load() != 0 || aborts.Load() != 1 {
		t.Fatalf("deadline response=%#v lasting=%d aborts=%d", response, lasting.Load(), aborts.Load())
	}
	close(release)
	time.Sleep(30 * time.Millisecond)
	if _, err := controller.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "late.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrRevoked) || lasting.Load() != 0 || aborts.Load() != 1 {
		t.Fatalf("late publish err=%v lasting=%d aborts=%d", err, lasting.Load(), aborts.Load())
	}
}

func TestDoHRPCStrictConfigMigrationAndSecretRefsOnly(t *testing.T) {
	configuration := testConfiguration()
	for name, wire := range map[string][]byte{
		"generation": configurationJSON(t, func() doh.Configuration { current := configuration; current.Generation = "other"; return current }()),
		"duplicate": configurationJSON(t, func() doh.Configuration {
			current := configuration
			current.Upstreams = append(current.Upstreams, current.Upstreams[0])
			return current
		}()),
		"plaintext-field": append(configurationJSON(t, configuration)[:len(configurationJSON(t, configuration))-1], []byte(`,"token":"raw-secret-material"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := doh.NewController(doh.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", requiredRPCGrants())); err != nil {
				t.Fatal(err)
			}
			response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire})
			if response.Error == nil || strings.Contains(response.Error.Error(), "raw-secret-material") {
				t.Fatalf("unsafe migration response=%#v", response)
			}
		})
	}
}

type resetCache struct {
	doh.Cache
	resets *atomic.Int32
}

type blockingGetCache struct {
	doh.Cache
	block func(context.Context) error
}

func (cache *blockingGetCache) Get(ctx context.Context, _ string, _ uint64) (doh.CacheEntry, bool, error) {
	return doh.CacheEntry{}, false, cache.block(ctx)
}

type blockingPutCache struct {
	*doh.MemoryCache
	putStarted  chan struct{}
	putCanceled chan struct{}
	releasePut  chan struct{}
	once        sync.Once
	mu          sync.Mutex
	events      []string
}

func newBlockingPutCache() *blockingPutCache {
	return &blockingPutCache{MemoryCache: doh.NewMemoryCache(8, 1<<20), putStarted: make(chan struct{}), putCanceled: make(chan struct{}), releasePut: make(chan struct{})}
}

func (cache *blockingPutCache) Put(ctx context.Context, key string, entry doh.CacheEntry) error {
	cache.once.Do(func() {
		close(cache.putStarted)
		go func() {
			<-ctx.Done()
			close(cache.putCanceled)
		}()
	})
	<-cache.releasePut
	cache.mu.Lock()
	cache.events = append(cache.events, "put")
	cache.mu.Unlock()
	return cache.MemoryCache.Put(context.Background(), key, entry)
}

func (cache *blockingPutCache) Reset(ctx context.Context, generation string) error {
	cache.mu.Lock()
	cache.events = append(cache.events, "reset")
	cache.mu.Unlock()
	return cache.MemoryCache.Reset(ctx, generation)
}

func (cache *blockingPutCache) Events() []string {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return append([]string(nil), cache.events...)
}

type resetFailureCache struct{ doh.Cache }

func (cache *resetFailureCache) Reset(context.Context, string) error {
	return errors.New("raw backend secret")
}

func (cache *resetCache) Reset(ctx context.Context, generation string) error {
	cache.resets.Add(1)
	return cache.Cache.Reset(ctx, generation)
}

func activatedController(t *testing.T, runtime doh.RuntimeAdapters, stopTimeout time.Duration) (*doh.Controller, *doh.Service) {
	t.Helper()
	var published *doh.Service
	runtime.Listener = doh.ListenerFunc(func(_ context.Context, _ string, service *doh.Service) error {
		published = service
		return nil
	})
	controller, err := doh.NewController(doh.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", StopTimeout: stopTimeout, DrainTimeout: stopTimeout,
		Admission: doh.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, doh.Configuration) (doh.PreparedAdmission, error) {
			return doh.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (doh.RuntimeAdapters, error) { return runtime, nil }}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1", requiredRPCGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationJSON(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if published == nil {
		t.Fatal("listener did not publish service")
	}
	return controller, published
}

func requiredRPCGrants() []string {
	return []string{"audit", "cache", "ip-policy", "listener", "log", "monotonic-clock", "network", "secret"}
}

func rpcHandshake(generation string, grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: doh.PluginID, PluginVersion: doh.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: generation}
}

func configurationJSON(t *testing.T, configuration doh.Configuration) []byte {
	t.Helper()
	wire, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
