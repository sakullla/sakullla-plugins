package doh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
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

func (cache *resetCache) Reset(ctx context.Context, generation string) error {
	cache.resets.Add(1)
	return cache.Cache.Reset(ctx, generation)
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
