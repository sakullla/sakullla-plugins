package cloudflaredns_test

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
	cloudflaredns "github.com/sakullla/sakullla-plugins/plugins/cloudflare-dns"
)

func TestCloudflareRPCGrantsGenerationAndDefaultFailClosed(t *testing.T) {
	controller, err := cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake([]string{"authorizer", "cloudflare-dns", "dynamic-ui", "log", "vault-secret"})); err == nil {
		t.Fatal("missing audit grant accepted")
	}
	controller, err = cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil || response.ABI != pluginsdk.RPCABIV1 {
		t.Fatalf("handshake=%#v err=%v", response, err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error == nil {
		t.Fatal("default admission did not fail closed")
	}
	if err := controller.Use(context.Background(), func(context.Context, *cloudflaredns.Service) error { return nil }); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("default Use err=%v", err)
	}
}

func TestCloudflareRPCInjectedLifecycleRevokeAndCleanup(t *testing.T) {
	vault, trace := newFakeVault(), &safeTrace{}
	runtime := runtimeFor(vault, newFakeDNS(vault), trace)
	var commits, aborts atomic.Int32
	controller, err := cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: cloudflaredns.TypedHandleAdmissionFunc(func(_ context.Context, request pluginsdk.RPCHandshakeRequest, configuration cloudflaredns.Configuration) (cloudflaredns.PreparedAdmission, error) {
		if request.Generation != configuration.Generation {
			t.Fatal("generation drift")
		}
		return cloudflaredns.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (cloudflaredns.RuntimeAdapters, error) { commits.Add(1); return runtime, nil }, AbortFunc: func() { aborts.Add(1) }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if err := controller.Use(context.Background(), func(ctx context.Context, service *cloudflaredns.Service) error {
		_, err := service.ListZones(ctx, validAction(""))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if commits.Load() != 1 {
		t.Fatalf("commits=%d", commits.Load())
	}
	if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if aborts.Load() != 1 {
		t.Fatalf("aborts=%d", aborts.Load())
	}
	if err := controller.Use(context.Background(), func(context.Context, *cloudflaredns.Service) error { return nil }); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("post-stop err=%v", err)
	}
}

func TestCloudflareRPCActivateLoadsEmptyCatalogAndResolves(t *testing.T) {
	vault, trace := newFakeVault(), &safeTrace{}
	runtime := runtimeFor(vault, newFakeDNS(vault), trace)
	controller, err := cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: cloudflaredns.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, cloudflaredns.Configuration) (cloudflaredns.PreparedAdmission, error) {
		return cloudflaredns.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (cloudflaredns.RuntimeAdapters, error) { return runtime, nil }, AbortFunc: func() {}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if err := controller.Use(context.Background(), func(ctx context.Context, service *cloudflaredns.Service) error {
		if _, err := service.CreateMapping(ctx, validAction(""), "example.com", []byte("token-mapped")); err != nil {
			return err
		}
		hit, err := service.ResolveToken(ctx, validAction(""), "www.example.com", []byte("token-fallback"))
		if err != nil {
			return err
		}
		defer hit.Clear()
		if hit.Fallback || !bytes.Equal(hit.Token(), []byte("token-mapped")) {
			t.Fatalf("hit=%#v token=%q", hit, hit.Token())
		}
		miss, err := service.ResolveToken(ctx, validAction(""), "other.test", []byte("token-fallback"))
		if err != nil {
			return err
		}
		defer miss.Clear()
		if !miss.Fallback || !bytes.Equal(miss.Token(), []byte("token-fallback")) {
			t.Fatalf("miss=%#v token=%q", miss, miss.Token())
		}
		_, err = service.ResolveToken(ctx, validAction(""), "missing.example", nil)
		if !errors.Is(err, cloudflaredns.ErrTokenUnavailable) || !strings.Contains(err.Error(), "missing.example") {
			t.Fatalf("unmapped err=%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCloudflareRPCLateAdmissionCannotPublishAndAborts(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var lasting, aborts atomic.Int32
	vault, trace := newFakeVault(), &safeTrace{}
	runtime := runtimeFor(vault, newFakeDNS(vault), trace)
	controller, err := cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond, Admission: cloudflaredns.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, cloudflaredns.Configuration) (cloudflaredns.PreparedAdmission, error) {
		return cloudflaredns.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (cloudflaredns.RuntimeAdapters, error) {
			lasting.Store(1)
			close(started)
			<-release
			return runtime, nil
		}, AbortFunc: func() { lasting.Store(0); aborts.Add(1) }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configurationWire(t, testConfiguration())}); response.Error != nil {
		t.Fatal(response.Error)
	}
	result := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		result <- controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	<-started
	response := <-result
	if response.Error == nil || lasting.Load() != 0 || aborts.Load() != 1 {
		t.Fatalf("deadline=%#v lasting=%d aborts=%d", response, lasting.Load(), aborts.Load())
	}
	close(release)
	time.Sleep(30 * time.Millisecond)
	if err := controller.Use(context.Background(), func(context.Context, *cloudflaredns.Service) error { return nil }); !errors.Is(err, cloudflaredns.ErrRevoked) || lasting.Load() != 0 || aborts.Load() != 1 {
		t.Fatalf("late err=%v lasting=%d aborts=%d", err, lasting.Load(), aborts.Load())
	}
}

func TestCloudflareRPCStrictConfigAndCanonicalEntrypoint(t *testing.T) {
	for name, wire := range map[string][]byte{
		"generation": configurationWire(t, cloudflaredns.Configuration{Generation: "other", SecretRef: "vault/cloudflare", ResourceGroupRef: "group/main"}),
		"plaintext":  append(configurationWire(t, testConfiguration())[:len(configurationWire(t, testConfiguration()))-1], []byte(`,"token":"raw-secret-material"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := cloudflaredns.NewController(cloudflaredns.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
				t.Fatal(err)
			}
			response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire})
			if response.Error == nil || strings.Contains(response.Error.Error(), "raw-secret-material") {
				t.Fatalf("response=%#v", response)
			}
		})
	}
	var output bytes.Buffer
	if err := cloudflaredns.RunEntrypoint(context.Background(), []string{cloudflaredns.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint=%q err=%v", output.String(), err)
	}
	if err := cloudflaredns.RunEntrypoint(context.Background(), nil, &output); !errors.Is(err, cloudflaredns.ErrTypedHandlesUnavailable) {
		t.Fatalf("default entrypoint=%v", err)
	}
}

func runtimeFor(vault *fakeVault, dns *fakeDNS, trace *safeTrace) cloudflaredns.RuntimeAdapters {
	return cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Operations: fakeInspector{vault: vault}, Lease: cloudflaredns.GenerationLeaseFunc(func() {}), Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, record cloudflaredns.UIProjection) error { trace.addUI(record); return nil }), Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error { trace.addAudit(record); return nil }), Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error { trace.addLog(record); return nil })}
}
func requiredGrants() []string {
	return []string{"audit", "authorizer", "cloudflare-dns", "dynamic-ui", "log", "vault-secret"}
}
func handshake(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: cloudflaredns.PluginID, PluginVersion: cloudflaredns.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1"}
}
func configurationWire(t *testing.T, configuration cloudflaredns.Configuration) []byte {
	t.Helper()
	wire, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
