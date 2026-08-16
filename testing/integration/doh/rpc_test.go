package doh_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/doh"
)

func TestDoHRPCEmptyConfigActivatesHTTPBackend(t *testing.T) {
	controller := newDoHController(t)
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1")); err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{nil, []byte("{}"), []byte(`{"upstreams":""}`)} {
		fresh := newDoHController(t)
		if _, err := fresh.Handshake(context.Background(), rpcHandshake("generation-1")); err != nil {
			t.Fatal(err)
		}
		if response := fresh.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: config}); response.Error != nil {
			t.Fatalf("prepare config=%q err=%v", config, response.Error)
		}
		if response := fresh.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
			t.Fatalf("activate config=%q err=%v", config, response.Error)
		}
		recorder := httptest.NewRecorder()
		fresh.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dns-query", nil))
		if recorder.Code == http.StatusServiceUnavailable {
			t.Fatalf("active handler was unavailable for config=%q", config)
		}
		if response := fresh.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
			t.Fatal(response.Error)
		}
		recorder = httptest.NewRecorder()
		fresh.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dns-query", nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("stopped handler status=%d", recorder.Code)
		}
	}
}

func TestDoHRPCRejectsUnknownConfigAndMissingGrant(t *testing.T) {
	controller := newDoHController(t)
	missing := rpcHandshake("generation-1")
	missing.GrantedScopes = nil
	if _, err := controller.Handshake(context.Background(), missing); err == nil {
		t.Fatal("missing http.outbound grant accepted")
	}

	controller = newDoHController(t)
	if _, err := controller.Handshake(context.Background(), rpcHandshake("generation-1")); err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{
		[]byte(`{"legacy":true}`),
		[]byte(`{"listener_ref":"listener/doh"}`),
		[]byte(`[]`),
		[]byte(`{"upstreams":[]}`),
		[]byte(`{"upstreams":[{"id":"one","endpoint":"1.1.1.1:53","priority":0,"enabled":true}]}`),
		[]byte("{\"upstreams\":\"ftp://example.com\"}"),
	} {
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: config}); response.Error == nil {
			t.Fatalf("invalid config accepted: %s", config)
		}
	}
}

func TestDoHRPCInactiveHandlerIsUnavailable(t *testing.T) {
	controller := newDoHController(t)
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dns-query", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", recorder.Code)
	}
}

func TestDoHRPCEntrypointHandshakeAndRuntimeStart(t *testing.T) {
	var output bytes.Buffer
	if err := doh.RunEntrypoint(context.Background(), []string{doh.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint=%q err=%v", output.String(), err)
	}
	err := doh.RunEntrypoint(context.Background(), nil, &output)
	if err == nil || strings.Contains(err.Error(), doh.ErrTypedHandlesUnavailable.Error()) {
		t.Fatalf("runtime entrypoint err=%v", err)
	}
}

func newDoHController(t *testing.T) *doh.Controller {
	t.Helper()
	controller, err := doh.NewController(doh.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func rpcHandshake(generation string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: doh.PluginID, PluginVersion: doh.PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: generation,
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
}
