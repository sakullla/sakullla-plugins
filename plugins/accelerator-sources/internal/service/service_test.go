package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/sourceproxy"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

type serviceResolver struct{}

func (serviceResolver) Lookup(context.Context, string) (upstream.DNSResult, error) {
	return upstream.DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Minute}, nil
}

type loopbackResolver struct{}

func (loopbackResolver) Lookup(context.Context, string) (upstream.DNSResult, error) {
	return upstream.DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, TTL: time.Minute}, nil
}

func TestRegistryServiceExposesStandardV2Handler(t *testing.T) {
	endpoint, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Registry: registry.Options{Sources: []registry.Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}}})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Docker-Distribution-Api-Version") != "registry/2.0" {
		t.Fatalf("unexpected v2 ping: status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func TestConnectionPoolServiceCloseIsIdempotent(t *testing.T) {
	endpoint, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Registry: registry.Options{Sources: []registry.Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("closed service used upstream state: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestServiceRoutesNpmPrefixesToSourceProxy(t *testing.T) {
	const fakeMetadata = `{"fake":"npm-metadata"}`
	var upstreamPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamPaths = append(upstreamPaths, request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, fakeMetadata)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dockerEndpoint, err := url.Parse("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := upstream.New(upstream.Options{Resolver: loopbackResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{
		Upstream: manager,
		Registry: registry.Options{Sources: []registry.Source{{Name: "docker.io", Endpoint: dockerEndpoint, AllowHTTP: true, AllowPrivate: true}}},
		SourceProxy: sourceproxy.Options{
			Targets: map[string]*url.URL{
				"github.com":         endpoint,
				"registry.npmjs.org": endpoint,
			},
			AllowHTTP:    true,
			AllowPrivate: true,
		},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	defer func() { _ = handler.Close() }()
	for _, target := range []string{"/npm/express", "/registry.npmjs.org/express"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != fakeMetadata {
			t.Fatalf("%s did not stream fake npm upstream: status=%d body=%q", target, recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%s did not hit source proxy passthrough headers: content-type=%q", target, got)
		}
	}
	if len(upstreamPaths) != 2 || upstreamPaths[0] != "/express" || upstreamPaths[1] != "/express" {
		t.Fatalf("npm prefixes did not resolve to the registry path: %v", upstreamPaths)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/github.com/owner/project", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != fakeMetadata {
		t.Fatalf("existing github prefix regressed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Docker-Distribution-Api-Version") != "registry/2.0" {
		t.Fatalf("registry prefix regressed: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 || recorder.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("web fallback regressed: status=%d bytes=%d headers=%v", recorder.Code, recorder.Body.Len(), recorder.Header())
	}
}

func TestConnectionPoolExternalManagerSurvivesConstructionFailure(t *testing.T) {
	manager, err := upstream.New(upstream.Options{Resolver: serviceResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, err = NewHandler(Options{
		Upstream: manager,
		SourceProxy: sourceproxy.Options{Targets: map[string]*url.URL{
			"github.com": {Scheme: "ftp", Host: "example.com"},
		}},
	})
	if err == nil {
		t.Fatal("invalid child handler unexpectedly constructed")
	}
	request := httptest.NewRequest(http.MethodGet, "https://example.com/file", nil)
	if _, prepareErr := manager.PrepareRequest(request, upstream.Policy{}); errors.Is(prepareErr, upstream.ErrClosed) {
		t.Fatal("service closed an externally owned manager after construction failure")
	}
}
