package service

import (
	"context"
	"errors"
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
