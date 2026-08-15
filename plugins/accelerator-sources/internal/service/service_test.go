package service

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
)

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
