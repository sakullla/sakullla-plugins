package catalog

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

type catalogResolver struct{}

func (catalogResolver) Lookup(context.Context, string) (upstream.DNSResult, error) {
	return upstream.DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, TTL: time.Minute}, nil
}

func TestSearchAndTagsUseDockerHubCatalogRoutes(t *testing.T) {
	requests := make(chan *http.Request, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(request.Context())
		writer.Header().Set("Content-Type", "application/json")
		if strings.Contains(request.URL.Path, "/namespaces/") {
			_, _ = io.WriteString(writer, `{"count":1,"next":null,"previous":null,"results":[{"name":"latest","full_size":123,"tag_status":"active"}]}`)
			return
		}
		_, _ = io.WriteString(writer, `{"count":0,"next":null,"previous":null,"results":[]}`)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	manager, err := upstream.New(upstream.Options{Resolver: catalogResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager, Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ route, contains string }{
		{"/api/search?q=nginx&page_size=200", `"count":0`},
		{"/api/tags?image=alpine", `"name":"latest"`},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, fixture.route, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), fixture.contains) {
			t.Fatalf("route %q failed: status=%d body=%q", fixture.route, recorder.Code, recorder.Body.String())
		}
	}
	search := <-requests
	if search.URL.Path != "/v2/search/repositories/" || search.URL.Query().Get("query") != "nginx" || search.URL.Query().Get("page_size") != "25" {
		t.Fatalf("unexpected search request: %s", search.URL.String())
	}
	tags := <-requests
	if tags.URL.Path != "/v2/namespaces/library/repositories/alpine/tags" || tags.URL.Query().Get("page") != "1" || tags.URL.Query().Get("page_size") != "25" || tags.Header.Get("Authorization") != "" {
		t.Fatalf("unexpected tags request: %s", tags.URL.String())
	}
	if manager.Snapshot().UpstreamCalls != 2 {
		t.Fatalf("catalog bypassed shared upstream metrics: %+v", manager.Snapshot())
	}
}

func TestSearchRejectsMissingQuery(t *testing.T) {
	manager, err := upstream.New(upstream.Options{Resolver: catalogResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/search", nil))
	if recorder.Code != http.StatusBadRequest || manager.Snapshot().UpstreamCalls != 0 {
		t.Fatalf("invalid search reached upstream: status=%d metrics=%+v", recorder.Code, manager.Snapshot())
	}
}
