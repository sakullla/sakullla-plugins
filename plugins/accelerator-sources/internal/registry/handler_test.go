package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryProductCorpusRoutesSupportedRegistries(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testing", "corpus", "accelerator-sources", "registry", "routes.json"))
	if err != nil {
		t.Fatalf("read registry corpus: %v", err)
	}
	var cases []struct {
		Name         string `json:"name"`
		RequestPath  string `json:"request_path"`
		Registry     string `json:"registry"`
		UpstreamPath string `json:"upstream_path"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("decode registry corpus: %v", err)
	}
	handler, err := NewHandler(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			resolved, err := handler.resolve(testCase.RequestPath)
			if err != nil {
				t.Fatalf("resolve route: %v", err)
			}
			if resolved.source.Name != testCase.Registry || resolved.upstreamPath != testCase.UpstreamPath {
				t.Fatalf("resolved to %s %s, want %s %s", resolved.source.Name, resolved.upstreamPath, testCase.Registry, testCase.UpstreamPath)
			}
		})
	}
}

func TestRegistryBearerTokenAndMultiArchitectureManifest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":123,"platform":{"architecture":"amd64","os":"linux"}}]}`)
	digest := registryDigest(manifest)
	var registryServer *httptest.Server
	var tokenCalls atomic.Int32
	registryServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenCalls.Add(1)
			if request.URL.Query().Get("service") != "fixture-registry" || request.URL.Query().Get("scope") != "repository:library/alpine:pull" {
				t.Errorf("unexpected token query: %s", request.URL.RawQuery)
			}
			_, _ = io.WriteString(writer, `{"access_token":"fixture-token"}`)
		case "/v2/library/alpine/manifests/latest":
			if request.Header.Get("Authorization") != "Bearer fixture-token" {
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture-registry",scope="repository:library/alpine:pull"`, registryServer.URL+"/token"))
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			writer.Header().Set("Docker-Content-Digest", digest)
			_, _ = writer.Write(manifest)
		default:
			t.Errorf("unexpected upstream path: %s", request.URL.Path)
			http.NotFound(writer, request)
		}
	}))
	defer registryServer.Close()
	handler := newFixtureHandler(t, registryServer.URL)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v2/alpine/manifests/", nil)
	request.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), manifest) {
		t.Fatalf("unexpected manifest response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Docker-Content-Digest") != digest || tokenCalls.Load() != 1 {
		t.Fatalf("token or digest boundary not applied: calls=%d digest=%q", tokenCalls.Load(), recorder.Header().Get("Docker-Content-Digest"))
	}
}

func TestRegistryBlobRangeAndRedirect(t *testing.T) {
	blob := []byte("abcdefghij")
	digest := registryDigest(blob)
	cdn := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "bytes=2-5" {
			t.Errorf("range not forwarded: %q", request.Header.Get("Range"))
		}
		if request.Header.Get("Authorization") != "" {
			t.Error("authorization leaked across redirect authority")
		}
		writer.Header().Set("Content-Range", "bytes 2-5/10")
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(blob[2:6])
	}))
	defer cdn.Close()
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "bytes=2-5" {
			t.Errorf("range not forwarded before redirect: %q", request.Header.Get("Range"))
		}
		http.Redirect(writer, request, cdn.URL+"/layer", http.StatusTemporaryRedirect)
	}))
	defer registryServer.Close()
	handler := newFixtureHandler(t, registryServer.URL)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v2/example/app/blobs/"+digest, nil)
	request.Header.Set("Range", "bytes=2-5")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "cdef" || recorder.Header().Get("Content-Range") != "bytes 2-5/10" {
		t.Fatalf("unexpected range response: status=%d range=%q body=%q", recorder.Code, recorder.Header().Get("Content-Range"), recorder.Body.String())
	}
}

func TestRegistryLargeBlobStreamsFirstByteAndFinalDigest(t *testing.T) {
	body := bytes.Repeat([]byte("large-registry-layer-"), 128*1024)
	digest := registryDigest(body)
	release := make(chan struct{})
	firstChunk := body[:128]
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		writer.Header().Set("Docker-Content-Digest", digest)
		_, _ = writer.Write(firstChunk)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release
		_, _ = writer.Write(body[len(firstChunk):])
	}))
	defer registryServer.Close()
	handler := newFixtureHandler(t, registryServer.URL)
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	response, err := http.Get(proxy.URL + "/v2/example/app/blobs/" + digest)
	if err != nil {
		t.Fatalf("get streamed blob: %v", err)
	}
	defer response.Body.Close()
	gotFirst := make([]byte, len(firstChunk))
	if _, err := io.ReadFull(response.Body, gotFirst); err != nil {
		t.Fatalf("read first streamed bytes: %v", err)
	}
	if !bytes.Equal(gotFirst, firstChunk) {
		t.Fatal("first streamed bytes differ")
	}
	close(release)
	remainder, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read remainder: %v", err)
	}
	complete := append(append([]byte(nil), gotFirst...), remainder...)
	if !bytes.Equal(complete, body) || registryDigest(complete) != digest {
		t.Fatal("large blob was duplicated, truncated, or corrupted")
	}
}

func TestRegistryCancellationReachesUpstream(t *testing.T) {
	first := []byte("first")
	digest := registryDigest(first)
	upstreamCanceled := make(chan struct{})
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Docker-Content-Digest", digest)
		_, _ = writer.Write(first)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		<-request.Context().Done()
		close(upstreamCanceled)
	}))
	defer registryServer.Close()
	handler := newFixtureHandler(t, registryServer.URL)
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxy.URL+"/v2/example/app/blobs/"+digest, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("start cancellable stream: %v", err)
	}
	buffer := make([]byte, len(first))
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	cancel()
	_ = response.Body.Close()
	select {
	case <-upstreamCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not reach registry upstream")
	}
}

func TestRegistryMidstreamFailureDoesNotAppendError(t *testing.T) {
	prefix := []byte("partial-layer")
	digest := registryDigest(prefix)
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(prefix)+100))
		writer.Header().Set("Docker-Content-Digest", digest)
		_, _ = writer.Write(prefix)
	}))
	defer registryServer.Close()
	proxy := httptest.NewServer(newFixtureHandler(t, registryServer.URL))
	defer proxy.Close()
	response, err := http.Get(proxy.URL + "/v2/example/app/blobs/" + digest)
	if err != nil {
		t.Fatalf("start failed stream: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr == nil {
		t.Fatal("expected truncated stream error")
	}
	if !bytes.Equal(body, prefix) || bytes.Contains(body, []byte(`"errors"`)) {
		t.Fatalf("stream failure changed or appended to bytes: %q", body)
	}
}

func TestRegistryRejectsBadManifestDigestAndUnsupportedTargets(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("0", 64))
		_, _ = writer.Write(manifest)
	}))
	defer registryServer.Close()
	handler := newFixtureHandler(t, registryServer.URL)

	badDigest := httptest.NewRecorder()
	handler.ServeHTTP(badDigest, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if badDigest.Code != http.StatusBadGateway || !strings.Contains(badDigest.Body.String(), "DIGEST_INVALID") || bytes.Contains(badDigest.Body.Bytes(), manifest) {
		t.Fatalf("bad manifest was not rejected cleanly: status=%d body=%s", badDigest.Code, badDigest.Body.String())
	}

	invalidManifestServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"schemaVersion":1}`))
	}))
	defer invalidManifestServer.Close()
	invalidManifest := httptest.NewRecorder()
	newFixtureHandler(t, invalidManifestServer.URL).ServeHTTP(invalidManifest, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if invalidManifest.Code != http.StatusBadGateway || !strings.Contains(invalidManifest.Body.String(), "MANIFEST_INVALID") {
		t.Fatalf("invalid manifest response: status=%d body=%s", invalidManifest.Code, invalidManifest.Body.String())
	}

	unsupported := httptest.NewRecorder()
	handler.ServeHTTP(unsupported, httptest.NewRequest(http.MethodGet, "/v2/evil.example/app/manifests/latest", nil))
	if unsupported.Code != http.StatusNotFound || !strings.Contains(unsupported.Body.String(), "REGISTRY_UNSUPPORTED") {
		t.Fatalf("unsupported registry response: status=%d body=%s", unsupported.Code, unsupported.Body.String())
	}
}

func TestRegistryRejectsLoopbackWithoutFixtureOverride(t *testing.T) {
	endpoint, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Sources: []Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true}}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "UPSTREAM_FORBIDDEN") {
		t.Fatalf("loopback upstream was not rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func newFixtureHandler(t *testing.T, endpointValue string) *Handler {
	t.Helper()
	endpoint, err := url.Parse(endpointValue)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Sources: []Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func registryDigest(body []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(body))
}
