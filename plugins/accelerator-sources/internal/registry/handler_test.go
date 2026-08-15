package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	upstreamclient "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
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
	var manifestCalls atomic.Int32
	var unauthenticatedRemote, authenticatedRemote string
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
				unauthenticatedRemote = request.RemoteAddr
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture-registry",scope="repository:library/alpine:pull"`, registryServer.URL+"/token"))
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(writer, "bounded challenge body")
				return
			}
			authenticatedRemote = request.RemoteAddr
			manifestCalls.Add(1)
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
	if unauthenticatedRemote == "" || authenticatedRemote != unauthenticatedRemote {
		t.Fatalf("401 body was not drained for connection reuse: unauth=%q auth=%q", unauthenticatedRemote, authenticatedRemote)
	}
	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodGet, "/v2/alpine/manifests/", nil)
	secondRequest.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")
	handler.ServeHTTP(second, secondRequest)
	if second.Code != http.StatusOK || tokenCalls.Load() != 1 || manifestCalls.Load() != 1 {
		t.Fatalf("warm token/manifest cache missed: token=%d manifest=%d status=%d", tokenCalls.Load(), manifestCalls.Load(), second.Code)
	}
	differentAccept := httptest.NewRecorder()
	differentRequest := httptest.NewRequest(http.MethodGet, "/v2/alpine/manifests/", nil)
	differentRequest.Header.Set("Accept", "application/vnd.docker.distribution.manifest.list.v2+json")
	handler.ServeHTTP(differentAccept, differentRequest)
	if differentAccept.Code != http.StatusOK || tokenCalls.Load() != 1 || manifestCalls.Load() != 2 {
		t.Fatalf("manifest Accept cache key collapsed: token=%d manifest=%d status=%d", tokenCalls.Load(), manifestCalls.Load(), differentAccept.Code)
	}
}

func TestTokenCacheIssuedAtEarlyRefreshAndRepeated401(t *testing.T) {
	clock := &registryFakeClock{now: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}
	var tokenCalls atomic.Int32
	var tokenServer *httptest.Server
	tokenServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := tokenCalls.Add(1)
		_, _ = fmt.Fprintf(writer, `{"token":"token-%d","issued_at":%q,"expires_in":60}`, call, clock.Now().Format(time.RFC3339))
	}))
	defer tokenServer.Close()
	handler := newClockFixtureHandler(t, tokenServer.URL, clock)
	resolved, err := handler.resolve("/v2/example/app/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	challenge := fmt.Sprintf(`Bearer realm=%q,service="fixture",scope="repository:example/app:pull"`, tokenServer.URL)
	first, _, err := handler.fetchToken(context.Background(), resolved, challenge)
	if err != nil || first.Value != "token-1" {
		t.Fatalf("initial token: %+v %v", first, err)
	}
	clock.Advance(29 * time.Second)
	second, _, err := handler.fetchToken(context.Background(), resolved, challenge)
	if err != nil || second != first || tokenCalls.Load() != 1 {
		t.Fatalf("token refreshed before boundary: %+v calls=%d err=%v", second, tokenCalls.Load(), err)
	}
	clock.Advance(2 * time.Second)
	third, _, err := handler.fetchToken(context.Background(), resolved, challenge)
	if err != nil || third.Version != first.Version || third.Value != "token-1" {
		t.Fatalf("early refresh did not serve valid stale token: %+v calls=%d err=%v", third, tokenCalls.Load(), err)
	}
	var refreshed upstreamclient.TokenEntry
	for deadline := time.Now().Add(time.Second); ; {
		refreshed, _, err = handler.fetchToken(context.Background(), resolved, challenge)
		if err == nil && refreshed.Value == "token-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background token refresh did not publish: %+v calls=%d err=%v", refreshed, tokenCalls.Load(), err)
		}
		time.Sleep(time.Millisecond)
	}
	if refreshed.Version == first.Version || tokenCalls.Load() != 2 {
		t.Fatalf("token refresh version/call boundary: first=%+v refreshed=%+v calls=%d", first, refreshed, tokenCalls.Load())
	}

	received := time.Date(2026, 8, 15, 1, 0, 0, 0, time.UTC)
	expiresAt, refreshAt, err := tokenCacheTiming(received, received.Add(-10*time.Second).Format(time.RFC3339), 100)
	if err != nil || !expiresAt.Equal(received.Add(90*time.Second)) || !refreshAt.Equal(received.Add(60*time.Second)) {
		t.Fatalf("issued_at timing: expiry=%s refresh=%s err=%v", expiresAt, refreshAt, err)
	}
	if ttl, swr := tokenCacheWindows(received, refreshAt, expiresAt); ttl != time.Minute || swr != 30*time.Second {
		t.Fatalf("token fresh/SWR windows: ttl=%s swr=%s", ttl, swr)
	}
	if expiresAt, refreshAt, err := tokenCacheTiming(received, "", 300); err != nil || !expiresAt.Equal(received.Add(300*time.Second)) || !refreshAt.Equal(received.Add(240*time.Second)) {
		t.Fatalf("80%% timing: expiry=%s refresh=%s err=%v", expiresAt, refreshAt, err)
	}
	if expiresAt, refreshAt, err := tokenCacheTiming(received, "", 0); err != nil || !expiresAt.Equal(received.Add(time.Minute)) || !refreshAt.Equal(received.Add(30*time.Second)) {
		t.Fatalf("default timing: expiry=%s refresh=%s err=%v", expiresAt, refreshAt, err)
	}
	if _, _, err := tokenCacheTiming(received, received.Add(-2*time.Minute).Format(time.RFC3339), 60); !errors.Is(err, errUpstreamAuth) {
		t.Fatalf("expired token was accepted: %v", err)
	}

	blob := []byte("delayed-revocation-fixture")
	blobDigest := registryDigest(blob)
	var registryServer *httptest.Server
	var issued, oldAttempts, newAttempts atomic.Int32
	allOld := make(chan struct{})
	registryServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			issued.Add(1)
			_, _ = io.WriteString(writer, `{"token":"retry-token","expires_in":300}`)
		case "/v2/example/app/blobs/" + blobDigest:
			authorization := request.Header.Get("Authorization")
			if authorization == "" {
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture",scope="repository:example/app:pull"`, registryServer.URL+"/token"))
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			if authorization == "Bearer retry-token" {
				oldWave := false
				for !oldWave {
					current := oldAttempts.Load()
					if current >= 100 {
						break
					}
					oldWave = oldAttempts.CompareAndSwap(current, current+1)
					if oldWave && current+1 == 100 {
						close(allOld)
					}
				}
				if !oldWave {
					newAttempts.Add(1)
					writer.Header().Set("Docker-Content-Digest", blobDigest)
					_, _ = writer.Write(blob)
					return
				}
				<-allOld
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture",scope="repository:example/app:pull"`, registryServer.URL+"/token"))
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Error(writer, "unexpected authorization", http.StatusUnauthorized)
		}
	}))
	defer registryServer.Close()
	retryHandler := newFixtureHandlerWithMaxConnections(t, registryServer.URL, 128)
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			recorder := httptest.NewRecorder()
			retryHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/blobs/"+blobDigest, nil))
			if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), blob) {
				t.Errorf("repeated 401 response: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		}()
	}
	wait.Wait()
	if issued.Load() != 2 || oldAttempts.Load() != 100 || newAttempts.Load() != 100 {
		t.Fatalf("100-way repeated 401 did not converge: tokens=%d old=%d new=%d", issued.Load(), oldAttempts.Load(), newAttempts.Load())
	}
}

func TestManifestCacheConditionalRequestsMatchColdAndWarm(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)
	const etag = `"manifest-etag"`
	const modified = "Wed, 21 Oct 2015 07:28:00 GMT"
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("ETag", etag)
		writer.Header().Set("Last-Modified", modified)
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		if request.Header.Get("If-None-Match") == etag || request.Header.Get("If-Modified-Since") == modified {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = writer.Write(manifest)
	}))
	defer registryServer.Close()
	for _, testCase := range []struct{ name, header, value string }{
		{name: "etag", header: "If-None-Match", value: etag},
		{name: "last modified", header: "If-Modified-Since", value: modified},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			warmHandler := newFixtureHandler(t, registryServer.URL)
			warm := httptest.NewRecorder()
			warmHandler.ServeHTTP(warm, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
			if warm.Code != http.StatusOK {
				t.Fatalf("warm fill: %d %s", warm.Code, warm.Body.String())
			}
			warmConditional := httptest.NewRecorder()
			warmRequest := httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil)
			warmRequest.Header.Set(testCase.header, testCase.value)
			warmHandler.ServeHTTP(warmConditional, warmRequest)

			coldHandler := newFixtureHandler(t, registryServer.URL)
			coldConditional := httptest.NewRecorder()
			coldRequest := httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil)
			coldRequest.Header.Set(testCase.header, testCase.value)
			coldHandler.ServeHTTP(coldConditional, coldRequest)
			if warmConditional.Code != http.StatusNotModified || coldConditional.Code != http.StatusNotModified || warmConditional.Body.Len() != 0 || coldConditional.Body.Len() != 0 {
				t.Fatalf("conditional behavior differs: warm=%d/%q cold=%d/%q", warmConditional.Code, warmConditional.Body.String(), coldConditional.Code, coldConditional.Body.String())
			}
		})
	}
}

func TestManifestCacheValidatorRefreshWindowsAnd4xxInvalidation(t *testing.T) {
	clock := &registryFakeClock{now: time.Unix(1, 0)}
	v1 := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)
	v2 := bytes.Replace(v1, []byte(`"size":1`), []byte(`"size":2`), 1)
	v3 := bytes.Replace(v1, []byte(`"size":1`), []byte(`"size":3`), 1)
	var mode atomic.Int32
	var calls atomic.Int32
	refreshed := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		switch mode.Load() {
		case 0:
			writer.Header().Set("ETag", `"v1"`)
			_, _ = writer.Write(v1)
		case 1:
			if request.Header.Get("If-None-Match") != `"v1"` {
				t.Errorf("refresh omitted cached validator: %q", request.Header.Get("If-None-Match"))
			}
			writer.Header().Set("ETag", `"v2"`)
			_, _ = writer.Write(v2)
			select {
			case refreshed <- struct{}{}:
			default:
			}
		case 2:
			writer.WriteHeader(http.StatusNotFound)
		case 3:
			writer.Header().Set("ETag", `"v3"`)
			_, _ = writer.Write(v3)
		case 4:
			if request.Header.Get("If-None-Match") != `"v1"` {
				t.Errorf("304 refresh omitted cached validator: %q", request.Header.Get("If-None-Match"))
			}
			writer.Header().Set("ETag", `"v1"`)
			writer.WriteHeader(http.StatusNotModified)
			select {
			case refreshed <- struct{}{}:
			default:
			}
		}
	}))
	defer server.Close()
	handler := newClockFixtureHandler(t, server.URL, clock)
	path := "/v2/example/app/manifests/latest"
	cacheKey := strings.Join([]string{"docker.io", "example/app", "latest", "", "anonymous", "true", "true"}, "\x00")
	request := func(header string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if header != "" {
			req.Header.Set("If-None-Match", header)
		}
		handler.ServeHTTP(recorder, req)
		return recorder
	}
	if response := request(""); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), v1) {
		t.Fatalf("manifest fill: %d %s", response.Code, response.Body.String())
	}
	if response := request(`"v1"`); response.Code != http.StatusNotModified || calls.Load() != 1 {
		t.Fatalf("fresh conditional was not local: status=%d calls=%d", response.Code, calls.Load())
	}
	mode.Store(4)
	clock.Advance(61 * time.Second)
	if response := request(""); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), v1) {
		t.Fatalf("SWR did not serve verified stale body: %d %s", response.Code, response.Body.String())
	}
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("validator refresh did not start")
	}
	for deadline := time.Now().Add(time.Second); ; {
		if _, found := handler.upstream.Manifests().Get(cacheKey); found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("304 refresh did not publish extended entry")
		}
		time.Sleep(time.Millisecond)
	}
	clock.Advance(59 * time.Second)
	if response := request(""); response.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("upstream 304 did not extend freshness: status=%d calls=%d", response.Code, calls.Load())
	}
	mode.Store(1)
	clock.Advance(2 * time.Second)
	if response := request(""); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), v1) {
		t.Fatalf("second SWR did not serve verified stale body: %d %s", response.Code, response.Body.String())
	}
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("conditional 200 refresh did not start")
	}
	deadline := time.Now().Add(time.Second)
	for {
		response := request("")
		if bytes.Equal(response.Body.Bytes(), v2) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("conditional 200 did not replace cache: %s", response.Body.String())
		}
		time.Sleep(time.Millisecond)
	}
	mode.Store(2)
	clock.Advance(91 * time.Second)
	if response := request(""); response.Code != http.StatusNotFound {
		t.Fatalf("authoritative 4xx served SIE: status=%d body=%s", response.Code, response.Body.String())
	}
	mode.Store(3)
	if response := request(""); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), v3) {
		t.Fatalf("4xx did not invalidate cache: status=%d body=%s", response.Code, response.Body.String())
	}
	if ttl, swr, sie := manifestCacheWindows(strings.Repeat("a", 0) + "sha256:" + strings.Repeat("a", 64)); ttl != 10*time.Minute || swr != 5*time.Minute || sie != 30*time.Minute {
		t.Fatalf("digest windows: %s %s %s", ttl, swr, sie)
	}
	if ttl, swr, sie := manifestCacheWindows("latest"); ttl != time.Minute || swr != 30*time.Second || sie != 5*time.Minute {
		t.Fatalf("tag windows: %s %s %s", ttl, swr, sie)
	}
}

func TestManifestCacheConflicting304MetadataPermanentlyInvalidates(t *testing.T) {
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)
	digest := registryDigest(body)
	entry := upstreamclient.ManifestEntry{Status: http.StatusOK, Body: body, Digest: digest, Header: http.Header{
		"Content-Type":          []string{"application/vnd.oci.image.manifest.v1+json"},
		"Content-Length":        []string{strconv.Itoa(len(body))},
		"Docker-Content-Digest": []string{digest},
		"Etag":                  []string{`"v1"`},
	}}
	for _, testCase := range []struct {
		name   string
		header string
		value  func([]byte) string
	}{
		{name: "digest", header: "Docker-Content-Digest", value: func([]byte) string { return "sha256:" + strings.Repeat("b", 64) }},
		{name: "content type", header: "Content-Type", value: func([]byte) string { return "application/vnd.oci.image.index.v1+json" }},
		{name: "content length", header: "Content-Length", value: func(body []byte) string { return strconv.Itoa(len(body) + 1) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			clock := &registryFakeClock{now: time.Unix(1, 0)}
			conflict := make(http.Header)
			conflict.Set(testCase.header, testCase.value(body))
			validationErr := validateManifest304(entry, conflict)
			if validationErr == nil {
				t.Fatal("conflicting 304 metadata was accepted")
			}
			cache := upstreamclient.NewCache[upstreamclient.ManifestEntry](clock, 8, 1<<20)
			_, err := cache.GetOrLoad(context.Background(), "manifest", func(context.Context) (upstreamclient.Loaded[upstreamclient.ManifestEntry], error) {
				return upstreamclient.Loaded[upstreamclient.ManifestEntry]{Value: entry, Size: int64(len(body)), TTL: time.Second, StaleIfError: time.Second}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(1500 * time.Millisecond)
			_, err = cache.GetOrLoad(context.Background(), "manifest", func(context.Context) (upstreamclient.Loaded[upstreamclient.ManifestEntry], error) {
				return upstreamclient.Loaded[upstreamclient.ManifestEntry]{}, upstreamclient.PermanentCacheError(validationErr)
			})
			if !errors.Is(err, upstreamclient.ErrPermanentCache) {
				t.Fatalf("conflicting 304 was not permanent: %v", err)
			}
			if _, found := cache.Peek("manifest"); found {
				t.Fatal("conflicting 304 did not invalidate cached representation")
			}
		})
	}
	matching := http.Header{
		"Content-Type":          []string{entry.Header.Get("Content-Type")},
		"Content-Length":        []string{entry.Header.Get("Content-Length")},
		"Docker-Content-Digest": []string{entry.Digest},
		"Etag":                  []string{`"v1-next"`},
	}
	if err := validateManifest304(entry, matching); err != nil {
		t.Fatalf("matching 304 metadata rejected: %v", err)
	}
	updated := entry.Header.Clone()
	mergeManifestValidators(updated, matching)
	if updated.Get("ETag") != `"v1-next"` || updated.Get("Content-Length") != strconv.Itoa(len(body)) || updated.Get("Docker-Content-Digest") != digest {
		t.Fatalf("304 validator merge altered representation metadata: %v", updated)
	}
}

func TestWarmPathRegistryTokenManifestAndBlobWorkload(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)
	blob := bytes.Repeat([]byte("registry-performance-layer"), 4096)
	blobDigest := registryDigest(blob)
	var tokenCalls, manifestCalls, blobCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenCalls.Add(1)
			_, _ = io.WriteString(writer, `{"token":"warm-token","expires_in":300}`)
		case "/v2/example/app/manifests/latest":
			if request.Header.Get("Authorization") != "Bearer warm-token" {
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture",scope="repository:example/app:pull"`, server.URL+"/token"))
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(writer, "challenge")
				return
			}
			manifestCalls.Add(1)
			writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = writer.Write(manifest)
		case "/v2/example/app/blobs/" + blobDigest:
			blobCalls.Add(1)
			writer.Header().Set("Docker-Content-Digest", blobDigest)
			_, _ = writer.Write(blob)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	handler := newFixtureHandler(t, server.URL)
	requestManifest := func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
		if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), manifest) {
			t.Errorf("manifest workload response: %d %q", recorder.Code, recorder.Body.Bytes())
		}
	}
	for wave := 0; wave < 2; wave++ {
		var wait sync.WaitGroup
		for range 100 {
			wait.Add(1)
			go func() { defer wait.Done(); requestManifest() }()
		}
		wait.Wait()
	}
	if tokenCalls.Load() != 1 || manifestCalls.Load() != 1 {
		t.Fatalf("warm token/manifest operations were not reduced by 90%%: token=%d manifest=%d", tokenCalls.Load(), manifestCalls.Load())
	}
	for range 10 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/blobs/"+blobDigest, nil))
		if recorder.Code != http.StatusOK || registryDigest(recorder.Body.Bytes()) != blobDigest {
			t.Fatalf("streamed blob digest mismatch: status=%d", recorder.Code)
		}
	}
	if blobCalls.Load() != 10 {
		t.Fatalf("blob was cached instead of streamed: calls=%d", blobCalls.Load())
	}
	metrics := handler.upstream.Snapshot()
	if metrics.ReusedConnections == 0 || metrics.TransferredBytes < uint64(len(blob)*10) {
		t.Fatalf("warm workload metrics missing reuse/bytes: %+v", metrics)
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
	var registryServer *httptest.Server
	registryServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/token" {
			_, _ = io.WriteString(writer, `{"token":"blob-token"}`)
			return
		}
		if request.Header.Get("Range") != "bytes=2-5" {
			t.Errorf("range not forwarded before redirect: %q", request.Header.Get("Range"))
		}
		if request.Header.Get("Authorization") != "Bearer blob-token" {
			writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="fixture-registry",scope="repository:example/app:pull"`, registryServer.URL+"/token"))
			writer.WriteHeader(http.StatusUnauthorized)
			return
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

func TestRegistryPartialRangeRejectsWrongOrTruncatedIntervals(t *testing.T) {
	blob := []byte("abcdefghij")
	digest := registryDigest(blob)
	t.Run("wrong interval", func(t *testing.T) {
		registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Range", "bytes 3-6/10")
			writer.Header().Set("Docker-Content-Digest", digest)
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write(blob[3:7])
		}))
		defer registryServer.Close()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v2/example/app/blobs/"+digest, nil)
		request.Header.Set("Range", "bytes=2-5")
		newFixtureHandler(t, registryServer.URL).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "RANGE_INVALID") {
			t.Fatalf("wrong interval response: status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("chunked truncation", func(t *testing.T) {
		registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Range", "bytes 2-5/10")
			writer.Header().Set("Docker-Content-Digest", digest)
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write(blob[2:4])
			writer.(http.Flusher).Flush()
		}))
		defer registryServer.Close()
		proxy := httptest.NewServer(newFixtureHandler(t, registryServer.URL))
		defer proxy.Close()
		request, _ := http.NewRequest(http.MethodGet, proxy.URL+"/v2/example/app/blobs/"+digest, nil)
		request.Header.Set("Range", "bytes=2-5")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("start partial stream: %v", err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr == nil || !bytes.Equal(body, blob[2:4]) || bytes.Contains(body, []byte(`"errors"`)) {
			t.Fatalf("truncated partial stream was not aborted cleanly: err=%v body=%q", readErr, body)
		}
	})
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

func TestRegistrySameLengthWrongDigestAbortsStream(t *testing.T) {
	correct := []byte("correct-layer-content")
	wrong := []byte("tampered-layer-bytes!")
	if len(correct) != len(wrong) {
		t.Fatal("fixture bodies must be the same length")
	}
	digest := registryDigest(correct)
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(wrong)))
		writer.Header().Set("Docker-Content-Digest", digest)
		_, _ = writer.Write(wrong)
	}))
	defer registryServer.Close()
	proxy := httptest.NewServer(newFixtureHandler(t, registryServer.URL))
	defer proxy.Close()
	response, err := http.Get(proxy.URL + "/v2/example/app/blobs/" + digest)
	if err != nil {
		t.Fatalf("start digest failure stream: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr == nil {
		t.Fatal("same-length digest failure completed successfully")
	}
	if !bytes.Equal(body, wrong) || bytes.Contains(body, []byte(`"errors"`)) {
		t.Fatalf("digest failure appended or changed content: %q", body)
	}
}

func TestRegistryRejectsBadManifestDigestAndUnsupportedTargets(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}`)
	registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
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
		_, _ = writer.Write([]byte(`{"schemaVersion":2}`))
	}))
	defer invalidManifestServer.Close()
	invalidManifest := httptest.NewRecorder()
	newFixtureHandler(t, invalidManifestServer.URL).ServeHTTP(invalidManifest, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if invalidManifest.Code != http.StatusBadGateway || !strings.Contains(invalidManifest.Body.String(), "MANIFEST_INVALID") {
		t.Fatalf("invalid manifest response: status=%d body=%s", invalidManifest.Code, invalidManifest.Body.String())
	}

	headMismatch := httptest.NewRecorder()
	headRequest := httptest.NewRequest(http.MethodHead, "/v2/example/app/manifests/"+registryDigest(manifest), nil)
	handler.ServeHTTP(headMismatch, headRequest)
	if headMismatch.Code != http.StatusBadGateway || !strings.Contains(headMismatch.Body.String(), "DIGEST_INVALID") {
		t.Fatalf("digest-addressed HEAD mismatch response: status=%d body=%s", headMismatch.Code, headMismatch.Body.String())
	}

	unsupported := httptest.NewRecorder()
	handler.ServeHTTP(unsupported, httptest.NewRequest(http.MethodGet, "/v2/evil.example/app/manifests/latest", nil))
	if unsupported.Code != http.StatusNotFound || !strings.Contains(unsupported.Body.String(), "REGISTRY_UNSUPPORTED") {
		t.Fatalf("unsupported registry response: status=%d body=%s", unsupported.Code, unsupported.Body.String())
	}
}

func TestRegistryRejectsContradictoryManifestMediaTypes(t *testing.T) {
	index := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}]}`)
	image := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":1},"layers":[]}`)
	cases := []struct {
		name        string
		body        []byte
		contentType string
	}{
		{name: "index body labeled image", body: index, contentType: "application/vnd.oci.image.manifest.v1+json"},
		{name: "image body labeled index", body: image, contentType: "application/vnd.oci.image.index.v1+json"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			registryServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", testCase.contentType)
				_, _ = writer.Write(testCase.body)
			}))
			defer registryServer.Close()
			recorder := httptest.NewRecorder()
			newFixtureHandler(t, registryServer.URL).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "MANIFEST_INVALID") {
				t.Fatalf("contradictory media types were accepted: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
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

func TestRegistryRejectsPrivateRedirectAndNonHTTPSPort(t *testing.T) {
	publicEndpoint, _ := url.Parse("https://registry.public.test")
	source := &Source{Name: "docker.io", Endpoint: publicEndpoint}
	handler := &Handler{}
	privateEndpoint, _ := url.Parse("https://169.254.1.1/layer")
	if err := handler.validateOutbound(context.Background(), source, privateEndpoint, false); !errors.Is(err, errUnsafeUpstream) {
		t.Fatalf("private redirect was not rejected before its dial: %v", err)
	}

	portEndpoint, _ := url.Parse("https://registry.public.test:444/v2")
	if err := handler.validateOutbound(context.Background(), source, portEndpoint, false); !errors.Is(err, errUnsafeUpstream) {
		t.Fatalf("non-HTTPS-default port was accepted: %v", err)
	}
}

func TestRegistryRebindingIsRejectedAtPinnedDial(t *testing.T) {
	endpoint, _ := url.Parse("https://rebind.public.test")
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("8.8.8.8")}},
		{{IP: net.ParseIP("127.0.0.1")}},
	}}
	var dialed string
	manager, err := upstreamclient.New(upstreamclient.Options{
		Resolver: upstreamclient.NetResolverAdapter{Resolver: resolver, TTL: time.Minute},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("fixture dial stopped")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: manager, Sources: []Source{{Name: "docker.io", Endpoint: endpoint}}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("fixture pinned dial response: calls=%d status=%d body=%s", resolver.calls.Load(), recorder.Code, recorder.Body.String())
	}
	if resolver.calls.Load() != 1 || dialed != "8.8.8.8:443" {
		t.Fatalf("verified address lease was not pinned: calls=%d dialed=%q", resolver.calls.Load(), dialed)
	}
}

func TestRegistryCustomTLSDialHookCannotBypassPinnedDial(t *testing.T) {
	endpoint, _ := url.Parse("https://tls-hook.public.test")
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("8.8.8.8")}},
		{{IP: net.ParseIP("127.0.0.1")}},
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	var hookCalls atomic.Int32
	transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		hookCalls.Add(1)
		return nil, errors.New("unsafe TLS hook called")
	}
	manager, err := upstreamclient.New(upstreamclient.Options{
		Client:   &http.Client{Transport: transport},
		Resolver: upstreamclient.NetResolverAdapter{Resolver: resolver, TTL: time.Minute},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("fixture dial stopped")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: manager, Sources: []Source{{Name: "docker.io", Endpoint: endpoint}}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v2/example/app/manifests/latest", nil))
	if hookCalls.Load() != 0 {
		t.Fatalf("custom TLS hook bypassed pinned dial: calls=%d", hookCalls.Load())
	}
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "UPSTREAM_UNAVAILABLE") {
		t.Fatalf("pinned dial did not reject rebinding: status=%d body=%s", recorder.Code, recorder.Body.String())
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

func newFixtureHandlerWithMaxConnections(t *testing.T, endpointValue string, maxConnections int) *Handler {
	t.Helper()
	endpoint, err := url.Parse(endpointValue)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := upstreamclient.New(upstreamclient.Options{MaxConnsPerHost: maxConnections})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: manager, Sources: []Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}})
	if err != nil {
		_ = manager.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

type registryFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *registryFakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *registryFakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func newClockFixtureHandler(t *testing.T, endpointValue string, clock upstreamclient.Clock) *Handler {
	t.Helper()
	endpoint, err := url.Parse(endpointValue)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := upstreamclient.New(upstreamclient.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: manager, Sources: []Source{{Name: "docker.io", Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}})
	if err != nil {
		_ = manager.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func registryDigest(body []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(body))
}

type sequenceResolver struct {
	calls   atomic.Int32
	answers [][]net.IPAddr
}

func (resolver *sequenceResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	index := int(resolver.calls.Add(1)) - 1
	if index >= len(resolver.answers) {
		index = len(resolver.answers) - 1
	}
	return resolver.answers[index], nil
}
