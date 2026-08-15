package imagetar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

type offlineResolver struct{}

func (offlineResolver) Lookup(context.Context, string) (upstream.DNSResult, error) {
	return upstream.DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, TTL: time.Minute}, nil
}

type offlineClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *offlineClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *offlineClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestOfflinePlatformSelectionBatchTarAndDigest(t *testing.T) {
	layerTar, layer := makeLayerFixture(t, bytes.Repeat([]byte("layer-content-"), 4096))
	config := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%q]}}`, digest(layerTar)))
	configDescriptor := descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest(config), Size: int64(len(config))}
	layerDescriptor := descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digest(layer), Size: int64(len(layer))}
	selected := manifestDocument{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: configDescriptor, Layers: []descriptor{layerDescriptor}}
	selectedBody, _ := json.Marshal(selected)
	selectedDigest := digest(selectedBody)
	index := manifestDocument{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []descriptor{
		{Digest: digest([]byte("arm")), Size: 3, Platform: platform{OS: "linux", Architecture: "arm64"}},
		{Digest: selectedDigest, Size: int64(len(selectedBody)), Platform: platform{OS: "linux", Architecture: "amd64"}},
	}}
	indexBody, _ := json.Marshal(index)
	var selectedCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/manifests/latest"):
			writer.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_, _ = writer.Write(indexBody)
		case strings.HasSuffix(request.URL.Path, "/manifests/"+selectedDigest):
			selectedCalls.Add(1)
			writer.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = writer.Write(selectedBody)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+configDescriptor.Digest):
			_, _ = writer.Write(config)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+layerDescriptor.Digest):
			_, _ = writer.Write(layer)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	handler, manager := newOfflineFixture(t, server.URL)
	defer manager.Close()
	body := `{"images":["example/app:latest","example/second:latest"],"platform":"linux/amd64"}`
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/offline", strings.NewReader(body)))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/x-tar" {
		t.Fatalf("offline response failed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	entries := readTar(t, recorder.Body.Bytes())
	if !bytes.Equal(entries[digestHex(configDescriptor.Digest)+".json"], config) {
		t.Fatal("config entry was truncated or changed")
	}
	if !bytes.Equal(entries[digestHex(layerDescriptor.Digest)+"/layer.tar"], layerTar) {
		t.Fatal("layer entry was truncated or changed")
	}
	if countTarEntry(t, recorder.Body.Bytes(), digestHex(layerDescriptor.Digest)+"/layer.tar") != 1 {
		t.Fatal("shared batch layer was written more than once")
	}
	var archiveManifest []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if err := json.Unmarshal(entries["manifest.json"], &archiveManifest); err != nil || len(archiveManifest) != 2 {
		t.Fatalf("invalid batch manifest: err=%v body=%s", err, entries["manifest.json"])
	}
	if selectedCalls.Load() != 2 {
		t.Fatalf("each repository should resolve its selected platform manifest, calls=%d", selectedCalls.Load())
	}
	if manager.Snapshot().TransferredBytes < uint64(len(layer)) {
		t.Fatalf("offline layers bypassed shared upstream metrics: %+v", manager.Snapshot())
	}
}

func TestOfflinePreparedDownloadUsesTrustedAuthorityAndOneTimeToken(t *testing.T) {
	handler, manager := newOfflineFixture(t, "http://127.0.0.1:1")
	defer manager.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/offline/prepare", strings.NewReader(`{"image":"alpine:latest","platform":"linux/amd64"}`))
	request.Header.Set("Forwarded", `for=203.0.113.5;proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("prepare failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil || !strings.HasPrefix(payload["download_url"], "https://mirror.example.com/api/offline/") {
		t.Fatalf("untrusted download URL: err=%v payload=%v", err, payload)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/api/offline/prepare", strings.NewReader(`{"image":"alpine"}`)))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing authority accepted: %d", missing.Code)
	}
}

func TestOfflineRejectsUnsupportedRegistry(t *testing.T) {
	handler, manager := newOfflineFixture(t, "http://127.0.0.1:1")
	defer manager.Close()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/offline?image=registry.invalid/acme/app:latest", nil))
	if recorder.Code != http.StatusBadGateway || manager.Snapshot().UpstreamCalls != 0 {
		t.Fatalf("unsupported registry reached upstream: status=%d metrics=%+v", recorder.Code, manager.Snapshot())
	}
}

func TestOfflineManifestIntegrityAndMediaTypeFailClosed(t *testing.T) {
	valid := manifestDocument{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: descriptor{Digest: digest([]byte("config")), Size: 6}, Layers: []descriptor{{Digest: digest([]byte("layer")), Size: 5}}}
	body, _ := json.Marshal(valid)
	wrongDigest := digest([]byte("different"))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/manifests/latest") {
			writer.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
		} else {
			writer.Header().Set("Content-Type", valid.MediaType)
		}
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	handler, manager := newOfflineFixture(t, server.URL)
	defer manager.Close()
	for _, image := range []string{"example/app:latest", "example/app@" + wrongDigest} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/offline?image="+url.QueryEscape(image), nil))
		if recorder.Code != http.StatusBadGateway || recorder.Header().Get("Content-Type") == "application/x-tar" {
			t.Fatalf("invalid manifest %q entered tar stream: status=%d type=%q", image, recorder.Code, recorder.Header().Get("Content-Type"))
		}
	}
}

func TestOfflineLayerDiffIDMismatchCannotCompleteArchive(t *testing.T) {
	layerTar, layer := makeLayerFixture(t, []byte("layer"))
	config := []byte(fmt.Sprintf(`{"rootfs":{"type":"layers","diff_ids":[%q]}}`, digest([]byte("wrong-uncompressed-layer"))))
	document := manifestDocument{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest(config), Size: int64(len(config))}, Layers: []descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digest(layer), Size: int64(len(layer))}}}
	body, _ := json.Marshal(document)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			writer.Header().Set("Content-Type", document.MediaType)
			_, _ = writer.Write(body)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+document.Config.Digest):
			_, _ = writer.Write(config)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+document.Layers[0].Digest):
			_, _ = writer.Write(layer)
		}
	}))
	defer server.Close()
	handler, manager := newOfflineFixture(t, server.URL)
	defer manager.Close()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/offline?image=example/app:latest", nil))
	entries := readTar(t, recorder.Body.Bytes())
	if _, found := entries[digestHex(document.Layers[0].Digest)+"/layer.tar"]; found {
		t.Fatalf("diffID-mismatched layer entered archive; raw=%d compressed=%d", len(layerTar), len(layer))
	}
}

func TestOfflineTokenFakeClockNeverCrossesExpiresAt(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	clock := &offlineClock{now: base}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) > 1 {
			http.Error(writer, "temporary", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"token": "short-lived", "expires_in": 100, "issued_at": base.Format(time.RFC3339)})
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	manager, err := upstream.New(upstream.Options{Resolver: offlineResolver{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager, Sources: map[string]Source{"docker.io": {Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := handler.parseImageRef("example/app:latest")
	challenge := `Bearer realm="` + server.URL + `",service="fixture",scope="repository:example/app:pull"`
	first, err := handler.fetchToken(context.Background(), ref, challenge)
	if err != nil || first.entry.Value != "short-lived" {
		t.Fatalf("initial token failed: lease=%+v err=%v", first, err)
	}
	clock.Advance(91 * time.Second)
	stale, err := handler.fetchToken(context.Background(), ref, challenge)
	if err != nil || stale.entry.Version != first.entry.Version {
		t.Fatalf("early refresh did not serve still-valid token: lease=%+v err=%v", stale, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if calls.Load() != 2 {
		t.Fatalf("early refresh did not start: calls=%d", calls.Load())
	}
	clock.Advance(10 * time.Second)
	if _, err := handler.fetchToken(context.Background(), ref, challenge); err == nil {
		t.Fatal("token remained usable after its real expiresAt")
	}
}

func TestOfflineStreamingFirstByteAndCancellation(t *testing.T) {
	layerTar, layer := makeLayerFixture(t, bytes.Repeat([]byte("slow-layer"), 4096))
	config := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%q]}}`, digest(layerTar)))
	document := manifestDocument{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Config: descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest(config), Size: int64(len(config))}, Layers: []descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digest(layer), Size: int64(len(layer))}}}
	manifestBody, _ := json.Marshal(document)
	layerStarted := make(chan struct{})
	layerCanceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			writer.Header().Set("Content-Type", document.MediaType)
			_, _ = writer.Write(manifestBody)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+document.Config.Digest):
			_, _ = writer.Write(config)
		case strings.HasSuffix(request.URL.Path, "/blobs/"+document.Layers[0].Digest):
			close(layerStarted)
			<-request.Context().Done()
			close(layerCanceled)
		}
	}))
	defer server.Close()
	handler, manager := newOfflineFixture(t, server.URL)
	defer manager.Close()
	service := httptest.NewServer(handler)
	defer service.Close()
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, service.URL+"/api/offline?image=example/app:latest", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-layerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("layer request did not start")
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatalf("tar first byte was blocked by the layer body: %v", err)
	}
	cancel()
	select {
	case <-layerCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("client cancellation did not reach the active layer request")
	}
}

func newOfflineFixture(t *testing.T, rawEndpoint string) (*Handler, *upstream.Manager) {
	t.Helper()
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := upstream.New(upstream.Options{Resolver: offlineResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Options{Upstream: manager, Sources: map[string]Source{"docker.io": {Endpoint: endpoint, AllowHTTP: true, AllowPrivate: true}}})
	if err != nil {
		manager.Close()
		t.Fatal(err)
	}
	return handler, manager
}

func readTar(t *testing.T, value []byte) map[string][]byte {
	t.Helper()
	entries := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(value))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = body
	}
	return entries
}

func countTarEntry(t *testing.T, value []byte, name string) int {
	t.Helper()
	count := 0
	reader := tar.NewReader(bytes.NewReader(value))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return count
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == name {
			count++
		}
	}
}

func makeLayerFixture(t *testing.T, content []byte) ([]byte, []byte) {
	t.Helper()
	var raw bytes.Buffer
	archive := tar.NewWriter(&raw)
	if err := archive.WriteHeader(&tar.Header{Name: "payload.bin", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zipper := gzip.NewWriter(&compressed)
	if _, err := zipper.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes(), compressed.Bytes()
}
