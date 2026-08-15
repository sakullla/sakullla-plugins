package sourceproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

type fixtureResolver struct{ address net.IP }

func (resolver fixtureResolver) Lookup(context.Context, string) (upstream.DNSResult, error) {
	return upstream.DNSResult{Addresses: []net.IPAddr{{IP: resolver.address}}, TTL: time.Minute}, nil
}

func fixtureHandler(t *testing.T, serve http.HandlerFunc) (*Handler, *upstream.Manager) {
	t.Helper()
	server := httptest.NewServer(serve)
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := upstream.New(upstream.Options{Resolver: fixtureResolver{address: net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	targets := map[string]*url.URL{}
	for _, host := range []string{"github.com", "api.github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com", "huggingface.co"} {
		targets[host] = endpoint
	}
	handler, err := NewHandler(Options{Upstream: manager, Targets: targets, AllowHTTP: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	return handler, manager
}

func TestGitHubBlobToRawStreaming(t *testing.T) {
	payload := strings.Repeat("release-byte-", 4096)
	handler, manager := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/owner/project/main/dist.bin" || request.Header.Get("Range") != "bytes=10-" {
			t.Errorf("unexpected upstream request: path=%q range=%q", request.URL.Path, request.Header.Get("Range"))
		}
		writer.Header().Set("Content-Length", "53248")
		_, _ = io.WriteString(writer, payload)
	})
	request := httptest.NewRequest(http.MethodGet, "/github.com/owner/project/blob/main/dist.bin", nil)
	request.Header.Set("Range", "bytes=10-")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != payload {
		t.Fatalf("unexpected proxy response: status=%d bytes=%d", recorder.Code, recorder.Body.Len())
	}
	if manager.Snapshot().UpstreamCalls != 1 || manager.Snapshot().TransferredBytes != uint64(len(payload)) {
		t.Fatalf("source request did not use shared metrics: %+v", manager.Snapshot())
	}
}

func TestGitHubOriginalURLPrefix(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/owner/project/releases/download/v1/tool" {
			t.Errorf("unexpected original URL target %q", request.URL.Path)
		}
		_, _ = io.WriteString(writer, "release")
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/https://github.com/owner/project/releases/download/v1/tool", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "release" {
		t.Fatalf("original URL prefix failed: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestGitHubHTTPSHTTP2ConcurrencyReuse(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 2 {
			t.Errorf("source request did not negotiate HTTP/2: %s", request.Proto)
		}
		_, _ = io.WriteString(writer, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	manager, err := upstream.New(upstream.Options{Client: server.Client(), Resolver: fixtureResolver{address: net.ParseIP("127.0.0.1")}, MaxConnsPerHost: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager, Targets: map[string]*url.URL{"github.com": endpoint}, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsFound := make(chan string, 100)
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/github.com/acme/project/releases/latest", nil))
			if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
				errorsFound <- recorder.Body.String()
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	if len(errorsFound) != 0 {
		t.Fatalf("concurrent source requests failed: %q", <-errorsFound)
	}
	metrics := manager.Snapshot()
	if metrics.HTTP2Requests != 100 || metrics.NewConnections > 8 || metrics.TLSHandshakes > 8 {
		t.Fatalf("source path did not reuse bounded HTTP/2 pool: %+v", metrics)
	}
}

func TestHuggingFaceLargeFileStreaming(t *testing.T) {
	payload := strings.Repeat("hf-lfs", 16384)
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/org/model/resolve/main/model.bin" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		_, _ = io.WriteString(writer, payload)
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/huggingface.co/org/model/resolve/main/model.bin", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != payload {
		t.Fatalf("unexpected Hugging Face response: status=%d bytes=%d", recorder.Code, recorder.Body.Len())
	}
}

func TestScriptHEADUsesTransformedRepresentationWithoutRangeMetadata(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead || request.Header.Get("Range") != "" || request.Header.Get("If-Range") != "" {
			t.Errorf("HEAD script forwarded source range semantics: method=%s range=%q if-range=%q", request.Method, request.Header.Get("Range"), request.Header.Get("If-Range"))
		}
		writer.Header().Set("Accept-Ranges", "bytes")
		writer.Header().Set("Content-Range", "bytes 0-9/100")
		writer.Header().Set("Content-Length", "100")
		writer.Header().Set("ETag", `"source-etag"`)
		writer.WriteHeader(http.StatusOK)
	})
	request := httptest.NewRequest(http.MethodHead, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
	request.Header.Set("Range", "bytes=10-")
	request.Header.Set("If-Range", `"source-etag"`)
	request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("HEAD script response failed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	for _, header := range []string{"Accept-Ranges", "Content-Range", "Content-Length", "ETag"} {
		if value := recorder.Header().Get(header); value != "" {
			t.Fatalf("HEAD transformed response retained %s=%q", header, value)
		}
	}
}

func TestScriptRejectsPartialUpstreamAndClearsRangeHeaders(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "" || request.Header.Get("If-Range") != "" {
			t.Errorf("script forwarded range headers: %v", request.Header)
		}
		writer.Header().Set("Accept-Ranges", "bytes")
		writer.Header().Set("Content-Range", "bytes 0-9/100")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(writer, "partial")
	})
	request := httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.ps1", nil)
	request.Header.Set("Range", "bytes=0-9")
	request.Header.Set("If-Range", `"source"`)
	request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("partial script upstream was accepted: status=%d", recorder.Code)
	}
	if recorder.Header().Get("Accept-Ranges") != "" || recorder.Header().Get("Content-Range") != "" {
		t.Fatalf("partial script leaked range metadata: %v", recorder.Header())
	}
}

func TestScriptRejectsOversizedKnownContentLengthForGETAndHEAD(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Length", strconv.Itoa(maxScriptBytes+1))
				writer.WriteHeader(http.StatusOK)
			})
			request := httptest.NewRequest(method, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
			request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
			request.Header.Set("X-Forwarded-Proto", "https")
			request.Header.Set("X-Forwarded-Host", "mirror.example.com")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("oversized script was accepted: status=%d", recorder.Code)
			}
		})
	}
}

func TestScriptRejectsOversizedUnknownContentLength(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.(http.Flusher).Flush()
		_, _ = io.WriteString(writer, strings.Repeat("x", maxScriptBytes+1))
	})
	request := httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
	request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("unknown-length oversized script was accepted: status=%d", recorder.Code)
	}
}

func TestGitHubStreamingChunkedTruncationAbortsClientRead(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffered, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n")
		_ = buffered.Flush()
	}))
	defer upstreamServer.Close()
	endpoint, _ := url.Parse(upstreamServer.URL)
	manager, err := upstream.New(upstream.Options{Resolver: fixtureResolver{address: net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager, Targets: map[string]*url.URL{"github.com": endpoint}, AllowHTTP: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(handler)
	defer service.Close()
	response, err := http.Get(service.URL + "/github.com/acme/project/releases/download/v1/file.bin")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr == nil || string(body) != "helloworld" {
		t.Fatalf("truncated chunked stream appeared complete: body=%q err=%v", body, readErr)
	}
}

func TestScriptRewriteRequiresTrustedAuthority(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "curl https://github.com/acme/tool/releases/download/v1/tool\n")
	})
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing authority was accepted: %d", missing.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
	request.Header.Set("Forwarded", `for=203.0.113.8;proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "https://mirror.example.com/github.com/acme/tool/") {
		t.Fatalf("script was not safely rewritten: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestScriptRequestsIdentityEncoding(t *testing.T) {
	handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("script accepted encoded upstream body: %q", request.Header.Get("Accept-Encoding"))
		}
		_, _ = io.WriteString(writer, "curl https://github.com/acme/tool/archive/main.tar.gz\n")
	})
	request := httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "mirror.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("script failed: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestScriptRejectsActualCompressedEncoding(t *testing.T) {
	var compressed bytes.Buffer
	zipper := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(zipper, "curl https://github.com/acme/tool/archive/main.tar.gz\n")
	_ = zipper.Close()
	brotli, err := base64.StdEncoding.DecodeString("GzYAAMTcRqka0q7bknPIFF70LKZBCkFV53rYOz1Uct8IeGN9+cIPtVHAtTrcRWBom0I94j9N")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		encoding string
		body     []byte
	}{{"gzip", compressed.Bytes()}, {"br", brotli}} {
		t.Run(fixture.encoding, func(t *testing.T) {
			handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", fixture.encoding)
				_, _ = writer.Write(fixture.body)
			})
			request := httptest.NewRequest(http.MethodGet, "/raw.githubusercontent.com/acme/tool/main/install.sh", nil)
			request.Header.Set("Forwarded", `proto=https;host=mirror.example.com`)
			request.Header.Set("X-Forwarded-Proto", "https")
			request.Header.Set("X-Forwarded-Host", "mirror.example.com")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadGateway || bytes.Contains(recorder.Body.Bytes(), fixture.body) {
				t.Fatalf("encoded script was treated as plaintext: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestGitHubPOSTRedirectReplaysBodyOnlyFor307And308(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			payload := strings.Repeat("git-want-line\n", 128)
			var bodies []string
			handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, request *http.Request) {
				body, _ := io.ReadAll(request.Body)
				bodies = append(bodies, string(body))
				if len(bodies) == 1 {
					writer.Header().Set("Location", "/replayed/git-upload-pack")
					writer.WriteHeader(status)
					return
				}
				_, _ = io.WriteString(writer, "result")
			})
			request := httptest.NewRequest(http.MethodPost, "/github.com/acme/project.git/git-upload-pack", strings.NewReader(payload))
			request.Header.Set("Content-Type", "application/x-git-upload-pack-request")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Body.String() != "result" || len(bodies) != 2 || bodies[0] != payload || bodies[1] != payload {
				t.Fatalf("POST body was not replayed: status=%d bodies=%d", recorder.Code, len(bodies))
			}
		})
	}
}

func TestGitHubPOSTRedirectRejectsMethodChangingStatuses(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			handler, _ := fixtureHandler(t, func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.Header().Set("Location", "/must-not-run/git-upload-pack")
				writer.WriteHeader(status)
				_, _ = io.WriteString(writer, "redirect")
			})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/github.com/acme/project.git/git-upload-pack", strings.NewReader("want")))
			if recorder.Code != http.StatusBadGateway || calls.Load() != 1 {
				t.Fatalf("method-changing POST redirect was followed: status=%d calls=%d", recorder.Code, calls.Load())
			}
		})
	}
}

type cancelingBody struct {
	cancel context.CancelFunc
	done   bool
}

func (body *cancelingBody) Read(buffer []byte) (int, error) {
	if body.done {
		return 0, io.EOF
	}
	body.done = true
	copy(buffer, "partial-git-body")
	body.cancel()
	return len("partial-git-body"), nil
}

func (*cancelingBody) Close() error { return nil }

func TestGitHubPOSTCancellationCleansReplaySpool(t *testing.T) {
	temporary := t.TempDir()
	t.Setenv("TMP", temporary)
	t.Setenv("TEMP", temporary)
	handler, _ := fixtureHandler(t, func(http.ResponseWriter, *http.Request) { t.Fatal("canceled request reached upstream") })
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/github.com/acme/project.git/git-upload-pack", nil).WithContext(ctx)
	request.Body = &cancelingBody{cancel: cancel}
	request.ContentLength = -1
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled POST left replay spool: entries=%v err=%v", entries, err)
	}
}

func TestGitHubRedirectBodyIsDrainedForConnectionReuse(t *testing.T) {
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			writer.Header().Set("Location", "/final")
			writer.WriteHeader(http.StatusFound)
			_, _ = io.WriteString(writer, strings.Repeat("redirect", 1024))
			return
		}
		_, _ = io.WriteString(writer, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	manager, err := upstream.New(upstream.Options{Resolver: fixtureResolver{address: net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager, Targets: map[string]*url.URL{"github.com": endpoint}, AllowHTTP: true, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/github.com/start", nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
			t.Fatalf("redirect failed: %d %q", recorder.Code, recorder.Body.String())
		}
	}
	if newConnections.Load() != 1 {
		t.Fatalf("redirect body prevented connection reuse: connections=%d", newConnections.Load())
	}
}

func TestGitHubRejectsUnsupportedAndPrivateTargets(t *testing.T) {
	manager, err := upstream.New(upstream.Options{Resolver: fixtureResolver{address: net.ParseIP("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	handler, err := NewHandler(Options{Upstream: manager})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/example.com/file", "/proxy/127.0.0.1/file"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("unsupported target %q returned %d", target, recorder.Code)
		}
	}
}
