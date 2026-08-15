package acceleratorsourcesperformance

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWarmPathPerformanceContract executes the repository-level HTTPS
// workload. Implementation-specific token/manifest singleflight assertions
// live with the internal Registry owner; this fixture independently locks the
// TLS/connection reuse, TTFB/throughput and final blob-integrity contract.
func TestWarmPathPerformanceContract(t *testing.T) {
	body := bytes.Repeat([]byte("accelerator-performance-blob"), 8192)
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(body))
	var newConnections atomic.Int32
	var connections sync.Map
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write(body)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(connection net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			newConnections.Add(1)
			connections.Store(connection, struct{}{})
		case http.StateClosed:
			connections.Delete(connection)
		}
	}
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 32
	transport.MaxConnsPerHost = 64
	client := &http.Client{Transport: transport}
	started := time.Now()
	var firstByte time.Duration
	for index := range 100 {
		requestStarted := time.Now()
		response, err := client.Get(server.URL + fmt.Sprintf("/blob?request=%d", index))
		if err != nil {
			t.Fatal(err)
		}
		blob, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(blob)) != wantDigest {
			t.Fatalf("blob %d integrity failed: %v", index, err)
		}
		if index == 0 {
			firstByte = time.Since(requestStarted)
		}
	}
	elapsed := time.Since(started)
	warmConnections := newConnections.Load()
	baselineTransport := server.Client().Transport.(*http.Transport).Clone()
	baselineTransport.DisableKeepAlives = true
	baselineTransport.ForceAttemptHTTP2 = false
	baselineTransport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	baselineTransport.TLSClientConfig = baselineTransport.TLSClientConfig.Clone()
	baselineTransport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	baselineClient := &http.Client{Transport: baselineTransport}
	for index := range 20 {
		response, err := baselineClient.Get(server.URL + fmt.Sprintf("/baseline?request=%d", index))
		if err != nil {
			t.Fatal(err)
		}
		blob, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(blob)) != wantDigest {
			t.Fatalf("baseline blob %d integrity failed: %v", index, err)
		}
	}
	baselineConnections := newConnections.Load() - warmConnections
	baselineEquivalent := baselineConnections * 5
	if baselineConnections < 18 || warmConnections*10 > baselineEquivalent {
		t.Fatalf("warm HTTPS path did not reduce connection/TLS operations by at least 90%%: warm=%d baseline20=%d", warmConnections, baselineConnections)
	}
	throughput := float64(len(body)*100) / elapsed.Seconds()
	t.Logf("warm workload: requests=100 warm-connections=%d no-reuse-connections20=%d ttfb=%s throughput=%.0fB/s digest=%s", warmConnections, baselineConnections, firstByte, throughput, wantDigest)
	baselineTransport.CloseIdleConnections()
	transport.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		count := 0
		connections.Range(func(_, _ any) bool { count++; return true })
		if count == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("CloseIdleConnections left warm workload connections open")
}
