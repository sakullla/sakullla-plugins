package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func TestDNSConcurrentColdMissTTLNegativeRecoveryAndEviction(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	var calls atomic.Int32
	resolver := ResolverFunc(func(_ context.Context, host string) (DNSResult, error) {
		calls.Add(1)
		if host == "negative.test" && calls.Load() < 3 {
			return DNSResult{NegativeTTL: 2 * time.Second}, ErrDNSNotFound
		}
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: 2 * time.Second}, nil
	})
	cache := NewDNSCache(clock, resolver, 2)
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			addresses, err := cache.Resolve(context.Background(), "cold.test")
			if err != nil || len(addresses) != 1 {
				t.Errorf("cold resolve: addresses=%v err=%v", addresses, err)
			}
		}()
	}
	wait.Wait()
	if calls.Load() != 1 {
		t.Fatalf("100 cold misses made %d DNS queries", calls.Load())
	}
	clock.Advance(3 * time.Second)
	if _, err := cache.Resolve(context.Background(), "negative.test"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("negative lookup: %v", err)
	}
	before := calls.Load()
	if _, err := cache.Resolve(context.Background(), "negative.test"); !errors.Is(err, ErrDNSNotFound) || calls.Load() != before {
		t.Fatalf("negative cache miss: calls=%d err=%v", calls.Load(), err)
	}
	clock.Advance(3 * time.Second)
	addresses, err := cache.Resolve(context.Background(), "negative.test")
	if err != nil || len(addresses) != 1 {
		t.Fatalf("negative expiry did not recover: %v %v", addresses, err)
	}
	_, _ = cache.Resolve(context.Background(), "third.test")
	_, _ = cache.Resolve(context.Background(), "fourth.test")
	before = calls.Load()
	_, _ = cache.Resolve(context.Background(), "negative.test")
	if calls.Load() == before {
		t.Fatal("bounded DNS LRU did not evict an old entry")
	}
}

func TestTokenCacheAndManifestCacheSingleflightTTLAndBytes(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	cache := NewCache[string](clock, 2, 8)
	var loads atomic.Int32
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := cache.GetOrLoad(context.Background(), "token", func(context.Context) (Loaded[string], error) {
				loads.Add(1)
				time.Sleep(time.Millisecond)
				return Loaded[string]{Value: "value", Size: 5, TTL: 2 * time.Second}, nil
			})
			if err != nil || value != "value" {
				t.Errorf("cache load: value=%q err=%v", value, err)
			}
		}()
	}
	wait.Wait()
	if loads.Load() != 1 {
		t.Fatalf("100 cache fills invoked loader %d times", loads.Load())
	}
	clock.Advance(3 * time.Second)
	_, _ = cache.GetOrLoad(context.Background(), "token", func(context.Context) (Loaded[string], error) {
		loads.Add(1)
		return Loaded[string]{Value: "new", Size: 3, TTL: time.Minute}, nil
	})
	if loads.Load() != 2 {
		t.Fatal("expired cache entry was not refreshed")
	}
	_, _ = cache.GetOrLoad(context.Background(), "manifest-a", fixedLoad("aaaa", time.Minute))
	_, _ = cache.GetOrLoad(context.Background(), "manifest-b", fixedLoad("bbbb", time.Minute))
	if _, found := cache.Get("token"); found {
		t.Fatal("byte/entry bounded cache did not evict LRU")
	}
}

func fixedLoad(value string, ttl time.Duration) func(context.Context) (Loaded[string], error) {
	return func(context.Context) (Loaded[string], error) {
		return Loaded[string]{Value: value, Size: int64(len(value)), TTL: ttl}, nil
	}
}

func TestConnectionPoolHTTPSHTTP2ReuseLimitAndClose(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		if request.URL.Path == "/blocked" {
			<-release
		}
		_, _ = io.WriteString(writer, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	manager := fixtureTLSManager(t, server, 2)
	defer manager.Close()

	for range 10 {
		response := doFixtureRequest(t, manager, server, "/warm")
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	metrics := manager.Snapshot()
	if metrics.TLSHandshakes == 0 || metrics.ReusedConnections == 0 || metrics.HTTP2Requests == 0 {
		t.Fatalf("HTTPS/H2 reuse metrics missing: %+v", metrics)
	}

	// HTTP/2 multiplexing can exceed TCP MaxConnsPerHost by design; the bound
	// applies to connections, while requests reuse those connections.
	var wait sync.WaitGroup
	for range 10 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := doFixtureRequest(t, manager, server, "/blocked")
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wait.Wait()
	if manager.Snapshot().NewConnections > 2 {
		t.Fatalf("per-host connection bound exceeded: %+v", manager.Snapshot())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	request := fixtureRequest(t, server, "/closed")
	if _, err := manager.Do(request, Policy{AllowPrivate: true}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed manager accepted request: %v", err)
	}
}

func TestConnectionPoolDefaultPolicy(t *testing.T) {
	manager, err := New(Options{Resolver: ResolverFunc(func(context.Context, string) (DNSResult, error) {
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Minute}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	transport := manager.transport
	if !transport.ForceAttemptHTTP2 || transport.MaxIdleConns != 256 || transport.MaxIdleConnsPerHost != 32 || transport.MaxConnsPerHost != 64 || transport.IdleConnTimeout != 90*time.Second || transport.ResponseHeaderTimeout != 30*time.Second || transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("unexpected connection pool defaults: %+v", transport)
	}
}

func TestWarmPathReducesDNSAndTLSOperations(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "warm")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	manager := fixtureTLSManager(t, server, 4)
	defer manager.Close()
	started := time.Now()
	for range 20 {
		response := doFixtureRequest(t, manager, server, "/warm")
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	metrics := manager.Snapshot()
	if metrics.DNSQueries > 2 || metrics.TLSHandshakes > 2 {
		t.Fatalf("warm path did not reduce DNS/TLS by at least 90%% from 20-call no-reuse baseline: %+v", metrics)
	}
	elapsed := time.Since(started)
	throughput := float64(metrics.TransferredBytes) / elapsed.Seconds()
	t.Logf("warm path metrics: DNS=%d TLS=%d reused=%d HTTP2=%d TTFB-total=%s bytes=%d throughput=%.0fB/s", metrics.DNSQueries, metrics.TLSHandshakes, metrics.ReusedConnections, metrics.HTTP2Requests, time.Duration(metrics.FirstResponseBytes), metrics.TransferredBytes, throughput)
}

func fixtureTLSManager(t *testing.T, server *httptest.Server, maxConnections int) *Manager {
	t.Helper()
	serverURL, _ := url.Parse(server.URL)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.InsecureSkipVerify = true // local ephemeral TLS fixture
	manager, err := New(Options{
		Client: &http.Client{Transport: transport}, MaxConnsPerHost: maxConnections,
		Resolver: ResolverFunc(func(context.Context, string) (DNSResult, error) {
			return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, TTL: time.Minute}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = serverURL
	return manager
}

func fixtureRequest(t *testing.T, server *httptest.Server, path string) *http.Request {
	t.Helper()
	serverURL, _ := url.Parse(server.URL)
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://fixture.test:%s%s", serverURL.Port(), path), nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func doFixtureRequest(t *testing.T, manager *Manager, server *httptest.Server, path string) *http.Response {
	t.Helper()
	response, err := manager.Do(fixtureRequest(t, server, path), Policy{AllowPrivate: true})
	if err != nil {
		t.Fatalf("fixture request: %v", err)
	}
	return response
}
