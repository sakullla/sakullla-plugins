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

func TestDNSTransientLeaderFailureDoesNotPoisonCache(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	resolver := ResolverFunc(func(ctx context.Context, _ string) (DNSResult, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return DNSResult{NegativeTTL: time.Minute}, ctx.Err()
		}
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Minute}, nil
	})
	cache := NewDNSCache(nil, resolver, 8)
	ctx, cancel := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() { _, err := cache.Resolve(ctx, "transient.test"); leaderDone <- err }()
	<-started
	waiterDone := make(chan error, 1)
	go func() { _, err := cache.Resolve(context.Background(), "transient.test"); waiterDone <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if !errors.Is(<-leaderDone, context.Canceled) || !errors.Is(<-waiterDone, context.Canceled) {
		t.Fatal("cold flight did not broadcast its transient failure")
	}
	addresses, err := cache.Resolve(context.Background(), "transient.test")
	if err != nil || len(addresses) != 1 || calls.Load() != 2 {
		t.Fatalf("transient failure poisoned DNS cache: addresses=%v calls=%d err=%v", addresses, calls.Load(), err)
	}
}

func TestDNSZeroTTLAndSWRSingleRefresh(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	var zeroCalls atomic.Int32
	zeroCache := NewDNSCache(clock, ResolverFunc(func(context.Context, string) (DNSResult, error) {
		zeroCalls.Add(1)
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: 0}, nil
	}), 8)
	_, _ = zeroCache.Resolve(context.Background(), "zero.test")
	_, _ = zeroCache.Resolve(context.Background(), "zero.test")
	if zeroCalls.Load() != 2 {
		t.Fatalf("zero TTL answer was cached: calls=%d", zeroCalls.Load())
	}

	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls atomic.Int32
	cache := NewDNSCache(clock, ResolverFunc(func(context.Context, string) (DNSResult, error) {
		call := calls.Add(1)
		if call == 2 {
			close(refreshStarted)
			<-releaseRefresh
		}
		address := "8.8.8.8"
		if call > 1 {
			address = "1.1.1.1"
		}
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP(address)}}, TTL: 2 * time.Second}, nil
	}), 8)
	_, _ = cache.Resolve(context.Background(), "swr.test")
	clock.Advance(3 * time.Second)
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			addresses, err := cache.Resolve(context.Background(), "swr.test")
			if err != nil || addresses[0].IP.String() != "8.8.8.8" {
				t.Errorf("SWR did not return stale positive answer: %v %v", addresses, err)
			}
		}()
	}
	wait.Wait()
	<-refreshStarted
	if calls.Load() != 2 {
		t.Fatalf("100 expired DNS requests started %d refreshes", calls.Load()-1)
	}
	close(releaseRefresh)
}

func TestDNSMixedZeroAndPositiveTTLAlwaysKeepsZero(t *testing.T) {
	for _, values := range [][]time.Duration{{0, time.Minute}, {time.Minute, 0}} {
		minimum := time.Duration(0)
		initialized := false
		for _, value := range values {
			minimum, initialized = lowerTTL(minimum, initialized, value)
		}
		if !initialized || minimum != 0 {
			t.Fatalf("mixed TTL order %v produced %s", values, minimum)
		}
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

func TestTokenCacheAtomicFillAndFlightRegistration(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	cache := NewCache[string](clock, 4, 1024)
	cache.mu.Lock()
	started := make(chan struct{})
	done := make(chan struct{})
	var loaderCalls atomic.Int32
	go func() {
		close(started)
		value, err := cache.GetOrLoad(context.Background(), "token", func(context.Context) (Loaded[string], error) {
			loaderCalls.Add(1)
			return Loaded[string]{Value: "duplicate", Size: 9, TTL: time.Minute}, nil
		})
		if err != nil || value != "filled" {
			t.Errorf("atomic fill lookup: value=%q err=%v", value, err)
		}
		close(done)
	}()
	<-started
	// Publish under the exact lock that owns both lookup and flight
	// registration. The blocked caller must observe this completed fill and
	// cannot create a second serial loader wave.
	cache.setLocked("token", Loaded[string]{Value: "filled", Size: 6, TTL: time.Minute})
	cache.mu.Unlock()
	<-done
	if loaderCalls.Load() != 0 {
		t.Fatalf("completed fill raced into %d duplicate loader calls", loaderCalls.Load())
	}
}

func TestManifestCacheSWRSingleRefreshSIEAndPermanentInvalidation(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	cache := NewCache[string](clock, 8, 1024)
	var loads atomic.Int32
	initial := func(context.Context) (Loaded[string], error) {
		loads.Add(1)
		return Loaded[string]{Value: "v1", Size: 2, TTL: time.Second, StaleWhileRevalidate: 10 * time.Second, StaleIfError: time.Minute}, nil
	}
	if value, err := cache.GetOrLoad(context.Background(), "manifest", initial); err != nil || value != "v1" {
		t.Fatalf("initial fill: %q %v", value, err)
	}
	clock.Advance(2 * time.Second)
	refreshStarted := make(chan struct{})
	release := make(chan struct{})
	refresh := func(context.Context) (Loaded[string], error) {
		if loads.Add(1) == 2 {
			close(refreshStarted)
			<-release
		}
		return Loaded[string]{Value: "v2", Size: 2, TTL: time.Second, StaleWhileRevalidate: 10 * time.Second, StaleIfError: time.Minute}, nil
	}
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := cache.GetOrLoad(context.Background(), "manifest", refresh)
			if err != nil || value != "v1" {
				t.Errorf("manifest SWR: %q %v", value, err)
			}
		}()
	}
	wait.Wait()
	<-refreshStarted
	if loads.Load() != 2 {
		t.Fatalf("100 expired manifests started %d refreshes", loads.Load()-1)
	}
	close(release)
	refreshed := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if current, found := cache.Get("manifest"); found && current == "v2" {
			refreshed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !refreshed {
		t.Fatal("background manifest refresh did not publish")
	}
	clock.Advance(12 * time.Second)
	value, err := cache.GetOrLoad(context.Background(), "manifest", func(context.Context) (Loaded[string], error) {
		return Loaded[string]{}, errors.New("temporary upstream failure")
	})
	if err != nil || value != "v2" {
		t.Fatalf("manifest stale-if-error failed: %q %v", value, err)
	}
	_, err = cache.GetOrLoad(context.Background(), "manifest", func(context.Context) (Loaded[string], error) {
		return Loaded[string]{}, PermanentCacheError(errors.New("integrity failure"))
	})
	if !errors.Is(err, ErrPermanentCache) {
		t.Fatalf("permanent failure served stale manifest: %v", err)
	}
	if _, found := cache.Get("manifest"); found {
		t.Fatal("permanent manifest failure did not invalidate stale entry")
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

func TestConnectionPoolSecurityPolicyIsolation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true // local policy-isolation fixture
	var lookups atomic.Int32
	resolver := ResolverFunc(func(context.Context, string) (DNSResult, error) {
		if lookups.Add(1) == 1 {
			return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, TTL: time.Minute}, nil
		}
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Minute}, nil
	})
	var mu sync.Mutex
	var dialed []string
	manager, err := New(Options{
		Client: &http.Client{Transport: transport}, Resolver: resolver,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, address)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	request, _ := http.NewRequest(http.MethodGet, "https://policy.test/value", nil)
	response, err := manager.Do(request, Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	manager.dns.Delete("policy.test")
	request, _ = http.NewRequest(http.MethodGet, "https://policy.test/value", nil)
	response, err = manager.Do(request, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 2 || dialed[0] != "127.0.0.1:443" || dialed[1] != "8.8.8.8:443" {
		t.Fatalf("security policies reused one connection pool: dials=%v", dialed)
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
