package doh_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/doh"
)

func TestDoHRFC8484GETPOSTAndStrictGrammar(t *testing.T) {
	query := dnsQuery(7, "Example.COM", 1)
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			service, resolverCalls, _, _ := testService(t, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 30), nil })
			request := validHTTPRequest(method, query, []byte("valid-token"))
			response, err := service.Serve(context.Background(), request)
			if err != nil || response.Status != "200" || response.ContentType != "application/dns-message" || binary.BigEndian.Uint16(response.Body[:2]) != 7 || resolverCalls.Load() != 1 {
				t.Fatalf("RFC8484 response=%#v calls=%d err=%v", response, resolverCalls.Load(), err)
			}
		})
	}

	invalid := []doh.HTTPRequest{
		{Method: "PUT", Accept: "application/dns-message", Token: []byte("valid-token")},
		{Method: "GET", Query: "dns=" + base64.RawURLEncoding.EncodeToString(query) + "&x=1", Accept: "application/dns-message", Token: []byte("valid-token")},
		{Method: "GET", Query: "dns=bad=padding", Accept: "application/dns-message", Token: []byte("valid-token")},
		{Method: "POST", ContentType: "application/json", Accept: "application/dns-message", Body: query, Token: []byte("valid-token")},
		{Method: "POST", ContentType: "application/dns-message", Accept: "*/*", Body: query, Token: []byte("valid-token")},
		{Method: "POST", ContentType: "application/dns-message", Accept: "application/dns-message", Body: make([]byte, doh.MaxDNSRequestBytes+1), Token: []byte("valid-token")},
	}
	for index, request := range invalid {
		service, calls, _, _ := testService(t, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 30), nil })
		if _, err := service.Serve(context.Background(), request); err == nil || calls.Load() != 0 {
			t.Fatalf("invalid RFC8484 case %d err=%v calls=%d", index, err, calls.Load())
		}
	}
}

func TestDoHTokenRotationIPPolicyAndRevokeBeforeCacheOrUpstream(t *testing.T) {
	query := dnsQuery(1, "secret-name.example", 1)
	cache := &countingCache{Cache: doh.NewMemoryCache(8, 1<<20)}
	var resolverCalls, tokenCalls, policyCalls atomic.Int32
	currentToken := atomic.Value{}
	currentToken.Store("new-token")
	runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) {
		resolverCalls.Add(1)
		return positiveResponse(request.DNSMessage, 10), nil
	})
	runtime.Tokens = doh.TokenVerifierFunc(func(_ context.Context, ref string, credential []byte) error {
		tokenCalls.Add(1)
		if ref != "secret/token" || string(credential) != currentToken.Load().(string) {
			return errors.New("raw token backend secret")
		}
		return nil
	})
	runtime.Policy = doh.IPPolicyEvaluatorFunc(func(_ context.Context, ref string, source doh.SourceIdentity) error {
		policyCalls.Add(1)
		if ref != "policy/shared" || source.Attestation != "allowed-source" {
			return errors.New("raw CIDR material")
		}
		return nil
	})
	service, err := doh.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, token, source string
		want                error
	}{
		{name: "rotated", token: "old-token", source: "allowed-source", want: doh.ErrInvalidToken},
		{name: "policy", token: "new-token", source: "denied-source", want: doh.ErrIPPolicyDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validHTTPRequest("POST", query, []byte(test.token))
			request.Source.Attestation = test.source
			_, err := service.Serve(context.Background(), request)
			if !errors.Is(err, test.want) || strings.Contains(fmt.Sprint(err), "raw") || resolverCalls.Load() != 0 || cache.gets.Load() != 0 {
				t.Fatalf("admission err=%v upstream=%d cache=%d", err, resolverCalls.Load(), cache.gets.Load())
			}
		})
	}
	if tokenCalls.Load() != 2 || policyCalls.Load() != 1 {
		t.Fatalf("token=%d policy=%d", tokenCalls.Load(), policyCalls.Load())
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := validHTTPRequest("POST", query, []byte("new-token"))
	request.Source.Attestation = "allowed-source"
	if _, err := service.Serve(context.Background(), request); !errors.Is(err, doh.ErrRevoked) || resolverCalls.Load() != 0 {
		t.Fatalf("revoke err=%v calls=%d", err, resolverCalls.Load())
	}
}

func TestDoHTTLNegativeCacheCapacityAndPoisoning(t *testing.T) {
	clock := &fakeClock{now: uint64(time.Second)}
	cache := doh.NewMemoryCache(2, 1<<20)
	var resolverCalls atomic.Int32
	runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) {
		resolverCalls.Add(1)
		return positiveResponse(request.DNSMessage, 2), nil
	})
	runtime.Clock = clock
	service, err := doh.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	request := validHTTPRequest("POST", dnsQuery(1, "cache.example", 1), []byte("valid-token"))
	if _, err := service.Serve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Body = dnsQuery(2, "CACHE.example", 1)
	response, err := service.Serve(context.Background(), request)
	if err != nil || !response.CacheHit || binary.BigEndian.Uint16(response.Body[:2]) != 2 || resolverCalls.Load() != 1 {
		t.Fatalf("TTL hit=%#v calls=%d err=%v", response, resolverCalls.Load(), err)
	}
	clock.now = uint64(3 * time.Second)
	if response, err = service.Serve(context.Background(), request); err != nil || response.CacheHit || resolverCalls.Load() != 2 {
		t.Fatalf("TTL expiry=%#v calls=%d err=%v", response, resolverCalls.Load(), err)
	}

	negativeRuntime := testRuntime(doh.NewMemoryCache(2, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		return negativeResponse(request.DNSMessage, 60, 5), nil
	})
	negativeRuntime.Clock = &fakeClock{now: uint64(time.Second)}
	negative, err := doh.NewService(testConfiguration(), negativeRuntime)
	if err != nil {
		t.Fatal(err)
	}
	negativeRequest := validHTTPRequest("GET", dnsQuery(8, "missing.example", 1), []byte("valid-token"))
	if _, err := negative.Serve(context.Background(), negativeRequest); err != nil {
		t.Fatal(err)
	}
	negativeRequest.Query = "dns=" + base64.RawURLEncoding.EncodeToString(dnsQuery(9, "missing.example", 1))
	if response, err := negative.Serve(context.Background(), negativeRequest); err != nil || !response.CacheHit {
		t.Fatalf("negative cache response=%#v err=%v", response, err)
	}

	poisonRuntime := testRuntime(doh.NewMemoryCache(2, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		return positiveResponse(dnsQuery(999, "other.example", 1), 10), nil
	})
	poison, err := doh.NewService(testConfiguration(), poisonRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := poison.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "victim.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrNoHealthyUpstream) {
		t.Fatalf("poisoning err=%v", err)
	}

	bounded := doh.NewMemoryCache(1, doh.MaxDNSResponseBytes+128)
	capacityRuntime := testRuntime(bounded, func(request doh.ResolveRequest) ([]byte, error) {
		resolverCalls.Add(1)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	capacity, err := doh.NewService(testConfiguration(), capacityRuntime)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.example", "two.example", "one.example"} {
		if _, err := capacity.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(3, name, 1), []byte("valid-token"))); err != nil {
			t.Fatal(err)
		}
	}
	if entries, bytes := bounded.Stats(); entries != 1 || bytes > doh.MaxDNSResponseBytes+128 {
		t.Fatalf("cache entries=%d bytes=%d", entries, bytes)
	}

	t.Run("TTL-boundaries-and-monotonic-clock", func(t *testing.T) {
		configuration := testConfiguration()
		configuration.MinTTLSeconds, configuration.MaxTTLSeconds = 5, 10
		boundaryClock := &fakeClock{now: uint64(time.Second)}
		var shortCalls atomic.Int32
		shortRuntime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
			shortCalls.Add(1)
			return positiveResponse(request.DNSMessage, 3), nil
		})
		shortRuntime.Clock = boundaryClock
		shortService, err := doh.NewService(configuration, shortRuntime)
		if err != nil {
			t.Fatal(err)
		}
		shortRequest := validHTTPRequest("POST", dnsQuery(1, "short.example", 1), []byte("valid-token"))
		if _, err := shortService.Serve(context.Background(), shortRequest); err != nil {
			t.Fatal(err)
		}
		if _, err := shortService.Serve(context.Background(), shortRequest); err != nil || shortCalls.Load() != 2 {
			t.Fatalf("below-min TTL was cached calls=%d err=%v", shortCalls.Load(), err)
		}

		var longCalls atomic.Int32
		longRuntime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
			longCalls.Add(1)
			return positiveResponse(request.DNSMessage, 100), nil
		})
		longRuntime.Clock = boundaryClock
		longService, err := doh.NewService(configuration, longRuntime)
		if err != nil {
			t.Fatal(err)
		}
		longRequest := validHTTPRequest("POST", dnsQuery(1, "long.example", 1), []byte("valid-token"))
		if _, err := longService.Serve(context.Background(), longRequest); err != nil {
			t.Fatal(err)
		}
		boundaryClock.now = uint64(11 * time.Second)
		if response, err := longService.Serve(context.Background(), longRequest); err != nil || response.CacheHit || longCalls.Load() != 2 {
			t.Fatalf("max TTL cap response=%#v calls=%d err=%v", response, longCalls.Load(), err)
		}
		boundaryClock.now = uint64(10 * time.Second)
		if _, err := longService.Serve(context.Background(), longRequest); !errors.Is(err, doh.ErrClockUnavailable) {
			t.Fatalf("monotonic regression err=%v", err)
		}
	})
}

func TestDoHFailoverTimeoutConcurrencyIsolationAndLateResult(t *testing.T) {
	configuration := testConfiguration()
	configuration.Upstreams = []doh.Upstream{{ID: "first", EndpointRef: "upstream/first", Priority: 0, Enabled: true}, {ID: "second", EndpointRef: "upstream/second", Priority: 1, Enabled: true}}
	runtime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		if request.EndpointRef == "upstream/first" {
			return nil, errors.New("raw upstream secret")
		}
		return positiveResponse(request.DNSMessage, 10), nil
	})
	service, err := doh.NewService(configuration, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "failover.example", 1), []byte("valid-token"))); err != nil {
		t.Fatal(err)
	}
	statuses := service.Statuses()
	if statuses[0].ID != "first" || statuses[0].Result != "failed" || statuses[1].Result != "healthy" {
		t.Fatalf("failover statuses=%#v", statuses)
	}

	configuration.MaxConcurrency, configuration.UpstreamTimeoutMS, configuration.RequestTimeoutMS = 1, 20, 100
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	blockingRuntime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return positiveResponse(request.DNSMessage, 10), nil
	})
	blocking, err := doh.NewService(configuration, blockingRuntime)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := blocking.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "slow.example", 1), []byte("valid-token")))
		result <- err
	}()
	<-started
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err=%v", err)
	}
	if _, err := blocking.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(2, "parallel.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrConcurrencyExhausted) {
		t.Fatalf("pool saturation err=%v", err)
	}
	close(release)
	time.Sleep(20 * time.Millisecond)
	if statuses := blocking.Statuses(); statuses[0].Result != "timeout" {
		t.Fatalf("late result corrupted status=%#v", statuses)
	}
}

func TestDoHRedactedAuditLogAndBackendFailures(t *testing.T) {
	secret := "super-secret-token-and-qname"
	var logs []doh.QueryLog
	var audits []doh.AuditRecord
	var mu sync.Mutex
	runtime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
	runtime.Logger = doh.QueryLoggerFunc(func(_ context.Context, record doh.QueryLog) error {
		mu.Lock()
		logs = append(logs, record)
		mu.Unlock()
		return nil
	})
	runtime.Auditor = doh.AuditorFunc(func(_ context.Context, record doh.AuditRecord) error {
		mu.Lock()
		audits = append(audits, record)
		mu.Unlock()
		return nil
	})
	service, err := doh.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	request := validHTTPRequest("POST", dnsQuery(1, secret+".example", 1), []byte(secret))
	if _, err := service.Serve(context.Background(), request); !errors.Is(err, doh.ErrInvalidToken) {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(struct {
		Logs   []doh.QueryLog
		Audits []doh.AuditRecord
	}{logs, audits})
	if strings.Contains(string(wire), secret) || len(logs) != 1 || len(audits) != 2 {
		t.Fatalf("unsafe logs/audits=%s", wire)
	}

	runtime = testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 10), nil })
	runtime.Logger = doh.QueryLoggerFunc(func(context.Context, doh.QueryLog) error { return errors.New("raw log material") })
	service, _ = doh.NewService(testConfiguration(), runtime)
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "log.example", 1), []byte("valid-token"))); !errors.Is(err, doh.ErrLogUnavailable) || strings.Contains(fmt.Sprint(err), "raw") {
		t.Fatalf("log failure=%v", err)
	}
}

type fakeClock struct{ now uint64 }

func (clock *fakeClock) Now(context.Context) (uint64, error) { return clock.now, nil }

type countingCache struct {
	doh.Cache
	gets atomic.Int32
}

func (cache *countingCache) Get(ctx context.Context, key string, now uint64) (doh.CacheEntry, bool, error) {
	cache.gets.Add(1)
	return cache.Cache.Get(ctx, key, now)
}

func testService(t *testing.T, resolve func(doh.ResolveRequest) ([]byte, error)) (*doh.Service, *atomic.Int32, *[]doh.QueryLog, *[]doh.AuditRecord) {
	t.Helper()
	var calls atomic.Int32
	var logs []doh.QueryLog
	var audits []doh.AuditRecord
	runtime := testRuntime(doh.NewMemoryCache(8, 1<<20), func(request doh.ResolveRequest) ([]byte, error) { calls.Add(1); return resolve(request) })
	runtime.Logger = doh.QueryLoggerFunc(func(_ context.Context, record doh.QueryLog) error { logs = append(logs, record); return nil })
	runtime.Auditor = doh.AuditorFunc(func(_ context.Context, record doh.AuditRecord) error { audits = append(audits, record); return nil })
	service, err := doh.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	return service, &calls, &logs, &audits
}

func testRuntime(cache doh.Cache, resolve func(doh.ResolveRequest) ([]byte, error)) doh.RuntimeAdapters {
	return doh.RuntimeAdapters{
		Listener: doh.ListenerFunc(func(context.Context, string, *doh.Service) error { return nil }),
		Tokens: doh.TokenVerifierFunc(func(_ context.Context, _ string, credential []byte) error {
			if string(credential) != "valid-token" {
				return errors.New("raw token")
			}
			return nil
		}),
		Policy: doh.IPPolicyEvaluatorFunc(func(_ context.Context, _ string, source doh.SourceIdentity) error {
			if source.Attestation != "allowed-source" {
				return errors.New("raw source")
			}
			return nil
		}),
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) { return resolve(request) }), Clock: &fakeClock{now: uint64(time.Second)}, Cache: cache,
		Logger: doh.QueryLoggerFunc(func(context.Context, doh.QueryLog) error { return nil }), Auditor: doh.AuditorFunc(func(context.Context, doh.AuditRecord) error { return nil }),
	}
}

func testConfiguration() doh.Configuration {
	return doh.Configuration{Generation: "generation-1", ListenerRef: "listener/doh", TokenSecretRef: "secret/token", IPPolicyRef: "policy/shared", RequestTimeoutMS: 1000, UpstreamTimeoutMS: 100, MaxConcurrency: 4, CacheEntries: 8, CacheBytes: 1 << 20, MinTTLSeconds: 1, MaxTTLSeconds: 3600, Upstreams: []doh.Upstream{{ID: "primary", EndpointRef: "upstream/primary", Enabled: true}}}
}

func validHTTPRequest(method string, query, token []byte) doh.HTTPRequest {
	request := doh.HTTPRequest{Method: method, Accept: "application/dns-message", Token: token, Source: doh.SourceIdentity{Attestation: "allowed-source"}}
	if method == "GET" {
		request.Query = "dns=" + base64.RawURLEncoding.EncodeToString(query)
	} else {
		request.ContentType, request.Body = "application/dns-message", query
	}
	return request
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:2], id)
	binary.BigEndian.PutUint16(wire[2:4], 0x0100)
	binary.BigEndian.PutUint16(wire[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return wire
}

func positiveResponse(query []byte, ttl uint32) []byte {
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), 0, 4, 192, 0, 2, 1)
	return response
}

func negativeResponse(query []byte, ttl, minimum uint32) []byte {
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[8:10], 1)
	rdata := []byte{0, 0}
	for _, value := range []uint32{1, 2, 3, 4, minimum} {
		rdata = append(rdata, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	response = append(response, 0xc0, 0x0c, 0, 6, 0, 1, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), 0, byte(len(rdata)))
	return append(response, rdata...)
}
