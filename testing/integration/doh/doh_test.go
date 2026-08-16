package doh_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/doh"
)

func TestDoHRFC8484GETPOSTAndStrictGrammar(t *testing.T) {
	query := dnsQuery(7, "Example.COM", 1)
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			service, resolverCalls := testService(t, func(request doh.ResolveRequest) ([]byte, error) {
				return positiveResponse(request.DNSMessage, 30), nil
			})
			response, err := service.Serve(context.Background(), validHTTPRequest(method, query, ""))
			if err != nil || response.Status != "200" || response.ContentType != "application/dns-message" || binary.BigEndian.Uint16(response.Body[:2]) != 7 || resolverCalls.Load() != 1 {
				t.Fatalf("RFC8484 response=%#v calls=%d err=%v", response, resolverCalls.Load(), err)
			}
		})
	}
	for name, accept := range map[string]string{
		"omitted":              "",
		"wildcard":             "*/*",
		"application-wildcard": "application/*",
		"media-list":           "application/json, application/dns-message; q=0.5",
	} {
		t.Run("accept-"+name, func(t *testing.T) {
			service, calls := testService(t, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 30), nil })
			request := validHTTPRequest("POST", query, "")
			request.Accept = accept
			if response, err := service.Serve(context.Background(), request); err != nil || response.Status != "200" || calls.Load() != 1 {
				t.Fatalf("Accept %q response=%#v calls=%d err=%v", accept, response, calls.Load(), err)
			}
		})
	}
	for _, method := range []string{"GET", "POST"} {
		t.Run(method+"-edns-do-padding", func(t *testing.T) {
			ednsQuery := withEDNS(query, true, 12, []byte{0, 0, 0, 0})
			service, calls := testService(t, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 30), nil })
			if response, err := service.Serve(context.Background(), validHTTPRequest(method, ednsQuery, "")); err != nil || response.Status != "200" || calls.Load() != 1 {
				t.Fatalf("EDNS response=%#v calls=%d err=%v", response, calls.Load(), err)
			}
		})
	}

	invalid := []doh.HTTPRequest{
		{Method: "PUT", Accept: "application/dns-message"},
		{Method: "GET", Query: "dns=" + base64.RawURLEncoding.EncodeToString(query) + "&x=1", Accept: "application/dns-message"},
		{Method: "GET", Query: "dns=bad=padding", Accept: "application/dns-message"},
		{Method: "POST", ContentType: "application/json", Accept: "application/dns-message", Body: query},
		{Method: "POST", ContentType: "application/dns-message", Accept: "application/json", Body: query},
		{Method: "POST", ContentType: "application/dns-message", Accept: "application/dns-message", Body: make([]byte, doh.MaxDNSRequestBytes+1)},
	}
	for index, request := range invalid {
		service, calls := testService(t, func(request doh.ResolveRequest) ([]byte, error) { return positiveResponse(request.DNSMessage, 30), nil })
		if _, err := service.Serve(context.Background(), request); err == nil || calls.Load() != 0 {
			t.Fatalf("invalid RFC8484 case %d err=%v calls=%d", index, err, calls.Load())
		}
	}
}

func TestDoHHandlerAnswersWithoutTokenOrIPPolicy(t *testing.T) {
	var calls atomic.Int32
	controller := activateController(t, nil, func(request doh.ResolveRequest) ([]byte, error) {
		calls.Add(1)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	for _, test := range []struct {
		method string
		query  []byte
	}{
		{method: http.MethodGet, query: dnsQuery(3, "open-get.example", 1)},
		{method: http.MethodPost, query: dnsQuery(4, "open-post.example", 1)},
	} {
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, dnsHTTPRequest(test.method, test.query, ""))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/dns-message" || !bytes.Equal(recorder.Body.Bytes()[:2], test.query[:2]) {
			t.Fatalf("%s status=%d body=%q", test.method, recorder.Code, recorder.Body.Bytes())
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestDoHHandlerInvalidRFC8484Is4xxWithoutOutbound(t *testing.T) {
	var calls atomic.Int32
	controller := activateController(t, nil, func(request doh.ResolveRequest) ([]byte, error) {
		calls.Add(1)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	cases := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/dns-query", nil),
		httptest.NewRequest(http.MethodPut, "/dns-query", nil),
		dnsHTTPRequest(http.MethodPost, dnsQuery(1, "bad-media.example", 1), ""),
	}
	cases[2].Header.Set("Content-Type", "application/json")
	for index, request := range cases {
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, request)
		if recorder.Code < 400 || recorder.Code >= 500 || calls.Load() != 0 {
			t.Fatalf("case %d status=%d calls=%d", index, recorder.Code, calls.Load())
		}
	}
}

func TestDoHEmptyUpstreamsUseDefault(t *testing.T) {
	if doh.DefaultUpstreamEndpoint != "https://dns.google/dns-query" {
		t.Fatalf("default upstream=%q", doh.DefaultUpstreamEndpoint)
	}
	query := dnsQuery(1, "default.example", 1)
	for name, config := range map[string]doh.PluginConfig{
		"omitted": {},
		"empty":   {Upstreams: ""},
	} {
		t.Run(name, func(t *testing.T) {
			var seen []string
			service, err := doh.NewService(doh.ConfigurationFromPlugin(config), doh.RuntimeAdapters{
				Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
					seen = append(seen, request.Endpoint)
					return positiveResponse(request.DNSMessage, 30), nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, "")); err != nil {
				t.Fatal(err)
			}
			if len(seen) != 1 || seen[0] != doh.DefaultUpstreamEndpoint {
				t.Fatalf("upstreams=%v", seen)
			}
		})
	}
}

func TestDoHConfiguredUpstreamsOverrideDefault(t *testing.T) {
	const custom = "https://resolver.example/dns-query"
	var seen []string
	service, err := doh.NewService(doh.ConfigurationFromPlugin(doh.PluginConfig{
		Upstreams: custom,
	}), doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
			seen = append(seen, request.Endpoint)
			return positiveResponse(request.DNSMessage, 30), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "custom.example", 1), "")); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != custom {
		t.Fatalf("upstreams=%v", seen)
	}
}

func TestDoHBareIPUpstreamUsesUDP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, doh.MaxDNSResponseBytes)
		read, addr, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			return
		}
		_, _ = conn.WriteTo(positiveResponse(buffer[:read], 30), addr)
	}()
	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	service, err := doh.NewService(doh.ConfigurationFromPlugin(doh.PluginConfig{
		Upstreams: host + ":" + port,
	}), doh.RuntimeAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	query := dnsQuery(11, "bare-ip.example", 1)
	response, err := service.Serve(context.Background(), validHTTPRequest("POST", query, ""))
	if err != nil || response.Status != "200" || binary.BigEndian.Uint16(response.Body[:2]) != 11 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
}

func TestDoHNoHealthyUpstreamIs5xxNotSuccessDNS(t *testing.T) {
	var calls atomic.Int32
	controller := activateController(t, []byte(`{"upstreams":"https://down.example/dns-query"}`), func(request doh.ResolveRequest) ([]byte, error) {
		calls.Add(1)
		return nil, errors.New("upstream down")
	})
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, dnsHTTPRequest(http.MethodPost, dnsQuery(1, "fail.example", 1), ""))
	if recorder.Code < 500 || recorder.Header().Get("Content-Type") == "application/dns-message" || calls.Load() != 1 {
		t.Fatalf("status=%d type=%q calls=%d body=%q", recorder.Code, recorder.Header().Get("Content-Type"), calls.Load(), recorder.Body.Bytes())
	}
}

func TestDoHQueryECSIsNotOverwrittenByForwarded(t *testing.T) {
	queryIP := net.ParseIP("198.51.100.10")
	query := withECS(dnsQuery(4, "ecs-query.example", 1), queryIP, 24)
	var outbound []byte
	service, _ := testService(t, func(request doh.ResolveRequest) ([]byte, error) {
		outbound = append([]byte(nil), request.DNSMessage...)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	request := validHTTPRequest("POST", query, `for=203.0.113.20;proto=https;host=dns.example`)
	if _, err := service.Serve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	family, prefix, address, ok := extractECS(outbound)
	if !ok || family != 1 || prefix != 24 || !address.Equal(net.ParseIP("198.51.100.0")) {
		t.Fatalf("outbound ECS family=%d prefix=%d ip=%v ok=%v", family, prefix, address, ok)
	}
}

func TestDoHForwardedForInjectsECSWhenQueryHasNone(t *testing.T) {
	query := dnsQuery(5, "ecs-forwarded.example", 1)
	var outbound []byte
	service, _ := testService(t, func(request doh.ResolveRequest) ([]byte, error) {
		outbound = append([]byte(nil), request.DNSMessage...)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, `for=203.0.113.40`)); err != nil {
		t.Fatal(err)
	}
	family, prefix, address, ok := extractECS(outbound)
	if !ok || family != 1 || prefix == 0 || !address.Equal(net.ParseIP("203.0.113.0")) {
		t.Fatalf("injected ECS family=%d prefix=%d ip=%v ok=%v", family, prefix, address, ok)
	}
}

func TestDoHResolvesWithoutECSWhenNeitherPresent(t *testing.T) {
	query := dnsQuery(6, "no-ecs.example", 1)
	var outbound []byte
	service, calls := testService(t, func(request doh.ResolveRequest) ([]byte, error) {
		outbound = append([]byte(nil), request.DNSMessage...)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	request := validHTTPRequest("POST", query, "")
	request.Forwarded = "proto=https;host=dns.example"
	if response, err := service.Serve(context.Background(), request); err != nil || response.Status != "200" || calls.Load() != 1 {
		t.Fatalf("response=%#v calls=%d err=%v", response, calls.Load(), err)
	}
	if _, _, _, ok := extractECS(outbound); ok {
		t.Fatalf("unexpected ECS in outbound")
	}
}

func TestDoHIgnoresXForwardedFor(t *testing.T) {
	query := dnsQuery(8, "xff.example", 1)
	var outbound []byte
	controller := activateController(t, nil, func(request doh.ResolveRequest) ([]byte, error) {
		outbound = append([]byte(nil), request.DNSMessage...)
		return positiveResponse(request.DNSMessage, 30), nil
	})
	httpRequest := dnsHTTPRequest(http.MethodPost, query, "")
	httpRequest.Header.Set("X-Forwarded-For", "203.0.113.99")
	httpRequest.RemoteAddr = "192.0.2.10:443"
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, httpRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d", recorder.Code)
	}
	if _, _, _, ok := extractECS(outbound); ok {
		t.Fatalf("X-Forwarded-For leaked into ECS")
	}
}

func TestDoHCacheIsolatesECSSources(t *testing.T) {
	query := dnsQuery(9, "shared.example", 1)
	var calls atomic.Int32
	service, err := doh.NewService(testConfiguration(), doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
			calls.Add(1)
			return positiveResponse(request.DNSMessage, 30), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, `for=203.0.113.10`)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", withECS(query, net.ParseIP("198.51.100.1"), 24), `for=203.0.113.10`)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("ecs sources shared cache calls=%d", calls.Load())
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, `for=203.0.113.10`)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("forwarded ECS cache missed calls=%d", calls.Load())
	}
}

func TestDoHTTLNegativeCacheAndPoisoning(t *testing.T) {
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
	request := validHTTPRequest("POST", dnsQuery(1, "cache.example", 1), "")
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

	poisonRuntime := testRuntime(doh.NewMemoryCache(2, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		return positiveResponse(dnsQuery(999, "other.example", 1), 10), nil
	})
	poison, err := doh.NewService(testConfiguration(), poisonRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := poison.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "victim.example", 1), "")); !errors.Is(err, doh.ErrNoHealthyUpstream) {
		t.Fatalf("poisoning err=%v", err)
	}
}

func TestDoHDefaultClockAllowsRepeatedQueries(t *testing.T) {
	var calls atomic.Int32
	service, err := doh.NewService(testConfiguration(), doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
			calls.Add(1)
			return positiveResponse(request.DNSMessage, 30), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := validHTTPRequest("POST", dnsQuery(1, "monotonic.example", 1), "")
	if _, err := service.Serve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), request); err != nil || calls.Load() != 1 {
		t.Fatalf("default clock second serve err=%v calls=%d", err, calls.Load())
	}
}

func TestDoHInjectedClockBackwardFailsClosed(t *testing.T) {
	clock := &fakeClock{now: uint64(2 * time.Second)}
	runtime := testRuntime(doh.NewMemoryCache(2, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		return positiveResponse(request.DNSMessage, 30), nil
	})
	runtime.Clock = clock
	service, err := doh.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	request := validHTTPRequest("POST", dnsQuery(1, "backward.example", 1), "")
	if _, err := service.Serve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.now = uint64(time.Second)
	if _, err := service.Serve(context.Background(), request); !errors.Is(err, doh.ErrClockUnavailable) {
		t.Fatalf("backward clock err=%v", err)
	}
}

func TestDoHCacheHitPayloadValidation(t *testing.T) {
	query := dnsQuery(9, "cache-validation.example", 1)
	wrongQuestion := positiveResponse(dnsQuery(0, "other.example", 1), 30)
	binary.BigEndian.PutUint16(wrongQuestion[:2], 0)
	malformed := make([]byte, 17)
	for name, payload := range map[string][]byte{
		"empty":          {},
		"one-byte":       {0},
		"oversize":       make([]byte, doh.MaxDNSResponseBytes+1),
		"wrong-question": wrongQuestion,
		"malformed":      malformed,
	} {
		t.Run(name, func(t *testing.T) {
			cache := &fixedHitCache{entry: doh.CacheEntry{Response: payload, ExpiresAt: uint64(time.Hour)}}
			var resolverCalls atomic.Int32
			runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) {
				resolverCalls.Add(1)
				return positiveResponse(request.DNSMessage, 30), nil
			})
			service, err := doh.NewService(testConfiguration(), runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, "")); !errors.Is(err, doh.ErrCacheUnavailable) || resolverCalls.Load() != 0 {
				t.Fatalf("cache payload err=%v resolver=%d", err, resolverCalls.Load())
			}
		})
	}
}

func TestDoHCacheHitRemainingTTLAndExpiryBinding(t *testing.T) {
	query := dnsQuery(9, "cache-ttl.example", 1)
	normalize := func(wire []byte) []byte {
		wire = append([]byte(nil), wire...)
		binary.BigEndian.PutUint16(wire[:2], 0)
		return wire
	}
	t.Run("late-positive-hit", func(t *testing.T) {
		cache := &fixedHitCache{entry: doh.CacheEntry{Response: normalize(positiveResponse(query, 30)), StoredAt: uint64(time.Second), ExpiresAt: uint64(31 * time.Second)}}
		runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return nil, errors.New("unexpected resolver") })
		runtime.Clock = &fakeClock{now: uint64(26 * time.Second)}
		service, err := doh.NewService(testConfiguration(), runtime)
		if err != nil {
			t.Fatal(err)
		}
		response, err := service.Serve(context.Background(), validHTTPRequest("POST", query, ""))
		if err != nil || !response.CacheHit || firstAnswerTTL(response.Body) != 5 {
			t.Fatalf("late hit response=%#v TTL=%d err=%v", response, firstAnswerTTL(response.Body), err)
		}
	})
	t.Run("negative-SOA-hit", func(t *testing.T) {
		cache := &fixedHitCache{entry: doh.CacheEntry{Response: normalize(negativeResponse(query, 60, 30)), StoredAt: uint64(time.Second), ExpiresAt: uint64(31 * time.Second)}}
		runtime := testRuntime(cache, func(request doh.ResolveRequest) ([]byte, error) { return nil, errors.New("unexpected resolver") })
		runtime.Clock = &fakeClock{now: uint64(21 * time.Second)}
		service, err := doh.NewService(testConfiguration(), runtime)
		if err != nil {
			t.Fatal(err)
		}
		response, err := service.Serve(context.Background(), validHTTPRequest("POST", query, ""))
		soaTTL, minimum := negativeSOATTLs(response.Body)
		if err != nil || !response.CacheHit || soaTTL != 10 || minimum != 10 {
			t.Fatalf("negative hit response=%#v SOA=%d minimum=%d err=%v", response, soaTTL, minimum, err)
		}
	})
	for name, entry := range map[string]doh.CacheEntry{
		"zero-TTL":      {Response: normalize(positiveResponse(query, 0)), StoredAt: uint64(time.Second), ExpiresAt: uint64(2 * time.Second)},
		"forged-expiry": {Response: normalize(positiveResponse(query, 5)), StoredAt: uint64(time.Second), ExpiresAt: uint64(20 * time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			runtime := testRuntime(&fixedHitCache{entry: entry}, func(request doh.ResolveRequest) ([]byte, error) { return nil, errors.New("unexpected resolver") })
			runtime.Clock = &fakeClock{now: uint64(time.Second)}
			service, err := doh.NewService(testConfiguration(), runtime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, "")); !errors.Is(err, doh.ErrCacheUnavailable) {
				t.Fatalf("cache binding err=%v", err)
			}
		})
	}
	t.Run("below-configured-minimum", func(t *testing.T) {
		configuration := testConfiguration()
		configuration.MinTTLSeconds = 10
		entry := doh.CacheEntry{Response: normalize(positiveResponse(query, 5)), StoredAt: uint64(time.Second), ExpiresAt: uint64(6 * time.Second)}
		runtime := testRuntime(&fixedHitCache{entry: entry}, func(request doh.ResolveRequest) ([]byte, error) { return nil, errors.New("unexpected resolver") })
		runtime.Clock = &fakeClock{now: uint64(time.Second)}
		service, err := doh.NewService(configuration, runtime)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Serve(context.Background(), validHTTPRequest("POST", query, "")); !errors.Is(err, doh.ErrCacheUnavailable) {
			t.Fatalf("minimum binding err=%v", err)
		}
	})
}

func TestDoHFailoverUsesConfiguredOrder(t *testing.T) {
	configuration := testConfiguration()
	configuration.Upstreams = []doh.Upstream{
		{ID: "first", Endpoint: "https://first.example/dns-query", Priority: 0, Enabled: true},
		{ID: "second", Endpoint: "https://second.example/dns-query", Priority: 1, Enabled: true},
	}
	runtime := testRuntime(doh.NewMemoryCache(4, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		if request.Endpoint == "https://first.example/dns-query" {
			return nil, errors.New("first down")
		}
		return positiveResponse(request.DNSMessage, 10), nil
	})
	service, err := doh.NewService(configuration, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "failover.example", 1), "")); err != nil {
		t.Fatal(err)
	}
	statuses := service.Statuses()
	if statuses[0].ID != "first" || statuses[0].Result != "failed" || statuses[1].Result != "healthy" {
		t.Fatalf("failover statuses=%#v", statuses)
	}
}

func TestDoHCommentsAndDomainRouting(t *testing.T) {
	var seen []string
	service, err := doh.NewService(doh.ConfigurationFromPlugin(doh.PluginConfig{
		Upstreams: "# comment\nhttps://default.example/dns-query\n[/example.local/]https://local-a.example/dns-query https://local-b.example/dns-query",
	}), doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
			seen = append(seen, request.Endpoint)
			if request.Endpoint == "https://local-a.example/dns-query" {
				return nil, errors.New("local-a down")
			}
			return positiveResponse(request.DNSMessage, 10), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "www.example.local", 1), "")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(2, "other.example", 1), "")); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0] != "https://local-a.example/dns-query" || seen[1] != "https://local-b.example/dns-query" || seen[2] != "https://default.example/dns-query" {
		t.Fatalf("seen=%v", seen)
	}
}

func TestDoHDomainListDoesNotFallBackToDefault(t *testing.T) {
	var seen []string
	service, err := doh.NewService(doh.ConfigurationFromPlugin(doh.PluginConfig{
		Upstreams: "https://default.example/dns-query\n[/example.local/]https://local.example/dns-query",
	}), doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) {
			seen = append(seen, request.Endpoint)
			return nil, errors.New("down")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "example.local", 1), "")); !errors.Is(err, doh.ErrNoHealthyUpstream) {
		t.Fatalf("err=%v", err)
	}
	if len(seen) != 1 || seen[0] != "https://local.example/dns-query" {
		t.Fatalf("seen=%v", seen)
	}
}

func TestDoHRevokeBeforeUpstream(t *testing.T) {
	var resolverCalls atomic.Int32
	service, err := doh.NewService(testConfiguration(), testRuntime(doh.NewMemoryCache(8, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		resolverCalls.Add(1)
		return positiveResponse(request.DNSMessage, 10), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Serve(context.Background(), validHTTPRequest("POST", dnsQuery(1, "revoked.example", 1), "")); !errors.Is(err, doh.ErrRevoked) || resolverCalls.Load() != 0 {
		t.Fatalf("revoke err=%v calls=%d", err, resolverCalls.Load())
	}
}

type fakeClock struct{ now uint64 }

func (clock *fakeClock) Now(context.Context) (uint64, error) { return clock.now, nil }

func testService(t *testing.T, resolve func(doh.ResolveRequest) ([]byte, error)) (*doh.Service, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	service, err := doh.NewService(testConfiguration(), testRuntime(doh.NewMemoryCache(8, 1<<20), func(request doh.ResolveRequest) ([]byte, error) {
		calls.Add(1)
		return resolve(request)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return service, &calls
}

func testRuntime(cache doh.Cache, resolve func(doh.ResolveRequest) ([]byte, error)) doh.RuntimeAdapters {
	return doh.RuntimeAdapters{
		Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) { return resolve(request) }),
		Clock:    &fakeClock{now: uint64(time.Second)},
		Cache:    cache,
	}
}

func testConfiguration() doh.Configuration {
	return doh.Configuration{
		RequestTimeoutMS: 1000, UpstreamTimeoutMS: 100, MaxConcurrency: 4,
		CacheEntries: 8, CacheBytes: 1 << 20, MinTTLSeconds: 1, MaxTTLSeconds: 3600,
		Upstreams: []doh.Upstream{{ID: "primary", Endpoint: "https://primary.example/dns-query", Enabled: true}},
	}
}

func activateController(t *testing.T, config []byte, resolve func(doh.ResolveRequest) ([]byte, error)) *doh.Controller {
	t.Helper()
	controller, err := doh.NewController(doh.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		NewService: func(plugin doh.PluginConfig) (*doh.Service, error) {
			return doh.NewService(doh.ConfigurationFromPlugin(plugin), doh.RuntimeAdapters{
				Resolver: doh.ResolverFunc(func(_ context.Context, request doh.ResolveRequest) ([]byte, error) { return resolve(request) }),
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: doh.PluginID, PluginVersion: doh.PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: "generation-1",
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller
}

func validHTTPRequest(method string, query []byte, forwarded string) doh.HTTPRequest {
	request := doh.HTTPRequest{Method: method, Accept: "application/dns-message", Forwarded: forwarded}
	if method == "GET" {
		request.Query = "dns=" + base64.RawURLEncoding.EncodeToString(query)
	} else {
		request.ContentType, request.Body = "application/dns-message", query
	}
	return request
}

func dnsHTTPRequest(method string, query []byte, forwarded string) *http.Request {
	var body io.Reader
	target := "/dns-query"
	if method == http.MethodGet {
		target += "?dns=" + base64.RawURLEncoding.EncodeToString(query)
	} else {
		body = bytes.NewReader(query)
	}
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Accept", "application/dns-message")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/dns-message")
	}
	if forwarded != "" {
		request.Header.Set("Forwarded", forwarded)
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

func withEDNS(query []byte, dnssecOK bool, optionCode uint16, option []byte) []byte {
	wire := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(wire[10:12], 1)
	flags := uint32(0)
	if dnssecOK {
		flags = 0x8000
	}
	wire = append(wire, 0, 0, 41, 0x04, 0xd0, byte(flags>>24), byte(flags>>16), byte(flags>>8), byte(flags))
	wire = append(wire, 0, byte(len(option)+4), byte(optionCode>>8), byte(optionCode), byte(len(option)>>8), byte(len(option)))
	return append(wire, option...)
}

func withECS(query []byte, ip net.IP, prefix uint8) []byte {
	v4 := ip.To4()
	if v4 == nil {
		panic("withECS requires IPv4")
	}
	nbytes := int((prefix + 7) / 8)
	payload := []byte{0, 1, prefix, 0}
	payload = append(payload, v4[:nbytes]...)
	return withEDNS(query, false, 8, payload)
}

func extractECS(wire []byte) (uint16, uint8, net.IP, bool) {
	if len(wire) < 17 {
		return 0, 0, nil, false
	}
	if binary.BigEndian.Uint16(wire[10:12]) == 0 {
		return 0, 0, nil, false
	}
	offset := dnsQuestionEnd(wire)
	if offset+11 > len(wire) || wire[offset] != 0 || binary.BigEndian.Uint16(wire[offset+1:offset+3]) != 41 {
		return 0, 0, nil, false
	}
	rdataLength := int(binary.BigEndian.Uint16(wire[offset+9 : offset+11]))
	rdataStart, rdataEnd := offset+11, offset+11+rdataLength
	if rdataEnd > len(wire) {
		return 0, 0, nil, false
	}
	for rdataStart < rdataEnd {
		if rdataStart+4 > rdataEnd {
			return 0, 0, nil, false
		}
		code := binary.BigEndian.Uint16(wire[rdataStart : rdataStart+2])
		length := int(binary.BigEndian.Uint16(wire[rdataStart+2 : rdataStart+4]))
		payload := wire[rdataStart+4 : rdataStart+4+length]
		if code == 8 && length >= 4 {
			family := binary.BigEndian.Uint16(payload[:2])
			prefix := payload[2]
			addr := payload[4:]
			var ip net.IP
			if family == 1 {
				full := make(net.IP, 4)
				copy(full, addr)
				ip = net.IP(full)
			} else {
				full := make(net.IP, 16)
				copy(full, addr)
				ip = net.IP(full)
			}
			return family, prefix, ip, true
		}
		rdataStart += 4 + length
	}
	return 0, 0, nil, false
}

type fixedHitCache struct{ entry doh.CacheEntry }

func (cache *fixedHitCache) Get(context.Context, string, uint64) (doh.CacheEntry, bool, error) {
	return doh.CacheEntry{Response: append([]byte(nil), cache.entry.Response...), StoredAt: cache.entry.StoredAt, ExpiresAt: cache.entry.ExpiresAt}, true, nil
}
func (*fixedHitCache) Put(context.Context, string, doh.CacheEntry) error { return nil }
func (*fixedHitCache) Reset(context.Context, string) error               { return nil }

func negativeResponse(query []byte, ttl, minimum uint32) []byte {
	questionEnd := dnsQuestionEnd(query)
	response := append([]byte(nil), query[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[8:10], 1)
	rdata := []byte{0, 0}
	for _, value := range []uint32{1, 2, 3, 4, minimum} {
		rdata = append(rdata, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	response = append(response, 0xc0, 0x0c, 0, 6, 0, 1, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), 0, byte(len(rdata)))
	response = append(response, rdata...)
	return append(response, query[questionEnd:]...)
}

func firstAnswerTTL(response []byte) uint32 {
	offset := dnsQuestionEnd(response)
	return binary.BigEndian.Uint32(response[offset+6 : offset+10])
}

func negativeSOATTLs(response []byte) (uint32, uint32) {
	offset := dnsQuestionEnd(response)
	ttl := binary.BigEndian.Uint32(response[offset+6 : offset+10])
	rdataLength := int(binary.BigEndian.Uint16(response[offset+10 : offset+12]))
	return ttl, binary.BigEndian.Uint32(response[offset+12+rdataLength-4 : offset+12+rdataLength])
}

func positiveResponse(query []byte, ttl uint32) []byte {
	questionEnd := dnsQuestionEnd(query)
	response := append([]byte(nil), query[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), 0, 4, 192, 0, 2, 1)
	return append(response, query[questionEnd:]...)
}

func dnsQuestionEnd(query []byte) int {
	offset := 12
	for query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	return offset + 5
}
