package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	release := make(chan struct{})
	var calls atomic.Int32
	resolver := ResolverFunc(func(ctx context.Context, _ string) (DNSResult, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
				return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Minute}, nil
			case <-ctx.Done():
				return DNSResult{}, ctx.Err()
			}
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
	if !errors.Is(<-leaderDone, context.Canceled) {
		t.Fatal("leader cancellation did not cancel only its waiter")
	}
	close(release)
	if err := <-waiterDone; err != nil {
		t.Fatalf("independent waiter did not receive manager-owned refresh: %v", err)
	}
	addresses, err := cache.Resolve(context.Background(), "transient.test")
	if err != nil || len(addresses) != 1 || calls.Load() != 1 {
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
	var negativeZeroCalls atomic.Int32
	negativeZeroCache := NewDNSCache(clock, ResolverFunc(func(context.Context, string) (DNSResult, error) {
		negativeZeroCalls.Add(1)
		return DNSResult{NegativeTTL: 0}, ErrDNSNotFound
	}), 8)
	_, _ = negativeZeroCache.Resolve(context.Background(), "negative-zero.test")
	_, _ = negativeZeroCache.Resolve(context.Background(), "negative-zero.test")
	if negativeZeroCalls.Load() != 2 {
		t.Fatalf("zero TTL negative answer was cached: calls=%d", negativeZeroCalls.Load())
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

func TestDNSWireRCODEClassificationAndTCPFallback(t *testing.T) {
	query, id, err := dnsQuery("fixture.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	soa := dnsFixtureRecord(6, 60, make([]byte, 20))
	binary.BigEndian.PutUint32(soa[len(soa)-4:], 30)
	for _, testCase := range []struct {
		name        string
		flags       uint16
		authority   []byte
		notFound    bool
		wantWireErr bool
	}{
		{name: "nxdomain", flags: 0x8183, notFound: true},
		{name: "authoritative nodata", flags: 0x8180, authority: soa, notFound: true},
		{name: "servfail", flags: 0x8182, wantWireErr: true},
		{name: "refused", flags: 0x8185, wantWireErr: true},
		{name: "non-authoritative empty", flags: 0x8180, wantWireErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := dnsFixtureResponse(query, testCase.flags, nil, testCase.authority)
			_, _, _, _, _, parseErr := parseDNSResponse(response, id, 1, "fixture.test")
			if errors.Is(parseErr, ErrDNSNotFound) != testCase.notFound || (testCase.wantWireErr && !errors.Is(parseErr, errDNSWire)) {
				t.Fatalf("classification: %v", parseErr)
			}
		})
	}

	tcp, udp := listenDNSFixture(t)
	defer tcp.Close()
	defer udp.Close()
	serverDone := make(chan error, 2)
	go func() {
		buffer := make([]byte, 512)
		count, peer, readErr := udp.ReadFrom(buffer)
		if readErr == nil {
			truncated := dnsFixtureResponse(buffer[:count], 0x8380, nil, nil)
			_, readErr = udp.WriteTo(truncated, peer)
		}
		serverDone <- readErr
	}()
	go func() {
		connection, acceptErr := tcp.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		var prefix [2]byte
		if _, acceptErr = io.ReadFull(connection, prefix[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		request := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, acceptErr = io.ReadFull(connection, request); acceptErr == nil {
			answer := dnsFixtureRecord(1, 60, []byte{8, 8, 4, 4})
			response := dnsFixtureResponse(request, 0x8180, answer, nil)
			framed := make([]byte, len(response)+2)
			binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
			copy(framed[2:], response)
			_, acceptErr = connection.Write(framed)
		}
		serverDone <- acceptErr
	}()
	resolver := &WireResolver{Servers: []string{tcp.Addr().String()}, Timeout: 2 * time.Second}
	addresses, ttl, _, err := resolver.lookupType(context.Background(), "fixture.test", 1)
	if err != nil || len(addresses) != 1 || !addresses[0].IP.Equal(net.ParseIP("8.8.4.4")) || ttl != time.Minute {
		t.Fatalf("TCP fallback: addresses=%v ttl=%s err=%v", addresses, ttl, err)
	}
	for range 2 {
		if err := <-serverDone; err != nil {
			t.Fatalf("DNS fixture: %v", err)
		}
	}
}

func TestDNSCNAMEChainTTLOnlyTargetZeroAndLoop(t *testing.T) {
	t.Run("short chain TTL", func(t *testing.T) {
		query, id, err := dnsQuery("alias.test", 1)
		if err != nil {
			t.Fatal(err)
		}
		response := dnsFixtureResponseRecords(query, 0x8180, [][]byte{
			dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 5, dnsFixtureName("target.test")),
			dnsFixtureNamedRecord(dnsFixtureName("target.test"), 1, 60, []byte{8, 8, 8, 8}),
		}, nil)
		addresses, ttl, _, canonical, hops, err := parseDNSResponse(response, id, 1, "alias.test")
		if err != nil || len(addresses) != 1 || addresses[0].IP.String() != "8.8.8.8" || ttl != 5*time.Second || canonical != "" || hops != 1 {
			t.Fatalf("CNAME TTL chain: addresses=%v ttl=%s canonical=%q hops=%d err=%v", addresses, ttl, canonical, hops, err)
		}
	})

	t.Run("zero chain TTL is not cached", func(t *testing.T) {
		var exchanges atomic.Int32
		resolver := &WireResolver{Servers: []string{"fixture"}}
		resolver.exchangeHook = func(_ context.Context, _ string, query []byte) ([]byte, error) {
			exchanges.Add(1)
			_, queryType := dnsFixtureQuestion(t, query)
			target := "zero-target.test"
			var terminal []byte
			if queryType == 1 {
				terminal = []byte{1, 1, 1, 1}
			} else {
				terminal = net.ParseIP("2001:4860:4860::8888").To16()
			}
			return dnsFixtureResponseRecords(query, 0x8180, [][]byte{
				dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 0, dnsFixtureName(target)),
				dnsFixtureNamedRecord(dnsFixtureName(target), queryType, 60, terminal),
			}, nil), nil
		}
		cache := NewDNSCache(&fakeClock{now: time.Unix(1, 0)}, resolver, 8)
		for range 2 {
			addresses, err := cache.Resolve(context.Background(), "zero-alias.test")
			if err != nil || len(addresses) != 2 {
				t.Fatalf("zero CNAME resolve: %v %v", addresses, err)
			}
		}
		if exchanges.Load() != 4 {
			t.Fatalf("zero CNAME TTL was cached: exchanges=%d", exchanges.Load())
		}
	})

	t.Run("only CNAME continues in owner context", func(t *testing.T) {
		type ownerKey struct{}
		ctx := context.WithValue(context.Background(), ownerKey{}, "owner")
		var exchanges atomic.Int32
		resolver := &WireResolver{Servers: []string{"fixture"}}
		resolver.exchangeHook = func(hookContext context.Context, _ string, query []byte) ([]byte, error) {
			if hookContext.Value(ownerKey{}) != "owner" {
				t.Error("canonical query lost owner context")
			}
			exchanges.Add(1)
			name, queryType := dnsFixtureQuestion(t, query)
			if name == "only-alias.test" {
				return dnsFixtureResponseRecords(query, 0x8180, [][]byte{
					dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 7, dnsFixtureName("canonical.test")),
				}, nil), nil
			}
			if name != "canonical.test" || queryType != 1 {
				t.Fatalf("unexpected canonical query: name=%q type=%d", name, queryType)
			}
			return dnsFixtureResponseRecords(query, 0x8180, [][]byte{
				dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 1, 60, []byte{1, 0, 0, 1}),
			}, nil), nil
		}
		addresses, ttl, _, err := resolver.lookupType(ctx, "only-alias.test", 1)
		if err != nil || len(addresses) != 1 || addresses[0].IP.String() != "1.0.0.1" || ttl != 7*time.Second || exchanges.Load() != 2 {
			t.Fatalf("only-CNAME resolution: addresses=%v ttl=%s exchanges=%d err=%v", addresses, ttl, exchanges.Load(), err)
		}
	})

	t.Run("loop and hop overflow", func(t *testing.T) {
		var exchanges atomic.Int32
		resolver := &WireResolver{Servers: []string{"fixture"}}
		resolver.exchangeHook = func(_ context.Context, _ string, query []byte) ([]byte, error) {
			exchanges.Add(1)
			name, _ := dnsFixtureQuestion(t, query)
			target := "loop-b.test"
			if name == target {
				target = "loop-a.test"
			}
			return dnsFixtureResponseRecords(query, 0x8180, [][]byte{
				dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 10, dnsFixtureName(target)),
			}, nil), nil
		}
		if _, _, _, err := resolver.lookupType(context.Background(), "loop-a.test", 1); !errors.Is(err, errDNSWire) || exchanges.Load() != 2 {
			t.Fatalf("CNAME loop: exchanges=%d err=%v", exchanges.Load(), err)
		}

		query, id, err := dnsQuery("overflow.test", 1)
		if err != nil {
			t.Fatal(err)
		}
		owner := []byte{0xc0, 0x0c}
		records := make([][]byte, 0, maxDNSCNAMEHops+2)
		for index := 0; index <= maxDNSCNAMEHops; index++ {
			target := fmt.Sprintf("hop-%d.test", index)
			records = append(records, dnsFixtureNamedRecord(owner, 5, 60, dnsFixtureName(target)))
			owner = dnsFixtureName(target)
		}
		records = append(records, dnsFixtureNamedRecord(owner, 1, 60, []byte{9, 9, 9, 9}))
		response := dnsFixtureResponseRecords(query, 0x8180, records, nil)
		if _, _, _, _, _, err := parseDNSResponse(response, id, 1, "overflow.test"); !errors.Is(err, errDNSWire) {
			t.Fatalf("overlong CNAME chain accepted: %v", err)
		}
	})
}

func TestDNSCNAMENegativeTTLPropagationAndZeroCache(t *testing.T) {
	soa := dnsFixtureRecord(6, 60, make([]byte, 20))
	binary.BigEndian.PutUint32(soa[len(soa)-4:], 60)
	for _, testCase := range []struct {
		name  string
		flags uint16
	}{
		{name: "same response NXDOMAIN", flags: 0x8183},
		{name: "same response NODATA", flags: 0x8180},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			query, id, err := dnsQuery("negative-alias.test", 1)
			if err != nil {
				t.Fatal(err)
			}
			response := dnsFixtureResponseRecords(query, testCase.flags, [][]byte{
				dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 5, dnsFixtureName("missing.test")),
			}, [][]byte{soa})
			_, _, negativeTTL, _, hops, err := parseDNSResponse(response, id, 1, "negative-alias.test")
			if !errors.Is(err, ErrDNSNotFound) || negativeTTL != 5*time.Second || hops != 1 {
				t.Fatalf("CNAME negative TTL: ttl=%s hops=%d err=%v", negativeTTL, hops, err)
			}
		})
	}

	t.Run("only CNAME to NXDOMAIN", func(t *testing.T) {
		var exchanges atomic.Int32
		resolver := &WireResolver{Servers: []string{"fixture"}}
		resolver.exchangeHook = func(_ context.Context, _ string, query []byte) ([]byte, error) {
			exchanges.Add(1)
			name, _ := dnsFixtureQuestion(t, query)
			if name == "recursive-negative.test" {
				return dnsFixtureResponseRecords(query, 0x8180, [][]byte{
					dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, 7, dnsFixtureName("missing-target.test")),
				}, nil), nil
			}
			return dnsFixtureResponseRecords(query, 0x8183, nil, [][]byte{soa}), nil
		}
		_, _, negativeTTL, err := resolver.lookupType(context.Background(), "recursive-negative.test", 1)
		if !errors.Is(err, ErrDNSNotFound) || negativeTTL != 7*time.Second || exchanges.Load() != 2 {
			t.Fatalf("recursive CNAME negative TTL: ttl=%s exchanges=%d err=%v", negativeTTL, exchanges.Load(), err)
		}
	})

	t.Run("zero CNAME negative is not cached", func(t *testing.T) {
		for _, zeroType := range []uint16{1, 28} {
			var exchanges atomic.Int32
			resolver := &WireResolver{Servers: []string{"fixture"}}
			resolver.exchangeHook = func(_ context.Context, _ string, query []byte) ([]byte, error) {
				exchanges.Add(1)
				_, queryType := dnsFixtureQuestion(t, query)
				ttl := uint32(5)
				if queryType == zeroType {
					ttl = 0
				}
				return dnsFixtureResponseRecords(query, 0x8183, [][]byte{
					dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, 5, ttl, dnsFixtureName("zero-missing.test")),
				}, [][]byte{soa}), nil
			}
			cache := NewDNSCache(&fakeClock{now: time.Unix(1, 0)}, resolver, 8)
			for range 2 {
				if _, err := cache.Resolve(context.Background(), "zero-negative.test"); !errors.Is(err, ErrDNSNotFound) {
					t.Fatalf("zero CNAME negative resolve: %v", err)
				}
			}
			if exchanges.Load() != 4 {
				t.Fatalf("zero CNAME type %d negative was cached: exchanges=%d", zeroType, exchanges.Load())
			}
		}
	})
}

func listenDNSFixture(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	for port := 20053; port < 40053; port++ {
		address := fmt.Sprintf("127.0.0.1:%d", port)
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		udp, err := net.ListenPacket("udp4", address)
		if err == nil {
			return tcp, udp
		}
		_ = tcp.Close()
	}
	t.Fatal("no shared TCP/UDP fixture port available")
	return nil, nil
}

func TestDNSRCODETransientColdSWRAndSIEBoundaries(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	var calls atomic.Int32
	refreshDone := make(chan struct{}, 1)
	mode := atomic.Int32{}
	cache := NewDNSCache(clock, ResolverFunc(func(context.Context, string) (DNSResult, error) {
		calls.Add(1)
		switch mode.Load() {
		case 0:
			return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, TTL: time.Second}, nil
		case 1:
			select {
			case refreshDone <- struct{}{}:
			default:
			}
			return DNSResult{}, errDNSWire
		default:
			return DNSResult{NegativeTTL: time.Minute}, ErrDNSNotFound
		}
	}), 8)
	if addresses, err := cache.Resolve(context.Background(), "rcode.test"); err != nil || len(addresses) != 1 {
		t.Fatalf("positive fill: %v %v", addresses, err)
	}
	mode.Store(1)
	clock.Advance(2 * time.Second)
	if addresses, err := cache.Resolve(context.Background(), "rcode.test"); err != nil || addresses[0].IP.String() != "8.8.8.8" {
		t.Fatalf("SWR did not serve stale on transient RCODE: %v %v", addresses, err)
	}
	select {
	case <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("SWR transient refresh did not complete")
	}
	clock.Advance(30 * time.Second)
	if addresses, err := cache.Resolve(context.Background(), "rcode.test"); err != nil || addresses[0].IP.String() != "8.8.8.8" {
		t.Fatalf("SIE did not serve stale on transient RCODE: %v %v", addresses, err)
	}
	mode.Store(2)
	if _, err := cache.Resolve(context.Background(), "rcode.test"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("authoritative negative did not invalidate SIE: %v", err)
	}
	before := calls.Load()
	if _, err := cache.Resolve(context.Background(), "rcode.test"); !errors.Is(err, ErrDNSNotFound) || calls.Load() != before {
		t.Fatalf("authoritative negative was not strictly cached: calls=%d err=%v", calls.Load(), err)
	}

	var coldCalls atomic.Int32
	cold := NewDNSCache(clock, ResolverFunc(func(context.Context, string) (DNSResult, error) {
		if coldCalls.Add(1) == 1 {
			return DNSResult{}, errDNSWire
		}
		return DNSResult{Addresses: []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, TTL: time.Minute}, nil
	}), 8)
	if _, err := cold.Resolve(context.Background(), "cold-rcode.test"); !errors.Is(err, errDNSWire) {
		t.Fatalf("cold transient RCODE classification: %v", err)
	}
	if addresses, err := cold.Resolve(context.Background(), "cold-rcode.test"); err != nil || len(addresses) != 1 || coldCalls.Load() != 2 {
		t.Fatalf("cold transient RCODE poisoned cache: %v calls=%d err=%v", addresses, coldCalls.Load(), err)
	}
}

func dnsFixtureResponse(query []byte, flags uint16, answers []byte, authority []byte) []byte {
	var answerRecords, authorityRecords [][]byte
	if len(answers) > 0 {
		answerRecords = [][]byte{answers}
	}
	if len(authority) > 0 {
		authorityRecords = [][]byte{authority}
	}
	return dnsFixtureResponseRecords(query, flags, answerRecords, authorityRecords)
}

func dnsFixtureResponseRecords(query []byte, flags uint16, answers [][]byte, authority [][]byte) []byte {
	response := make([]byte, 12, 12+len(query)-12+len(answers)+len(authority))
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(response[8:10], uint16(len(authority)))
	response = append(response, query[12:]...)
	for _, record := range answers {
		response = append(response, record...)
	}
	for _, record := range authority {
		response = append(response, record...)
	}
	return response
}

func dnsFixtureRecord(recordType uint16, ttl uint32, data []byte) []byte {
	return dnsFixtureNamedRecord([]byte{0xc0, 0x0c}, recordType, ttl, data)
}

func dnsFixtureNamedRecord(owner []byte, recordType uint16, ttl uint32, data []byte) []byte {
	record := append([]byte(nil), owner...)
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[0:2], recordType)
	binary.BigEndian.PutUint16(header[2:4], 1)
	binary.BigEndian.PutUint32(header[4:8], ttl)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(data)))
	record = append(record, header...)
	record = append(record, data...)
	return record
}

func dnsFixtureName(name string) []byte {
	result := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0)
}

func dnsFixtureQuestion(t *testing.T, query []byte) (string, uint16) {
	t.Helper()
	name, next, err := readDNSName(query, 12)
	if err != nil || next+4 > len(query) {
		t.Fatalf("invalid fixture query: %v", err)
	}
	return name, binary.BigEndian.Uint16(query[next : next+2])
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

func TestTokenCacheRefreshSWRFailureAndHardExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	cache := NewCache[TokenEntry](clock, 8, 1024)
	initial := TokenEntry{Value: "token-1", ExpiresAt: clock.Now().Add(time.Minute), Version: 1}
	if value, err := cache.GetOrLoad(context.Background(), "token", func(context.Context) (Loaded[TokenEntry], error) {
		return Loaded[TokenEntry]{Value: initial, Size: 7, TTL: 30 * time.Second, StaleWhileRevalidate: 30 * time.Second}, nil
	}); err != nil || value.Version != 1 {
		t.Fatalf("initial token fill: %+v %v", value, err)
	}
	clock.Advance(31 * time.Second)
	started := make(chan struct{})
	release := make(chan struct{})
	var refreshes atomic.Int32
	failedRefresh := func(context.Context) (Loaded[TokenEntry], error) {
		if refreshes.Add(1) == 1 {
			close(started)
		}
		<-release
		return Loaded[TokenEntry]{}, errors.New("token endpoint unavailable")
	}
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := cache.GetOrLoad(context.Background(), "token", failedRefresh)
			if err != nil || value.Version != 1 {
				t.Errorf("token SWR did not serve unexpired token: %+v %v", value, err)
			}
		}()
	}
	wait.Wait()
	<-started
	if refreshes.Load() != 1 {
		t.Fatalf("100 token SWR callers started %d refreshes", refreshes.Load())
	}
	clock.Advance(29 * time.Second)
	hardContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, hardErr := cache.GetOrLoad(hardContext, "token", fixedTokenLoad(TokenEntry{Value: "unexpected"}, time.Minute))
	cancel()
	if !errors.Is(hardErr, context.DeadlineExceeded) {
		t.Fatalf("hard expiry served token during blocked refresh: %v", hardErr)
	}
	close(release)
	for deadline := time.Now().Add(time.Second); ; {
		cache.mu.Lock()
		flights := len(cache.flights)
		cache.mu.Unlock()
		if flights == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed token refresh did not clean up")
		}
		time.Sleep(time.Millisecond)
	}
	if _, found := cache.Get("token"); found {
		t.Fatal("token survived its real expiresAt")
	}
	newToken := TokenEntry{Value: "token-2", ExpiresAt: clock.Now().Add(time.Minute), Version: 2}
	value, err := cache.GetOrLoad(context.Background(), "token", fixedTokenLoad(newToken, 30*time.Second))
	if err != nil || value.Version != 2 {
		t.Fatalf("hard-expired token did not recover: %+v %v", value, err)
	}
}

func fixedTokenLoad(value TokenEntry, ttl time.Duration) func(context.Context) (Loaded[TokenEntry], error) {
	return func(context.Context) (Loaded[TokenEntry], error) {
		return Loaded[TokenEntry]{Value: value, Size: int64(len(value.Value)), TTL: ttl}, nil
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

func TestConnectionPoolCloseCancelsAndWaitsForRefresh(t *testing.T) {
	manager, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	ended := make(chan struct{})
	waiter := make(chan error, 1)
	go func() {
		_, err := manager.Tokens().GetOrLoad(context.Background(), "stalled", func(ctx context.Context) (Loaded[TokenEntry], error) {
			close(started)
			<-ctx.Done()
			close(ended)
			return Loaded[TokenEntry]{}, ctx.Err()
		})
		waiter <- err
	}()
	<-started
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel refresh")
	}
	if !errors.Is(<-waiter, context.Canceled) {
		t.Fatal("refresh waiter did not observe manager cancellation")
	}
	if _, found := manager.Tokens().Get("stalled"); found {
		t.Fatal("closed generation published a refresh")
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
