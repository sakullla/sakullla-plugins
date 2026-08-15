package upstream

import (
	"container/list"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

var ErrDNSNotFound = errors.New("DNS name not found")

type DNSResult struct {
	Addresses   []net.IPAddr
	TTL         time.Duration
	NegativeTTL time.Duration
}

type Resolver interface {
	Lookup(context.Context, string) (DNSResult, error)
}

type ResolverFunc func(context.Context, string) (DNSResult, error)

func (function ResolverFunc) Lookup(ctx context.Context, host string) (DNSResult, error) {
	return function(ctx, host)
}

// NetResolverAdapter supports hosts where DNS TTLs are unavailable. Production
// uses WireResolver; this adapter primarily keeps deterministic local fixtures
// small while still exercising cache and address-lease policy.
type NetResolverAdapter struct {
	Resolver interface {
		LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	}
	TTL         time.Duration
	NegativeTTL time.Duration
}

func (adapter NetResolverAdapter) Lookup(ctx context.Context, host string) (DNSResult, error) {
	resolver := adapter.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		err = ErrDNSNotFound
	}
	if adapter.TTL <= 0 {
		adapter.TTL = time.Minute
	}
	if adapter.NegativeTTL <= 0 {
		adapter.NegativeTTL = 15 * time.Second
	}
	return DNSResult{Addresses: addresses, TTL: adapter.TTL, NegativeTTL: adapter.NegativeTTL}, err
}

type dnsEntry struct {
	host      string
	addresses []net.IPAddr
	err       error
	negative  bool
	expiresAt time.Time
	swrUntil  time.Time
	sieUntil  time.Time
}

type dnsCall struct {
	done   chan struct{}
	result []net.IPAddr
	err    error
}

type DNSCache struct {
	mu         sync.Mutex
	clock      Clock
	resolver   Resolver
	maxEntries int
	entries    map[string]*list.Element
	lru        *list.List
	flights    map[string]*dnsCall
	closed     bool
	onQuery    func()
	onHit      func()
	onMiss     func()
	onEvict    func()
}

func NewDNSCache(clock Clock, resolver Resolver, maxEntries int) *DNSCache {
	if clock == nil {
		clock = realClock{}
	}
	if resolver == nil {
		resolver = NetResolverAdapter{}
	}
	if maxEntries <= 0 {
		maxEntries = 256
	}
	return &DNSCache{clock: clock, resolver: resolver, maxEntries: maxEntries, entries: make(map[string]*list.Element), lru: list.New(), flights: make(map[string]*dnsCall)}
}

func (cache *DNSCache) WithMetrics(query func(), hit func(), miss func(), evict func()) *DNSCache {
	cache.mu.Lock()
	cache.onQuery, cache.onHit, cache.onMiss, cache.onEvict = query, hit, miss, evict
	cache.mu.Unlock()
	return cache
}

func (cache *DNSCache) Resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if address := net.ParseIP(host); address != nil {
		return []net.IPAddr{{IP: address}}, nil
	}
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return nil, ErrClosed
	}
	var stale []net.IPAddr
	staleAllowed := false
	if element, found := cache.entries[host]; found {
		entry := element.Value.(*dnsEntry)
		now := cache.clock.Now()
		if now.Before(entry.expiresAt) {
			cache.lru.MoveToFront(element)
			if cache.onHit != nil {
				cache.onHit()
			}
			result := cloneAddresses(entry.addresses)
			err := entry.err
			cache.mu.Unlock()
			return result, err
		}
		if !entry.negative && now.Before(entry.swrUntil) {
			if cache.onHit != nil {
				cache.onHit()
			}
			if _, running := cache.flights[host]; !running {
				call := &dnsCall{done: make(chan struct{})}
				cache.flights[host] = call
				go cache.runLookup(context.Background(), host, call)
			}
			result := cloneAddresses(entry.addresses)
			cache.mu.Unlock()
			return result, nil
		}
		if !entry.negative && now.Before(entry.sieUntil) {
			stale, staleAllowed = cloneAddresses(entry.addresses), true
		} else {
			cache.removeLocked(element)
		}
	}
	if cache.onMiss != nil {
		cache.onMiss()
	}
	if call, found := cache.flights[host]; found {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			if call.err != nil && staleAllowed && !errors.Is(call.err, ErrDNSNotFound) {
				return stale, nil
			}
			return cloneAddresses(call.result), call.err
		}
	}
	call := &dnsCall{done: make(chan struct{})}
	cache.flights[host] = call
	cache.mu.Unlock()

	cache.runLookup(ctx, host, call)
	if call.err != nil && staleAllowed && !errors.Is(call.err, ErrDNSNotFound) {
		return stale, nil
	}
	return cloneAddresses(call.result), call.err
}

func (cache *DNSCache) runLookup(ctx context.Context, host string, call *dnsCall) {
	if cache.onQuery != nil {
		cache.onQuery()
	}
	lookup, err := cache.resolver.Lookup(ctx, host)
	call.result, call.err = cloneAddresses(lookup.Addresses), err
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cacheable := false
	negative := false
	ttl := lookup.TTL
	if err == nil && ttl > 0 && len(lookup.Addresses) > 0 {
		cacheable = true
	} else if errors.Is(err, ErrDNSNotFound) && lookup.NegativeTTL > 0 {
		cacheable, negative, ttl = true, true, lookup.NegativeTTL
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
	}
	if cacheable && !cache.closed {
		if old, found := cache.entries[host]; found {
			cache.removeLocked(old)
		}
		expiresAt := cache.clock.Now().Add(ttl)
		entry := &dnsEntry{host: host, addresses: cloneAddresses(call.result), err: err, negative: negative, expiresAt: expiresAt, swrUntil: expiresAt, sieUntil: expiresAt}
		if !negative {
			entry.swrUntil = expiresAt.Add(30 * time.Second)
			entry.sieUntil = entry.swrUntil.Add(2 * time.Minute)
		}
		cache.entries[host] = cache.lru.PushFront(entry)
		for cache.lru.Len() > cache.maxEntries {
			cache.removeLocked(cache.lru.Back())
		}
	} else if errors.Is(err, ErrDNSNotFound) || err == nil {
		if old, found := cache.entries[host]; found {
			cache.removeLocked(old)
		}
	}
	delete(cache.flights, host)
	close(call.done)
}

func cloneAddresses(input []net.IPAddr) []net.IPAddr {
	result := make([]net.IPAddr, len(input))
	copy(result, input)
	return result
}

func (cache *DNSCache) removeLocked(element *list.Element) {
	entry := element.Value.(*dnsEntry)
	delete(cache.entries, entry.host)
	cache.lru.Remove(element)
	if cache.onEvict != nil {
		cache.onEvict()
	}
}

func (cache *DNSCache) Close() {
	cache.mu.Lock()
	cache.closed = true
	cache.entries = make(map[string]*list.Element)
	cache.lru.Init()
	cache.mu.Unlock()
}

func (cache *DNSCache) Delete(host string) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	cache.mu.Lock()
	if element, found := cache.entries[host]; found {
		cache.removeLocked(element)
	}
	cache.mu.Unlock()
}
