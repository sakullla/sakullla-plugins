package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrUnsafeAddress = errors.New("upstream address is forbidden")
	ErrUnsafePort    = errors.New("upstream port is forbidden")
)

type Policy struct {
	AllowHTTP    bool
	AllowPrivate bool
}

type Options struct {
	Resolver Resolver
	Clock    Clock
	Client   *http.Client
	Dial     func(context.Context, string, string) (net.Conn, error)

	MaxDNSEntries         int
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	DialTimeout           time.Duration
	TokenEntries          int
	TokenBytes            int64
	ManifestEntries       int
	ManifestBytes         int64
}

type TokenEntry struct {
	Value     string
	ExpiresAt time.Time
	Version   uint64
}

type ManifestEntry struct {
	Status int
	Header http.Header
	Body   []byte
	Digest string
}

type counters struct {
	dnsQueries, dnsHits, dnsMisses, dnsEvictions        atomic.Uint64
	cacheHits, cacheMisses, cacheEvictions              atomic.Uint64
	newConnections, reusedConnections, tlsHandshakes    atomic.Uint64
	poolWaitNanos                                       atomic.Uint64
	upstreamCalls, firstResponseBytes, transferredBytes atomic.Uint64
	http2Requests                                       atomic.Uint64
}

type Metrics struct {
	DNSQueries, DNSHits, DNSMisses, DNSEvictions        uint64
	CacheHits, CacheMisses, CacheEvictions              uint64
	NewConnections, ReusedConnections, TLSHandshakes    uint64
	PoolWaitNanos                                       uint64
	UpstreamCalls, FirstResponseBytes, TransferredBytes uint64
	HTTP2Requests                                       uint64
}

type Manager struct {
	client           *http.Client
	transport        *http.Transport
	privateClient    *http.Client
	privateTransport *http.Transport
	dns              *DNSCache
	tokens           *Cache[TokenEntry]
	manifests        *Cache[ManifestEntry]
	metrics          counters
	baseDial         func(context.Context, string, string) (net.Conn, error)
	refreshes        *refreshGroup
	clock            Clock
	tokenVersion     atomic.Uint64
	closed           atomic.Bool
}

type addressLease struct {
	authority string
	addresses []net.IPAddr
	private   bool
}

type leaseKey struct{}

func New(options Options) (*Manager, error) {
	if options.Clock == nil {
		options.Clock = realClock{}
	}
	if options.Resolver == nil {
		options.Resolver = NewWireResolver()
	}
	if options.Client == nil {
		options.Client = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	}
	client := *options.Client
	transport, ok := client.Transport.(*http.Transport)
	if client.Transport == nil {
		transport, ok = http.DefaultTransport.(*http.Transport).Clone(), true
	} else if ok {
		transport = transport.Clone()
	}
	if !ok {
		return nil, errors.New("upstream client requires *http.Transport")
	}
	applyTransportDefaults(transport, options)
	transport.Proxy = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	manager := &Manager{client: &client, transport: transport, refreshes: newRefreshGroup(30 * time.Second), clock: options.Clock}
	if options.Dial != nil {
		manager.baseDial = options.Dial
	} else {
		manager.baseDial = (&net.Dialer{Timeout: defaultDuration(options.DialTimeout, 10*time.Second), KeepAlive: 30 * time.Second}).DialContext
	}
	manager.dns = NewDNSCache(options.Clock, options.Resolver, options.MaxDNSEntries).withRefreshGroup(manager.refreshes).WithMetrics(
		func() { manager.metrics.dnsQueries.Add(1) }, func() { manager.metrics.dnsHits.Add(1) },
		func() { manager.metrics.dnsMisses.Add(1) }, func() { manager.metrics.dnsEvictions.Add(1) },
	)
	manager.tokens = NewCache[TokenEntry](options.Clock, defaultInt(options.TokenEntries, 256), defaultInt64(options.TokenBytes, 1<<20)).withRefreshGroup(manager.refreshes).WithMetrics(
		func() { manager.metrics.cacheHits.Add(1) }, func() { manager.metrics.cacheMisses.Add(1) }, func() { manager.metrics.cacheEvictions.Add(1) },
	)
	manager.manifests = NewCache[ManifestEntry](options.Clock, defaultInt(options.ManifestEntries, 256), defaultInt64(options.ManifestBytes, 32<<20)).withRefreshGroup(manager.refreshes).WithMetrics(
		func() { manager.metrics.cacheHits.Add(1) }, func() { manager.metrics.cacheMisses.Add(1) }, func() { manager.metrics.cacheEvictions.Add(1) },
	)
	transport.DialContext = manager.dialContext
	client.Transport = transport
	manager.client = &client
	privateTransport := transport.Clone()
	privateTransport.DialContext = manager.dialContext
	privateClient := client
	privateClient.Transport = privateTransport
	manager.privateTransport = privateTransport
	manager.privateClient = &privateClient
	return manager, nil
}

func applyTransportDefaults(transport *http.Transport, options Options) {
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = defaultInt(options.MaxIdleConns, 256)
	transport.MaxIdleConnsPerHost = defaultInt(options.MaxIdleConnsPerHost, 32)
	transport.MaxConnsPerHost = defaultInt(options.MaxConnsPerHost, 64)
	transport.IdleConnTimeout = defaultDuration(options.IdleConnTimeout, 90*time.Second)
	transport.TLSHandshakeTimeout = defaultDuration(options.TLSHandshakeTimeout, 10*time.Second)
	transport.ResponseHeaderTimeout = defaultDuration(options.ResponseHeaderTimeout, 30*time.Second)
	transport.ExpectContinueTimeout = time.Second
}

func defaultInt(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultInt64(value int64, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func (manager *Manager) PrepareRequest(request *http.Request, policy Policy) (*http.Request, error) {
	if manager.closed.Load() {
		return nil, ErrClosed
	}
	if request == nil || request.URL == nil || request.URL.User != nil || request.URL.Hostname() == "" || request.URL.Fragment != "" {
		return nil, ErrUnsafeAddress
	}
	if request.URL.Scheme != "https" && !(policy.AllowHTTP && request.URL.Scheme == "http") {
		return nil, ErrUnsafeAddress
	}
	port := request.URL.Port()
	if port == "" {
		if request.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if !policy.AllowPrivate && port != "443" {
		return nil, ErrUnsafePort
	}
	addresses, err := manager.dns.Resolve(request.Context(), request.URL.Hostname())
	if err != nil || len(addresses) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsafeAddress
	}
	if !policy.AllowPrivate {
		for _, address := range addresses {
			if !IsPublicIP(address.IP) {
				// Forbidden answers are never retained as a reusable lease/cache
				// hit, including mixed public/private DNS responses.
				manager.dns.Delete(request.URL.Hostname())
				return nil, ErrUnsafeAddress
			}
		}
	}
	authority := net.JoinHostPort(strings.ToLower(request.URL.Hostname()), port)
	lease := addressLease{authority: authority, addresses: cloneAddresses(addresses), private: policy.AllowPrivate}
	ctx := context.WithValue(request.Context(), leaseKey{}, lease)
	ctx = manager.withTrace(ctx)
	return request.WithContext(ctx), nil
}

func (manager *Manager) Do(request *http.Request, policy Policy) (*http.Response, error) {
	prepared, err := manager.PrepareRequest(request, policy)
	if err != nil {
		return nil, err
	}
	manager.metrics.upstreamCalls.Add(1)
	client := manager.client
	if policy.AllowPrivate {
		client = manager.privateClient
	}
	response, err := client.Do(prepared)
	if response != nil && response.ProtoMajor == 2 {
		manager.metrics.http2Requests.Add(1)
	}
	if response != nil && response.Body != nil {
		response.Body = countingReadCloser{ReadCloser: response.Body, count: manager.AddTransferredBytes}
	}
	return response, err
}

type countingReadCloser struct {
	io.ReadCloser
	count func(int64)
}

func (reader countingReadCloser) Read(buffer []byte) (int, error) {
	count, err := reader.ReadCloser.Read(buffer)
	reader.count(int64(count))
	return count, err
}

func (manager *Manager) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	lease, found := ctx.Value(leaseKey{}).(addressLease)
	if !found || !strings.EqualFold(lease.authority, address) || len(lease.addresses) == 0 {
		return nil, ErrUnsafeAddress
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || (!lease.private && port != "443") {
		return nil, ErrUnsafePort
	}
	var dialErr error
	for _, candidate := range lease.addresses {
		if !lease.private && !IsPublicIP(candidate.IP) {
			return nil, ErrUnsafeAddress
		}
		connection, err := manager.baseDial(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if err == nil {
			manager.metrics.newConnections.Add(1)
			return connection, nil
		}
		dialErr = err
	}
	return nil, dialErr
}

func (manager *Manager) withTrace(ctx context.Context) context.Context {
	started := time.Now()
	var poolStarted time.Time
	trace := &httptrace.ClientTrace{
		GetConn: func(string) { poolStarted = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			if !poolStarted.IsZero() {
				manager.metrics.poolWaitNanos.Add(uint64(time.Since(poolStarted)))
			}
			if info.Reused {
				manager.metrics.reusedConnections.Add(1)
			}
		},
		TLSHandshakeStart: func() { manager.metrics.tlsHandshakes.Add(1) },
		GotFirstResponseByte: func() {
			elapsed := time.Since(started)
			if elapsed > 0 {
				manager.metrics.firstResponseBytes.Add(uint64(elapsed))
			}
		},
	}
	return httptrace.WithClientTrace(ctx, trace)
}

func (manager *Manager) AddTransferredBytes(value int64) {
	if value > 0 {
		manager.metrics.transferredBytes.Add(uint64(value))
	}
}

func (manager *Manager) Tokens() *Cache[TokenEntry]       { return manager.tokens }
func (manager *Manager) Manifests() *Cache[ManifestEntry] { return manager.manifests }
func (manager *Manager) Client() *http.Client             { return manager.client }
func (manager *Manager) Now() time.Time                   { return manager.clock.Now() }
func (manager *Manager) NewTokenEntry(value string, expiresAt time.Time) TokenEntry {
	return TokenEntry{Value: value, ExpiresAt: expiresAt, Version: manager.tokenVersion.Add(1)}
}

func (manager *Manager) Snapshot() Metrics {
	return Metrics{
		DNSQueries: manager.metrics.dnsQueries.Load(), DNSHits: manager.metrics.dnsHits.Load(), DNSMisses: manager.metrics.dnsMisses.Load(), DNSEvictions: manager.metrics.dnsEvictions.Load(),
		CacheHits: manager.metrics.cacheHits.Load(), CacheMisses: manager.metrics.cacheMisses.Load(), CacheEvictions: manager.metrics.cacheEvictions.Load(),
		NewConnections: manager.metrics.newConnections.Load(), ReusedConnections: manager.metrics.reusedConnections.Load(), TLSHandshakes: manager.metrics.tlsHandshakes.Load(), PoolWaitNanos: manager.metrics.poolWaitNanos.Load(),
		UpstreamCalls: manager.metrics.upstreamCalls.Load(), FirstResponseBytes: manager.metrics.firstResponseBytes.Load(), TransferredBytes: manager.metrics.transferredBytes.Load(), HTTP2Requests: manager.metrics.http2Requests.Load(),
	}
}

func (manager *Manager) Close() error {
	if manager.closed.CompareAndSwap(false, true) {
		manager.dns.Close()
		manager.tokens.Close()
		manager.manifests.Close()
		manager.refreshes.close()
		manager.transport.CloseIdleConnections()
		manager.privateTransport.CloseIdleConnections()
	}
	return nil
}

func IsPublicIP(address net.IP) bool {
	return address != nil && !address.IsUnspecified() && !address.IsLoopback() && !address.IsPrivate() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast()
}
