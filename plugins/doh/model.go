package doh

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PluginID                 = "doh"
	PluginVersion            = "0.1.0"
	ProviderID               = "default"
	DNSQueryPath             = "/dns-query"
	DefaultUpstreamID        = "default"
	DefaultUpstreamEndpoint  = "https://cloudflare-dns.com/dns-query"
	MaxConfigBytes           = 1 << 20
	MaxPluginConfigBytes     = 4096
	MaxUpstreams             = 8
	MaxDNSRequestBytes       = 4096
	MaxDNSResponseBytes      = 65535
	defaultRequestTimeoutMS  = 2000
	defaultUpstreamTimeoutMS = 1000
	defaultMaxConcurrency    = 8
	defaultCacheEntries      = 256
	defaultCacheBytes        = 1 << 20
	defaultMinTTLSeconds     = 1
	defaultMaxTTLSeconds     = 3600
)

var (
	ErrInvalidRequest          = errors.New("invalid DoH request")
	ErrUnsupportedMediaType    = errors.New("unsupported DNS media type")
	ErrRequestTooLarge         = errors.New("DNS request exceeds bound")
	ErrResponseTooLarge        = errors.New("DNS response exceeds bound")
	ErrInvalidDNSMessage       = errors.New("invalid DNS message")
	ErrResponseMismatch        = errors.New("DNS response does not match request")
	ErrConcurrencyExhausted    = errors.New("request concurrency exhausted")
	ErrNoHealthyUpstream       = errors.New("no healthy upstream")
	ErrUpstreamFailed          = errors.New("upstream failed")
	ErrClockUnavailable        = errors.New("monotonic clock unavailable")
	ErrCacheUnavailable        = errors.New("cache unavailable")
	ErrTypedHandlesUnavailable = errors.New("canonical typed DoH handles unavailable")
	ErrRevoked                 = errors.New("DoH generation revoked")
)

var opaqueRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type Upstream struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
}

type PluginConfig struct {
	Upstreams []UpstreamConfig `json:"upstreams,omitempty"`
}

type UpstreamConfig struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
}

type Configuration struct {
	RequestTimeoutMS  int64      `json:"request_timeout_ms"`
	UpstreamTimeoutMS int64      `json:"upstream_timeout_ms"`
	MaxConcurrency    int        `json:"max_concurrency"`
	CacheEntries      int        `json:"cache_entries"`
	CacheBytes        int        `json:"cache_bytes"`
	MinTTLSeconds     uint32     `json:"min_ttl_seconds"`
	MaxTTLSeconds     uint32     `json:"max_ttl_seconds"`
	Upstreams         []Upstream `json:"upstreams"`
}

func ConfigurationFromPlugin(config PluginConfig) Configuration {
	configuration := Configuration{}
	for _, upstream := range config.Upstreams {
		configuration.Upstreams = append(configuration.Upstreams, Upstream{
			ID:       upstream.ID,
			Endpoint: upstream.Endpoint,
			Priority: upstream.Priority,
			Enabled:  upstream.Enabled,
		})
	}
	return configuration
}

func applyConfigurationDefaults(configuration Configuration) Configuration {
	if configuration.RequestTimeoutMS == 0 {
		configuration.RequestTimeoutMS = defaultRequestTimeoutMS
	}
	if configuration.UpstreamTimeoutMS == 0 {
		configuration.UpstreamTimeoutMS = defaultUpstreamTimeoutMS
	}
	if configuration.MaxConcurrency == 0 {
		configuration.MaxConcurrency = defaultMaxConcurrency
	}
	if configuration.CacheEntries == 0 {
		configuration.CacheEntries = defaultCacheEntries
	}
	if configuration.CacheBytes == 0 {
		configuration.CacheBytes = defaultCacheBytes
	}
	if configuration.MinTTLSeconds == 0 && configuration.MaxTTLSeconds == 0 {
		configuration.MinTTLSeconds = defaultMinTTLSeconds
		configuration.MaxTTLSeconds = defaultMaxTTLSeconds
	}
	if len(configuration.Upstreams) == 0 {
		configuration.Upstreams = []Upstream{{
			ID:       DefaultUpstreamID,
			Endpoint: DefaultUpstreamEndpoint,
			Enabled:  true,
		}}
	}
	return configuration
}

func (configuration Configuration) Validate() error {
	if configuration.RequestTimeoutMS < 1 || configuration.RequestTimeoutMS > 10000 || configuration.UpstreamTimeoutMS < 1 || configuration.UpstreamTimeoutMS > configuration.RequestTimeoutMS ||
		configuration.MaxConcurrency < 1 || configuration.MaxConcurrency > 256 || configuration.CacheEntries < 1 || configuration.CacheEntries > 4096 ||
		configuration.CacheBytes < MaxDNSResponseBytes || configuration.CacheBytes > 64<<20 || configuration.MinTTLSeconds > configuration.MaxTTLSeconds || configuration.MaxTTLSeconds > 86400 ||
		len(configuration.Upstreams) > MaxUpstreams {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(configuration.Upstreams))
	for _, upstream := range configuration.Upstreams {
		if !opaqueRefPattern.MatchString(upstream.ID) || len(upstream.Endpoint) == 0 || len(upstream.Endpoint) > 256 || upstream.Priority < -1000 || upstream.Priority > 1000 {
			return ErrInvalidRequest
		}
		if _, exists := seen[upstream.ID]; exists {
			return ErrInvalidRequest
		}
		seen[upstream.ID] = struct{}{}
	}
	return nil
}

func (configuration Configuration) orderedUpstreams() []Upstream {
	upstreams := append([]Upstream(nil), configuration.Upstreams...)
	sort.Slice(upstreams, func(left, right int) bool {
		if upstreams[left].Priority != upstreams[right].Priority {
			return upstreams[left].Priority < upstreams[right].Priority
		}
		return upstreams[left].ID < upstreams[right].ID
	})
	return upstreams
}

type HTTPRequest struct {
	Method, Query, ContentType, Accept, Forwarded string
	Body                                          []byte
}

type HTTPResponse struct {
	Status, ContentType string
	Body                []byte
	CacheHit            bool
}

type ResolveRequest struct {
	Endpoint   string
	DNSMessage []byte
	MaxBytes   int
}

type Resolver interface {
	Resolve(context.Context, ResolveRequest) ([]byte, error)
}

type ResolverFunc func(context.Context, ResolveRequest) ([]byte, error)

func (function ResolverFunc) Resolve(ctx context.Context, request ResolveRequest) ([]byte, error) {
	return function(ctx, request)
}

type MonotonicClock interface {
	Now(context.Context) (uint64, error)
}

type MonotonicClockFunc func(context.Context) (uint64, error)

func (function MonotonicClockFunc) Now(ctx context.Context) (uint64, error) { return function(ctx) }

type systemClock struct{}

func (systemClock) Now(context.Context) (uint64, error) {
	return uint64(time.Now().UnixNano()), nil
}

type CacheEntry struct {
	Response  []byte
	StoredAt  uint64
	ExpiresAt uint64
}

type Cache interface {
	Get(context.Context, string, uint64) (CacheEntry, bool, error)
	Put(context.Context, string, CacheEntry) error
	Reset(context.Context, string) error
}

type RuntimeAdapters struct {
	Resolver Resolver
	Clock    MonotonicClock
	Cache    Cache
}

func (runtime RuntimeAdapters) withDefaults(configuration Configuration) RuntimeAdapters {
	if runtime.Cache == nil {
		runtime.Cache = NewMemoryCache(configuration.CacheEntries, configuration.CacheBytes)
	}
	if runtime.Clock == nil {
		runtime.Clock = systemClock{}
	}
	if runtime.Resolver == nil {
		runtime.Resolver = newHTTPUpstreamResolver()
	}
	return runtime
}

type UpstreamStatus struct {
	ID, Result string
	Failures   uint64
}

type Service struct {
	configuration Configuration
	runtime       RuntimeAdapters
	semaphore     chan struct{}
	live          atomic.Bool
	requestCtx    context.Context
	requestCancel context.CancelFunc
	requestMu     sync.Mutex
	requestCount  uint64
	requestZero   chan struct{}
	leaseMu       sync.RWMutex
	requestLease  func(context.Context, HTTPRequest) (HTTPResponse, error)
	closeOnce     sync.Once
	closeDone     chan struct{}
	closeMu       sync.Mutex
	closeErr      error
	statusMu      sync.Mutex
	statuses      []UpstreamStatus
	clockMu       sync.Mutex
	clockSet      bool
	lastNow       uint64
}

func requestTimeout(configuration Configuration) time.Duration {
	return time.Duration(configuration.RequestTimeoutMS) * time.Millisecond
}

func upstreamTimeout(configuration Configuration) time.Duration {
	return time.Duration(configuration.UpstreamTimeoutMS) * time.Millisecond
}
