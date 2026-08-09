package doh

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID            = "doh"
	PluginVersion       = "0.1.0"
	MaxConfigBytes      = 1 << 20
	MaxUpstreams        = 8
	MaxDNSRequestBytes  = 4096
	MaxDNSResponseBytes = 65535
)

var (
	ErrInvalidRequest          = errors.New("invalid DoH request")
	ErrUnsupportedMediaType    = errors.New("unsupported DNS media type")
	ErrRequestTooLarge         = errors.New("DNS request exceeds bound")
	ErrResponseTooLarge        = errors.New("DNS response exceeds bound")
	ErrInvalidDNSMessage       = errors.New("invalid DNS message")
	ErrResponseMismatch        = errors.New("DNS response does not match request")
	ErrInvalidToken            = errors.New("token rejected")
	ErrIPPolicyDenied          = errors.New("source policy denied")
	ErrConcurrencyExhausted    = errors.New("request concurrency exhausted")
	ErrNoHealthyUpstream       = errors.New("no healthy upstream")
	ErrUpstreamFailed          = errors.New("upstream failed")
	ErrClockUnavailable        = errors.New("monotonic clock unavailable")
	ErrCacheUnavailable        = errors.New("cache unavailable")
	ErrLogUnavailable          = errors.New("query log unavailable")
	ErrAuditUnavailable        = errors.New("audit unavailable")
	ErrTypedHandlesUnavailable = errors.New("canonical typed DoH handles unavailable")
	ErrRevoked                 = errors.New("DoH generation revoked")
)

var opaqueRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type Upstream struct {
	ID          string `json:"id"`
	EndpointRef string `json:"endpoint_ref"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}

type Configuration struct {
	Generation        string     `json:"generation"`
	ListenerRef       string     `json:"listener_ref"`
	TokenSecretRef    string     `json:"token_secret_ref"`
	IPPolicyRef       string     `json:"ip_policy_ref"`
	RequestTimeoutMS  int64      `json:"request_timeout_ms"`
	UpstreamTimeoutMS int64      `json:"upstream_timeout_ms"`
	MaxConcurrency    int        `json:"max_concurrency"`
	CacheEntries      int        `json:"cache_entries"`
	CacheBytes        int        `json:"cache_bytes"`
	MinTTLSeconds     uint32     `json:"min_ttl_seconds"`
	MaxTTLSeconds     uint32     `json:"max_ttl_seconds"`
	Upstreams         []Upstream `json:"upstreams"`
}

func (configuration Configuration) Validate() error {
	if !opaqueRefPattern.MatchString(configuration.Generation) || !opaqueRefPattern.MatchString(configuration.ListenerRef) ||
		!opaqueRefPattern.MatchString(configuration.TokenSecretRef) || !opaqueRefPattern.MatchString(configuration.IPPolicyRef) {
		return ErrInvalidRequest
	}
	if configuration.RequestTimeoutMS < 1 || configuration.RequestTimeoutMS > 10000 || configuration.UpstreamTimeoutMS < 1 || configuration.UpstreamTimeoutMS > configuration.RequestTimeoutMS ||
		configuration.MaxConcurrency < 1 || configuration.MaxConcurrency > 256 || configuration.CacheEntries < 1 || configuration.CacheEntries > 4096 ||
		configuration.CacheBytes < MaxDNSResponseBytes || configuration.CacheBytes > 64<<20 || configuration.MinTTLSeconds > configuration.MaxTTLSeconds || configuration.MaxTTLSeconds > 86400 ||
		len(configuration.Upstreams) == 0 || len(configuration.Upstreams) > MaxUpstreams {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(configuration.Upstreams))
	for _, upstream := range configuration.Upstreams {
		if !opaqueRefPattern.MatchString(upstream.ID) || !opaqueRefPattern.MatchString(upstream.EndpointRef) || upstream.Priority < -1000 || upstream.Priority > 1000 {
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
	Method, Query, ContentType, Accept string
	Body, Token                        []byte
	Source                             SourceIdentity
}

type HTTPResponse struct {
	Status, ContentType string
	Body                []byte
	CacheHit            bool
}

type SourceIdentity struct{ Attestation string }

type TokenVerifier interface {
	Verify(context.Context, string, []byte) error
}

type TokenVerifierFunc func(context.Context, string, []byte) error

func (function TokenVerifierFunc) Verify(ctx context.Context, secretRef string, credential []byte) error {
	return function(ctx, secretRef, credential)
}

type IPPolicyEvaluator interface {
	Allow(context.Context, string, SourceIdentity) error
}

type IPPolicyEvaluatorFunc func(context.Context, string, SourceIdentity) error

func (function IPPolicyEvaluatorFunc) Allow(ctx context.Context, policyRef string, source SourceIdentity) error {
	return function(ctx, policyRef, source)
}

type ResolveRequest struct {
	EndpointRef string
	DNSMessage  []byte
	MaxBytes    int
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

type CacheEntry struct {
	Response  []byte
	ExpiresAt uint64
}

type Cache interface {
	Get(context.Context, string, uint64) (CacheEntry, bool, error)
	Put(context.Context, string, CacheEntry) error
	Reset(context.Context, string) error
}

type QueryLog struct {
	QueryDigest, QType, Result, UpstreamID string
	CacheHit                               bool
}

type QueryLogger interface {
	Log(context.Context, QueryLog) error
}
type QueryLoggerFunc func(context.Context, QueryLog) error

func (function QueryLoggerFunc) Log(ctx context.Context, record QueryLog) error {
	return function(ctx, record)
}

type AuditRecord struct {
	Action, Outcome, OperationKey, QueryDigest string
}

type Auditor interface {
	Audit(context.Context, AuditRecord) error
}
type AuditorFunc func(context.Context, AuditRecord) error

func (function AuditorFunc) Audit(ctx context.Context, record AuditRecord) error {
	return function(ctx, record)
}

type Listener interface {
	Register(context.Context, string, *Service) error
}
type ListenerFunc func(context.Context, string, *Service) error

func (function ListenerFunc) Register(ctx context.Context, listenerRef string, service *Service) error {
	return function(ctx, listenerRef, service)
}

type RuntimeAdapters struct {
	Listener Listener
	Tokens   TokenVerifier
	Policy   IPPolicyEvaluator
	Resolver Resolver
	Clock    MonotonicClock
	Cache    Cache
	Logger   QueryLogger
	Auditor  Auditor
}

func (runtime RuntimeAdapters) valid() bool {
	return runtime.Listener != nil && runtime.Tokens != nil && runtime.Policy != nil && runtime.Resolver != nil && runtime.Clock != nil && runtime.Cache != nil && runtime.Logger != nil && runtime.Auditor != nil
}

type PreparedAdmission interface {
	Commit(context.Context) (RuntimeAdapters, error)
	Abort()
}

type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) (RuntimeAdapters, error)
	AbortFunc  func()
}

func (prepared PreparedAdmissionFuncs) Commit(ctx context.Context) (RuntimeAdapters, error) {
	if prepared.CommitFunc == nil {
		return RuntimeAdapters{}, ErrTypedHandlesUnavailable
	}
	return prepared.CommitFunc(ctx)
}
func (prepared PreparedAdmissionFuncs) Abort() {
	if prepared.AbortFunc != nil {
		prepared.AbortFunc()
	}
}

type TypedHandleAdmission interface {
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)

func (function TypedHandleAdmissionFunc) Prepare(ctx context.Context, request pluginsdk.RPCHandshakeRequest, configuration Configuration) (PreparedAdmission, error) {
	return function(ctx, request, configuration)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
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
	operation     atomic.Uint64
	requestCtx    context.Context
	requestCancel context.CancelFunc
	requestMu     sync.Mutex
	requestCount  uint64
	requestZero   chan struct{}
	leaseMu       sync.RWMutex
	requestLease  func(context.Context, HTTPRequest) (HTTPResponse, error)
	commitMu      sync.Mutex
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
