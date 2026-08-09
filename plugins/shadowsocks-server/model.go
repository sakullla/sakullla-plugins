package shadowsocksserver

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID       = "shadowsocks-server"
	PluginVersion  = "0.1.0"
	MaxConfigBytes = 1 << 20
	MaxUsers       = 256
)

var (
	ErrInvalid                 = errors.New("invalid Shadowsocks configuration")
	ErrDenied                  = errors.New("Shadowsocks admission denied")
	ErrExpired                 = errors.New("Shadowsocks user expired")
	ErrQuota                   = errors.New("Shadowsocks quota exceeded")
	ErrReplay                  = errors.New("Shadowsocks replay rejected")
	ErrRevoked                 = errors.New("Shadowsocks generation revoked")
	ErrTypedHandlesUnavailable = errors.New("canonical typed Shadowsocks handles unavailable")
)
var refPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type User struct {
	ID            string `json:"id"`
	SecretRef     string `json:"secret_ref"`
	SecretVersion string `json:"secret_version"`
	Enabled       bool   `json:"enabled"`
	ExpiresAt     uint64 `json:"expires_at"`
	QuotaBytes    uint64 `json:"quota_bytes"`
}
type Configuration struct {
	Generation  string `json:"generation"`
	ListenerRef string `json:"listener_ref"`
	Cipher      string `json:"cipher"`
	MaxSessions int    `json:"max_sessions"`
	Users       []User `json:"users"`
}

func (c Configuration) Validate() error {
	if !refPattern.MatchString(c.Generation) || !refPattern.MatchString(c.ListenerRef) || c.MaxSessions < 1 || c.MaxSessions > 4096 || len(c.Users) > MaxUsers {
		return ErrInvalid
	}
	if !SupportedMethod(c.Cipher) {
		return ErrInvalid
	}
	seen := map[string]struct{}{}
	for _, u := range c.Users {
		if !refPattern.MatchString(u.ID) || !refPattern.MatchString(u.SecretRef) || !refPattern.MatchString(u.SecretVersion) || u.QuotaBytes == 0 {
			return ErrInvalid
		}
		if _, ok := seen[u.ID]; ok {
			return ErrInvalid
		}
		seen[u.ID] = struct{}{}
	}
	return nil
}

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type AdmissionRequest struct {
	Protocol                Protocol
	UserID                  string
	Credential, ReplayToken []byte
}
type SecretVerifier interface {
	Verify(context.Context, string, string, []byte) error
	Resolve(context.Context, string, string) ([]byte, error)
}

// TrafficReservation is a capability-backed atomic quota reservation. Commit
// must reject final bytes beyond the quota and Release must be idempotent.
type TrafficReservation interface {
	Commit(context.Context, uint64) error
	Release(context.Context) error
}
type Traffic interface {
	Reserve(context.Context, string, uint64, string) (TrafficReservation, error)
}
type Clock interface {
	Now(context.Context) (uint64, error)
}
type ReplayGuard interface {
	Admit(context.Context, string, []byte) error
}
type Listener interface {
	Register(context.Context, string, *Service) error
}
type Vault interface {
	Rotate(context.Context, string, string, string, string) (*SecretOnce, error)
}
type Auditor interface {
	Audit(context.Context, AuditRecord) error
}
type AuditRecord struct{ Action, Outcome, UserID, OperationKey string }
type SecretOnce struct {
	SecretRef, SecretVersion string
	mu                       sync.Mutex
	material                 []byte
	consumed                 bool
	owner                    *Service
	generation               string
}

func NewSecretOnce(ref, version string, material []byte) *SecretOnce {
	return &SecretOnce{SecretRef: ref, SecretVersion: version, material: append([]byte(nil), material...)}
}
func (s *SecretOnce) RevealOnce() []byte {
	if s == nil {
		return nil
	}
	if s.owner != nil && !s.owner.claimSecret(s) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed {
		return nil
	}
	s.consumed = true
	out := append([]byte(nil), s.material...)
	clear(s.material)
	s.material = nil
	return out
}
func (s *SecretOnce) discard() {
	if s == nil {
		return
	}
	s.mu.Lock()
	clear(s.material)
	s.material = nil
	s.consumed = true
	s.mu.Unlock()
}

type RuntimeAdapters struct {
	Secrets  SecretVerifier
	Traffic  Traffic
	Clock    Clock
	Replay   ReplayGuard
	Listener Listener
	Vault    Vault
	Auditor  Auditor
}

func (r RuntimeAdapters) valid() bool {
	return r.Secrets != nil && r.Traffic != nil && r.Clock != nil && r.Replay != nil && r.Listener != nil && r.Vault != nil && r.Auditor != nil
}

type PreparedAdmission interface {
	Commit(context.Context) (RuntimeAdapters, error)
	Abort()
}
type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) (RuntimeAdapters, error)
	AbortFunc  func()
}

func (p PreparedAdmissionFuncs) Commit(c context.Context) (RuntimeAdapters, error) {
	if p.CommitFunc == nil {
		return RuntimeAdapters{}, ErrTypedHandlesUnavailable
	}
	return p.CommitFunc(c)
}
func (p PreparedAdmissionFuncs) Abort() {
	if p.AbortFunc != nil {
		p.AbortFunc()
	}
}

type TypedHandleAdmission interface {
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)

func (f TypedHandleAdmissionFunc) Prepare(c context.Context, r pluginsdk.RPCHandshakeRequest, v Configuration) (PreparedAdmission, error) {
	return f(c, r, v)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
}

type Service struct {
	mu            sync.Mutex
	configuration Configuration
	runtime       RuntimeAdapters
	live          atomic.Bool
	sessions      sync.WaitGroup
	slots         chan struct{}
	hostSlots     chan struct{}
	hostMu        sync.Mutex
	hostOpen      bool
	hostCalls     sync.WaitGroup
	root          context.Context
	cancel        context.CancelFunc
	secrets       map[*SecretOnce]struct{}
	engines       map[string]*ProtocolEngine
}
type flowToken struct {
	mu          sync.Mutex
	done        bool
	result      error
	service     *Service
	reservation TrafficReservation
}
type Flow struct{ token *flowToken }

func (f Flow) Close(bytes uint64) error {
	if f.token == nil {
		return nil
	}
	f.token.mu.Lock()
	defer f.token.mu.Unlock()
	if !f.token.done {
		f.token.done = true
		defer func() { <-f.token.service.slots; f.token.service.sessions.Done() }()
		f.token.result = f.token.service.cleanup(func(ctx context.Context) error { return f.token.reservation.Commit(ctx, bytes) })
		if f.token.result != nil {
			_ = f.token.service.cleanup(f.token.reservation.Release)
		}
	}
	return f.token.result
}
func clone(c Configuration) Configuration {
	c.Users = append([]User(nil), c.Users...)
	sort.Slice(c.Users, func(i, j int) bool { return c.Users[i].ID < c.Users[j].ID })
	return c
}
