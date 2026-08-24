package shadowsocksserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID             = "shadowsocks-server"
	PluginVersion        = "0.1.2"
	MaxConfigBytes       = 1 << 20
	MaxUsers             = 256
	UnlimitedQuotaBytes  = ^uint64(0)
	DefaultLegacyMethod  = "aes-256-gcm"
	DefaultSS2022Method  = "2022-blake3-aes-256-gcm"
	AccountFamilyLegacy  = "ss"
	AccountFamily2022    = "ss2022"
	ServerPSKID          = "server-psk"
	defaultSecretVersion = "v1"
	accountIDPrefix      = "acct-"
	accountSecretPrefix  = "secret/"
	serverPSKSecretRef   = "secret/server-psk"
	accountIDRandomBytes = 8
)

var (
	ErrInvalid                 = errors.New("invalid Shadowsocks configuration")
	ErrDenied                  = errors.New("Shadowsocks admission denied")
	ErrExpired                 = errors.New("Shadowsocks user expired")
	ErrQuota                   = errors.New("Shadowsocks quota exceeded")
	ErrReplay                  = errors.New("Shadowsocks replay rejected")
	ErrRevoked                 = errors.New("Shadowsocks generation revoked")
	ErrDisabled                = errors.New("Shadowsocks account disabled")
	ErrTypedHandlesUnavailable = errors.New("canonical typed Shadowsocks handles unavailable")
)
var refPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type User struct {
	ID            string `json:"id"`
	Method        string `json:"method,omitempty"`
	SecretRef     string `json:"secret_ref"`
	SecretVersion string `json:"secret_version"`
	Enabled       bool   `json:"enabled"`
	ExpiresAt     uint64 `json:"expires_at"`
	QuotaBytes    uint64 `json:"quota_bytes"`
}
type Configuration struct {
	Generation       string `json:"generation"`
	ListenerRef      string `json:"listener_ref"`
	Cipher           string `json:"cipher"`
	ServerPSKRef     string `json:"server_psk_ref,omitempty"`
	ServerPSKVersion string `json:"server_psk_version,omitempty"`
	MaxSessions      int    `json:"max_sessions"`
	Users            []User `json:"users"`
}

// AccountSpec creates one account without quota or expiry. Family selects
// traditional SS or SS2022 when Method is omitted.
type AccountSpec struct {
	ID     string `json:"id,omitempty"`
	Family string `json:"family,omitempty"`
	Method string `json:"method,omitempty"`
}

// AccountRecord is the plugin account API projection. It never includes
// secret material or generation identity.
type AccountRecord struct {
	ID            string `json:"id"`
	Family        string `json:"family"`
	Method        string `json:"method"`
	Enabled       bool   `json:"enabled"`
	SecretVersion string `json:"secret_version"`
	ExpiresAt     uint64 `json:"expires_at,omitempty"`
	QuotaBytes    uint64 `json:"quota_bytes,omitempty"`
}

func (c Configuration) Validate() error {
	if !refPattern.MatchString(c.Generation) || !refPattern.MatchString(c.ListenerRef) || c.MaxSessions < 1 || c.MaxSessions > 4096 || len(c.Users) > MaxUsers {
		return ErrInvalid
	}
	if !SupportedMethod(c.Cipher) {
		return ErrInvalid
	}
	if c.ServerPSKRef != "" || c.ServerPSKVersion != "" {
		if !refPattern.MatchString(c.ServerPSKRef) || !refPattern.MatchString(c.ServerPSKVersion) {
			return ErrInvalid
		}
	}
	seen := map[string]struct{}{}
	for _, u := range c.Users {
		if !refPattern.MatchString(u.ID) || !refPattern.MatchString(u.SecretRef) || !refPattern.MatchString(u.SecretVersion) {
			return ErrInvalid
		}
		if method := u.ResolvedMethod(c.Cipher); !SupportedMethod(method) {
			return ErrInvalid
		}
		if _, ok := seen[u.ID]; ok {
			return ErrInvalid
		}
		seen[u.ID] = struct{}{}
	}
	return nil
}

func SS2022Method(method string) bool {
	return strings.HasPrefix(method, "2022-")
}

func AccountFamilyOf(method string) string {
	if SS2022Method(method) {
		return AccountFamily2022
	}
	return AccountFamilyLegacy
}

func (u User) ResolvedMethod(defaultMethod string) string {
	if u.Method != "" {
		return u.Method
	}
	return defaultMethod
}

func (u User) EffectiveQuota() uint64 {
	if u.QuotaBytes == 0 {
		return UnlimitedQuotaBytes
	}
	return u.QuotaBytes
}

func (u User) Expired(now uint64) bool {
	return u.ExpiresAt > 0 && now >= u.ExpiresAt
}

func (spec AccountSpec) resolveMethod(defaultMethod string) (string, error) {
	if spec.Method != "" {
		if !SupportedMethod(spec.Method) {
			return "", ErrInvalid
		}
		if spec.Family != "" && AccountFamilyOf(spec.Method) != spec.Family {
			return "", ErrInvalid
		}
		return spec.Method, nil
	}
	switch spec.Family {
	case "":
		if !SupportedMethod(defaultMethod) {
			return "", ErrInvalid
		}
		return defaultMethod, nil
	case AccountFamilyLegacy:
		return DefaultLegacyMethod, nil
	case AccountFamily2022:
		return DefaultSS2022Method, nil
	default:
		return "", ErrInvalid
	}
}

func NewAccountID() (string, error) {
	var raw [accountIDRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := accountIDPrefix + hex.EncodeToString(raw[:])
	if !refPattern.MatchString(id) {
		return "", ErrInvalid
	}
	return id, nil
}

func AccountSecretRef(id string) string {
	return accountSecretPrefix + id
}

func ServerPSKSecretRef() string {
	return serverPSKSecretRef
}

func InitialSecretVersion() string {
	return defaultSecretVersion
}

func (c Configuration) User(id string) (User, bool) {
	_, user, ok := c.lookupUser(id)
	return user, ok
}

func (c Configuration) lookupUser(id string) (int, User, bool) {
	for i, user := range c.Users {
		if user.ID == id {
			return i, user, true
		}
	}
	return -1, User{}, false
}

func (c Configuration) AccountRecord(user User) AccountRecord {
	method := user.ResolvedMethod(c.Cipher)
	return AccountRecord{
		ID:            user.ID,
		Family:        AccountFamilyOf(method),
		Method:        method,
		Enabled:       user.Enabled,
		SecretVersion: user.SecretVersion,
		ExpiresAt:     user.ExpiresAt,
		QuotaBytes:    user.QuotaBytes,
	}
}

func (c Configuration) ListAccounts() []AccountRecord {
	accounts := make([]AccountRecord, 0, len(c.Users))
	for _, user := range clone(c).Users {
		accounts = append(accounts, c.AccountRecord(user))
	}
	return accounts
}

func (c Configuration) HasSS2022() bool {
	for _, user := range c.Users {
		if SS2022Method(user.ResolvedMethod(c.Cipher)) {
			return true
		}
	}
	return false
}

// CreateAccount appends one enabled account. Quota and expiry stay unset.
// Generation is not changed.
func (c Configuration) CreateAccount(spec AccountSpec, secretRef, secretVersion string) (Configuration, User, error) {
	next := clone(c)
	id := spec.ID
	if id == "" {
		generated, err := NewAccountID()
		if err != nil {
			return Configuration{}, User{}, err
		}
		id = generated
	}
	method, err := spec.resolveMethod(next.Cipher)
	if err != nil {
		return Configuration{}, User{}, err
	}
	if secretRef == "" {
		secretRef = AccountSecretRef(id)
	}
	if secretVersion == "" {
		secretVersion = defaultSecretVersion
	}
	if !refPattern.MatchString(id) || !refPattern.MatchString(secretRef) || !refPattern.MatchString(secretVersion) || len(next.Users) >= MaxUsers {
		return Configuration{}, User{}, ErrInvalid
	}
	if _, _, exists := next.lookupUser(id); exists {
		return Configuration{}, User{}, ErrInvalid
	}
	user := User{ID: id, Method: method, SecretRef: secretRef, SecretVersion: secretVersion, Enabled: true}
	next.Users = append(next.Users, user)
	if err := next.Validate(); err != nil {
		return Configuration{}, User{}, err
	}
	return next, user, nil
}

// SetAccountEnabled toggles one account. It does not revoke the generation.
func (c Configuration) SetAccountEnabled(id string, enabled bool) (Configuration, error) {
	next := clone(c)
	index, _, ok := next.lookupUser(id)
	if !ok {
		return Configuration{}, ErrDenied
	}
	next.Users[index].Enabled = enabled
	return next, nil
}

// ReplaceUserSecret CAS-updates one account secret and leaves Generation intact.
func (c Configuration) ReplaceUserSecret(id, expectedVersion, newRef, newVersion string) (Configuration, error) {
	next := clone(c)
	index, current, ok := next.lookupUser(id)
	if !ok || expectedVersion == "" || current.SecretVersion != expectedVersion {
		return Configuration{}, ErrDenied
	}
	if !refPattern.MatchString(newRef) || !refPattern.MatchString(newVersion) {
		return Configuration{}, ErrInvalid
	}
	next.Users[index].SecretRef, next.Users[index].SecretVersion = newRef, newVersion
	return next, nil
}

// ReplaceServerPSK CAS-updates the instance SS2022 server PSK. User identity
// PSK versions and Generation stay unchanged.
func (c Configuration) ReplaceServerPSK(expectedVersion, newRef, newVersion string) (Configuration, error) {
	if c.ServerPSKVersion != expectedVersion {
		return Configuration{}, ErrDenied
	}
	if !refPattern.MatchString(newRef) || !refPattern.MatchString(newVersion) {
		return Configuration{}, ErrInvalid
	}
	next := clone(c)
	next.ServerPSKRef, next.ServerPSKVersion = newRef, newVersion
	return next, nil
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

// TrafficReservation is a capability-backed atomic quota reservation. Consume
// is called before bytes are forwarded; it must fail without consuming when
// the requested allowance would exceed the user's quota. Consume, Finish and
// Abort must be linearizable: once Finish or Abort commits, a late Consume must
// fail without changing the ledger.
type TrafficReservation interface {
	Consume(context.Context, uint64) error
	Finish(context.Context) error
	Abort(context.Context) error
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
	cleanupSlots  chan struct{}
	hostMu        sync.Mutex
	hostOpen      bool
	hostCalls     sync.WaitGroup
	root          context.Context
	cancel        context.CancelFunc
	secrets       map[*SecretOnce]struct{}
	engines       map[string]*ProtocolEngine
	engineGate    sync.RWMutex
}
type flowToken struct {
	mu          sync.Mutex
	done        bool
	result      error
	service     *Service
	reservation TrafficReservation
}
type Flow struct{ token *flowToken }

func (f Flow) Close() error {
	return f.close()
}

func (f Flow) Consume(ctx context.Context, bytes uint64) error {
	if f.token == nil {
		return nil
	}
	f.token.mu.Lock()
	defer f.token.mu.Unlock()
	if f.token.done {
		return f.token.result
	}
	if bytes == 0 {
		return nil
	}
	if err := f.token.service.host(ctx, func(ctx context.Context) error { return f.token.reservation.Consume(ctx, bytes) }); err != nil {
		f.token.result = ErrQuota
		f.token.finishLocked(false)
		return f.token.result
	}
	return nil
}

func (f Flow) close() error {
	if f.token == nil {
		return nil
	}
	f.token.mu.Lock()
	defer f.token.mu.Unlock()
	if !f.token.done {
		f.token.finishLocked(true)
	}
	return f.token.result
}

func (f *flowToken) finishLocked(success bool) {
	if f.done {
		return
	}
	f.done = true
	defer func() { <-f.service.slots; f.service.sessions.Done() }()
	if success {
		f.result = f.service.cleanup(f.reservation.Finish)
	}
	if !success || f.result != nil {
		abortErr := f.service.cleanup(f.reservation.Abort)
		if f.result == nil {
			f.result = abortErr
		}
	}
}
func clone(c Configuration) Configuration {
	c.Users = append([]User(nil), c.Users...)
	sort.Slice(c.Users, func(i, j int) bool { return c.Users[i].ID < c.Users[j].ID })
	return c
}
