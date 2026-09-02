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
	PluginVersion        = "0.1.11"
	MaxConfigBytes       = 1 << 20
	MaxListeners         = 256
	MaxUsers             = 256
	UnlimitedQuotaBytes  = ^uint64(0)
	DefaultMaxSessions   = 256
	DefaultLegacyMethod  = "aes-256-gcm"
	DefaultSS2022Method  = "2022-blake3-aes-128-gcm"
	AccountFamilyLegacy  = "ss"
	AccountFamily2022    = "ss2022"
	ServerPSKID          = "server-psk"
	defaultSecretVersion = "v1"
	accountIDPrefix      = "acct-"
	listenIDPrefix       = "listen-"
	accountSecretPrefix  = "secret/"
	serverPSKSecretRef   = "secret/server-psk"
	accountIDRandomBytes = 8
	maxUserNameBytes     = 128
	maxAgentIDBytes      = 128
	minAutoListenPort    = 8388
	legacyPasswordBytes  = 16
	legacyPasswordAlpha  = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
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
	ErrAgentOffline            = errors.New("target Agent is offline")
	ErrListenBind              = errors.New("listen bind failed")
	ErrPortConflict            = errors.New("该节点已使用此端口")
	ErrExecutionUnavailable    = errors.New("该节点暂时无法执行监听")
	ErrTraditionalMultiUser    = errors.New("传统方法不能在同一端口追加用户")
)
var refPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type User struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	SecretRef     string `json:"secret_ref"`
	SecretVersion string `json:"secret_version"`
	Enabled       bool   `json:"enabled"`
}

type ListenRule struct {
	ID                  string `json:"id"`
	AgentID             string `json:"agent_id"`
	Port                int    `json:"port"`
	Method              string `json:"method"`
	ServerSecretRef     string `json:"server_secret_ref,omitempty"`
	ServerSecretVersion string `json:"server_secret_version,omitempty"`
	Users               []User `json:"users"`
}

type Configuration struct {
	Generation       string       `json:"generation,omitempty"`
	ResourceGroupRef string       `json:"resource_group_ref,omitempty"`
	Listeners        []ListenRule `json:"listeners"`
}

// AccountSpec creates one account without quota or expiry. Family selects
// traditional SS or SS2022 when Method is omitted.
type AccountSpec struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Family string `json:"family,omitempty"`
	Method string `json:"method,omitempty"`
}

// ListenSpec creates a listen or appends a user on a selected Agent.
type ListenSpec struct {
	AgentID   string `json:"agent_id,omitempty"`
	ListenID  string `json:"listen_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Method    string `json:"method,omitempty"`
	Port      int    `json:"port,omitempty"`
	Password  string `json:"password,omitempty"`
	ServerPSK string `json:"server_psk,omitempty"`
}

// AccountRecord is the plugin account API projection. It never includes
// secret material or generation identity.
type AccountRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Family        string `json:"family"`
	Method        string `json:"method"`
	Enabled       bool   `json:"enabled"`
	SecretVersion string `json:"secret_version"`
}

func (c Configuration) Validate() error {
	if c.Generation != "" && !refPattern.MatchString(c.Generation) {
		return ErrInvalid
	}
	if c.ResourceGroupRef != "" && !refPattern.MatchString(c.ResourceGroupRef) {
		return ErrInvalid
	}
	if len(c.Listeners) > MaxListeners {
		return ErrInvalid
	}
	listenerIDs := map[string]struct{}{}
	userIDs := map[string]struct{}{}
	ports := map[string]map[int]struct{}{}
	totalUsers := 0
	for _, listener := range c.Listeners {
		if err := listener.Validate(); err != nil {
			return err
		}
		if _, ok := listenerIDs[listener.ID]; ok {
			return ErrInvalid
		}
		listenerIDs[listener.ID] = struct{}{}
		used, ok := ports[listener.AgentID]
		if !ok {
			used = map[int]struct{}{}
			ports[listener.AgentID] = used
		}
		if _, ok = used[listener.Port]; ok {
			return ErrInvalid
		}
		used[listener.Port] = struct{}{}
		totalUsers += len(listener.Users)
		if totalUsers > MaxUsers {
			return ErrInvalid
		}
		for _, user := range listener.Users {
			if _, ok = userIDs[user.ID]; ok {
				return ErrInvalid
			}
			userIDs[user.ID] = struct{}{}
		}
	}
	return nil
}

func (l ListenRule) Validate() error {
	if !refPattern.MatchString(l.ID) || !validAgentID(l.AgentID) || l.Port < 1 || l.Port > 65535 || !SupportedMethod(l.Method) {
		return ErrInvalid
	}
	if l.ServerSecretRef != "" || l.ServerSecretVersion != "" {
		if !SS2022Method(l.Method) || !refPattern.MatchString(l.ServerSecretRef) || !refPattern.MatchString(l.ServerSecretVersion) {
			return ErrInvalid
		}
	}
	if !SS2022Method(l.Method) && len(l.Users) > 1 {
		return ErrInvalid
	}
	if len(l.Users) > MaxUsers {
		return ErrInvalid
	}
	seen := map[string]struct{}{}
	for _, user := range l.Users {
		if err := user.Validate(); err != nil {
			return err
		}
		if _, ok := seen[user.ID]; ok {
			return ErrInvalid
		}
		seen[user.ID] = struct{}{}
	}
	return nil
}

func (u User) Validate() error {
	if !refPattern.MatchString(u.ID) || !refPattern.MatchString(u.SecretRef) || !refPattern.MatchString(u.SecretVersion) {
		return ErrInvalid
	}
	if strings.ContainsAny(u.Name, "\r\n\x00") || len(u.Name) > maxUserNameBytes {
		return ErrInvalid
	}
	return nil
}

func validAgentID(value string) bool {
	return value != "" && len(value) <= maxAgentIDBytes && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00\t ")
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
		if defaultMethod == "" {
			defaultMethod = DefaultSS2022Method
		}
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

func NewListenID() (string, error) {
	id, err := NewAccountID()
	if err != nil {
		return "", err
	}
	id = listenIDPrefix + strings.TrimPrefix(id, accountIDPrefix)
	if !refPattern.MatchString(id) {
		return "", ErrInvalid
	}
	return id, nil
}

func DefaultUserName(id string) string {
	trimmed := strings.TrimPrefix(id, accountIDPrefix)
	if trimmed == "" || trimmed == id {
		return id
	}
	return "user-" + trimmed
}

func GenerateLegacyPassword() (string, error) {
	raw := make([]byte, legacyPasswordBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, legacyPasswordBytes)
	alpha := []byte(legacyPasswordAlpha)
	for i, value := range raw {
		out[i] = alpha[int(value)%len(alpha)]
	}
	clear(raw)
	return string(out), nil
}

func ServerPSKSecretRefFor(listenID string) string {
	if listenID == "" {
		return serverPSKSecretRef
	}
	return accountSecretPrefix + "server/" + listenID
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
	_, _, user, ok := c.lookupUser(id)
	return user, ok
}

func (c Configuration) lookupUser(id string) (listenerIdx, userIdx int, user User, ok bool) {
	for i, listener := range c.Listeners {
		for j, current := range listener.Users {
			if current.ID == id {
				return i, j, current, true
			}
		}
	}
	return -1, -1, User{}, false
}

func (c Configuration) userListener(id string) (ListenRule, User, bool) {
	listenerIdx, _, user, ok := c.lookupUser(id)
	if !ok {
		return ListenRule{}, User{}, false
	}
	return c.Listeners[listenerIdx], user, true
}

func (c Configuration) allUsers() []User {
	users := make([]User, 0, len(c.Listeners))
	for _, listener := range c.Listeners {
		users = append(users, listener.Users...)
	}
	return users
}

func (c Configuration) firstListenerID() string {
	if len(c.Listeners) == 0 {
		return ""
	}
	return c.Listeners[0].ID
}

func (c Configuration) instanceServerPSK() (ref, version string) {
	for _, listener := range c.Listeners {
		if listener.ServerSecretRef != "" && listener.ServerSecretVersion != "" {
			return listener.ServerSecretRef, listener.ServerSecretVersion
		}
	}
	return "", ""
}

func (c Configuration) ss2022ListenerByServerVersion(version string) (ListenRule, bool) {
	if version == "" {
		return ListenRule{}, false
	}
	for _, listener := range c.Listeners {
		if SS2022Method(listener.Method) && listener.ServerSecretVersion == version {
			return listener, true
		}
	}
	return ListenRule{}, false
}

func (c Configuration) ServerPSKVersion() string {
	_, version := c.instanceServerPSK()
	return version
}

func (c Configuration) listenerIndexForMethod(method string) (int, error) {
	if !SupportedMethod(method) {
		return -1, ErrInvalid
	}
	for i, listener := range c.Listeners {
		if listener.Method != method {
			continue
		}
		if SS2022Method(method) {
			if len(listener.Users) >= MaxUsers {
				continue
			}
			return i, nil
		}
		if len(listener.Users) >= 1 {
			continue
		}
		return i, nil
	}
	return -1, ErrInvalid
}

func (c *Configuration) ensureListenerForMethod(method string) (int, error) {
	if index, err := c.listenerIndexForMethod(method); err == nil {
		return index, nil
	}
	agentID := "agent-1"
	if len(c.Listeners) > 0 {
		agentID = c.Listeners[0].AgentID
	}
	port := 0
	used := map[int]struct{}{}
	for _, listener := range c.Listeners {
		if listener.AgentID == agentID {
			used[listener.Port] = struct{}{}
		}
	}
	for candidate := 8388; candidate <= 65535; candidate++ {
		if _, ok := used[candidate]; !ok {
			port = candidate
			break
		}
	}
	if port == 0 || !validAgentID(agentID) {
		return -1, ErrInvalid
	}
	id, err := NewAccountID()
	if err != nil {
		return -1, err
	}
	id = "listen-" + strings.TrimPrefix(id, accountIDPrefix)
	if !refPattern.MatchString(id) {
		return -1, ErrInvalid
	}
	c.Listeners = append(c.Listeners, ListenRule{ID: id, AgentID: agentID, Port: port, Method: method})
	return len(c.Listeners) - 1, nil
}

func (c Configuration) ListenersForAgent(agentID string) []ListenRule {
	out := make([]ListenRule, 0, len(c.Listeners))
	for _, listener := range clone(c).Listeners {
		if listener.AgentID == agentID {
			out = append(out, listener)
		}
	}
	return out
}

func (c Configuration) Listen(id string) (ListenRule, bool) {
	for _, listener := range c.Listeners {
		if listener.ID == id {
			return listener, true
		}
	}
	return ListenRule{}, false
}

func (c Configuration) usedPorts(agentID string) map[int]string {
	used := map[int]string{}
	for _, listener := range c.Listeners {
		if listener.AgentID == agentID {
			used[listener.Port] = listener.ID
		}
	}
	return used
}

func (c Configuration) NextListenPort(agentID string) (int, error) {
	used := c.usedPorts(agentID)
	for port := minAutoListenPort; port <= 65535; port++ {
		if _, ok := used[port]; !ok {
			return port, nil
		}
	}
	return 0, ErrInvalid
}

func (c Configuration) PortConflict(agentID string, port int, exceptListenID string) bool {
	if port < 1 || port > 65535 || !validAgentID(agentID) {
		return false
	}
	owner, ok := c.usedPorts(agentID)[port]
	return ok && owner != exceptListenID
}

func (spec ListenSpec) resolveMethod() (string, error) {
	return AccountSpec{Method: spec.Method}.resolveMethod(DefaultSS2022Method)
}

// CreateListen adds one listen with one enabled user. Duplicate ports on the
// same agent are rejected. Traditional methods cannot share a port.
func (c Configuration) CreateListen(spec ListenSpec, user User, serverRef, serverVersion string) (Configuration, ListenRule, User, error) {
	next := clone(c)
	if !validAgentID(spec.AgentID) {
		return Configuration{}, ListenRule{}, User{}, ErrAgentOffline
	}
	method, err := spec.resolveMethod()
	if err != nil {
		return Configuration{}, ListenRule{}, User{}, err
	}
	listenID := spec.ListenID
	if listenID == "" {
		listenID, err = NewListenID()
		if err != nil {
			return Configuration{}, ListenRule{}, User{}, err
		}
	}
	port := spec.Port
	if port == 0 {
		port, err = next.NextListenPort(spec.AgentID)
		if err != nil {
			return Configuration{}, ListenRule{}, User{}, err
		}
	}
	if port < 1 || port > 65535 {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	if next.PortConflict(spec.AgentID, port, "") {
		return Configuration{}, ListenRule{}, User{}, ErrPortConflict
	}
	if _, exists := next.Listen(listenID); exists {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	if user.ID == "" {
		user.ID, err = NewAccountID()
		if err != nil {
			return Configuration{}, ListenRule{}, User{}, err
		}
	}
	if user.Name == "" {
		user.Name = DefaultUserName(user.ID)
	}
	if user.SecretRef == "" {
		user.SecretRef = AccountSecretRef(user.ID)
	}
	if user.SecretVersion == "" {
		user.SecretVersion = defaultSecretVersion
	}
	user.Enabled = true
	if err := user.Validate(); err != nil {
		return Configuration{}, ListenRule{}, User{}, err
	}
	if _, _, _, exists := next.lookupUser(user.ID); exists {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	listener := ListenRule{ID: listenID, AgentID: spec.AgentID, Port: port, Method: method, Users: []User{user}}
	if SS2022Method(method) {
		if serverRef == "" {
			serverRef = ServerPSKSecretRefFor(listenID)
		}
		if serverVersion == "" {
			serverVersion = defaultSecretVersion
		}
		listener.ServerSecretRef, listener.ServerSecretVersion = serverRef, serverVersion
	} else if serverRef != "" || serverVersion != "" {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	next.Listeners = append(next.Listeners, listener)
	if err := next.Validate(); err != nil {
		if next.PortConflict(spec.AgentID, port, listenID) {
			return Configuration{}, ListenRule{}, User{}, ErrPortConflict
		}
		return Configuration{}, ListenRule{}, User{}, err
	}
	created, _ := next.Listen(listenID)
	return next, created, user, nil
}

// AppendListenUser adds one user to an existing SS2022 listen. Traditional
// methods reject a second user. Method, port, and server PSK are reused.
func (c Configuration) AppendListenUser(listenID string, user User) (Configuration, ListenRule, User, error) {
	next := clone(c)
	listener, ok := next.Listen(listenID)
	if !ok {
		return Configuration{}, ListenRule{}, User{}, ErrDenied
	}
	if !SS2022Method(listener.Method) {
		return Configuration{}, ListenRule{}, User{}, ErrTraditionalMultiUser
	}
	if user.ID == "" {
		id, err := NewAccountID()
		if err != nil {
			return Configuration{}, ListenRule{}, User{}, err
		}
		user.ID = id
	}
	if user.Name == "" {
		user.Name = DefaultUserName(user.ID)
	}
	if user.SecretRef == "" {
		user.SecretRef = AccountSecretRef(user.ID)
	}
	if user.SecretVersion == "" {
		user.SecretVersion = defaultSecretVersion
	}
	user.Enabled = true
	if err := user.Validate(); err != nil {
		return Configuration{}, ListenRule{}, User{}, err
	}
	if _, _, _, exists := next.lookupUser(user.ID); exists {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	if len(next.allUsers()) >= MaxUsers {
		return Configuration{}, ListenRule{}, User{}, ErrInvalid
	}
	for i, current := range next.Listeners {
		if current.ID != listenID {
			continue
		}
		next.Listeners[i].Users = append(next.Listeners[i].Users, user)
		if err := next.Validate(); err != nil {
			return Configuration{}, ListenRule{}, User{}, err
		}
		return next, next.Listeners[i], user, nil
	}
	return Configuration{}, ListenRule{}, User{}, ErrDenied
}

func (c Configuration) DeleteUser(id string) (Configuration, ListenRule, error) {
	next := clone(c)
	listenerIdx, userIdx, _, ok := next.lookupUser(id)
	if !ok {
		return Configuration{}, ListenRule{}, ErrDenied
	}
	listener := next.Listeners[listenerIdx]
	users := append([]User(nil), listener.Users...)
	next.Listeners[listenerIdx].Users = append(users[:userIdx], users[userIdx+1:]...)
	return next, next.Listeners[listenerIdx], nil
}

func (c Configuration) DeleteListen(id string) (Configuration, ListenRule, error) {
	next := clone(c)
	for i, listener := range next.Listeners {
		if listener.ID != id {
			continue
		}
		next.Listeners = append(append([]ListenRule(nil), next.Listeners[:i]...), next.Listeners[i+1:]...)
		return next, listener, nil
	}
	return Configuration{}, ListenRule{}, ErrDenied
}

func (c Configuration) AccountRecord(user User) AccountRecord {
	listener, current, ok := c.userListener(user.ID)
	if !ok {
		current = user
	}
	method := listener.Method
	return AccountRecord{
		ID:            current.ID,
		Name:          current.Name,
		Family:        AccountFamilyOf(method),
		Method:        method,
		Enabled:       current.Enabled,
		SecretVersion: current.SecretVersion,
	}
}

func (c Configuration) ListAccounts() []AccountRecord {
	accounts := make([]AccountRecord, 0)
	for _, listener := range clone(c).Listeners {
		for _, user := range listener.Users {
			accounts = append(accounts, AccountRecord{
				ID:            user.ID,
				Name:          user.Name,
				Family:        AccountFamilyOf(listener.Method),
				Method:        listener.Method,
				Enabled:       user.Enabled,
				SecretVersion: user.SecretVersion,
			})
		}
	}
	return accounts
}

func (c Configuration) HasSS2022() bool {
	for _, listener := range c.Listeners {
		if SS2022Method(listener.Method) {
			return true
		}
	}
	return false
}

// CreateAccount appends one enabled user onto a listener of the requested method.
// Traditional methods reject a second user. Generation is not changed.
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
	method, err := spec.resolveMethod(DefaultSS2022Method)
	if err != nil {
		return Configuration{}, User{}, err
	}
	if secretRef == "" {
		secretRef = AccountSecretRef(id)
	}
	if secretVersion == "" {
		secretVersion = defaultSecretVersion
	}
	name := spec.Name
	if name == "" {
		name = id
	}
	if !refPattern.MatchString(id) || !refPattern.MatchString(secretRef) || !refPattern.MatchString(secretVersion) || len(next.allUsers()) >= MaxUsers {
		return Configuration{}, User{}, ErrInvalid
	}
	if _, _, _, exists := next.lookupUser(id); exists {
		return Configuration{}, User{}, ErrInvalid
	}
	index, err := next.ensureListenerForMethod(method)
	if err != nil {
		return Configuration{}, User{}, err
	}
	user := User{ID: id, Name: name, SecretRef: secretRef, SecretVersion: secretVersion, Enabled: true}
	next.Listeners[index].Users = append(next.Listeners[index].Users, user)
	if err := next.Validate(); err != nil {
		return Configuration{}, User{}, err
	}
	return next, user, nil
}

// SetAccountEnabled toggles one account. It does not revoke the generation.
func (c Configuration) SetAccountEnabled(id string, enabled bool) (Configuration, error) {
	next := clone(c)
	listenerIdx, userIdx, _, ok := next.lookupUser(id)
	if !ok {
		return Configuration{}, ErrDenied
	}
	next.Listeners[listenerIdx].Users[userIdx].Enabled = enabled
	return next, nil
}

// ReplaceUserSecret CAS-updates one account secret and leaves Generation intact.
func (c Configuration) ReplaceUserSecret(id, expectedVersion, newRef, newVersion string) (Configuration, error) {
	next := clone(c)
	listenerIdx, userIdx, current, ok := next.lookupUser(id)
	if !ok || expectedVersion == "" || current.SecretVersion != expectedVersion {
		return Configuration{}, ErrDenied
	}
	if !refPattern.MatchString(newRef) || !refPattern.MatchString(newVersion) {
		return Configuration{}, ErrInvalid
	}
	next.Listeners[listenerIdx].Users[userIdx].SecretRef, next.Listeners[listenerIdx].Users[userIdx].SecretVersion = newRef, newVersion
	return next, nil
}

// ReplaceServerPSK CAS-updates one SS2022 listener server PSK. User identity
// PSK versions and Generation stay unchanged.
func (c Configuration) ReplaceServerPSK(listenerID, expectedVersion, newRef, newVersion string) (Configuration, error) {
	if listenerID == "" || expectedVersion == "" || !refPattern.MatchString(newRef) || !refPattern.MatchString(newVersion) {
		return Configuration{}, ErrInvalid
	}
	next := clone(c)
	for i, listener := range next.Listeners {
		if listener.ID != listenerID {
			continue
		}
		if !SS2022Method(listener.Method) || listener.ServerSecretVersion != expectedVersion {
			return Configuration{}, ErrDenied
		}
		next.Listeners[i].ServerSecretRef, next.Listeners[i].ServerSecretVersion = newRef, newVersion
		return next, nil
	}
	return Configuration{}, ErrDenied
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
func cloneListeners(listeners []ListenRule) []ListenRule {
	return clone(Configuration{Listeners: listeners}).Listeners
}

func clone(c Configuration) Configuration {
	listeners := make([]ListenRule, len(c.Listeners))
	for i, listener := range c.Listeners {
		listener.Users = append([]User(nil), listener.Users...)
		sort.Slice(listener.Users, func(a, b int) bool { return listener.Users[a].ID < listener.Users[b].ID })
		listeners[i] = listener
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].ID < listeners[j].ID })
	c.Listeners = listeners
	return c
}
