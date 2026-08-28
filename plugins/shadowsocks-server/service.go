package shadowsocksserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// AccountShare is one account plus the current listen projection. Accounts
// remain when the public host is missing; URI and QR stay empty.
type AccountShare struct {
	Account   AccountRecord
	Endpoint  ShareEndpoint
	Share     SIP002Share
	Available bool
	Reason    string
}

// ListenBindingSource is the optional Host view of the actual bound port.
type ListenBindingSource interface {
	ListenBinding(context.Context, string) (ListenBinding, error)
}

// NodeAddressSource is the optional Host view of this node's public addresses.
type NodeAddressSource interface {
	NodeAddresses(context.Context) (NodeAddresses, error)
}

type listenShareAttachment struct {
	binding ListenBinding
	node    NodeAddresses
}

var (
	listenShareMu sync.Mutex
	listenShares  = map[*Service]*listenShareAttachment{}
)

// SelectPublicHost picks DDNS, otherwise IPv4, otherwise IPv6. It never
// returns 0.0.0.0, ::, or a loopback address.
func SelectPublicHost(node NodeAddresses) (string, bool) {
	host, _, ok := node.SelectHost()
	return host, ok
}

const hostCallTimeout = time.Second

type callResult[T any] struct {
	value T
	err   error
}

// awaitHost bounds cooperative calls and discards late results. Each ignored
// cancellation consumes a fixed generation call slot; process isolation is the
// final termination boundary for a broken Host adapter.
func awaitHost[T any](ctx context.Context, s *Service, cleanup bool, f func(context.Context) (T, error)) (T, error) {
	var zero T
	callCtx, cancel := context.WithTimeout(ctx, hostCallTimeout)
	stop := func() bool { return true }
	s.hostMu.Lock()
	if !cleanup && !s.hostOpen {
		s.hostMu.Unlock()
		cancel()
		return zero, ErrRevoked
	}
	s.hostCalls.Add(1)
	s.hostMu.Unlock()
	if !cleanup {
		stop = context.AfterFunc(s.root, cancel)
	}
	defer func() { stop(); cancel() }()
	callSlots := s.hostSlots
	if cleanup {
		callSlots = s.cleanupSlots
	}
	select {
	case callSlots <- struct{}{}:
	case <-callCtx.Done():
		s.hostCalls.Done()
		return zero, callCtx.Err()
	}
	result := make(chan callResult[T], 1)
	go func() {
		value, err := f(callCtx)
		result <- callResult[T]{value, err}
		<-callSlots
		s.hostCalls.Done()
	}()
	select {
	case <-callCtx.Done():
		return zero, callCtx.Err()
	case outcome := <-result:
		if err := callCtx.Err(); err != nil {
			return zero, err
		}
		return outcome.value, outcome.err
	}
}
func engineFromMaterial(method string, material []byte, serverPSK string) (*ProtocolEngine, error) {
	if !SS2022Method(method) {
		return NewProtocolEngine(method, material)
	}
	if serverPart, userPart, ok := splitSS2022ClientPassword(material); ok {
		mapped, err := SS2022ClientPassword(method, serverPart, userPart)
		if err != nil {
			return nil, err
		}
		return NewProtocolEngine(method, []byte(mapped))
	}
	userEnc, err := MapSS2022PSK(method, string(material))
	if err != nil {
		return nil, err
	}
	if serverPSK == "" {
		return NewProtocolEngine(method, []byte(userEnc))
	}
	serverEnc, err := MapSS2022PSK(method, serverPSK)
	if err != nil {
		return nil, err
	}
	return NewSS2022IdentityEngine(method, []byte(serverEnc), []byte(userEnc))
}

func ss2022ClientPasswordFromEngine(engine *ProtocolEngine) (string, error) {
	user, identity, err := engine.keysSnapshot()
	if err != nil {
		return "", err
	}
	defer clear(user)
	defer clear(identity)
	if len(identity) == 0 {
		return "", ErrInvalid
	}
	return base64.StdEncoding.EncodeToString(identity) + ":" + base64.StdEncoding.EncodeToString(user), nil
}

func encodedPSK(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func (s *Service) resolveSecret(ctx context.Context, ref, version string) ([]byte, error) {
	material, err := awaitHost(ctx, s, false, func(ctx context.Context) ([]byte, error) {
		return s.runtime.Secrets.Resolve(ctx, ref, version)
	})
	if err != nil {
		return nil, ErrTypedHandlesUnavailable
	}
	return material, nil
}

func (s *Service) rotateVault(ctx context.Context, id, ref, version, generation, scope string) (*SecretOnce, error) {
	op := sha256.Sum256([]byte(generation + "\x00" + id + "\x00" + ref + "\x00" + version + "\x00" + scope))
	secret, err := awaitHost(ctx, s, false, func(ctx context.Context) (*SecretOnce, error) {
		return s.runtime.Vault.Rotate(ctx, id, ref, version, hex.EncodeToString(op[:]))
	})
	if err != nil {
		return nil, ErrDenied
	}
	if secret == nil || !refPattern.MatchString(secret.SecretRef) || !refPattern.MatchString(secret.SecretVersion) {
		secret.discard()
		return nil, ErrInvalid
	}
	return secret, nil
}

func (s *Service) resolveUserEngine(ctx context.Context, method, ref, version, serverPSK string) (*ProtocolEngine, error) {
	material, err := s.resolveSecret(ctx, ref, version)
	if err != nil {
		return nil, err
	}
	engine, err := engineFromMaterial(method, material, serverPSK)
	clear(material)
	return engine, err
}

func NewService(c Configuration, r RuntimeAdapters) (*Service, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !r.valid() {
		return nil, ErrTypedHandlesUnavailable
	}
	root, cancel := context.WithCancel(context.Background())
	s := &Service{
		configuration: clone(c), runtime: r,
		slots: make(chan struct{}, DefaultMaxSessions), hostSlots: make(chan struct{}, DefaultMaxSessions), cleanupSlots: make(chan struct{}, DefaultMaxSessions*2),
		hostOpen: true, root: root, cancel: cancel, secrets: map[*SecretOnce]struct{}{}, engines: map[string]*ProtocolEngine{},
	}
	s.live.Store(true)
	return s, nil
}
func (s *Service) Initialize(ctx context.Context) error {
	s.mu.Lock()
	listeners := append([]ListenRule(nil), s.configuration.Listeners...)
	s.mu.Unlock()
	for _, listener := range listeners {
		serverPSK := ""
		if listener.ServerSecretRef != "" && listener.ServerSecretVersion != "" {
			material, err := s.resolveSecret(ctx, listener.ServerSecretRef, listener.ServerSecretVersion)
			if err != nil {
				return err
			}
			serverPSK = string(material)
			clear(material)
		}
		for _, user := range listener.Users {
			if !user.Enabled {
				continue
			}
			engine, err := s.resolveUserEngine(ctx, listener.Method, user.SecretRef, user.SecretVersion, serverPSK)
			if err != nil {
				return err
			}
			s.mu.Lock()
			if !s.live.Load() {
				s.mu.Unlock()
				engine.Destroy()
				return ErrRevoked
			}
			s.engines[user.ID] = engine
			s.mu.Unlock()
		}
	}
	return nil
}

func (s *Service) ListAccounts() []AccountRecord {
	return s.Snapshot().ListAccounts()
}

// CreateAccount mints one enabled user through the plugin API. Traditional SS
// and SS2022 can share the instance; quota and expiry stay on safe defaults.
func (s *Service) CreateAccount(ctx context.Context, spec AccountSpec) (User, *SecretOnce, error) {
	if err := ctx.Err(); err != nil {
		return User{}, nil, err
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		return User{}, nil, ErrRevoked
	}
	generation := s.configuration.Generation
	s.mu.Unlock()
	method, err := spec.resolveMethod(DefaultSS2022Method)
	if err != nil {
		return User{}, nil, err
	}
	if spec.ID == "" {
		id, idErr := NewAccountID()
		if idErr != nil {
			return User{}, nil, ErrDenied
		}
		spec.ID = id
	}
	s.mu.Lock()
	listenerIdx, listenerErr := s.configuration.ensureListenerForMethod(method)
	serverRef, serverVersion := "", ""
	if listenerErr == nil {
		// clone re-sorts Listeners by ID; keep the ensured listener by ID, not index.
		listenerID := s.configuration.Listeners[listenerIdx].ID
		s.configuration = clone(s.configuration)
		for _, listener := range s.configuration.Listeners {
			if listener.ID != listenerID {
				continue
			}
			serverRef, serverVersion = listener.ServerSecretRef, listener.ServerSecretVersion
			break
		}
	}
	s.mu.Unlock()
	if listenerErr != nil {
		return User{}, nil, listenerErr
	}
	var mintedServer *SecretOnce
	serverPSK := ""
	if SS2022Method(method) {
		if serverRef != "" && serverVersion != "" {
			material, resolveErr := s.resolveSecret(ctx, serverRef, serverVersion)
			if resolveErr != nil {
				return User{}, nil, resolveErr
			}
			serverPSK = string(material)
			clear(material)
		} else {
			mintedServer, err = s.rotateVault(ctx, ServerPSKID, ServerPSKSecretRef(), InitialSecretVersion(), generation, "server-psk")
			if err != nil {
				return User{}, nil, err
			}
			material, resolveErr := s.resolveSecret(ctx, mintedServer.SecretRef, mintedServer.SecretVersion)
			if resolveErr != nil {
				mintedServer.discard()
				return User{}, nil, resolveErr
			}
			serverPSK = string(material)
			serverRef, serverVersion = mintedServer.SecretRef, mintedServer.SecretVersion
			clear(material)
		}
	}
	secret, err := s.rotateVault(ctx, spec.ID, AccountSecretRef(spec.ID), InitialSecretVersion(), generation, "user")
	if err != nil {
		if mintedServer != nil {
			mintedServer.discard()
		}
		return User{}, nil, err
	}
	material, err := s.resolveSecret(ctx, secret.SecretRef, secret.SecretVersion)
	if err != nil {
		secret.discard()
		if mintedServer != nil {
			mintedServer.discard()
		}
		return User{}, nil, err
	}
	engine, err := engineFromMaterial(method, material, serverPSK)
	if err != nil {
		clear(material)
		secret.discard()
		if mintedServer != nil {
			mintedServer.discard()
		}
		return User{}, nil, err
	}
	client := append([]byte(nil), material...)
	if SS2022Method(method) {
		userMaterial := material
		serverMaterial := []byte(serverPSK)
		if serverPart, userPart, ok := splitSS2022ClientPassword(material); ok {
			serverMaterial, userMaterial = serverPart, userPart
		}
		mapped, mapErr := SS2022ClientPassword(method, serverMaterial, userMaterial)
		if mapErr != nil {
			clear(material)
			engine.Destroy()
			secret.discard()
			if mintedServer != nil {
				mintedServer.discard()
			}
			return User{}, nil, mapErr
		}
		client = []byte(mapped)
	}
	clear(material)
	revealed := NewSecretOnce(secret.SecretRef, secret.SecretVersion, client)
	secret.discard()
	s.engineGate.Lock()
	user, installed, err := s.installCreatedAccount(spec, revealed, engine, serverRef, serverVersion, mintedServer)
	s.engineGate.Unlock()
	if err != nil {
		return User{}, nil, err
	}
	if auditErr := s.audit(ctx, AuditRecord{Action: "create-account", Outcome: "succeeded", UserID: user.ID}); auditErr != nil {
		return user, installed, auditErr
	}
	return user, installed, nil
}

func (s *Service) installCreatedAccount(spec AccountSpec, secret *SecretOnce, engine *ProtocolEngine, serverRef, serverVersion string, mintedServer *SecretOnce) (User, *SecretOnce, error) {
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		engine.Destroy()
		secret.discard()
		if mintedServer != nil {
			mintedServer.discard()
		}
		return User{}, nil, ErrRevoked
	}
	next, user, err := s.configuration.CreateAccount(spec, secret.SecretRef, secret.SecretVersion)
	if err != nil {
		s.mu.Unlock()
		engine.Destroy()
		secret.discard()
		if mintedServer != nil {
			mintedServer.discard()
		}
		return User{}, nil, err
	}
	if serverRef != "" {
		if listenerIdx, _, _, ok := next.lookupUser(user.ID); ok && next.Listeners[listenerIdx].ServerSecretVersion == "" {
			next.Listeners[listenerIdx].ServerSecretRef, next.Listeners[listenerIdx].ServerSecretVersion = serverRef, serverVersion
		}
	}
	s.configuration = next
	s.engines[user.ID] = engine
	secret.owner, secret.generation = s, s.configuration.Generation
	s.secrets[secret] = struct{}{}
	if mintedServer != nil {
		mintedServer.owner, mintedServer.generation = s, s.configuration.Generation
		s.secrets[mintedServer] = struct{}{}
	}
	s.mu.Unlock()
	return user, secret, nil
}

func (s *Service) DisableAccount(ctx context.Context, userID string) error {
	return s.SetAccountEnabled(ctx, userID, false)
}

func (s *Service) EnableAccount(ctx context.Context, userID string) error {
	return s.SetAccountEnabled(ctx, userID, true)
}

// SetAccountEnabled flips one user's enabled flag. It does not call Disable, so
// the generation stays live and an unrotated password works again after enable.
func (s *Service) SetAccountEnabled(ctx context.Context, userID string, enabled bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		return ErrRevoked
	}
	listener, user, ok := s.configuration.userListener(userID)
	if !ok {
		s.mu.Unlock()
		return ErrDenied
	}
	needEngine := enabled && s.engines[userID] == nil
	method := listener.Method
	serverRef, serverVersion := listener.ServerSecretRef, listener.ServerSecretVersion
	if !needEngine {
		next, err := s.configuration.SetAccountEnabled(userID, enabled)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.configuration = next
		s.mu.Unlock()
		return s.auditAccountToggle(ctx, userID, enabled)
	}
	s.mu.Unlock()
	serverPSK := ""
	if SS2022Method(method) && serverRef != "" && serverVersion != "" {
		material, err := s.resolveSecret(ctx, serverRef, serverVersion)
		if err != nil {
			return err
		}
		serverPSK = string(material)
		clear(material)
	}
	engine, err := s.resolveUserEngine(ctx, method, user.SecretRef, user.SecretVersion, serverPSK)
	if err != nil {
		return err
	}
	s.engineGate.Lock()
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		s.engineGate.Unlock()
		engine.Destroy()
		return ErrRevoked
	}
	next, err := s.configuration.SetAccountEnabled(userID, true)
	if err != nil {
		s.mu.Unlock()
		s.engineGate.Unlock()
		engine.Destroy()
		return err
	}
	s.configuration = next
	if s.engines[userID] == nil {
		s.engines[userID] = engine
		engine = nil
	}
	s.mu.Unlock()
	s.engineGate.Unlock()
	if engine != nil {
		engine.Destroy()
	}
	return s.auditAccountToggle(ctx, userID, true)
}

func (s *Service) auditAccountToggle(ctx context.Context, userID string, enabled bool) error {
	action := "disable-account"
	if enabled {
		action = "enable-account"
	}
	return s.audit(ctx, AuditRecord{Action: action, Outcome: "succeeded", UserID: userID})
}

func (s *Service) Engine(userID string) (*ProtocolEngine, bool) {
	s.engineGate.RLock()
	defer s.engineGate.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	engine, ok := s.engines[userID]
	return engine, ok
}
func (s *Service) host(ctx context.Context, f func(context.Context) error) error {
	_, err := awaitHost(ctx, s, false, func(ctx context.Context) (struct{}, error) { return struct{}{}, f(ctx) })
	return err
}
func (s *Service) cleanup(f func(context.Context) error) error {
	_, err := awaitHost(context.Background(), s, true, func(ctx context.Context) (struct{}, error) { return struct{}{}, f(ctx) })
	return err
}
func (s *Service) audit(ctx context.Context, r AuditRecord) error {
	if err := s.host(ctx, func(ctx context.Context) error { return s.runtime.Auditor.Audit(ctx, r) }); err != nil {
		return ErrDenied
	}
	return nil
}

func (s *Service) Admit(ctx context.Context, r AdmissionRequest) (Flow, error) {
	return s.admit(ctx, r, true)
}

// OpenTCP authenticates a complete first client request frame against the
// generation-owned user keys before admission. A successful AEAD tag is the
// protocol credential; plaintext passwords are never supplied by a listener.
func (s *Service) OpenTCP(ctx context.Context, wire []byte) (Flow, ProxyRequest, error) {
	flow, session, request, err := s.AcceptTCP(ctx, wire)
	if session != nil {
		session.Close()
	}
	return flow, request, err
}

// AcceptTCP returns the generation-owned stream state used for all subsequent
// request chunks and server response chunks on the same listener connection.
func (s *Service) AcceptTCP(ctx context.Context, wire []byte) (Flow, *TCPServerSession, ProxyRequest, error) {
	if len(wire) == 0 {
		return Flow{}, nil, ProxyRequest{}, ErrProtocol
	}
	now, err := awaitHost(ctx, s, false, s.runtime.Clock.Now)
	if err != nil {
		return Flow{}, nil, ProxyRequest{}, ErrDenied
	}
	s.engineGate.RLock()
	defer s.engineGate.RUnlock()
	s.mu.Lock()
	type candidate struct {
		userID string
		engine *ProtocolEngine
	}
	candidates := make([]candidate, 0)
	for _, listener := range s.configuration.Listeners {
		for _, user := range listener.Users {
			if engine := s.engines[user.ID]; user.Enabled && engine != nil {
				candidates = append(candidates, candidate{userID: user.ID, engine: engine})
			}
		}
	}
	s.mu.Unlock()
	instant := time.Unix(int64(now), 0)
	for _, candidate := range candidates {
		request, session, openErr := candidate.engine.OpenTCPServerSession(wire, instant)
		if openErr != nil {
			if errors.Is(openErr, ErrReplay) {
				return Flow{}, nil, ProxyRequest{}, openErr
			}
			continue
		}
		request.UserID = candidate.userID
		flow, admissionErr := s.admit(ctx, AdmissionRequest{Protocol: TCP, UserID: candidate.userID, ReplayToken: request.ReplayToken}, false)
		if admissionErr != nil {
			session.Close()
			return Flow{}, nil, ProxyRequest{}, admissionErr
		}
		if admissionErr = flow.Consume(ctx, uint64(len(request.Payload))); admissionErr != nil {
			session.Close()
			return Flow{}, nil, ProxyRequest{}, admissionErr
		}
		return flow, session, request, nil
	}
	return Flow{}, nil, ProxyRequest{}, ErrAuthentication
}

// OpenUDP authenticates one independent legacy UDP packet or one SS2022 UDP
// session packet, then applies the same replay, expiry and quota admission.
func (s *Service) OpenUDP(ctx context.Context, wire []byte) (Flow, ProxyRequest, error) {
	return s.openWire(ctx, UDP, wire)
}

func (s *Service) openWire(ctx context.Context, protocol Protocol, wire []byte) (Flow, ProxyRequest, error) {
	if len(wire) == 0 {
		return Flow{}, ProxyRequest{}, ErrProtocol
	}
	now, err := awaitHost(ctx, s, false, s.runtime.Clock.Now)
	if err != nil {
		return Flow{}, ProxyRequest{}, ErrDenied
	}
	s.engineGate.RLock()
	defer s.engineGate.RUnlock()
	s.mu.Lock()
	type candidate struct {
		userID string
		engine *ProtocolEngine
	}
	candidates := make([]candidate, 0)
	for _, listener := range s.configuration.Listeners {
		for _, user := range listener.Users {
			if engine := s.engines[user.ID]; user.Enabled && engine != nil {
				candidates = append(candidates, candidate{userID: user.ID, engine: engine})
			}
		}
	}
	s.mu.Unlock()
	instant := time.Unix(int64(now), 0)
	for _, candidate := range candidates {
		var request ProxyRequest
		if protocol == TCP {
			request, err = candidate.engine.OpenTCPRequest(wire, instant)
		} else {
			request, err = candidate.engine.OpenUDPPacket(wire, instant)
		}
		if err != nil {
			if errors.Is(err, ErrReplay) {
				return Flow{}, ProxyRequest{}, err
			}
			continue
		}
		request.UserID = candidate.userID
		flow, admissionErr := s.admit(ctx, AdmissionRequest{Protocol: protocol, UserID: candidate.userID, ReplayToken: request.ReplayToken}, false)
		if admissionErr != nil {
			return Flow{}, ProxyRequest{}, admissionErr
		}
		if admissionErr = flow.Consume(ctx, uint64(len(request.Payload))); admissionErr != nil {
			return Flow{}, ProxyRequest{}, admissionErr
		}
		return flow, request, nil
	}
	return Flow{}, ProxyRequest{}, ErrAuthentication
}

func (s *Service) admit(ctx context.Context, r AdmissionRequest, verifyCredential bool) (Flow, error) {
	if err := ctx.Err(); err != nil {
		return Flow{}, err
	}
	if r.Protocol != TCP && r.Protocol != UDP || len(r.ReplayToken) == 0 || verifyCredential && len(r.Credential) == 0 {
		return Flow{}, ErrInvalid
	}
	s.mu.Lock()
	if !s.live.Load() {
		s.mu.Unlock()
		return Flow{}, ErrRevoked
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return Flow{}, ErrDenied
	}
	s.sessions.Add(1)
	listener, user, found := s.configuration.userListener(r.UserID)
	generation, method := s.configuration.Generation, listener.Method
	s.mu.Unlock()
	releaseSlot := func() { <-s.slots; s.sessions.Done() }
	var reservation TrafficReservation
	fail := func(cause error) (Flow, error) {
		if reservation != nil {
			_ = s.cleanup(reservation.Abort)
		}
		releaseSlot()
		if err := s.audit(ctx, AuditRecord{Action: "admit", Outcome: "failed", UserID: r.UserID}); err != nil {
			return Flow{}, err
		}
		return Flow{}, cause
	}
	if !found || !user.Enabled {
		return fail(ErrDenied)
	}
	if _, clockErr := awaitHost(ctx, s, false, s.runtime.Clock.Now); clockErr != nil {
		return fail(ErrDenied)
	}
	credential, replay := append([]byte(nil), r.Credential...), append([]byte(nil), r.ReplayToken...)
	defer clear(credential)
	defer clear(replay)
	op := sha256.Sum256([]byte(generation + "\x00" + user.ID + "\x00" + string(replay)))
	opKey := hex.EncodeToString(op[:])
	var err error
	reservation, err = awaitHost(ctx, s, false, func(ctx context.Context) (TrafficReservation, error) {
		return s.runtime.Traffic.Reserve(ctx, user.ID, UnlimitedQuotaBytes, opKey)
	})
	if err != nil {
		return fail(ErrQuota)
	}
	if verifyCredential {
		credentialForHost := append([]byte(nil), credential...)
		if SS2022Method(method) {
			if _, userPSK, ok := splitSS2022ClientPassword(credentialForHost); ok {
				// Copy before clearing: split aliases into credentialForHost.
				extracted := append([]byte(nil), userPSK...)
				clear(credentialForHost)
				credentialForHost = extracted
			}
		}
		if err = s.host(ctx, func(ctx context.Context) error {
			defer clear(credentialForHost)
			return s.runtime.Secrets.Verify(ctx, user.SecretRef, user.SecretVersion, credentialForHost)
		}); err != nil {
			return fail(ErrDenied)
		}
	}
	replayForHost := append([]byte(nil), replay...)
	if err = s.host(ctx, func(ctx context.Context) error {
		defer clear(replayForHost)
		return s.runtime.Replay.Admit(ctx, user.ID, replayForHost)
	}); err != nil {
		return fail(ErrReplay)
	}
	if !s.live.Load() || s.root.Err() != nil {
		return fail(ErrRevoked)
	}
	if err = s.audit(ctx, AuditRecord{Action: "admit", Outcome: "succeeded", UserID: user.ID, OperationKey: opKey}); err != nil {
		return fail(err)
	}
	return Flow{token: &flowToken{service: s, reservation: reservation}}, nil
}
func (s *Service) Rotate(ctx context.Context, userID, expectedVersion string) (*SecretOnce, error) {
	s.mu.Lock()
	listener, current, ok := s.configuration.userListener(userID)
	generation := s.configuration.Generation
	method := listener.Method
	serverRef, serverVersion := listener.ServerSecretRef, listener.ServerSecretVersion
	s.mu.Unlock()
	if !ok || expectedVersion == "" || current.SecretVersion != expectedVersion {
		return nil, ErrDenied
	}
	secret, err := s.rotateVault(ctx, userID, current.SecretRef, current.SecretVersion, generation, "user")
	if err != nil {
		return nil, err
	}
	material, resolveErr := s.resolveSecret(ctx, secret.SecretRef, secret.SecretVersion)
	disableStale := func() {
		s.engineGate.Lock()
		defer s.engineGate.Unlock()
		s.mu.Lock()
		if listenerIdx, userIdx, user, found := s.configuration.lookupUser(userID); found && user.SecretRef == current.SecretRef && user.SecretVersion == current.SecretVersion {
			s.configuration.Listeners[listenerIdx].Users[userIdx].Enabled = false
			if engine := s.engines[userID]; engine != nil {
				engine.Destroy()
				delete(s.engines, userID)
			}
		}
		s.mu.Unlock()
		secret.discard()
	}
	if resolveErr != nil {
		clear(material)
		disableStale()
		return nil, ErrDenied
	}
	serverPSK := ""
	if SS2022Method(method) && serverRef != "" && serverVersion != "" {
		serverMaterial, serverErr := s.resolveSecret(ctx, serverRef, serverVersion)
		if serverErr != nil {
			clear(material)
			disableStale()
			return nil, ErrDenied
		}
		serverPSK = string(serverMaterial)
		clear(serverMaterial)
	}
	s.engineGate.Lock()
	defer s.engineGate.Unlock()
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		clear(material)
		secret.discard()
		return nil, ErrRevoked
	}
	if _, _, user, found := s.configuration.lookupUser(userID); !found || user.SecretRef != current.SecretRef || user.SecretVersion != current.SecretVersion {
		s.mu.Unlock()
		clear(material)
		secret.discard()
		return nil, ErrRevoked
	}
	if latest, latestUser, found := s.configuration.userListener(userID); found {
		method = latest.Method
		_ = latestUser
	}
	replacement, resolveErr := engineFromMaterial(method, material, serverPSK)
	clear(material)
	if resolveErr != nil {
		if listenerIdx, userIdx, user, found := s.configuration.lookupUser(userID); found && user.SecretRef == current.SecretRef && user.SecretVersion == current.SecretVersion {
			s.configuration.Listeners[listenerIdx].Users[userIdx].Enabled = false
			if engine := s.engines[userID]; engine != nil {
				engine.Destroy()
				delete(s.engines, userID)
			}
		}
		s.mu.Unlock()
		secret.discard()
		return nil, ErrDenied
	}
	next, replaceErr := s.configuration.ReplaceUserSecret(userID, current.SecretVersion, secret.SecretRef, secret.SecretVersion)
	if replaceErr != nil {
		s.mu.Unlock()
		replacement.Destroy()
		secret.discard()
		return nil, replaceErr
	}
	previous := s.engines[userID]
	s.configuration = next
	s.engines[userID] = replacement
	if SS2022Method(method) && replacement.HasIdentity() {
		if client, clientErr := ss2022ClientPasswordFromEngine(replacement); clientErr == nil {
			rotated := NewSecretOnce(secret.SecretRef, secret.SecretVersion, []byte(client))
			secret.discard()
			secret = rotated
		}
	}
	secret.owner, secret.generation = s, generation
	s.secrets[secret] = struct{}{}
	s.mu.Unlock()
	if previous != nil {
		previous.Destroy()
	}
	return secret, nil
}

// RotateServerPSK replaces one SS2022 listener server PSK. User identity PSKs
// stay; only that listener's client passwords serverPSK:userPSK become invalid.
func (s *Service) RotateServerPSK(ctx context.Context, expectedVersion string) (*SecretOnce, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		return nil, ErrRevoked
	}
	generation := s.configuration.Generation
	listener, ok := s.configuration.ss2022ListenerByServerVersion(expectedVersion)
	s.mu.Unlock()
	if !ok {
		return nil, ErrDenied
	}
	secret, err := s.rotateVault(ctx, ServerPSKID, listener.ServerSecretRef, listener.ServerSecretVersion, generation, "server-psk")
	if err != nil {
		return nil, err
	}
	material, err := s.resolveSecret(ctx, secret.SecretRef, secret.SecretVersion)
	if err != nil {
		secret.discard()
		return nil, err
	}
	serverPSK := string(material)
	clear(material)
	mapped, err := MapSS2022PSK(listener.Method, serverPSK)
	if err != nil {
		secret.discard()
		return nil, err
	}
	secret.mu.Lock()
	clear(secret.material)
	secret.material = append([]byte(nil), mapped...)
	secret.mu.Unlock()
	s.engineGate.Lock()
	installed, err := s.installRotatedServerPSK(listener.ID, expectedVersion, secret, mapped)
	s.engineGate.Unlock()
	if err != nil {
		return nil, err
	}
	if auditErr := s.audit(ctx, AuditRecord{Action: "rotate-server-psk", Outcome: "succeeded"}); auditErr != nil {
		return installed, auditErr
	}
	return installed, nil
}

func (s *Service) installRotatedServerPSK(listenerID, expectedVersion string, secret *SecretOnce, serverPSK string) (*SecretOnce, error) {
	type ss2022Account struct {
		id, method, userPSK string
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		secret.discard()
		return nil, ErrRevoked
	}
	listener, ok := s.configuration.ss2022ListenerByServerVersion(expectedVersion)
	if !ok || listener.ID != listenerID {
		s.mu.Unlock()
		secret.discard()
		return nil, ErrDenied
	}
	mapped, err := MapSS2022PSK(listener.Method, serverPSK)
	if err != nil {
		s.mu.Unlock()
		secret.discard()
		return nil, err
	}
	accounts := make([]ss2022Account, 0, len(listener.Users))
	for _, user := range listener.Users {
		engine := s.engines[user.ID]
		if engine == nil || !SS2022Method(engine.Name()) {
			continue
		}
		key, _, snapErr := engine.keysSnapshot()
		if snapErr != nil {
			s.mu.Unlock()
			secret.discard()
			return nil, ErrDenied
		}
		accounts = append(accounts, ss2022Account{id: user.ID, method: engine.Name(), userPSK: encodedPSK(key)})
		clear(key)
	}
	generation := s.configuration.Generation
	s.mu.Unlock()
	replacements := make(map[string]*ProtocolEngine, len(accounts))
	rollback := func() {
		for _, engine := range replacements {
			engine.Destroy()
		}
	}
	for _, account := range accounts {
		engine, buildErr := NewSS2022IdentityEngine(account.method, []byte(mapped), []byte(account.userPSK))
		if buildErr != nil {
			rollback()
			secret.discard()
			return nil, buildErr
		}
		replacements[account.id] = engine
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		rollback()
		secret.discard()
		return nil, ErrRevoked
	}
	next, err := s.configuration.ReplaceServerPSK(listenerID, expectedVersion, secret.SecretRef, secret.SecretVersion)
	if err != nil {
		s.mu.Unlock()
		rollback()
		secret.discard()
		return nil, err
	}
	previous := make([]*ProtocolEngine, 0, len(replacements))
	for id, engine := range replacements {
		if old := s.engines[id]; old != nil {
			previous = append(previous, old)
		}
		s.engines[id] = engine
	}
	s.configuration = next
	secret.owner, secret.generation = s, generation
	s.secrets[secret] = struct{}{}
	s.mu.Unlock()
	for _, old := range previous {
		old.Destroy()
	}
	return secret, nil
}
func (s *Service) claimSecret(secret *SecretOnce) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live.Load() || s.configuration.Generation != secret.generation {
		return false
	}
	if _, ok := s.secrets[secret]; !ok {
		return false
	}
	delete(s.secrets, secret)
	return true
}
func (s *Service) Snapshot() Configuration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.configuration)
}

func listenShareOf(s *Service) listenShareAttachment {
	listenShareMu.Lock()
	defer listenShareMu.Unlock()
	if current := listenShares[s]; current != nil {
		return *current
	}
	return listenShareAttachment{}
}

func updateListenShare(s *Service, update func(*listenShareAttachment)) {
	listenShareMu.Lock()
	defer listenShareMu.Unlock()
	current := listenShares[s]
	if current == nil {
		current = &listenShareAttachment{}
		listenShares[s] = current
	}
	update(current)
}

func forgetListenShare(s *Service) {
	listenShareMu.Lock()
	delete(listenShares, s)
	listenShareMu.Unlock()
}

func (s *Service) ListenBinding() ListenBinding {
	return listenShareOf(s).binding
}

func (s *Service) NodeAddresses() NodeAddresses {
	return listenShareOf(s).node
}

func (s *Service) ShareEndpoint() ShareEndpoint {
	state := listenShareOf(s)
	return ProjectShareEndpoint(state.binding, state.node)
}

// RefreshListenShare pulls the optional Host binding and node address views
// after Listener.Register. Missing projectors leave share unavailable.
func (s *Service) RefreshListenShare(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		return ErrRevoked
	}
	runtime := s.runtime
	ref := s.configuration.firstListenerID()
	s.mu.Unlock()
	if err := refreshListenBinding(ctx, s, runtime.Listener, ref); err != nil {
		return err
	}
	return refreshNodeAddresses(ctx, s, runtime.Listener)
}

func refreshListenBinding(ctx context.Context, s *Service, listener Listener, ref string) error {
	if src, ok := listener.(pluginsdk.DualStackListener); ok {
		binding, err := awaitHost(ctx, s, false, func(ctx context.Context) (pluginsdk.DualStackListenBinding, error) {
			return src.Binding(ctx, ref)
		})
		if err != nil {
			return err
		}
		mapped := ListenBinding{Port: binding.Port, BindHost: binding.BindHost, TCP: binding.TCP, UDP: binding.UDP}
		if err = mapped.Validate(); err != nil {
			return err
		}
		updateListenShare(s, func(current *listenShareAttachment) {
			current.binding = mapped
		})
		return nil
	}
	src, ok := listener.(ListenBindingSource)
	if !ok {
		return nil
	}
	binding, err := awaitHost(ctx, s, false, func(ctx context.Context) (ListenBinding, error) {
		return src.ListenBinding(ctx, ref)
	})
	if err != nil {
		return err
	}
	if err = binding.Validate(); err != nil {
		return err
	}
	updateListenShare(s, func(current *listenShareAttachment) {
		current.binding = binding
	})
	return nil
}

func refreshNodeAddresses(ctx context.Context, s *Service, listener Listener) error {
	if src, ok := listener.(pluginsdk.NodeAddressSource); ok {
		node, err := awaitHost(ctx, s, false, func(ctx context.Context) (pluginsdk.NodeAddresses, error) {
			return src.NodeAddresses(ctx)
		})
		if err != nil {
			return err
		}
		updateListenShare(s, func(current *listenShareAttachment) {
			current.node = NodeAddresses{DDNS: node.DDNS, IPv4: node.IPv4, IPv6: node.IPv6}
		})
		return nil
	}
	src, ok := listener.(NodeAddressSource)
	if !ok {
		return nil
	}
	node, err := awaitHost(ctx, s, false, func(ctx context.Context) (NodeAddresses, error) {
		return src.NodeAddresses(ctx)
	})
	if err != nil {
		return err
	}
	updateListenShare(s, func(current *listenShareAttachment) {
		current.node = node
	})
	return nil
}

func shareEndpointForListener(listener ListenRule, state listenShareAttachment) ShareEndpoint {
	return ProjectShareEndpoint(ListenBinding{
		Port:     listener.Port,
		BindHost: state.binding.BindHost,
		TCP:      true,
		UDP:      true,
	}, state.node)
}

func (s *Service) ShareAccount(ctx context.Context, userID string) (AccountShare, error) {
	if err := ctx.Err(); err != nil {
		return AccountShare{}, err
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		return AccountShare{}, ErrRevoked
	}
	snapshot := clone(s.configuration)
	s.mu.Unlock()
	listener, user, ok := snapshot.userListener(userID)
	if !ok {
		return AccountShare{}, ErrDenied
	}
	endpoint := shareEndpointForListener(listener, listenShareOf(s))
	out := AccountShare{Account: snapshot.AccountRecord(user), Endpoint: endpoint}
	if !endpoint.Available {
		out.Reason = endpoint.Reason
		if out.Reason == "" {
			out.Reason = MissingShareHost
		}
		return out, nil
	}
	password, method, err := s.shareClientPassword(ctx, user)
	if err != nil {
		out.Reason = "share unavailable"
		return out, nil
	}
	account := SIP002Account{Method: method, Host: endpoint.Host, Port: listener.Port, Name: user.Name}
	if SS2022Method(method) {
		server, identity, ok := splitSS2022ClientPassword([]byte(password))
		if !ok {
			out.Reason = "share unavailable"
			return out, nil
		}
		account.ServerPSK, account.IdentityPSK = string(server), string(identity)
	} else {
		account.Password = password
	}
	sip, err := BuildSIP002(account)
	if err != nil {
		out.Reason = "share unavailable"
		return out, nil
	}
	out.Share = sip
	out.Available = true
	return out, nil
}

func (s *Service) ListShares(ctx context.Context) ([]AccountShare, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	accounts := s.ListAccounts()
	shares := make([]AccountShare, 0, len(accounts))
	for _, account := range accounts {
		share, err := s.ShareAccount(ctx, account.ID)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func (s *Service) shareClientPassword(ctx context.Context, user User) (string, string, error) {
	s.engineGate.RLock()
	s.mu.Lock()
	engine := s.engines[user.ID]
	listener, _, ok := s.configuration.userListener(user.ID)
	method := listener.Method
	serverRef, serverVersion := listener.ServerSecretRef, listener.ServerSecretVersion
	_ = ok
	s.mu.Unlock()
	if SS2022Method(method) && engine != nil && engine.HasIdentity() {
		password, err := ss2022ClientPasswordFromEngine(engine)
		s.engineGate.RUnlock()
		return password, method, err
	}
	s.engineGate.RUnlock()
	material, err := s.resolveSecret(ctx, user.SecretRef, user.SecretVersion)
	if err != nil {
		return "", method, err
	}
	if !SS2022Method(method) {
		password := string(append([]byte(nil), material...))
		clear(material)
		return password, method, nil
	}
	if _, _, ok := splitSS2022ClientPassword(material); ok {
		password := string(append([]byte(nil), material...))
		clear(material)
		return password, method, nil
	}
	if serverRef == "" || serverVersion == "" {
		clear(material)
		return "", method, ErrInvalid
	}
	server, err := s.resolveSecret(ctx, serverRef, serverVersion)
	if err != nil {
		clear(material)
		return "", method, err
	}
	password, err := SS2022ClientPassword(method, server, material)
	clear(material)
	clear(server)
	return password, method, err
}

func (s *Service) Disable() {
	s.hostMu.Lock()
	s.hostOpen = false
	s.hostMu.Unlock()
	s.engineGate.Lock()
	defer s.engineGate.Unlock()
	s.mu.Lock()
	s.live.Store(false)
	s.cancel()
	for secret := range s.secrets {
		secret.discard()
		delete(s.secrets, secret)
	}
	for _, engine := range s.engines {
		engine.Destroy()
	}
	s.engines = map[string]*ProtocolEngine{}
	s.mu.Unlock()
	forgetListenShare(s)
}
func (s *Service) Drain(ctx context.Context) error {
	s.Disable()
	done := make(chan struct{})
	go func() {
		s.sessions.Wait()
		s.hostCalls.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) EgressProviders() []string { return nil }
