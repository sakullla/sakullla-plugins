package shadowsocksserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

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
	if SS2022Method(method) && serverPSK != "" {
		if _, _, ok := splitSS2022ClientPassword(material); ok {
			return NewProtocolEngine(method, material)
		}
		return NewSS2022IdentityEngine(method, []byte(serverPSK), material)
	}
	return NewProtocolEngine(method, material)
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
		slots: make(chan struct{}, c.MaxSessions), hostSlots: make(chan struct{}, c.MaxSessions), cleanupSlots: make(chan struct{}, c.MaxSessions*2),
		hostOpen: true, root: root, cancel: cancel, secrets: map[*SecretOnce]struct{}{}, engines: map[string]*ProtocolEngine{},
	}
	s.live.Store(true)
	return s, nil
}
func (s *Service) Initialize(ctx context.Context) error {
	s.mu.Lock()
	users := append([]User(nil), s.configuration.Users...)
	cipher := s.configuration.Cipher
	serverRef, serverVersion := s.configuration.ServerPSKRef, s.configuration.ServerPSKVersion
	s.mu.Unlock()
	var serverPSK string
	if serverRef != "" && serverVersion != "" {
		material, err := s.resolveSecret(ctx, serverRef, serverVersion)
		if err != nil {
			return err
		}
		serverPSK = string(material)
		clear(material)
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		engine, err := s.resolveUserEngine(ctx, user.ResolvedMethod(cipher), user.SecretRef, user.SecretVersion, serverPSK)
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
	cipher := s.configuration.Cipher
	serverRef, serverVersion := s.configuration.ServerPSKRef, s.configuration.ServerPSKVersion
	s.mu.Unlock()
	method, err := spec.resolveMethod(cipher)
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
	if SS2022Method(method) && serverPSK != "" {
		if _, _, ok := splitSS2022ClientPassword(material); !ok {
			client = []byte(serverPSK + ":" + string(material))
		}
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
	if user.QuotaBytes == 0 {
		user.QuotaBytes = UnlimitedQuotaBytes
		if index, _, ok := next.lookupUser(user.ID); ok {
			next.Users[index].QuotaBytes = UnlimitedQuotaBytes
		}
	}
	if serverRef != "" && next.ServerPSKVersion == "" {
		next.ServerPSKRef, next.ServerPSKVersion = serverRef, serverVersion
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
	_, user, ok := s.configuration.lookupUser(userID)
	if !ok {
		s.mu.Unlock()
		return ErrDenied
	}
	needEngine := enabled && s.engines[userID] == nil
	method := user.ResolvedMethod(s.configuration.Cipher)
	serverRef, serverVersion := s.configuration.ServerPSKRef, s.configuration.ServerPSKVersion
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
	candidates := make([]candidate, 0, len(s.configuration.Users))
	for _, user := range s.configuration.Users {
		if engine := s.engines[user.ID]; user.Enabled && engine != nil {
			candidates = append(candidates, candidate{userID: user.ID, engine: engine})
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
	candidates := make([]candidate, 0, len(s.configuration.Users))
	for _, user := range s.configuration.Users {
		if engine := s.engines[user.ID]; user.Enabled && engine != nil {
			candidates = append(candidates, candidate{userID: user.ID, engine: engine})
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
	var user User
	found := false
	for _, u := range s.configuration.Users {
		if u.ID == r.UserID {
			user, found = u, true
			break
		}
	}
	generation, cipher := s.configuration.Generation, s.configuration.Cipher
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
	now, err := awaitHost(ctx, s, false, s.runtime.Clock.Now)
	if err != nil {
		return fail(ErrDenied)
	}
	if user.Expired(now) {
		return fail(ErrExpired)
	}
	credential, replay := append([]byte(nil), r.Credential...), append([]byte(nil), r.ReplayToken...)
	defer clear(credential)
	defer clear(replay)
	op := sha256.Sum256([]byte(generation + "\x00" + user.ID + "\x00" + string(replay)))
	opKey := hex.EncodeToString(op[:])
	reservation, err = awaitHost(ctx, s, false, func(ctx context.Context) (TrafficReservation, error) {
		return s.runtime.Traffic.Reserve(ctx, user.ID, user.EffectiveQuota(), opKey)
	})
	if err != nil {
		return fail(ErrQuota)
	}
	if verifyCredential {
		credentialForHost := append([]byte(nil), credential...)
		if SS2022Method(user.ResolvedMethod(cipher)) {
			if _, userPSK, ok := splitSS2022ClientPassword(credentialForHost); ok {
				clear(credentialForHost)
				credentialForHost = append([]byte(nil), userPSK...)
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
	_, current, ok := s.configuration.lookupUser(userID)
	generation := s.configuration.Generation
	method := current.ResolvedMethod(s.configuration.Cipher)
	serverRef, serverVersion := s.configuration.ServerPSKRef, s.configuration.ServerPSKVersion
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
		if index, user, found := s.configuration.lookupUser(userID); found && user.SecretRef == current.SecretRef && user.SecretVersion == current.SecretVersion {
			s.configuration.Users[index].Enabled = false
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
	if index, user, found := s.configuration.lookupUser(userID); !found || user.SecretRef != current.SecretRef || user.SecretVersion != current.SecretVersion {
		s.mu.Unlock()
		clear(material)
		secret.discard()
		return nil, ErrRevoked
	} else {
		_ = index
	}
	method = current.ResolvedMethod(s.configuration.Cipher)
	if latest, found := s.configuration.User(userID); found {
		method = latest.ResolvedMethod(s.configuration.Cipher)
	}
	replacement, resolveErr := engineFromMaterial(method, material, serverPSK)
	clear(material)
	if resolveErr != nil {
		if index, user, found := s.configuration.lookupUser(userID); found && user.SecretRef == current.SecretRef && user.SecretVersion == current.SecretVersion {
			s.configuration.Users[index].Enabled = false
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

// RotateServerPSK replaces the instance SS2022 server PSK. User identity PSKs
// stay; every SS2022 client password serverPSK:userPSK becomes invalid.
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
	serverRef, serverVersion := s.configuration.ServerPSKRef, s.configuration.ServerPSKVersion
	s.mu.Unlock()
	if expectedVersion == "" || serverVersion != expectedVersion {
		return nil, ErrDenied
	}
	secret, err := s.rotateVault(ctx, ServerPSKID, serverRef, serverVersion, generation, "server-psk")
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
	s.engineGate.Lock()
	installed, err := s.installRotatedServerPSK(expectedVersion, secret, serverPSK)
	s.engineGate.Unlock()
	if err != nil {
		return nil, err
	}
	if auditErr := s.audit(ctx, AuditRecord{Action: "rotate-server-psk", Outcome: "succeeded"}); auditErr != nil {
		return installed, auditErr
	}
	return installed, nil
}

func (s *Service) installRotatedServerPSK(expectedVersion string, secret *SecretOnce, serverPSK string) (*SecretOnce, error) {
	type ss2022Account struct {
		id, method, userPSK string
	}
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil {
		s.mu.Unlock()
		secret.discard()
		return nil, ErrRevoked
	}
	if s.configuration.ServerPSKVersion != expectedVersion {
		s.mu.Unlock()
		secret.discard()
		return nil, ErrDenied
	}
	accounts := make([]ss2022Account, 0, len(s.engines))
	for id, engine := range s.engines {
		if engine == nil || !SS2022Method(engine.Name()) {
			continue
		}
		key, _, snapErr := engine.keysSnapshot()
		if snapErr != nil {
			s.mu.Unlock()
			secret.discard()
			return nil, ErrDenied
		}
		accounts = append(accounts, ss2022Account{id: id, method: engine.Name(), userPSK: encodedPSK(key)})
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
		engine, buildErr := NewSS2022IdentityEngine(account.method, []byte(serverPSK), []byte(account.userPSK))
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
	next, err := s.configuration.ReplaceServerPSK(expectedVersion, secret.SecretRef, secret.SecretVersion)
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
