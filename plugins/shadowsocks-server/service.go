package shadowsocksserver

import (
	"context"
	"crypto/sha256"
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
	for _, user := range s.configuration.Users {
		if !user.Enabled {
			continue
		}
		material, err := awaitHost(ctx, s, false, func(ctx context.Context) ([]byte, error) {
			return s.runtime.Secrets.Resolve(ctx, user.SecretRef, user.SecretVersion)
		})
		if err != nil {
			return ErrTypedHandlesUnavailable
		}
		engine, err := NewProtocolEngine(s.configuration.Cipher, material)
		clear(material)
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
	generation := s.configuration.Generation
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
	if user.ExpiresAt > 0 && now >= user.ExpiresAt {
		return fail(ErrExpired)
	}
	credential, replay := append([]byte(nil), r.Credential...), append([]byte(nil), r.ReplayToken...)
	defer clear(credential)
	defer clear(replay)
	op := sha256.Sum256([]byte(generation + "\x00" + user.ID + "\x00" + string(replay)))
	opKey := hex.EncodeToString(op[:])
	reservation, err = awaitHost(ctx, s, false, func(ctx context.Context) (TrafficReservation, error) {
		return s.runtime.Traffic.Reserve(ctx, user.ID, user.QuotaBytes, opKey)
	})
	if err != nil {
		return fail(ErrQuota)
	}
	if verifyCredential {
		credentialForHost := append([]byte(nil), credential...)
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
	index := -1
	var current User
	for i := range s.configuration.Users {
		if s.configuration.Users[i].ID == userID {
			index, current = i, s.configuration.Users[i]
			break
		}
	}
	generation, cipherName := s.configuration.Generation, s.configuration.Cipher
	s.mu.Unlock()
	if index < 0 || expectedVersion == "" || current.SecretVersion != expectedVersion {
		return nil, ErrDenied
	}
	op := sha256.Sum256([]byte(generation + "\x00" + userID + "\x00" + current.SecretRef + "\x00" + current.SecretVersion))
	secret, err := awaitHost(ctx, s, false, func(ctx context.Context) (*SecretOnce, error) {
		return s.runtime.Vault.Rotate(ctx, userID, current.SecretRef, current.SecretVersion, hex.EncodeToString(op[:]))
	})
	if err != nil {
		return nil, ErrDenied
	}
	if secret == nil || !refPattern.MatchString(secret.SecretRef) || !refPattern.MatchString(secret.SecretVersion) {
		secret.discard()
		return nil, ErrInvalid
	}
	material, resolveErr := awaitHost(ctx, s, false, func(ctx context.Context) ([]byte, error) {
		return s.runtime.Secrets.Resolve(ctx, secret.SecretRef, secret.SecretVersion)
	})
	var replacement *ProtocolEngine
	if resolveErr == nil {
		replacement, resolveErr = NewProtocolEngine(cipherName, material)
	}
	clear(material)
	if resolveErr != nil {
		s.engineGate.Lock()
		defer s.engineGate.Unlock()
		s.mu.Lock()
		if s.configuration.Users[index].SecretRef == current.SecretRef && s.configuration.Users[index].SecretVersion == current.SecretVersion {
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
	s.engineGate.Lock()
	defer s.engineGate.Unlock()
	s.mu.Lock()
	if !s.live.Load() || s.root.Err() != nil || s.configuration.Users[index].SecretRef != current.SecretRef || s.configuration.Users[index].SecretVersion != current.SecretVersion {
		s.mu.Unlock()
		replacement.Destroy()
		secret.discard()
		return nil, ErrRevoked
	}
	previous := s.engines[userID]
	s.configuration.Users[index].SecretRef, s.configuration.Users[index].SecretVersion = secret.SecretRef, secret.SecretVersion
	s.engines[userID] = replacement
	secret.owner, secret.generation = s, generation
	s.secrets[secret] = struct{}{}
	s.mu.Unlock()
	if previous != nil {
		previous.Destroy()
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
