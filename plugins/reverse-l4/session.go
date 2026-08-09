package reversel4

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrAdmissionClosed    = errors.New("mapping admission is closed")
	ErrGenerationMismatch = errors.New("mapping generation is stale")
	ErrMTLSRequired       = errors.New("core host did not attest an mTLS Agent session")
	ErrRetryNotReady      = errors.New("bounded reconnect delay has not elapsed")
	ErrInvalidState       = errors.New("mapping state transition is invalid")
)

type SessionState string

const (
	StateDisconnected  SessionState = "disconnected"
	StateConnecting    SessionState = "connecting"
	StateAuthenticated SessionState = "authenticated"
	StateUnavailable   SessionState = "unavailable"
	StateDraining      SessionState = "draining"
	StateDisabled      SessionState = "disabled"
	StateRevoked       SessionState = "revoked"
)

type SessionSnapshot struct {
	MappingID       string
	Protocol        Protocol
	Generation      string
	State           SessionState
	Accepting       bool
	MTLS            bool
	InFlight        uint64
	ReconnectAt     time.Time
	LastFailure     string
	ReleaseRequired bool
	ObservedAt      time.Time
}

// Clock is supplied by the Host adapter and must report a host-attested
// monotonic instant. Session transitions never accept caller-reported time.
type Clock interface {
	Now() time.Time
}

// Session is a pure business state machine. Authentication and resource
// events may only be supplied by a future canonical public typed Host API; the
// plugin does not dial, listen, terminate TLS, or mint Agent identity itself.
type Session struct {
	mu         sync.Mutex
	mapping    Mapping
	generation string
	backoff    Backoff
	clock      Clock

	state           SessionState
	accepting       bool
	mtls            bool
	inflight        uint64
	attempt         uint32
	reconnectAt     time.Time
	lastFailure     string
	drainTarget     SessionState
	releaseRequired bool
	observedAt      time.Time
}

func NewSession(mapping Mapping, generation string, backoff Backoff, clock Clock) (*Session, error) {
	if err := mapping.Validate(); err != nil {
		return nil, err
	}
	if !mapping.Enabled {
		return nil, errors.New("cannot create a session for a disabled mapping")
	}
	if !validOpaqueReference(generation) {
		return nil, errors.New("generation is invalid")
	}
	if err := backoff.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, errors.New("host-attested monotonic clock is required")
	}
	return &Session{
		mapping: mapping, generation: generation, backoff: backoff, clock: clock, state: StateDisconnected,
	}, nil
}

func (session *Session) BeginConnect() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != StateDisconnected {
		return fmt.Errorf("%w: connect from %s", ErrInvalidState, session.state)
	}
	session.accepting = false
	session.mtls = false
	session.state = StateConnecting
	return nil
}

// Authenticate consumes only a host-attested fact. It does not accept
// certificates, keys, or a plugin-owned identity.
func (session *Session) Authenticate(hostVerifiedMTLS bool) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	now := session.clock.Now()
	session.observedAt = now
	if session.state != StateConnecting {
		return fmt.Errorf("%w: authenticate from %s", ErrInvalidState, session.state)
	}
	if !hostVerifiedMTLS {
		session.disconnectLocked(now, ErrMTLSRequired.Error())
		return ErrMTLSRequired
	}
	session.state = StateAuthenticated
	session.accepting = true
	session.mtls = true
	session.attempt = 0
	session.reconnectAt = time.Time{}
	session.lastFailure = ""
	return nil
}

func (session *Session) Disconnect(reason string) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	now := session.clock.Now()
	session.observedAt = now
	if session.state != StateAuthenticated && session.state != StateConnecting {
		return fmt.Errorf("%w: disconnect from %s", ErrInvalidState, session.state)
	}
	if reason == "" {
		reason = "core session unavailable"
	}
	session.disconnectLocked(now, reason)
	return nil
}

func (session *Session) disconnectLocked(now time.Time, reason string) {
	delay := session.backoff.Delay(session.attempt)
	if session.attempt < ^uint32(0) {
		session.attempt++
	}
	session.state = StateUnavailable
	session.accepting = false
	session.mtls = false
	session.reconnectAt = session.clock.Now().Add(delay)
	session.lastFailure = reason
}

func (session *Session) Retry() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	now := session.clock.Now()
	session.observedAt = now
	if session.state != StateUnavailable {
		return fmt.Errorf("%w: retry from %s", ErrInvalidState, session.state)
	}
	if now.Before(session.reconnectAt) {
		return ErrRetryNotReady
	}
	session.state = StateConnecting
	session.lastFailure = ""
	return nil
}

func (session *Session) Admit(generation string) (*Flow, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if generation != session.generation {
		return nil, ErrGenerationMismatch
	}
	if session.state != StateAuthenticated || !session.accepting || !session.mtls {
		return nil, ErrAdmissionClosed
	}
	session.inflight++
	return &Flow{release: &flowRelease{session: session}}, nil
}

func (session *Session) BeginDisable() {
	session.beginDrain(StateDisabled)
}

func (session *Session) Revoke() {
	session.beginDrain(StateRevoked)
}

func (session *Session) beginDrain(target SessionState) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state == StateRevoked {
		return
	}
	if session.state == StateDisabled {
		if target == StateRevoked {
			session.state = StateRevoked
		}
		return
	}
	session.accepting = false
	session.mtls = false
	if target == StateRevoked || session.drainTarget != StateRevoked {
		session.drainTarget = target
	}
	session.state = StateDraining
	session.finishDrainLocked()
}

func (session *Session) finishDrainLocked() {
	if session.state == StateDraining && session.inflight == 0 {
		session.state = session.drainTarget
		session.releaseRequired = true
	}
}

// AcknowledgeRelease records completion from a future typed Host handle. It
// performs no Host call and cannot release or forge a resource itself.
func (session *Session) AcknowledgeRelease() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if (session.state != StateDisabled && session.state != StateRevoked) || !session.releaseRequired {
		return fmt.Errorf("%w: resource release is not pending", ErrInvalidState)
	}
	session.releaseRequired = false
	return nil
}

func (session *Session) Snapshot() SessionSnapshot {
	session.mu.Lock()
	defer session.mu.Unlock()
	return SessionSnapshot{
		MappingID: session.mapping.ID, Protocol: session.mapping.Protocol, Generation: session.generation,
		State: session.state, Accepting: session.accepting, MTLS: session.mtls, InFlight: session.inflight,
		ReconnectAt: session.reconnectAt, LastFailure: session.lastFailure, ReleaseRequired: session.releaseRequired,
		ObservedAt: session.observedAt,
	}
}

type Flow struct {
	release *flowRelease
}

type flowRelease struct {
	once    sync.Once
	session *Session
}

func (flow *Flow) Close() {
	if flow == nil || flow.release == nil || flow.release.session == nil {
		return
	}
	flow.release.once.Do(func() {
		flow.release.session.mu.Lock()
		if flow.release.session.inflight > 0 {
			flow.release.session.inflight--
		}
		flow.release.session.finishDrainLocked()
		flow.release.session.mu.Unlock()
	})
}
