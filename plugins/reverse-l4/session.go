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
}

// Session is a pure business state machine. Authentication and resource
// events may only be supplied by a future canonical public typed Host API; the
// plugin does not dial, listen, terminate TLS, or mint Agent identity itself.
type Session struct {
	mu         sync.Mutex
	mapping    Mapping
	generation string
	backoff    Backoff

	state           SessionState
	accepting       bool
	mtls            bool
	inflight        uint64
	attempt         uint32
	reconnectAt     time.Time
	lastFailure     string
	drainTarget     SessionState
	releaseRequired bool
}

func NewSession(mapping Mapping, generation string, backoff Backoff) (*Session, error) {
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
	return &Session{
		mapping: mapping, generation: generation, backoff: backoff, state: StateDisconnected,
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
func (session *Session) Authenticate(hostVerifiedMTLS bool, now time.Time) error {
	session.mu.Lock()
	defer session.mu.Unlock()
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

func (session *Session) Disconnect(now time.Time, reason string) error {
	session.mu.Lock()
	defer session.mu.Unlock()
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
	session.reconnectAt = now.Add(delay)
	session.lastFailure = reason
}

func (session *Session) Retry(now time.Time) error {
	session.mu.Lock()
	defer session.mu.Unlock()
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
	return &Flow{session: session}, nil
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
	if session.state == StateDisabled || session.state == StateRevoked {
		return
	}
	session.accepting = false
	session.mtls = false
	session.drainTarget = target
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
	}
}

type Flow struct {
	once    sync.Once
	session *Session
}

func (flow *Flow) Close() {
	if flow == nil || flow.session == nil {
		return
	}
	flow.once.Do(func() {
		flow.session.mu.Lock()
		flow.session.inflight--
		flow.session.finishDrainLocked()
		flow.session.mu.Unlock()
	})
}
