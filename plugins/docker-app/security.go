package dockerapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

var (
	ErrAuditRequired    = errors.New("trusted auditor is required")
	ErrInvalidPreview   = errors.New("preview does not match trusted inventory")
	ErrOperationFailed  = errors.New("broker operation failed")
	ErrReconcilePending = errors.New("reconciliation is pending")
	ErrStateConflict    = errors.New("deployment state version conflict")
)

// SafeError retains only a non-sensitive class and redacted message. It never
// stores or unwraps to the original error, so errors.As/Unwrap cannot recover
// secret-bearing broker or validation causes.
type SafeError struct {
	Class   error
	Message string
}

func (failure *SafeError) Error() string { return failure.Message }
func (failure *SafeError) Unwrap() error { return failure.Class }

func safeFailure(class error, err error) error {
	if err == nil {
		return nil
	}
	return &SafeError{Class: class, Message: class.Error()}
}

func canonicalDigest(value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

type Authorization struct {
	Token, AppID, Generation, PreviewDigest string
}

type AuthorizationVerifier interface {
	Verify(context.Context, Authorization, string, string, string) error
}
type AuthorizationVerifierFunc func(context.Context, Authorization, string, string, string) error

func (function AuthorizationVerifierFunc) Verify(ctx context.Context, authorization Authorization, appID, generation, digest string) error {
	return function(ctx, authorization, appID, generation, digest)
}

// ProgressJournal is the durable progress boundary used by broker operations.
// A production implementation must survive process restart. OperationJournal
// is the deterministic in-memory implementation used by the repository model.
type ProgressJournal interface {
	Completed(context.Context, string, string) (bool, error)
	MarkCompleted(context.Context, string, string) error
}

type OperationJournal struct {
	mu        sync.Mutex
	completed map[string]map[string]struct{}
}

func NewOperationJournal() *OperationJournal {
	return &OperationJournal{completed: make(map[string]map[string]struct{})}
}
func (journal *OperationJournal) Completed(_ context.Context, operation, effect string) (bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	_, exists := journal.completed[operation][effect]
	return exists, nil
}
func (journal *OperationJournal) MarkCompleted(_ context.Context, operation, effect string) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	effects := journal.completed[operation]
	if effects == nil {
		effects = make(map[string]struct{})
		journal.completed[operation] = effects
	}
	effects[effect] = struct{}{}
	return nil
}
