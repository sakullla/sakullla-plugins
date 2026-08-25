package dockerapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var secretAssignmentPattern = regexp.MustCompile(`(?i)((?:password|secret|token|key|credential|authorization)[=:\s]+)[^\s,;]+`)

func sanitizePublicText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if containsLocalDockerMarker(strings.ToLower(text)) {
		return ""
	}
	text = secretAssignmentPattern.ReplaceAllString(text, "${1}***")
	if strings.Contains(text, "\n") {
		text = strings.SplitN(text, "\n", 2)[0]
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 240 {
		text = strings.TrimSpace(text[:240])
	}
	return text
}

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
	message := class.Error()
	if cause := publicCause(err); cause != "" && cause != class.Error() && cause != ErrOperationFailed.Error() && cause != ErrTypedHandlesUnavailable.Error() {
		message = class.Error() + ": " + cause
	}
	return &SafeError{Class: class, Message: message}
}

func publicCause(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if safe, ok := err.(*SafeError); ok {
		text = strings.TrimSpace(strings.TrimPrefix(safe.Message, safe.Class.Error()+": "))
		if text == "" || text == safe.Class.Error() {
			return ""
		}
	}
	text = sanitizePublicText(text)
	if !strings.HasPrefix(text, "compose ") && !strings.HasPrefix(text, "files ") {
		return ""
	}
	return text
}

// TransientCredential is a parsed secret from compose or docker run.
// BindSecretRefs keeps Name as an opaque secret_ref and wipes Material.
type TransientCredential struct {
	Name     string
	Material []byte
}

// sensitiveEnvironmentName identifies environment keys whose values should be
// represented by opaque secret_refs. Ordinary runtime settings remain bounded
// configuration, but do not consume the secret reference budget.
func sensitiveEnvironmentName(name string) bool {
	parts := strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(name)), func(value rune) bool {
		letter := value >= 'A' && value <= 'Z'
		digit := value >= '0' && value <= '9'
		return !letter && !digit
	})
	for index, part := range parts {
		switch part {
		case "PASSWORD", "PASSWD", "SECRET", "CREDENTIAL", "CREDENTIALS", "AUTHORIZATION":
			return true
		case "TOKEN":
			if index == len(parts)-1 || index+1 < len(parts) && (parts[index+1] == "VALUE" || parts[index+1] == "SECRET") {
				return true
			}
		case "KEY":
			if index == len(parts)-1 && (index == 0 || parts[index-1] != "PUBLIC") {
				return true
			}
		}
	}
	return false
}

func sensitiveEnvironmentNames(names []string) []string {
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		if sensitiveEnvironmentName(name) {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

// BindSecretRefs converts transient credentials into opaque secret_refs.
// Material is wiped before return and is never copied into refs or errors.
func BindSecretRefs(credentials []TransientCredential) ([]string, error) {
	defer wipeCredentials(credentials)
	if len(credentials) > MaxSecretRefs {
		return nil, fmt.Errorf("%w: secret refs", ErrBoundExceeded)
	}
	refs := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if !boundedText(credential.Name, 128) {
			return nil, errors.New("secret reference is invalid")
		}
		refs = append(refs, credential.Name)
	}
	normalized, err := sortedUnique(refs, MaxSecretRefs)
	if err != nil {
		if errors.Is(err, ErrBoundExceeded) {
			return nil, err
		}
		return nil, errors.New("secret reference is invalid")
	}
	return normalized, nil
}

// AppWithBoundSecrets attaches bound secret_refs to an app and rejects any
// validation failure with a class error that cannot unwrap to material.
func AppWithBoundSecrets(app App, credentials []TransientCredential) (App, error) {
	refs, err := BindSecretRefs(credentials)
	if err != nil {
		return App{}, err
	}
	combined := append(append([]string(nil), app.SecretRefs...), refs...)
	normalized, err := sortedUnique(combined, MaxSecretRefs)
	if err != nil {
		if errors.Is(err, ErrBoundExceeded) {
			return App{}, err
		}
		return App{}, errors.New("secret reference is invalid")
	}
	app.SecretRefs = normalized
	if err := app.Validate(); err != nil {
		return App{}, safeFailure(ErrInvalidPreview, err)
	}
	return app, nil
}

func wipeCredentials(credentials []TransientCredential) {
	for index := range credentials {
		clear(credentials[index].Material)
		credentials[index].Material = nil
	}
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
