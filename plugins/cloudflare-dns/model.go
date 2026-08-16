package cloudflaredns

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID       = "cloudflare-dns"
	PluginVersion  = "0.1.0"
	MaxConfigBytes = 1 << 20
	MaxZones       = 256
	MaxRecords     = 1024
	MaxMappings    = 256
	MaxTokenBytes  = 8192
	MaxActiveCalls = 64
)

const (
	PermissionZoneRead    = "Zone:Read"
	PermissionDNSEdit     = "DNS:Edit"
	PermissionVaultEnroll = "Vault:Enroll"
	PermissionVaultRotate = "Vault:Rotate"
)

var (
	ErrInvalidInput            = errors.New("invalid Cloudflare DNS input")
	ErrBoundExceeded           = errors.New("Cloudflare DNS bound exceeded")
	ErrAuthorizationDenied     = errors.New("Cloudflare DNS authorization denied")
	ErrTokenInvalid            = errors.New("Cloudflare token invalid")
	ErrTokenStale              = errors.New("Cloudflare token handle stale")
	ErrZoneDenied              = errors.New("Cloudflare zone denied")
	ErrPermissionMissing       = errors.New("Cloudflare permission missing")
	ErrDNSOperationFailed      = errors.New("Cloudflare DNS operation failed")
	ErrVaultOperationFailed    = errors.New("Vault operation failed")
	ErrAuditUnavailable        = errors.New("Cloudflare audit unavailable")
	ErrUIUnavailable           = errors.New("Cloudflare dynamic UI unavailable")
	ErrLogUnavailable          = errors.New("Cloudflare event log unavailable")
	ErrReconcilePending        = errors.New("Cloudflare effect committed; reconciliation pending")
	ErrTypedHandlesUnavailable = errors.New("canonical typed Cloudflare handles unavailable")
	ErrRevoked                 = errors.New("Cloudflare generation revoked")
	ErrMappingConflict         = errors.New("Cloudflare mapping suffix already exists")
	ErrMappingNotFound         = errors.New("Cloudflare mapping not found")
	ErrTokenUnavailable        = errors.New("Cloudflare domain has no available token")
	ErrMappedTokenUnavailable  = errors.New("Cloudflare mapped token unavailable")
)

var refPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)

type Configuration struct {
	Generation       string `json:"generation"`
	SecretRef        string `json:"secret_ref"`
	ResourceGroupRef string `json:"resource_group_ref"`
}

func (configuration Configuration) Validate() error {
	if !refPattern.MatchString(configuration.Generation) || !refPattern.MatchString(configuration.SecretRef) || !refPattern.MatchString(configuration.ResourceGroupRef) {
		return ErrInvalidInput
	}
	return nil
}

type TokenAttestation struct {
	SecretRef, Version string
	Permissions        []string
	ZoneIDs            []string
	LastUsed           uint64
}

func (attestation TokenAttestation) hasPermission(permission string) bool {
	for _, current := range attestation.Permissions {
		if current == permission {
			return true
		}
	}
	return false
}
func (attestation TokenAttestation) hasZone(zoneID string) bool {
	for _, current := range attestation.ZoneIDs {
		if current == zoneID {
			return true
		}
	}
	return false
}

type TokenMetadata struct{ SecretRef, Version string }

type TokenMapping struct {
	Suffix     string `json:"suffix"`
	SecretRef  string `json:"secret_ref"`
	Version    string `json:"version"`
	Configured bool   `json:"configured"`
	UpdatedAt  uint64 `json:"updated_at"`
}

type IssuedToken struct {
	Domain    string
	Suffix    string
	SecretRef string
	Version   string
	Fallback  bool
	material  []byte
}

func (token IssuedToken) Token() []byte {
	return append([]byte(nil), token.material...)
}

func (token IssuedToken) MarshalJSON() ([]byte, error) {
	type issuedTokenJSON struct {
		Domain    string `json:"domain"`
		Suffix    string `json:"suffix"`
		SecretRef string `json:"secret_ref"`
		Version   string `json:"version"`
		Fallback  bool   `json:"fallback"`
	}
	return json.Marshal(issuedTokenJSON{Domain: token.Domain, Suffix: token.Suffix, SecretRef: token.SecretRef, Version: token.Version, Fallback: token.Fallback})
}

func (token *IssuedToken) Clear() {
	if token == nil {
		return
	}
	clear(token.material)
	token.material = nil
}

type Vault interface {
	Verify(context.Context, string) (TokenAttestation, error)
	// Enroll and Rotate must be capability-backed and exactly-once for the
	// stable operation key. A retry with the same key returns the same metadata.
	Enroll(context.Context, string, []byte, string) (TokenMetadata, error)
	// Rotate atomically compares expectedVersion with the current Vault
	// version before applying the exactly-once operation.
	Rotate(context.Context, string, string, []byte, string) (TokenMetadata, error)
	// Reveal returns a copy of stored token material for an enrolled secret_ref.
	Reveal(context.Context, string) ([]byte, error)
}

type Zone struct{ ID, Name string }

type DNSRecord struct {
	ID, ZoneID, Type, Name, Content string
	TTL                             uint32
}

func (record DNSRecord) Validate(write bool) error {
	if write && record.ID != "" && !refPattern.MatchString(record.ID) {
		return ErrInvalidInput
	}
	if !refPattern.MatchString(record.ZoneID) || len(record.Name) == 0 || len(record.Name) > 253 || len(record.Content) == 0 || len(record.Content) > 4096 || record.TTL > 86400 {
		return ErrInvalidInput
	}
	switch record.Type {
	case "A", "AAAA", "CNAME", "TXT", "MX":
	default:
		return ErrInvalidInput
	}
	return nil
}

type DNSHandle interface {
	// Inspect and all mutations use one authoritative operation journal.
	// Create, Update, and Delete atomically claim the operation key in that
	// journal and are exactly-once: concurrent calls with the same key either
	// return the same committed outcome or an inspectable pending/failure state.
	OperationInspector
	ListZones(context.Context, TokenAttestation, string) ([]Zone, error)
	ListRecords(context.Context, TokenAttestation, string, int) ([]DNSRecord, error)
	Create(context.Context, TokenAttestation, DNSRecord, string) (DNSRecord, error)
	Update(context.Context, TokenAttestation, DNSRecord, string) (DNSRecord, error)
	Delete(context.Context, TokenAttestation, string, string, string) error
}

type ActionContext struct {
	Phase, Actor, ResourceGroupRef, ZoneID, Permission, SecretRef, SecretVersion, OperationKey string
}

type OperationState string

const (
	OperationAbsent    OperationState = "absent"
	OperationUnknown   OperationState = "unknown"
	OperationCommitted OperationState = "committed"
	OperationFailed    OperationState = "failed"
)

type OperationOutcome struct {
	State  OperationState
	Record DNSRecord
	Token  TokenMetadata
}
type OperationInspector interface {
	Inspect(context.Context, string) (OperationOutcome, error)
}
type GenerationLease interface{ Revoke() }
type GenerationLeaseFunc func()

func (function GenerationLeaseFunc) Revoke() { function() }

type Authorizer interface {
	Authorize(context.Context, ActionContext) error
}
type AuthorizerFunc func(context.Context, ActionContext) error

func (function AuthorizerFunc) Authorize(ctx context.Context, action ActionContext) error {
	return function(ctx, action)
}

type UIProjection struct {
	Kind, Outcome, OperationKey, ZoneID, RecordID, RecordType, RecordName, Suffix, Domain string
	VisibleZones, MissingPermissions                                                      []string
	LastUsed                                                                              uint64
}

type DynamicUI interface {
	Emit(context.Context, UIProjection) error
}
type DynamicUIFunc func(context.Context, UIProjection) error

func (function DynamicUIFunc) Emit(ctx context.Context, projection UIProjection) error {
	return function(ctx, projection)
}

type AuditRecord struct {
	Action, Outcome, OperationKey, Actor, ResourceGroupRef, ZoneID, RecordID, Suffix, Domain string
}
type Auditor interface {
	Audit(context.Context, AuditRecord) error
}
type AuditorFunc func(context.Context, AuditRecord) error

func (function AuditorFunc) Audit(ctx context.Context, record AuditRecord) error {
	return function(ctx, record)
}

type EventRecord struct{ Action, Outcome, ZoneID, RecordID, Suffix, Domain, ErrorClass string }
type EventLogger interface {
	Log(context.Context, EventRecord) error
}
type EventLoggerFunc func(context.Context, EventRecord) error

func (function EventLoggerFunc) Log(ctx context.Context, record EventRecord) error {
	return function(ctx, record)
}

type RuntimeAdapters struct {
	Vault Vault
	DNS   DNSHandle
	// Operations is the authoritative journal for Vault enrollment/rotation.
	// DNS effects are inspected through DNSHandle itself.
	Operations OperationInspector
	Lease      GenerationLease
	Authorizer Authorizer
	UI         DynamicUI
	Auditor    Auditor
	Logger     EventLogger
	// Catalog reloads last-saved suffix mappings across Service reconstruction.
	// When nil, NewService starts empty; Controller.activate supplies a Vault
	// catalog so Stop/Activate and process restart keep the last save.
	Catalog mappingCatalog
}

func (runtime RuntimeAdapters) valid() bool {
	return runtime.Vault != nil && runtime.DNS != nil && runtime.Operations != nil && runtime.Lease != nil && runtime.Authorizer != nil && runtime.UI != nil && runtime.Auditor != nil && runtime.Logger != nil
}

type PreparedAdmission interface {
	Commit(context.Context) (RuntimeAdapters, error)
	Abort()
}
type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) (RuntimeAdapters, error)
	AbortFunc  func()
}

func (prepared PreparedAdmissionFuncs) Commit(ctx context.Context) (RuntimeAdapters, error) {
	if prepared.CommitFunc == nil {
		return RuntimeAdapters{}, ErrTypedHandlesUnavailable
	}
	return prepared.CommitFunc(ctx)
}
func (prepared PreparedAdmissionFuncs) Abort() {
	if prepared.AbortFunc != nil {
		prepared.AbortFunc()
	}
}

type TypedHandleAdmission interface {
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)

func (function TypedHandleAdmissionFunc) Prepare(ctx context.Context, request pluginsdk.RPCHandshakeRequest, configuration Configuration) (PreparedAdmission, error) {
	return function(ctx, request, configuration)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
}

type Service struct {
	configuration Configuration
	runtime       RuntimeAdapters
	live          atomic.Bool
	mu            sync.Mutex
	status        TokenAttestation
	mappings      map[string]storedMapping
	retired       map[string]uint64
	revision      uint64
	catalog       mappingCatalog
	catalogMu     sync.Mutex
	rootCtx       context.Context
	cancel        context.CancelFunc
	active        sync.WaitGroup
	slots         chan struct{}
	hostCalls     chan struct{}
	closeOnce     sync.Once
}

func sortedUnique(values []string, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, ErrBoundExceeded
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}
