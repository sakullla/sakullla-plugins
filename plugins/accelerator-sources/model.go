package acceleratorsources

import (
	"context"
	"errors"
	"sort"
	"sync"
)

const (
	PluginID      = "accelerator-sources"
	PluginVersion = "0.1.0"

	MaxSources        = 256
	MaxSourceIDBytes  = 64
	MaxSourceURLBytes = 2048
	MinManualPriority = -1000
	MaxManualPriority = 1000
)

var (
	ErrInvalidSource           = errors.New("accelerator source is invalid")
	ErrSourceExists            = errors.New("accelerator source already exists")
	ErrSourceNotFound          = errors.New("accelerator source was not found")
	ErrBoundExceeded           = errors.New("accelerator source bound exceeded")
	ErrAuditRequired           = errors.New("trusted audit handle is required")
	ErrAuditUnavailable        = errors.New("trusted audit is unavailable")
	ErrDynamicUIRequired       = errors.New("dynamic UI handle is required")
	ErrDynamicUIUnavailable    = errors.New("dynamic UI is unavailable")
	ErrTypedHandlesUnavailable = errors.New("canonical typed accelerator handles are unavailable")
	ErrSchedulerBusy           = errors.New("accelerator probe scheduler is still draining")
	ErrProbeRejected           = errors.New("attested probe observation was rejected")
	ErrProbeFailed             = errors.New("accelerator probe failed")
)

type Category string

const (
	CategoryDocker Category = "docker"
	CategoryGitHub Category = "github"
)

type Source struct {
	ID             string   `json:"id"`
	Category       Category `json:"category"`
	URL            string   `json:"url"`
	Enabled        bool     `json:"enabled"`
	ManualPriority int      `json:"manual_priority"`
}

func (source Source) Validate() error {
	if !validSourceID(source.ID) || (source.Category != CategoryDocker && source.Category != CategoryGitHub) || len(source.URL) == 0 || len(source.URL) > MaxSourceURLBytes || source.ManualPriority < MinManualPriority || source.ManualPriority > MaxManualPriority {
		return ErrInvalidSource
	}
	if _, err := CanonicalHTTPSURL(source.URL); err != nil {
		return ErrInvalidSource
	}
	return nil
}

func validSourceID(value string) bool {
	if len(value) == 0 || len(value) > MaxSourceIDBytes || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return false
		}
	}
	return true
}

type Availability string

const (
	AvailabilityUnknown     Availability = "unknown"
	AvailabilityAvailable   Availability = "available"
	AvailabilityUnavailable Availability = "unavailable"
)

type ProbeFailureClass string

const (
	ProbeFailureNone       ProbeFailureClass = ""
	ProbeFailureTimeout    ProbeFailureClass = "timeout"
	ProbeFailureTransport  ProbeFailureClass = "transport"
	ProbeFailureUntrusted  ProbeFailureClass = "untrusted-observation"
	ProbeFailureHTTPStatus ProbeFailureClass = "http-status"
)

type SourceStatus struct {
	Availability Availability      `json:"availability"`
	LatencyNanos int64             `json:"latency_nanos"`
	Failure      ProbeFailureClass `json:"failure,omitempty"`
	Sequence     uint64            `json:"sequence"`
}

type SourceRecord struct {
	Source Source       `json:"source"`
	Status SourceStatus `json:"status"`
}

type AuditRecord struct {
	Action, Outcome, SourceID string
}

type Auditor interface {
	Audit(context.Context, AuditRecord) error
}

type AuditorFunc func(context.Context, AuditRecord) error

func (function AuditorFunc) Audit(ctx context.Context, record AuditRecord) error {
	return function(ctx, record)
}

type DynamicEvent struct {
	Kind, Action, SourceID string
	Status                 SourceStatus
}

type DynamicUI interface {
	Emit(context.Context, DynamicEvent) error
}

type DynamicUIFunc func(context.Context, DynamicEvent) error

func (function DynamicUIFunc) Emit(ctx context.Context, event DynamicEvent) error {
	return function(ctx, event)
}

type Manager struct {
	mu      sync.RWMutex
	sources map[string]SourceRecord
	seq     uint64
	auditor Auditor
	ui      DynamicUI

	probeMu     sync.Mutex
	probeActive bool
}

func NewManager(auditor Auditor, ui DynamicUI) *Manager {
	return &Manager{sources: make(map[string]SourceRecord), auditor: auditor, ui: ui}
}

func (manager *Manager) Create(ctx context.Context, source Source) error {
	if err := source.Validate(); err != nil {
		return manager.denied(ctx, "create", source.ID, err)
	}
	manager.mu.RLock()
	_, exists := manager.sources[source.ID]
	count := len(manager.sources)
	manager.mu.RUnlock()
	if exists {
		return manager.denied(ctx, "create", source.ID, ErrSourceExists)
	}
	if count >= MaxSources {
		return manager.denied(ctx, "create", source.ID, ErrBoundExceeded)
	}
	if err := manager.beforeEffect(ctx, "create", source.ID, DynamicEvent{Kind: "collection", Action: "create", SourceID: source.ID}); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, exists := manager.sources[source.ID]; exists {
		return ErrSourceExists
	}
	if len(manager.sources) >= MaxSources {
		return ErrBoundExceeded
	}
	manager.sources[source.ID] = SourceRecord{Source: source, Status: SourceStatus{Availability: AvailabilityUnknown}}
	return nil
}

func (manager *Manager) Update(ctx context.Context, source Source) error {
	if err := source.Validate(); err != nil {
		return manager.denied(ctx, "update", source.ID, err)
	}
	manager.mu.RLock()
	current, exists := manager.sources[source.ID]
	manager.mu.RUnlock()
	if !exists {
		return manager.denied(ctx, "update", source.ID, ErrSourceNotFound)
	}
	if err := manager.beforeEffect(ctx, "update", source.ID, DynamicEvent{Kind: "collection", Action: "update", SourceID: source.ID}); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	current, exists = manager.sources[source.ID]
	if !exists {
		return ErrSourceNotFound
	}
	if current.Source.URL != source.URL || current.Source.Category != source.Category {
		current.Status = SourceStatus{Availability: AvailabilityUnknown}
	}
	current.Source = source
	manager.sources[source.ID] = current
	return nil
}

func (manager *Manager) Delete(ctx context.Context, sourceID string) error {
	manager.mu.RLock()
	_, exists := manager.sources[sourceID]
	manager.mu.RUnlock()
	if !exists {
		return manager.denied(ctx, "delete", sourceID, ErrSourceNotFound)
	}
	if err := manager.beforeEffect(ctx, "delete", sourceID, DynamicEvent{Kind: "collection", Action: "delete", SourceID: sourceID}); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, exists := manager.sources[sourceID]; !exists {
		return ErrSourceNotFound
	}
	delete(manager.sources, sourceID)
	return nil
}

func (manager *Manager) SetEnabled(ctx context.Context, sourceID string, enabled bool) error {
	manager.mu.RLock()
	current, exists := manager.sources[sourceID]
	manager.mu.RUnlock()
	if !exists {
		return manager.denied(ctx, "enable", sourceID, ErrSourceNotFound)
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	if err := manager.beforeEffect(ctx, action, sourceID, DynamicEvent{Kind: "action", Action: action, SourceID: sourceID}); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	current, exists = manager.sources[sourceID]
	if !exists {
		return ErrSourceNotFound
	}
	current.Source.Enabled = enabled
	manager.sources[sourceID] = current
	return nil
}

// ReplaceFromV1 atomically migrates the plugin-owned configuration. Invalid or
// oversized input leaves the prior snapshot untouched.
func (manager *Manager) ReplaceFromV1(ctx context.Context, sources []Source) error {
	if len(sources) > MaxSources {
		return manager.denied(ctx, "migrate", "", ErrBoundExceeded)
	}
	next := make(map[string]SourceRecord, len(sources))
	for _, source := range sources {
		if err := source.Validate(); err != nil {
			return manager.denied(ctx, "migrate", source.ID, err)
		}
		if _, duplicate := next[source.ID]; duplicate {
			return manager.denied(ctx, "migrate", source.ID, ErrSourceExists)
		}
		next[source.ID] = SourceRecord{Source: source, Status: SourceStatus{Availability: AvailabilityUnknown}}
	}
	if err := manager.beforeEffect(ctx, "migrate", "", DynamicEvent{Kind: "collection", Action: "replace"}); err != nil {
		return err
	}
	manager.mu.Lock()
	manager.sources = next
	manager.seq = 0
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) Cleanup(ctx context.Context) error {
	if err := manager.beforeEffect(ctx, "cleanup", "", DynamicEvent{Kind: "collection", Action: "cleanup"}); err != nil {
		return err
	}
	manager.mu.Lock()
	manager.sources = make(map[string]SourceRecord)
	manager.seq = 0
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) Snapshot() []SourceRecord {
	manager.mu.RLock()
	result := make([]SourceRecord, 0, len(manager.sources))
	for _, record := range manager.sources {
		result = append(result, record)
	}
	manager.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Source.ID < result[j].Source.ID })
	return result
}

func (manager *Manager) beforeEffect(ctx context.Context, action, sourceID string, event DynamicEvent) error {
	if err := manager.auditAttempt(ctx, action, "authorized", sourceID); err != nil {
		return err
	}
	if manager.ui == nil {
		return ErrDynamicUIRequired
	}
	if err := manager.ui.Emit(ctx, event); err != nil {
		return ErrDynamicUIUnavailable
	}
	return nil
}

func (manager *Manager) denied(ctx context.Context, action, sourceID string, result error) error {
	if err := manager.auditAttempt(ctx, action, "denied", sourceID); err != nil {
		return err
	}
	return result
}

func (manager *Manager) auditAttempt(ctx context.Context, action, outcome, sourceID string) error {
	if manager.auditor == nil {
		return ErrAuditRequired
	}
	if err := manager.auditor.Audit(ctx, AuditRecord{Action: action, Outcome: outcome, SourceID: sourceID}); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (manager *Manager) updateStatus(ctx context.Context, sourceID string, status SourceStatus) error {
	manager.mu.RLock()
	_, exists := manager.sources[sourceID]
	manager.mu.RUnlock()
	if !exists {
		return ErrSourceNotFound
	}
	if manager.ui == nil {
		return ErrDynamicUIRequired
	}
	if err := manager.ui.Emit(ctx, DynamicEvent{Kind: "status", Action: "probe", SourceID: sourceID, Status: status}); err != nil {
		return ErrDynamicUIUnavailable
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, exists := manager.sources[sourceID]
	if !exists {
		return ErrSourceNotFound
	}
	manager.seq++
	status.Sequence = manager.seq
	record.Status = status
	manager.sources[sourceID] = record
	return nil
}

type SortMode string

const (
	SortManual       SortMode = "manual"
	SortAvailability SortMode = "availability"
	SortLatency      SortMode = "latency"
)

func SortRecords(records []SourceRecord, mode SortMode) []SourceRecord {
	result := append([]SourceRecord(nil), records...)
	sort.SliceStable(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if mode == SortAvailability || mode == SortLatency {
			ra, rb := availabilityRank(a.Status.Availability), availabilityRank(b.Status.Availability)
			if ra != rb {
				return ra < rb
			}
		}
		if mode == SortLatency && a.Status.Availability == AvailabilityAvailable && b.Status.Availability == AvailabilityAvailable && a.Status.LatencyNanos != b.Status.LatencyNanos {
			return a.Status.LatencyNanos < b.Status.LatencyNanos
		}
		if a.Source.ManualPriority != b.Source.ManualPriority {
			return a.Source.ManualPriority < b.Source.ManualPriority
		}
		return a.Source.ID < b.Source.ID
	})
	return result
}

func availabilityRank(value Availability) int {
	switch value {
	case AvailabilityAvailable:
		return 0
	case AvailabilityUnknown:
		return 1
	default:
		return 2
	}
}
