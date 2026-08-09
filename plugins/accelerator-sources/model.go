package acceleratorsources

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
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
	ErrProbeCanceled           = errors.New("accelerator probe call was canceled")
	ErrSourceChanged           = errors.New("accelerator source changed during the operation")
	ErrTerminalAuditPending    = errors.New("operation completed with terminal audit pending")
	ErrAdapterOperationFailed  = errors.New("accelerator handle operation failed")
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
	Source   Source       `json:"source"`
	Status   SourceStatus `json:"status"`
	Revision uint64       `json:"revision"`
}

type AuditRecord struct {
	Action, Outcome, SourceID string
	Operation                 uint64
	OperationKey              string
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
	mu       sync.RWMutex
	sources  map[string]SourceRecord
	seq      uint64
	revision uint64
	auditor  Auditor
	ui       DynamicUI

	probeMu     sync.Mutex
	probeActive bool
	probeEpoch  uint64
	activeProbe *probeCallEpoch

	auditMu       sync.Mutex
	flushMu       sync.Mutex
	operation     uint64
	pendingAudits []AuditRecord
}

func NewManager(auditor Auditor, ui DynamicUI) *Manager {
	return &Manager{sources: make(map[string]SourceRecord), auditor: auditor, ui: ui}
}

type operationFlow struct {
	manager   *Manager
	action    string
	sourceID  string
	operation uint64
}

func (manager *Manager) startOperation(ctx context.Context, action, sourceID string, event *DynamicEvent) (*operationFlow, error) {
	manager.auditMu.Lock()
	manager.operation++
	flow := &operationFlow{manager: manager, action: action, sourceID: sourceID, operation: manager.operation}
	manager.auditMu.Unlock()
	if err := manager.writeAudit(ctx, flow.record("started")); err != nil {
		return nil, err
	}
	if event != nil {
		if manager.ui == nil {
			return nil, flow.fail(ErrDynamicUIRequired, false)
		}
		if err := manager.ui.Emit(ctx, *event); err != nil {
			return nil, flow.fail(ErrDynamicUIUnavailable, false)
		}
	}
	return flow, nil
}

func (flow *operationFlow) record(outcome string) AuditRecord {
	return AuditRecord{Action: flow.action, Outcome: outcome, SourceID: flow.sourceID, Operation: flow.operation}
}

func (flow *operationFlow) finish(completed bool) error {
	return flow.terminal("succeeded", completed)
}

func (flow *operationFlow) fail(result error, completed bool) error {
	if err := flow.terminal("failed", completed); err != nil {
		return err
	}
	return result
}

func (flow *operationFlow) terminal(outcome string, completed bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err := flow.manager.writeAudit(ctx, flow.record(outcome))
	cancel()
	if err == nil {
		return nil
	}
	if !completed {
		return err
	}
	flow.manager.auditMu.Lock()
	flow.manager.pendingAudits = append(flow.manager.pendingAudits, flow.record(outcome))
	flow.manager.auditMu.Unlock()
	return ErrTerminalAuditPending
}

func (manager *Manager) writeAudit(ctx context.Context, record AuditRecord) error {
	if manager.auditor == nil {
		return ErrAuditRequired
	}
	if err := manager.auditor.Audit(ctx, record); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (manager *Manager) failedAttempt(ctx context.Context, action, sourceID string, result error) error {
	flow, err := manager.startOperation(ctx, action, sourceID, nil)
	if err != nil {
		return err
	}
	return flow.fail(result, false)
}

func (manager *Manager) PendingTerminalAudits() int {
	manager.auditMu.Lock()
	defer manager.auditMu.Unlock()
	return len(manager.pendingAudits)
}

func (manager *Manager) FlushTerminalAudits(ctx context.Context) error {
	manager.flushMu.Lock()
	defer manager.flushMu.Unlock()
	manager.auditMu.Lock()
	pending := append([]AuditRecord(nil), manager.pendingAudits...)
	manager.auditMu.Unlock()
	for _, record := range pending {
		if err := manager.writeAudit(ctx, record); err != nil {
			return err
		}
		manager.auditMu.Lock()
		for index, pendingRecord := range manager.pendingAudits {
			if pendingRecord == record {
				manager.pendingAudits = append(manager.pendingAudits[:index], manager.pendingAudits[index+1:]...)
				break
			}
		}
		manager.auditMu.Unlock()
	}
	return nil
}

func (manager *Manager) Create(ctx context.Context, source Source) error {
	if err := source.Validate(); err != nil {
		return manager.failedAttempt(ctx, "create", source.ID, err)
	}
	manager.mu.RLock()
	_, exists := manager.sources[source.ID]
	count := len(manager.sources)
	manager.mu.RUnlock()
	if exists {
		return manager.failedAttempt(ctx, "create", source.ID, ErrSourceExists)
	}
	if count >= MaxSources {
		return manager.failedAttempt(ctx, "create", source.ID, ErrBoundExceeded)
	}
	flow, err := manager.startOperation(ctx, "create", source.ID, &DynamicEvent{Kind: "collection", Action: "create", SourceID: source.ID})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	if _, exists := manager.sources[source.ID]; exists {
		manager.mu.Unlock()
		return flow.fail(ErrSourceExists, false)
	}
	if len(manager.sources) >= MaxSources {
		manager.mu.Unlock()
		return flow.fail(ErrBoundExceeded, false)
	}
	manager.sources[source.ID] = SourceRecord{Source: source, Status: SourceStatus{Availability: AvailabilityUnknown}, Revision: manager.nextRevisionLocked()}
	manager.mu.Unlock()
	return flow.finish(true)
}

func (manager *Manager) Update(ctx context.Context, source Source) error {
	if err := source.Validate(); err != nil {
		return manager.failedAttempt(ctx, "update", source.ID, err)
	}
	manager.mu.RLock()
	current, exists := manager.sources[source.ID]
	manager.mu.RUnlock()
	if !exists {
		return manager.failedAttempt(ctx, "update", source.ID, ErrSourceNotFound)
	}
	flow, err := manager.startOperation(ctx, "update", source.ID, &DynamicEvent{Kind: "collection", Action: "update", SourceID: source.ID})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	current, exists = manager.sources[source.ID]
	if !exists {
		manager.mu.Unlock()
		return flow.fail(ErrSourceNotFound, false)
	}
	if current.Source.URL != source.URL || current.Source.Category != source.Category {
		current.Status = SourceStatus{Availability: AvailabilityUnknown}
	}
	current.Source = source
	current.Revision = manager.nextRevisionLocked()
	manager.sources[source.ID] = current
	manager.mu.Unlock()
	return flow.finish(true)
}

func (manager *Manager) Delete(ctx context.Context, sourceID string) error {
	manager.mu.RLock()
	_, exists := manager.sources[sourceID]
	manager.mu.RUnlock()
	if !exists {
		return manager.failedAttempt(ctx, "delete", sourceID, ErrSourceNotFound)
	}
	flow, err := manager.startOperation(ctx, "delete", sourceID, &DynamicEvent{Kind: "collection", Action: "delete", SourceID: sourceID})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	if _, exists := manager.sources[sourceID]; !exists {
		manager.mu.Unlock()
		return flow.fail(ErrSourceNotFound, false)
	}
	manager.nextRevisionLocked()
	delete(manager.sources, sourceID)
	manager.mu.Unlock()
	return flow.finish(true)
}

func (manager *Manager) SetEnabled(ctx context.Context, sourceID string, enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	manager.mu.RLock()
	current, exists := manager.sources[sourceID]
	manager.mu.RUnlock()
	if !exists {
		return manager.failedAttempt(ctx, action, sourceID, ErrSourceNotFound)
	}
	flow, err := manager.startOperation(ctx, action, sourceID, &DynamicEvent{Kind: "action", Action: action, SourceID: sourceID})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	current, exists = manager.sources[sourceID]
	if !exists {
		manager.mu.Unlock()
		return flow.fail(ErrSourceNotFound, false)
	}
	current.Source.Enabled = enabled
	current.Revision = manager.nextRevisionLocked()
	manager.sources[sourceID] = current
	manager.mu.Unlock()
	return flow.finish(true)
}

// ReplaceFromV1 atomically migrates the plugin-owned configuration. Invalid or
// oversized input leaves the prior snapshot untouched.
func (manager *Manager) ReplaceFromV1(ctx context.Context, sources []Source) error {
	if len(sources) > MaxSources {
		return manager.failedAttempt(ctx, "migrate", "", ErrBoundExceeded)
	}
	nextSources := append([]Source(nil), sources...)
	sort.Slice(nextSources, func(i, j int) bool { return nextSources[i].ID < nextSources[j].ID })
	next := make(map[string]SourceRecord, len(nextSources))
	for _, source := range nextSources {
		if err := source.Validate(); err != nil {
			return manager.failedAttempt(ctx, "migrate", source.ID, err)
		}
		if _, duplicate := next[source.ID]; duplicate {
			return manager.failedAttempt(ctx, "migrate", source.ID, ErrSourceExists)
		}
		next[source.ID] = SourceRecord{Source: source, Status: SourceStatus{Availability: AvailabilityUnknown}}
	}
	flow, err := manager.startOperation(ctx, "migrate", "", &DynamicEvent{Kind: "collection", Action: "replace"})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	for _, source := range nextSources {
		record := next[source.ID]
		record.Revision = manager.nextRevisionLocked()
		next[source.ID] = record
	}
	manager.sources = next
	manager.mu.Unlock()
	return flow.finish(true)
}

func (manager *Manager) Cleanup(ctx context.Context) error {
	flow, err := manager.startOperation(ctx, "cleanup", "", &DynamicEvent{Kind: "collection", Action: "cleanup"})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	manager.nextRevisionLocked()
	manager.sources = make(map[string]SourceRecord)
	manager.mu.Unlock()
	return flow.finish(true)
}

func (manager *Manager) nextRevisionLocked() uint64 {
	manager.revision++
	return manager.revision
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

func (manager *Manager) updateStatus(ctx context.Context, expected SourceRecord, epoch *probeCallEpoch, status SourceStatus) error {
	manager.mu.Lock()
	if epoch == nil || !epoch.live.Load() || epoch.parent.Err() != nil {
		manager.mu.Unlock()
		return ErrProbeCanceled
	}
	record, exists := manager.sources[expected.Source.ID]
	if !exists || record.Revision != expected.Revision || record.Source != expected.Source || !record.Source.Enabled {
		manager.mu.Unlock()
		return ErrSourceChanged
	}
	manager.seq++
	status.Sequence = manager.seq
	record.Status = status
	manager.sources[expected.Source.ID] = record
	manager.mu.Unlock()
	if manager.ui == nil {
		return ErrDynamicUIRequired
	}
	if err := manager.ui.Emit(ctx, DynamicEvent{Kind: "status", Action: "probe", SourceID: expected.Source.ID, Status: status}); err != nil {
		return ErrDynamicUIUnavailable
	}
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
