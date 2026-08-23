package reversel4

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// statusCollectionTimeout is the single GET /api/mappings budget shared by
// every enabled mapping lookup. Deadline or cancel degrades unfinished
// entries to unknown instead of blocking the catalog.
const statusCollectionTimeout = 5 * time.Second

// recoveryScanInterval is the background retry period after the immediate
// activate scan. It is kept short relative to ordinary admin wait time and
// is package-internal; the external status SLA remains five seconds.
const recoveryScanInterval = time.Second

// recoveryAttemptTimeout bounds one recovery attempt's host I/O so a hung
// agent cannot stall the reconciler loop. Catalog load and commit hold
// service.mu only briefly, so Statuses and admin mutations do not wait on
// recovery RPCs.
const recoveryAttemptTimeout = 3 * time.Second

// Service orchestrates mapping records against two generic host effects: the
// entry-side host L4 rule and the host-managed reverse channel. Every mutation
// persists the durable catalog only after its host effects succeeded, and
// retries replay the same host operation ids, so partial failures converge
// without orphan rules or channels.
type Service struct {
	mu      sync.Mutex
	state   mappingState
	runtime *hostRuntime

	recoveryMu     sync.Mutex
	recoveryCancel context.CancelFunc
	recoveryDone   <-chan struct{}
}

func NewService(state mappingState, runtime *hostRuntime) (*Service, error) {
	if state == nil {
		return nil, errors.New("mapping state store is required")
	}
	return &Service{state: state, runtime: runtime}, nil
}

// runtimeAvailable reports whether host orchestration is currently usable.
// Read-only listing still works without it.
func (service *Service) runtimeAvailable() bool {
	return service != nil && service.runtime.available()
}

// List returns the durable catalog sorted by mapping id.
func (service *Service) List(ctx context.Context) ([]Mapping, error) {
	if service == nil {
		return nil, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	mappings := snapshot.clone().Mappings
	sortMappings(mappings)
	return mappings, nil
}

// Status projects one mapping with its current reverse-channel connectivity.
// A disabled mapping is offline by construction; an enabled mapping without a
// session reference reports unknown until its first ensure succeeds.
func (service *Service) Status(ctx context.Context, id string) (MappingStatus, error) {
	if service == nil {
		return MappingStatus{}, ErrStateUnavailable
	}
	service.mu.Lock()
	snapshot, err := service.state.Load(ctx)
	service.mu.Unlock()
	if err != nil {
		return MappingStatus{}, err
	}
	mapping, ok := snapshot.mapping(id)
	if !ok {
		return MappingStatus{}, ErrMappingNotFound
	}
	return service.channelStatusFor(ctx, mapping)
}

// Statuses projects the whole catalog with per-mapping reverse-channel
// connectivity for the management page. Enabled mappings are looked up
// concurrently under one five-second budget; a failing, canceled, or
// timed-out lookup degrades only that mapping to unknown.
func (service *Service) Statuses(ctx context.Context) ([]MappingStatus, error) {
	if service == nil {
		return nil, ErrStateUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	service.mu.Lock()
	snapshot, err := service.state.Load(ctx)
	service.mu.Unlock()
	if err != nil {
		return nil, err
	}
	statuses := make([]MappingStatus, len(snapshot.Mappings))
	filled := make([]bool, len(snapshot.Mappings))
	type lookupJob struct {
		index   int
		mapping Mapping
	}
	jobs := make([]lookupJob, 0, len(snapshot.Mappings))
	for index, mapping := range snapshot.Mappings {
		if mapping.Enabled && mapping.SessionRef != "" && service.runtimeAvailable() {
			jobs = append(jobs, lookupJob{index: index, mapping: mapping})
			continue
		}
		status, _ := service.lookupChannelStatus(ctx, mapping)
		statuses[index] = status
		filled[index] = true
	}
	if len(jobs) == 0 {
		return statuses, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, statusCollectionTimeout)
	defer cancel()
	type lookupResult struct {
		index  int
		status MappingStatus
	}
	results := make(chan lookupResult, len(jobs))
	for _, job := range jobs {
		go func(job lookupJob) {
			status, _ := service.lookupChannelStatus(lookupCtx, job.mapping)
			results <- lookupResult{index: job.index, status: status}
		}(job)
	}

	remaining := len(jobs)
	for remaining > 0 {
		select {
		case got := <-results:
			statuses[got.index] = got.status
			filled[got.index] = true
			remaining--
		case <-lookupCtx.Done():
			remaining = 0
		}
	}
	if lookupCtx.Err() != nil {
	drainStatusResults:
		for {
			select {
			case got := <-results:
				statuses[got.index] = got.status
				filled[got.index] = true
			default:
				break drainStatusResults
			}
		}
		for _, job := range jobs {
			if filled[job.index] {
				continue
			}
			statuses[job.index] = MappingStatus{
				Mapping:      job.mapping,
				ChannelState: ChannelUnknown,
				LastError:    statusLookupLastError(lookupCtx.Err()),
			}
		}
	}
	return statuses, nil
}

// channelStatusFor derives the management-page connectivity projection of one
// durable mapping record.
func (service *Service) channelStatusFor(ctx context.Context, mapping Mapping) (MappingStatus, error) {
	return service.lookupChannelStatus(ctx, mapping)
}

// lookupChannelStatus projects one mapping's live reverse-channel state.
// Host lookup errors are returned for single-item Status callers; Statuses
// keeps the unknown projection and bounded LastError instead.
func (service *Service) lookupChannelStatus(ctx context.Context, mapping Mapping) (MappingStatus, error) {
	status := MappingStatus{Mapping: mapping, ChannelState: ChannelUnknown}
	switch {
	case !mapping.Enabled:
		status.ChannelState = ChannelOffline
		return status, nil
	case mapping.SessionRef == "":
		return status, nil
	case !service.runtimeAvailable():
		status.LastError = statusLookupLastError(ErrHostRuntimeUnavailable)
		return status, nil
	default:
		session, err := service.runtime.channelStatus(ctx, mapping.SessionRef)
		if err != nil {
			if errors.Is(err, ErrHostRejectedRequest) {
				status.ChannelState = ChannelOffline
				status.LastError = "reverse channel session is gone"
				return status, nil
			}
			status.LastError = statusLookupLastError(err)
			return status, err
		}
		status.ChannelState = channelStateNormalize(session.State)
		status.LastError = safeHostText(session.LastError)
		return status, nil
	}
}

func statusLookupLastError(err error) string {
	kind := "host-error"
	message := "channel status is unavailable"
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			kind = "timeout"
		case errors.Is(err, context.Canceled):
			kind = "cancel"
		}
		message = err.Error()
	}
	return safeHostText(kind + ": " + message)
}

// Create provisions a new mapping: establish the reverse channel first, then
// point a host L4 rule at the returned entry-side bridge endpoint. A failed
// rule step leaves nothing persisted, and the retry replays the durable
// channel outcome before re-running only the rule step.
func (service *Service) Create(ctx context.Context, mapping Mapping) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	mapping.RuleRef, mapping.SessionRef, mapping.BridgeHost, mapping.BridgePort = "", "", "", 0
	mapping.Enabled = true
	mapping.Revision = 0
	mapping.RecoveryGeneration = 0
	assignID := mapping.ID == ""
	if !assignID {
		if err := mapping.Validate(); err != nil {
			return Mapping{}, err
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	if assignID {
		id, err := allocateMappingID(snapshot)
		if err != nil {
			return Mapping{}, err
		}
		mapping.ID = id
		if err := mapping.Validate(); err != nil {
			return Mapping{}, err
		}
	} else if _, exists := snapshot.mapping(mapping.ID); exists {
		return Mapping{}, ErrMappingExists
	}
	if len(snapshot.Mappings) >= MaxMappings {
		return Mapping{}, fmt.Errorf("%w: mappings maximum is %d", ErrBoundExceeded, MaxMappings)
	}
	revision := snapshot.Revision + 1
	session, err := service.ensureChannelFor(ctx, mapping, "", revision)
	if err != nil {
		return Mapping{}, err
	}
	rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", mapping.ID, revision), ruleRequest(mapping, session))
	if err != nil {
		// No compensating teardown: the durable ensure outcome is keyed to
		// this revision, so a retry re-attaches the same host session and
		// only the rule step runs again. Host sessions are owner-managed and
		// re-created on demand; orphan host rules are the visible resource
		// this path must never leave behind.
		return Mapping{}, err
	}
	created := mapping
	created.SessionRef = session.SessionRef
	created.BridgeHost, created.BridgePort = session.BridgeHost, session.BridgePort
	created.RuleRef = rule.RuleRef
	created.Revision = revision
	return created, service.commit(ctx, snapshot, created, nil)
}

// Update applies a new specification to an existing mapping. The client
// supplies only the user-facing spec; ownership references come from the
// durable record.
func (service *Service) Update(ctx context.Context, spec Mapping) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	existing, ok := snapshot.mapping(spec.ID)
	if !ok {
		return Mapping{}, ErrMappingNotFound
	}
	updated := spec
	updated.Enabled = existing.Enabled
	updated.RuleRef, updated.SessionRef = existing.RuleRef, existing.SessionRef
	updated.BridgeHost, updated.BridgePort = existing.BridgeHost, existing.BridgePort
	updated.Revision = existing.Revision
	updated.RecoveryGeneration = existing.RecoveryGeneration
	if err := updated.Validate(); err != nil {
		return Mapping{}, err
	}
	revision := existing.Revision + 1
	updated.Revision = revision

	entryMoved := updated.EntryAgentID != existing.EntryAgentID
	ownersMoved := entryMoved || updated.ExitAgentID != existing.ExitAgentID

	if !existing.Enabled {
		// The channel is torn down and the rule disabled; the new spec is
		// applied by the next enable, which re-ensures and re-points the rule.
		if entryMoved && existing.RuleRef != "" {
			if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", updated.ID, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		if entryMoved {
			updated.RuleRef, updated.BridgeHost, updated.BridgePort = "", "", 0
		}
		return updated, service.commit(ctx, snapshot, updated, nil)
	}

	reattach := ""
	if !ownersMoved {
		reattach = existing.SessionRef
	} else if existing.SessionRef != "" {
		if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", updated.ID, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return Mapping{}, err
		}
	}
	session, err := service.ensureChannelFor(ctx, updated, reattach, revision)
	if err != nil {
		return Mapping{}, err
	}
	updated.SessionRef = session.SessionRef
	updated.BridgeHost, updated.BridgePort = session.BridgeHost, session.BridgePort

	switch {
	case entryMoved:
		if existing.RuleRef != "" {
			if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", updated.ID, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	case existing.RuleRef == "":
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	default:
		request := ruleRequest(updated, session)
		request.RuleRef = existing.RuleRef
		enabled := true
		request.Enabled = &enabled
		if _, err := service.runtime.updateRule(ctx, mutationOperationKey("rule.update", updated.ID, revision), request); err != nil {
			if errors.Is(err, ErrHostRejectedRequest) {
				rule, createErr := service.runtime.createRule(ctx, mutationOperationKey("rule.create", updated.ID, revision), ruleRequest(updated, session))
				if createErr != nil {
					return Mapping{}, createErr
				}
				updated.RuleRef = rule.RuleRef
				break
			}
			return Mapping{}, err
		}
	}
	return updated, service.commit(ctx, snapshot, updated, nil)
}

// SetEnabled disables or re-enables one mapping. Disabling keeps the record
// and the (disabled) rule but tears the reverse channel down; enabling
// re-ensures the channel and re-points or recreates the rule.
func (service *Service) SetEnabled(ctx context.Context, id string, enabled bool) (Mapping, error) {
	if service == nil {
		return Mapping{}, ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, err
	}
	existing, ok := snapshot.mapping(id)
	if !ok {
		return Mapping{}, ErrMappingNotFound
	}
	if existing.Enabled == enabled {
		return existing, nil
	}
	revision := existing.Revision + 1
	updated := existing
	updated.Revision = revision

	if !enabled {
		if existing.SessionRef != "" {
			if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", id, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		if existing.RuleRef != "" {
			if _, err := service.runtime.setRuleEnabled(ctx, mutationOperationKey("rule.disable", id, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID), false); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
		}
		updated.Enabled = false
		updated.BridgeHost, updated.BridgePort = "", 0
		return updated, service.commit(ctx, snapshot, updated, nil)
	}

	session, err := service.ensureChannelFor(ctx, existing, existing.SessionRef, revision)
	if err != nil {
		return Mapping{}, err
	}
	updated.SessionRef = session.SessionRef
	updated.BridgeHost, updated.BridgePort = session.BridgeHost, session.BridgePort
	if existing.RuleRef == "" {
		rule, err := service.runtime.createRule(ctx, mutationOperationKey("rule.create", id, revision), ruleRequest(updated, session))
		if err != nil {
			return Mapping{}, err
		}
		updated.RuleRef = rule.RuleRef
	} else {
		request := ruleRequest(updated, session)
		request.RuleRef = existing.RuleRef
		enabled := true
		request.Enabled = &enabled
		if _, err := service.runtime.updateRule(ctx, mutationOperationKey("rule.update", id, revision), request); err != nil {
			if !errors.Is(err, ErrHostRejectedRequest) {
				return Mapping{}, err
			}
			rule, createErr := service.runtime.createRule(ctx, mutationOperationKey("rule.create", id, revision), ruleRequest(updated, session))
			if createErr != nil {
				return Mapping{}, createErr
			}
			updated.RuleRef = rule.RuleRef
		}
	}
	updated.Enabled = true
	return updated, service.commit(ctx, snapshot, updated, nil)
}

// Delete releases both host effects and removes the record. Rejected requests
// that mean the target is already gone clear the reference and continue, so
// the delete path is re-runnable after partial failures and leaves no orphan
// rule or channel behind.
func (service *Service) Delete(ctx context.Context, id string) error {
	if service == nil {
		return ErrStateUnavailable
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return err
	}
	existing, ok := snapshot.mapping(id)
	if !ok {
		return nil
	}
	revision := existing.Revision + 1
	if existing.SessionRef != "" {
		if err := service.runtime.teardownChannel(ctx, mutationOperationKey("channel.teardown", id, revision), existing.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
	}
	if existing.RuleRef != "" {
		if err := service.runtime.deleteRule(ctx, mutationOperationKey("rule.delete", id, revision), ruleRefRequest(existing.RuleRef, existing.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
	}
	return service.commit(ctx, snapshot, Mapping{}, &existing.ID)
}

// startRecovery launches one immediate catalog scan and a periodic retry
// loop. Activate must return without waiting for host I/O; Stop cancels the
// loop and waits for in-flight attempts to observe the cancel.
func (service *Service) startRecovery() {
	if service == nil {
		return
	}
	service.stopRecovery()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	service.recoveryMu.Lock()
	service.recoveryCancel = cancel
	service.recoveryDone = done
	service.recoveryMu.Unlock()
	go func() {
		defer close(done)
		service.recoveryLoop(ctx)
	}()
}

func (service *Service) stopRecovery() {
	if service == nil {
		return
	}
	service.recoveryMu.Lock()
	cancel := service.recoveryCancel
	done := service.recoveryDone
	service.recoveryCancel = nil
	service.recoveryDone = nil
	service.recoveryMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (service *Service) recoveryLoop(ctx context.Context) {
	service.recoverAll(ctx)
	ticker := time.NewTicker(recoveryScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.recoverAll(ctx)
		}
	}
}

func (service *Service) recoverAll(ctx context.Context) {
	if service == nil || !service.runtimeAvailable() {
		return
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return
		}
	}
	service.mu.Lock()
	snapshot, err := service.state.Load(ctx)
	service.mu.Unlock()
	if err != nil {
		return
	}
	for _, mapping := range snapshot.Mappings {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return
			}
		}
		if !mapping.Enabled {
			continue
		}
		_ = service.recoverMapping(ctx, mapping.ID)
	}
}

func (service *Service) recoverMapping(ctx context.Context, id string) error {
	if service == nil {
		return ErrStateUnavailable
	}
	if !service.runtimeAvailable() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	attemptCtx, cancel := context.WithTimeout(ctx, recoveryAttemptTimeout)
	defer cancel()

	mapping, ok, err := service.loadMapping(attemptCtx, id)
	if err != nil {
		return err
	}
	if !ok || !mapping.Enabled {
		return nil
	}

	needed, err := service.mappingNeedsRecovery(attemptCtx, mapping)
	if err != nil {
		return err
	}
	if !needed {
		return nil
	}

	claimed, ok, err := service.claimRecoveryAttempt(attemptCtx, mapping)
	if err != nil || !ok {
		return err
	}

	attempted := claimed
	session, err := service.ensureChannelRecovery(attemptCtx, claimed)
	if err != nil {
		return service.compensateClaimedRecovery(ctx, claimed, attempted, err)
	}
	attempted.SessionRef = session.SessionRef
	attempted.BridgeHost, attempted.BridgePort = session.BridgeHost, session.BridgePort
	if err := service.alignRecoveredRule(attemptCtx, &attempted, session); err != nil {
		return service.compensateClaimedRecovery(ctx, claimed, attempted, err)
	}
	return service.commitRecoveredMapping(attemptCtx, claimed, attempted)
}

// recoveryWorkContext keeps catalog reload and stale-effect teardown usable
// after a claimed attempt's deadline or cancel. Live contexts are reused.
func recoveryWorkContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), recoveryAttemptTimeout)
}

func (service *Service) compensateClaimedRecovery(parent context.Context, claimed, attempted Mapping, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), recoveryAttemptTimeout)
	defer cancel()
	current, ok, err := service.loadMapping(ctx, claimed.ID)
	if err != nil {
		return cause
	}
	if ok && current.Enabled && current.Revision == claimed.Revision && current.RecoveryGeneration == claimed.RecoveryGeneration {
		return cause
	}
	if err := service.abandonStaleRecovery(ctx, attempted, current, ok); err != nil {
		if cause == nil {
			return err
		}
		return errors.Join(cause, err)
	}
	return nil
}

func (service *Service) loadMapping(ctx context.Context, id string) (Mapping, bool, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, false, err
	}
	mapping, ok := snapshot.mapping(id)
	return mapping, ok, nil
}

func (service *Service) claimRecoveryAttempt(ctx context.Context, observed Mapping) (Mapping, bool, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	snapshot, err := service.state.Load(ctx)
	if err != nil {
		return Mapping{}, false, err
	}
	current, ok := snapshot.mapping(observed.ID)
	if !ok || !current.Enabled || current.Revision != observed.Revision || current.RecoveryGeneration != observed.RecoveryGeneration {
		return Mapping{}, false, nil
	}
	current.RecoveryGeneration++
	if err := service.commit(ctx, snapshot, current, nil); err != nil {
		return Mapping{}, false, err
	}
	return current, true, nil
}

func (service *Service) commitRecoveredMapping(ctx context.Context, claimed, restored Mapping) error {
	commitCtx, cancel := recoveryWorkContext(ctx)
	defer cancel()
	service.mu.Lock()
	snapshot, err := service.state.Load(commitCtx)
	if err != nil {
		service.mu.Unlock()
		return err
	}
	current, ok := snapshot.mapping(claimed.ID)
	if !ok || !current.Enabled || current.Revision != claimed.Revision || current.RecoveryGeneration != claimed.RecoveryGeneration {
		service.mu.Unlock()
		return service.abandonStaleRecovery(commitCtx, restored, current, ok)
	}
	err = service.commit(commitCtx, snapshot, restored, nil)
	service.mu.Unlock()
	return err
}

func (service *Service) abandonStaleRecovery(ctx context.Context, attempted, current Mapping, exists bool) error {
	workCtx, cancel := recoveryWorkContext(ctx)
	defer cancel()
	if !exists {
		return service.discardRecoveredHostEffects(workCtx, attempted, true)
	}
	if !current.Enabled {
		if err := service.discardRecoveredHostEffects(workCtx, attempted, false); err != nil {
			return err
		}
		if current.SessionRef != "" && current.SessionRef != attempted.SessionRef {
			if err := service.discardRecoveredHostEffects(workCtx, current, false); err != nil {
				return err
			}
		}
		return nil
	}
	return service.realignHostToMapping(workCtx, current)
}

func (service *Service) discardRecoveredHostEffects(ctx context.Context, mapping Mapping, removeRule bool) error {
	if mapping.SessionRef != "" {
		operation := recoveryOperationKey("channel.teardown", mapping.ID, mapping.Revision, mapping.RecoveryGeneration)
		if err := service.runtime.teardownChannel(ctx, operation, mapping.SessionRef); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
	}
	if mapping.RuleRef == "" {
		return nil
	}
	if removeRule {
		operation := recoveryOperationKey("rule.delete", mapping.ID, mapping.Revision, mapping.RecoveryGeneration)
		if err := service.runtime.deleteRule(ctx, operation, ruleRefRequest(mapping.RuleRef, mapping.EntryAgentID)); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
		return nil
	}
	operation := recoveryOperationKey("rule.disable", mapping.ID, mapping.Revision, mapping.RecoveryGeneration)
	if _, err := service.runtime.setRuleEnabled(ctx, operation, ruleRefRequest(mapping.RuleRef, mapping.EntryAgentID), false); err != nil && !errors.Is(err, ErrHostRejectedRequest) {
		return err
	}
	return nil
}

func (service *Service) realignHostToMapping(ctx context.Context, mapping Mapping) error {
	attempted := mapping
	session, err := service.ensureChannelRecovery(ctx, mapping)
	if err != nil {
		return service.compensateClaimedRecovery(ctx, mapping, attempted, err)
	}
	attempted.SessionRef = session.SessionRef
	attempted.BridgeHost, attempted.BridgePort = session.BridgeHost, session.BridgePort
	if err := service.alignRecoveredRule(ctx, &attempted, session); err != nil {
		return service.compensateClaimedRecovery(ctx, mapping, attempted, err)
	}
	commitCtx, cancel := recoveryWorkContext(ctx)
	defer cancel()
	service.mu.Lock()
	snapshot, err := service.state.Load(commitCtx)
	if err != nil {
		service.mu.Unlock()
		return service.compensateClaimedRecovery(ctx, mapping, attempted, err)
	}
	current, ok := snapshot.mapping(mapping.ID)
	if !ok || !current.Enabled || current.Revision != mapping.Revision || current.RecoveryGeneration != mapping.RecoveryGeneration {
		service.mu.Unlock()
		return service.abandonStaleRecovery(commitCtx, attempted, current, ok)
	}
	err = service.commit(commitCtx, snapshot, attempted, nil)
	service.mu.Unlock()
	if err != nil {
		return service.compensateClaimedRecovery(ctx, mapping, attempted, err)
	}
	return nil
}

func (service *Service) mappingNeedsRecovery(ctx context.Context, mapping Mapping) (bool, error) {
	if mapping.SessionRef == "" || mapping.RuleRef == "" {
		return true, nil
	}
	session, err := service.runtime.channelStatus(ctx, mapping.SessionRef)
	if err != nil {
		if errors.Is(err, ErrHostRejectedRequest) {
			return true, nil
		}
		return false, err
	}
	if channelStateNormalize(session.State) != ChannelOnline {
		return true, nil
	}
	if session.BridgeHost != "" && session.BridgePort > 0 &&
		(session.BridgeHost != mapping.BridgeHost || session.BridgePort != mapping.BridgePort) {
		return true, nil
	}
	return false, nil
}

func (service *Service) ensureChannelRecovery(ctx context.Context, mapping Mapping) (channelSession, error) {
	request := pluginsdk.ChannelReverseRequest{
		Action:       pluginsdk.ChannelReverseActionEnsure,
		EntryAgentID: mapping.EntryAgentID,
		ExitAgentID:  mapping.ExitAgentID,
		Protocol:     mapping.Protocol,
		BackendHost:  mapping.BackendHost,
		BackendPort:  mapping.BackendPort,
		RelayChain:   append([]int(nil), mapping.RelayChain...),
		SessionRef:   mapping.SessionRef,
	}
	if err := request.Validate(); err != nil {
		return channelSession{}, fmt.Errorf("%w: %v", ErrInvalidMapping, err)
	}
	operation := recoveryOperationKey("channel.ensure", mapping.ID, mapping.Revision, mapping.RecoveryGeneration)
	return service.runtime.ensureChannel(ctx, operation, request)
}

// recoveryOperationKey derives the host operation id for one recovery
// attempt. Mapping ID, user revision, generation, and action keep retries of
// the same attempt stable while later session-loss events mint a new id.
func recoveryOperationKey(action, mappingID string, revision, generation uint64) string {
	return stableOperationKey("reverse-l4", "recovery", action, mappingID, revisionString(revision), generationString(generation))
}

func generationString(generation uint64) string {
	return fmt.Sprintf("gen-%d", generation)
}

func (service *Service) alignRecoveredRule(ctx context.Context, mapping *Mapping, session channelSession) error {
	operation := func(action string) string {
		return recoveryOperationKey(action, mapping.ID, mapping.Revision, mapping.RecoveryGeneration)
	}
	if mapping.RuleRef == "" {
		rule, err := service.runtime.createRule(ctx, operation("rule.create"), ruleRequest(*mapping, session))
		if err != nil {
			return err
		}
		mapping.RuleRef = rule.RuleRef
		return nil
	}
	request := ruleRequest(*mapping, session)
	request.RuleRef = mapping.RuleRef
	enabled := true
	request.Enabled = &enabled
	if _, err := service.runtime.updateRule(ctx, operation("rule.update"), request); err != nil {
		if !errors.Is(err, ErrHostRejectedRequest) {
			return err
		}
		rule, createErr := service.runtime.createRule(ctx, operation("rule.create"), ruleRequest(*mapping, session))
		if createErr != nil {
			return createErr
		}
		mapping.RuleRef = rule.RuleRef
	}
	return nil
}

func (service *Service) ensureChannelFor(ctx context.Context, mapping Mapping, sessionRef string, revision uint64) (channelSession, error) {
	request := pluginsdk.ChannelReverseRequest{
		Action:       pluginsdk.ChannelReverseActionEnsure,
		EntryAgentID: mapping.EntryAgentID,
		ExitAgentID:  mapping.ExitAgentID,
		Protocol:     mapping.Protocol,
		BackendHost:  mapping.BackendHost,
		BackendPort:  mapping.BackendPort,
		RelayChain:   append([]int(nil), mapping.RelayChain...),
		SessionRef:   sessionRef,
	}
	if err := request.Validate(); err != nil {
		return channelSession{}, fmt.Errorf("%w: %v", ErrInvalidMapping, err)
	}
	operation := mutationOperationKey("channel.ensure", mapping.ID, revision)
	return service.runtime.ensureChannel(ctx, operation, request)
}

// ruleRequest projects a mapping onto the entry-side host L4 rule: the rule
// listens for visitor traffic and forwards to the channel bridge endpoint on
// the entry agent loopback. The mapping tag makes the mapping ownership
// recognizable in the host rule list alongside the injected plugin tag.
func ruleRequest(mapping Mapping, session channelSession) pluginsdk.L4RuleRequest {
	name := mapping.Name
	if name == "" {
		name = mapping.ID
	}
	return pluginsdk.L4RuleRequest{
		AgentID:    mapping.EntryAgentID,
		Name:       "reverse-l4/" + name,
		Protocol:   mapping.Protocol,
		ListenPort: mapping.ListenPort,
		Backends: []pluginsdk.L4RuleBackend{{
			Host: session.BridgeHost,
			Port: session.BridgePort,
		}},
		Tags: []string{"reverse-l4", "mapping/" + mapping.ID},
	}
}

func ruleRefRequest(ruleRef, entryAgentID string) pluginsdk.L4RuleRequest {
	return pluginsdk.L4RuleRequest{RuleRef: ruleRef, AgentID: entryAgentID}
}

func generateMappingID() (string, error) {
	var raw [mappingIDRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("%w: id", ErrInvalidMapping)
	}
	id := hex.EncodeToString(raw[:])
	if !validMappingID(id) {
		return "", fmt.Errorf("%w: id", ErrInvalidMapping)
	}
	return id, nil
}

func allocateMappingID(snapshot mappingStateSnapshot) (string, error) {
	for attempt := 0; attempt < mappingIDAllocTries; attempt++ {
		id, err := generateMappingID()
		if err != nil {
			return "", err
		}
		if _, exists := snapshot.mapping(id); !exists {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: generated mapping id", ErrMappingExists)
}

// commit persists one mutated mapping (or removes it when removedID is set)
// under a fresh catalog revision.
func (service *Service) commit(ctx context.Context, snapshot mappingStateSnapshot, mapping Mapping, removedID *string) error {
	next := mappingStateSnapshot{Revision: snapshot.Revision + 1, Mappings: make([]Mapping, 0, len(snapshot.Mappings)+1)}
	for _, existing := range snapshot.Mappings {
		if removedID != nil && existing.ID == *removedID {
			continue
		}
		if mapping.ID != "" && existing.ID == mapping.ID {
			next.Mappings = append(next.Mappings, mapping.Clone())
			continue
		}
		next.Mappings = append(next.Mappings, existing.Clone())
	}
	if mapping.ID != "" && removedID == nil {
		replaced := false
		for _, existing := range next.Mappings {
			if existing.ID == mapping.ID {
				replaced = true
				break
			}
		}
		if !replaced {
			next.Mappings = append(next.Mappings, mapping.Clone())
		}
	}
	sortMappings(next.Mappings)
	return service.state.Save(ctx, next)
}

// channelStateNormalizes maps any host session state onto the two-value
// connectivity projection used by management surfaces.
func channelStateNormalize(state string) string {
	state = strings.TrimSpace(state)
	if state == pluginsdk.ChannelReverseStateOnline {
		return ChannelOnline
	}
	return ChannelOffline
}
