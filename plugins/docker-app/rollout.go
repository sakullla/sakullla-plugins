package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Deployment struct {
	AppID, InstanceID, Image, RuleRef, RuleTarget, Generation string
	Phase                                                     RolloutPhase
	PendingInstance, DesiredRuleTarget, PriorRuleTarget       string
	PriorImage, PriorGeneration, PriorRuleRef, PriorInstance  string
	LastFailure, Lease                                        string
	LeaseUntil                                                time.Time
	FencingToken                                              uint64
	PriorAbsent                                               bool
	ImageDigest, AvailableDigest, PriorDigest                 string
	History                                                   []DeploymentRevision
}

type DeploymentRevision struct {
	InstanceID, Image, RuleRef, RuleTarget, Generation, ImageDigest string
}

type RolloutPhase string

const (
	PhasePulling        RolloutPhase = "pulling"
	PhaseStarting       RolloutPhase = "starting"
	PhaseReadiness      RolloutPhase = "readiness"
	PhaseCutover        RolloutPhase = "cutover"
	PhaseDraining       RolloutPhase = "draining"
	PhaseActive         RolloutPhase = "active"
	PhaseCleanupPending RolloutPhase = "cleanup-pending"
	PhaseRouteReconcile RolloutPhase = "route-reconcile"

	AppStatusUpdateAvailable AppStatus = "update-available"
	AppStatusPublishing      AppStatus = "publishing"
	AppStatusUnhealthy       AppStatus = "unhealthy"

	DefaultAutoUpdate = false
)

const DefaultCleanupTimeout = time.Second

type DeploymentRecord struct {
	Version uint64
	Value   Deployment
}

// DeploymentStateStore is a durable versioned fencing boundary. AcquireLease
// must issue a strictly increasing token for an app. All later writes require
// both the record version and that token. DeploymentStore is test-only.
type DeploymentStateStore interface {
	Load(context.Context, string) (DeploymentRecord, bool, error)
	AcquireLease(context.Context, string, uint64, Deployment, time.Time) (DeploymentRecord, error)
	CompareAndSwap(context.Context, string, uint64, uint64, Deployment) (DeploymentRecord, error)
	DeleteCAS(context.Context, string, uint64, uint64) error
}

type DeploymentStore struct {
	mu     sync.RWMutex
	values map[string]DeploymentRecord
	fences map[string]uint64
}

func NewDeploymentStore() *DeploymentStore {
	return &DeploymentStore{values: make(map[string]DeploymentRecord), fences: make(map[string]uint64)}
}
func (s *DeploymentStore) Load(_ context.Context, id string) (DeploymentRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.values[id]
	return r, ok, nil
}
func (s *DeploymentStore) AcquireLease(_ context.Context, id string, version uint64, value Deployment, until time.Time) (DeploymentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.values[id]
	if current.Version != version {
		return DeploymentRecord{}, ErrStateConflict
	}
	s.fences[id]++
	value.AppID, value.FencingToken, value.Lease, value.LeaseUntil = id, s.fences[id], fmt.Sprintf("fence-%d", s.fences[id]), until
	next := DeploymentRecord{Version: version + 1, Value: value}
	s.values[id] = next
	return next, nil
}
func (s *DeploymentStore) CompareAndSwap(_ context.Context, id string, version, fence uint64, value Deployment) (DeploymentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.values[id]
	if current.Version != version || current.Value.FencingToken != fence {
		return DeploymentRecord{}, ErrStateConflict
	}
	value.AppID, value.FencingToken = id, fence
	next := DeploymentRecord{Version: version + 1, Value: value}
	s.values[id] = next
	return next, nil
}
func (s *DeploymentStore) DeleteCAS(_ context.Context, id string, version, fence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.values[id]
	if !ok || current.Version != version || current.Value.FencingToken != fence {
		return ErrStateConflict
	}
	delete(s.values, id)
	return nil
}
func (s *DeploymentStore) Get(id string) (Deployment, bool) {
	r, ok, _ := s.Load(context.Background(), id)
	return r.Value, ok
}
func (s *DeploymentStore) Put(value Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.values[value.AppID]
	if value.FencingToken > s.fences[value.AppID] {
		s.fences[value.AppID] = value.FencingToken
	}
	s.values[value.AppID] = DeploymentRecord{Version: current.Version + 1, Value: value}
}

type RuntimeState struct {
	RuleTarget, CandidateInstance string
	Instances                     map[string]bool
}

// RolloutExecutor is a capability host boundary. It must reject every effect
// whose fencing token is lower than the highest token observed for the app.
type RolloutExecutor interface {
	Pull(context.Context, uint64, string) error
	Start(context.Context, uint64, App) (string, error)
	Ready(context.Context, uint64, string) error
	Cutover(context.Context, uint64, string, string) error
	Drain(context.Context, uint64, string) error
	Remove(context.Context, uint64, string) error
	Inspect(context.Context, uint64, string, string) (RuntimeState, error)
}

type Rollout struct {
	Store                         DeploymentStateStore
	Executor                      RolloutExecutor
	Auditor                       Auditor
	CleanupTimeout, LeaseDuration time.Duration
	Clock                         func() time.Time
}

// UpdatePolicy decides whether a newer image digest is published automatically.
// A nil AutoUpdate means DefaultAutoUpdate (false): digest changes are
// projected as a new version until ConfirmUpdate.
type UpdatePolicy struct {
	AutoUpdate *bool
}

func AutoUpdateEnabled(flag *bool) bool {
	if flag == nil {
		return DefaultAutoUpdate
	}
	return *flag
}

func (policy UpdatePolicy) Automatic() bool {
	return AutoUpdateEnabled(policy.AutoUpdate)
}

func AutoUpdatePolicy(enabled bool) UpdatePolicy {
	return UpdatePolicy{AutoUpdate: &enabled}
}

type UpdateObservation struct {
	CurrentDigest string
	LatestDigest  string
}

type RolloutNotice struct {
	UpdateAvailable bool
	Digest          string
}

type UpdateView struct {
	AutoUpdate bool
	HasUpdate  bool
	Published  bool
	Digest     string
}

func ProjectUpdate(policy UpdatePolicy, currentDigest, latestDigest string) RolloutNotice {
	if policy.Automatic() || latestDigest == "" || currentDigest == "" || latestDigest == currentDigest {
		return RolloutNotice{}
	}
	return RolloutNotice{UpdateAvailable: true, Digest: latestDigest}
}

func ProjectManagedStatus(running, unhealthy bool, deployment Deployment, policy UpdatePolicy, latestDigest string) AppStatus {
	if deployment.Phase != "" && deployment.Phase != PhaseActive {
		return AppStatusPublishing
	}
	if unhealthy {
		return AppStatusUnhealthy
	}
	digest := deployment.AvailableDigest
	if digest == "" {
		digest = latestDigest
	}
	if !policy.Automatic() && digest != "" && deployment.ImageDigest != "" && digest != deployment.ImageDigest {
		return AppStatusUpdateAvailable
	}
	if running {
		return AppStatusRunning
	}
	return AppStatusStopped
}

func (r Rollout) Update(ctx context.Context, app App) error {
	return r.publish(ctx, app, "")
}

func (r Rollout) AutoUpdate(ctx context.Context, app App, flag *bool, observed UpdateObservation) (UpdateView, error) {
	if err := r.ready(&app); err != nil {
		return UpdateView{}, err
	}
	view := UpdateView{AutoUpdate: AutoUpdateEnabled(flag)}
	record, existed, err := r.Store.Load(ctx, app.ID)
	if err != nil {
		return UpdateView{}, safeFailure(ErrOperationFailed, err)
	}
	if rolloutBusy(record.Value, existed, r.now()) {
		return UpdateView{}, ErrReconcilePending
	}
	current := observed.CurrentDigest
	if existed && record.Value.ImageDigest != "" {
		current = record.Value.ImageDigest
	}
	latest := observed.LatestDigest
	if latest == "" || current == "" || latest == current {
		if current != "" {
			available := record.Value.AvailableDigest
			if latest != "" && latest == current {
				available = ""
			}
			if err := r.rememberDigest(ctx, record, app, current, available, existed); err != nil {
				return UpdateView{}, err
			}
		}
		return view, nil
	}
	view.HasUpdate = true
	view.Digest = latest
	if !view.AutoUpdate {
		if err := r.rememberDigest(ctx, record, app, current, latest, existed); err != nil {
			return UpdateView{}, err
		}
		audit(r.Auditor, AuditRecord{Action: "rollout.available", Outcome: "projected", Detail: app.ID})
		return view, nil
	}
	if err := r.publish(ctx, app, latest); err != nil {
		return UpdateView{}, err
	}
	view.Published = true
	return view, nil
}

func (r Rollout) ConfirmUpdate(ctx context.Context, app App) error {
	if err := r.ready(&app); err != nil {
		return err
	}
	record, ok, err := r.Store.Load(ctx, app.ID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if !ok || record.Value.AvailableDigest == "" {
		audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if record.Value.AvailableDigest == record.Value.ImageDigest {
		return nil
	}
	return r.publish(ctx, app, record.Value.AvailableDigest)
}

func (r Rollout) Rollback(ctx context.Context, appID string) error {
	if err := r.ready(nil); err != nil {
		return err
	}
	record, ok, err := r.Store.Load(ctx, appID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if !ok || len(record.Value.History) == 0 {
		audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if rolloutBusy(record.Value, true, r.now()) {
		return ErrReconcilePending
	}
	current := record.Value
	rev := current.History[len(current.History)-1]
	if rev.InstanceID != "" {
		history := r.forgetGoneHistoryInstance(record, current.History, rev.InstanceID)
		if history[len(history)-1].InstanceID == "" {
			current.History = history
			if _, err := r.Store.CompareAndSwap(ctx, appID, record.Version, current.FencingToken, current); err != nil {
				return ErrReconcilePending
			}
			rev.InstanceID = ""
		}
	}
	if rev.InstanceID == "" || rev.Image == "" || rev.RuleRef == "" {
		app := App{ID: appID, Image: pinImageDigest(rev.Image, rev.ImageDigest), RuleRef: rev.RuleRef, Generation: rev.Generation}
		if err := app.Validate(); err != nil {
			audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
			return safeFailure(ErrInvalidPreview, err)
		}
		return r.publish(ctx, app, rev.ImageDigest)
	}
	// PendingInstance names the history instance so Reconcile cannot treat the
	// still-serving instance as disposable or Remove the rollback target.
	leased, err := r.Store.AcquireLease(ctx, appID, record.Version, historicalRollbackIntent(current, rev), r.now().Add(r.leaseDuration()))
	if err != nil {
		return ErrReconcilePending
	}
	r.progress(App{ID: appID}, PhaseCutover)
	if err := r.Executor.Cutover(ctx, leased.Value.FencingToken, rev.RuleRef, rev.InstanceID); err != nil {
		return r.abortHistoricalRollback(leased, current, false, err)
	}
	if current.InstanceID != "" && current.InstanceID != rev.InstanceID {
		r.progress(App{ID: appID}, PhaseDraining)
		if err := r.Executor.Drain(ctx, leased.Value.FencingToken, current.InstanceID); err != nil {
			return r.abortHistoricalRollback(leased, current, true, err)
		}
	}
	history := cloneRevisions(current.History)
	if n := len(history); n > 0 {
		history = history[:n-1]
	}
	target := rev.RuleTarget
	if target == "" {
		target = rev.InstanceID
	}
	restored := Deployment{
		AppID: appID, InstanceID: rev.InstanceID, Image: rev.Image, RuleRef: rev.RuleRef, RuleTarget: target,
		Generation: rev.Generation, Phase: PhaseActive, FencingToken: leased.Value.FencingToken,
		ImageDigest: rev.ImageDigest, History: history,
	}
	if _, err := r.Store.CompareAndSwap(ctx, appID, leased.Version, leased.Value.FencingToken, restored); err != nil {
		return ErrReconcilePending
	}
	audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "succeeded", Detail: appID})
	return nil
}

func historicalRollbackIntent(current Deployment, rev DeploymentRevision) Deployment {
	intent := current
	intent.Phase = PhaseCutover
	intent.PendingInstance = rev.InstanceID
	intent.DesiredRuleTarget = rev.InstanceID
	intent.PriorInstance = current.InstanceID
	intent.PriorImage = current.Image
	intent.PriorGeneration = current.Generation
	intent.PriorRuleRef = current.RuleRef
	intent.PriorRuleTarget = current.RuleTarget
	intent.PriorDigest = current.ImageDigest
	intent.PriorAbsent = false
	intent.Image = rev.Image
	intent.RuleRef = rev.RuleRef
	intent.Generation = rev.Generation
	intent.ImageDigest = rev.ImageDigest
	intent.AvailableDigest = ""
	return intent
}

func historicalRollbackPending(value Deployment) bool {
	if value.PendingInstance == "" {
		return false
	}
	for _, rev := range value.History {
		if rev.InstanceID == value.PendingInstance {
			return true
		}
	}
	return false
}

func clearHistoryInstance(history []DeploymentRevision, instanceID string) []DeploymentRevision {
	out := cloneRevisions(history)
	if instanceID == "" {
		return out
	}
	for i := range out {
		if out[i].InstanceID == instanceID {
			out[i].InstanceID = ""
		}
	}
	return out
}

func (r Rollout) forgetGoneHistoryInstance(record DeploymentRecord, history []DeploymentRevision, instanceID string) []DeploymentRevision {
	if instanceID == "" || len(history) == 0 {
		return history
	}
	ctx, cancel := r.cleanupContext()
	state, err := r.Executor.Inspect(ctx, record.Value.FencingToken, record.Value.AppID, record.Value.RuleRef)
	cancel()
	if err != nil || state.Instances[instanceID] {
		return history
	}
	return clearHistoryInstance(history, instanceID)
}

func (r Rollout) abortHistoricalRollback(record DeploymentRecord, original Deployment, routeMayPending bool, cause error) error {
	original.History = r.forgetGoneHistoryInstance(record, original.History, record.Value.PendingInstance)
	return r.restoreActive(record, original, routeMayPending, cause)
}

func (r Rollout) restoreHistoricalPrior(record DeploymentRecord, state RuntimeState, priorInstance, pending string, pendingExists bool) error {
	v, fence := record.Value, record.Value.FencingToken
	if v.PriorAbsent || priorInstance == "" || !state.Instances[priorInstance] {
		return r.release(record, ErrReconcilePending)
	}
	if state.RuleTarget != v.PriorRuleTarget && v.PriorRuleRef != "" && v.PriorRuleTarget != "" {
		ctx, cancel := r.cleanupContext()
		err := r.Executor.Cutover(ctx, fence, v.PriorRuleRef, v.PriorRuleTarget)
		cancel()
		if err != nil {
			return r.release(record, safeFailure(ErrOperationFailed, err))
		}
	}
	history := v.History
	if !pendingExists {
		history = clearHistoryInstance(history, pending)
	}
	prior := Deployment{
		AppID: v.AppID, InstanceID: priorInstance, Image: v.PriorImage, RuleRef: v.PriorRuleRef,
		RuleTarget: v.PriorRuleTarget, Generation: v.PriorGeneration, Phase: PhaseActive,
		FencingToken: fence, ImageDigest: v.PriorDigest, History: history,
	}
	ctx, cancel := r.cleanupContext()
	_, err := r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, prior)
	cancel()
	return err
}

func (r Rollout) restoreActive(record DeploymentRecord, original Deployment, routeMayPending bool, cause error) error {
	target := original.RuleTarget
	if target == "" {
		target = original.InstanceID
	}
	if routeMayPending && original.RuleRef != "" && target != "" {
		ctx, cancel := r.cleanupContext()
		err := r.Executor.Cutover(ctx, record.Value.FencingToken, original.RuleRef, target)
		cancel()
		if err != nil {
			cause = errors.Join(cause, err)
		}
	}
	restored := original
	restored.AppID = record.Value.AppID
	restored.Phase = PhaseActive
	restored.FencingToken = record.Value.FencingToken
	restored.Lease = ""
	restored.LeaseUntil = time.Time{}
	restored.PendingInstance = ""
	restored.DesiredRuleTarget = ""
	ctx, cancel := r.cleanupContext()
	_, persistErr := r.Store.CompareAndSwap(ctx, restored.AppID, record.Version, record.Value.FencingToken, restored)
	cancel()
	if persistErr != nil {
		return r.fail(errors.Join(cause, persistErr))
	}
	return r.fail(cause)
}

func (r Rollout) HealthRecover(ctx context.Context, app App) error {
	if err := r.ready(&app); err != nil {
		return err
	}
	record, existed, err := r.Store.Load(ctx, app.ID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if rolloutBusy(record.Value, existed, r.now()) {
		return ErrReconcilePending
	}
	digest := ""
	if existed && record.Value.ImageDigest != "" {
		app.Image = pinImageDigest(app.Image, record.Value.ImageDigest)
		digest = record.Value.ImageDigest
	}
	return r.publish(ctx, app, digest)
}

func (r Rollout) publish(ctx context.Context, app App, digest string) error {
	if r.Auditor == nil {
		return ErrAuditRequired
	}
	if err := app.Validate(); err != nil {
		audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	if r.Store == nil || r.Executor == nil {
		audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	prior, existed, err := r.Store.Load(ctx, app.ID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if existed && ((prior.Value.Phase != "" && prior.Value.Phase != PhaseActive) || (prior.Value.Lease != "" && prior.Value.LeaseUntil.After(r.now()))) {
		return ErrReconcilePending
	}
	// Acquiring the lease is also the first durable intent. A successful or
	// outcome-unknown AcquireLease must never leave a record that still looks
	// active while carrying the new desired metadata. Build this value from
	// scratch so recovery fields from an earlier rollout cannot leak forward.
	pulling := Deployment{
		AppID:             app.ID,
		InstanceID:        prior.Value.InstanceID,
		Image:             app.Image,
		RuleRef:           app.RuleRef,
		RuleTarget:        prior.Value.RuleTarget,
		Generation:        app.Generation,
		Phase:             PhasePulling,
		PriorImage:        prior.Value.Image,
		PriorGeneration:   prior.Value.Generation,
		PriorRuleRef:      prior.Value.RuleRef,
		PriorRuleTarget:   prior.Value.RuleTarget,
		PriorInstance:     prior.Value.InstanceID,
		PriorAbsent:       priorInstanceAbsent(existed, prior.Value.InstanceID),
		DesiredRuleTarget: "", // no candidate exists until Start succeeds
		ImageDigest:       digest,
		AvailableDigest:   prior.Value.AvailableDigest,
		PriorDigest:       prior.Value.ImageDigest,
		History:           cloneRevisions(prior.Value.History),
	}
	record, err := r.Store.AcquireLease(ctx, app.ID, prior.Version, pulling, r.now().Add(r.leaseDuration()))
	if err != nil {
		return ErrReconcilePending
	}
	r.progress(app, PhasePulling)
	if err = r.Executor.Pull(ctx, record.Value.FencingToken, app.Image); err != nil {
		return r.rollback(record, prior.Value, existed, "", false, err)
	}
	if record, err = r.intent(ctx, record, PhaseStarting, "", prior.Value.RuleTarget, ""); err != nil {
		return ErrReconcilePending
	}
	r.progress(app, PhaseStarting)
	pending, startErr := r.Executor.Start(ctx, record.Value.FencingToken, app)
	if startErr != nil {
		return r.rollback(record, prior.Value, existed, pending, false, startErr)
	}
	if record, err = r.intent(ctx, record, PhaseReadiness, pending, prior.Value.RuleTarget, prior.Value.RuleTarget); err != nil {
		return ErrReconcilePending
	}
	r.progress(app, PhaseReadiness)
	if err = r.Executor.Ready(ctx, record.Value.FencingToken, pending); err != nil {
		return r.rollback(record, prior.Value, existed, pending, false, err)
	}
	if record, err = r.intent(ctx, record, PhaseCutover, pending, prior.Value.RuleTarget, pending); err != nil {
		return ErrReconcilePending
	}
	r.progress(app, PhaseCutover)
	if err = r.Executor.Cutover(ctx, record.Value.FencingToken, app.RuleRef, pending); err != nil {
		return r.rollback(record, prior.Value, existed, pending, true, err)
	}
	if record, err = r.intent(ctx, record, PhaseDraining, pending, pending, pending); err != nil {
		return ErrReconcilePending
	}
	if existed && prior.Value.InstanceID != "" {
		r.progress(app, PhaseDraining)
		if err = r.Executor.Drain(ctx, record.Value.FencingToken, prior.Value.InstanceID); err != nil {
			return r.rollback(record, prior.Value, true, pending, true, err)
		}
	}
	active := Deployment{AppID: app.ID, InstanceID: pending, Image: app.Image, RuleRef: app.RuleRef, RuleTarget: pending, Generation: app.Generation, Phase: PhaseActive, FencingToken: record.Value.FencingToken, ImageDigest: digest, History: publishedHistory(record.Value)}
	if _, err = r.Store.CompareAndSwap(ctx, app.ID, record.Version, record.Value.FencingToken, active); err != nil {
		return ErrReconcilePending
	}
	audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func (r Rollout) intent(ctx context.Context, record DeploymentRecord, phase RolloutPhase, pending, actual, desired string) (DeploymentRecord, error) {
	v := record.Value
	v.Phase, v.PendingInstance, v.RuleTarget, v.DesiredRuleTarget = phase, pending, actual, desired
	return r.Store.CompareAndSwap(ctx, v.AppID, record.Version, v.FencingToken, v)
}

func (r Rollout) rollback(record DeploymentRecord, prior Deployment, existed bool, pending string, routeMayPending bool, cause error) error {
	v := record.Value
	v.PendingInstance, v.PriorAbsent, v.PriorRuleTarget, v.LastFailure = pending, priorInstanceAbsent(existed, prior.InstanceID), prior.RuleTarget, ErrOperationFailed.Error()
	phase := PhaseCleanupPending
	if routeMayPending {
		phase = PhaseRouteReconcile
	}
	v.Phase, v.DesiredRuleTarget = phase, prior.RuleTarget
	ctx, cancel := r.cleanupContext()
	next, persistErr := r.Store.CompareAndSwap(ctx, v.AppID, record.Version, v.FencingToken, v)
	cancel()
	if persistErr != nil {
		return r.fail(errors.Join(cause, persistErr))
	}
	reconcileErr := r.reconcileRecord(next)
	return r.fail(errors.Join(cause, reconcileErr))
}

func (r Rollout) Reconcile(ctx context.Context, appID string) error {
	if r.Auditor == nil {
		return ErrAuditRequired
	}
	if r.Store == nil || r.Executor == nil {
		audit(r.Auditor, AuditRecord{Action: "rollout.reconcile", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	record, ok, err := r.Store.Load(ctx, appID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if !ok || record.Value.Phase == PhaseActive || (record.Value.Lease != "" && record.Value.LeaseUntil.After(r.now())) {
		return ErrReconcilePending
	}
	v := record.Value
	v.Lease = ""
	leased, err := r.Store.AcquireLease(ctx, appID, record.Version, v, r.now().Add(r.leaseDuration()))
	if err != nil {
		return ErrReconcilePending
	}
	err = r.reconcileRecord(leased)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	audit(r.Auditor, AuditRecord{Action: "rollout.reconcile", Outcome: outcome, Detail: map[bool]string{true: ErrOperationFailed.Error(), false: appID}[err != nil]})
	return err
}

func (r Rollout) reconcileRecord(record DeploymentRecord) error {
	v, fence := record.Value, record.Value.FencingToken
	priorInstance := v.PriorInstance
	if priorInstance == "" {
		priorInstance = v.InstanceID
	}
	inspectRef := v.RuleRef
	if v.Phase != PhaseCutover && v.Phase != PhaseDraining && v.Phase != PhaseRouteReconcile && !v.PriorAbsent {
		inspectRef = v.PriorRuleRef
	}
	ctx, cancel := r.cleanupContext()
	state, inspectErr := r.Executor.Inspect(ctx, fence, v.AppID, inspectRef)
	cancel()
	if inspectErr != nil {
		return r.release(record, safeFailure(ErrOperationFailed, inspectErr))
	}
	pending := v.PendingInstance
	if pending == "" {
		pending = state.CandidateInstance
	}
	if pending != v.PendingInstance {
		v.PendingInstance = pending
		ctx, cancel = r.cleanupContext()
		var err error
		record, err = r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, v)
		cancel()
		if err != nil {
			return err
		}
	}
	priorExists := !v.PriorAbsent && priorInstance != "" && state.Instances[priorInstance]
	newExists := pending != "" && state.Instances[pending]
	unrelated := state.RuleTarget != "" && state.RuleTarget != v.PriorRuleTarget && state.RuleTarget != pending
	if unrelated {
		return r.release(record, ErrReconcilePending)
	}
	finishNew := (v.Phase == PhaseCutover || v.Phase == PhaseDraining) && newExists && state.RuleTarget == pending
	if !finishNew && historicalRollbackPending(v) {
		return r.restoreHistoricalPrior(record, state, priorInstance, pending, newExists)
	}
	if finishNew {
		if priorExists {
			ctx, cancel = r.cleanupContext()
			err := r.Executor.Drain(ctx, fence, priorInstance)
			cancel()
			if err != nil {
				return r.release(record, safeFailure(ErrOperationFailed, err))
			}
		}
		ctx, cancel = r.cleanupContext()
		post, err := r.Executor.Inspect(ctx, fence, v.AppID, v.RuleRef)
		cancel()
		if err != nil || !post.Instances[pending] || post.RuleTarget != pending {
			return r.release(record, ErrReconcilePending)
		}
		active := Deployment{AppID: v.AppID, InstanceID: pending, Image: v.Image, RuleRef: v.RuleRef, RuleTarget: pending, Generation: v.Generation, Phase: PhaseActive, FencingToken: fence, ImageDigest: v.ImageDigest, History: publishedHistory(v)}
		ctx, cancel = r.cleanupContext()
		_, err = r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, active)
		cancel()
		if err != nil {
			return err
		}
		return nil
	}
	if !v.PriorAbsent {
		if !priorExists {
			return r.release(record, ErrReconcilePending)
		}
		if state.RuleTarget != v.PriorRuleTarget {
			ctx, cancel = r.cleanupContext()
			err := r.Executor.Cutover(ctx, fence, v.PriorRuleRef, v.PriorRuleTarget)
			cancel()
			if err != nil {
				return r.release(record, safeFailure(ErrOperationFailed, err))
			}
		}
	} else if pending != "" && state.RuleTarget == pending {
		return r.release(record, ErrReconcilePending)
	}
	if newExists {
		v.Phase = PhaseCleanupPending
		ctx, cancel = r.cleanupContext()
		var err error
		record, err = r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, v)
		cancel()
		if err != nil {
			return err
		}
		ctx, cancel = r.cleanupContext()
		err = r.Executor.Remove(ctx, fence, pending)
		cancel()
		if err != nil {
			return r.release(record, safeFailure(ErrOperationFailed, err))
		}
	}
	ctx, cancel = r.cleanupContext()
	postRef := v.RuleRef
	if !v.PriorAbsent {
		postRef = v.PriorRuleRef
	}
	post, err := r.Executor.Inspect(ctx, fence, v.AppID, postRef)
	cancel()
	if err != nil || (pending != "" && post.Instances[pending]) {
		return r.release(record, ErrReconcilePending)
	}
	if v.PriorAbsent {
		if pending != "" && post.RuleTarget == pending {
			return r.release(record, ErrReconcilePending)
		}
		if v.PriorImage != "" || v.PriorDigest != "" || v.PriorGeneration != "" {
			restored := Deployment{
				AppID: v.AppID, Image: v.PriorImage, RuleRef: v.PriorRuleRef, Generation: v.PriorGeneration,
				Phase: PhaseActive, FencingToken: fence, ImageDigest: v.PriorDigest,
				AvailableDigest: v.AvailableDigest, History: cloneRevisions(v.History),
			}
			ctx, cancel = r.cleanupContext()
			_, err = r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, restored)
			cancel()
			return err
		}
		ctx, cancel = r.cleanupContext()
		err = r.Store.DeleteCAS(ctx, v.AppID, record.Version, fence)
		cancel()
		return err
	}
	if !post.Instances[priorInstance] || post.RuleTarget != v.PriorRuleTarget {
		return r.release(record, ErrReconcilePending)
	}
	prior := v
	prior.InstanceID, prior.Image, prior.Generation, prior.RuleRef = priorInstance, v.PriorImage, v.PriorGeneration, v.PriorRuleRef
	prior.Phase, prior.RuleTarget, prior.PendingInstance, prior.DesiredRuleTarget, prior.PriorRuleTarget, prior.LastFailure, prior.Lease, prior.LeaseUntil, prior.PriorAbsent = PhaseActive, v.PriorRuleTarget, "", "", "", "", "", time.Time{}, false
	prior.PriorImage, prior.PriorGeneration, prior.PriorRuleRef, prior.PriorInstance = "", "", "", ""
	prior.ImageDigest, prior.AvailableDigest, prior.PriorDigest = v.PriorDigest, "", ""
	ctx, cancel = r.cleanupContext()
	_, err = r.Store.CompareAndSwap(ctx, v.AppID, record.Version, fence, prior)
	cancel()
	return err
}

func (r Rollout) release(record DeploymentRecord, result error) error {
	v := record.Value
	v.Lease, v.LeaseUntil = "", time.Time{}
	ctx, cancel := r.cleanupContext()
	_, err := r.Store.CompareAndSwap(ctx, v.AppID, record.Version, v.FencingToken, v)
	cancel()
	return errors.Join(result, err)
}
func (r Rollout) cleanupContext() (context.Context, context.CancelFunc) {
	d := r.CleanupTimeout
	if d <= 0 {
		d = DefaultCleanupTimeout
	}
	return context.WithTimeout(context.Background(), d)
}
func (r Rollout) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}
func (r Rollout) leaseDuration() time.Duration {
	if r.LeaseDuration > 0 {
		return r.LeaseDuration
	}
	return 30 * time.Second
}
func (r Rollout) progress(app App, phase RolloutPhase) {
	audit(r.Auditor, AuditRecord{Action: "rollout.progress", Outcome: string(phase), Detail: app.ID})
}
func (r Rollout) fail(err error) error {
	audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "failed", Detail: ErrOperationFailed.Error()})
	return safeFailure(ErrOperationFailed, err)
}

func (r Rollout) ready(app *App) error {
	if r.Auditor == nil {
		return ErrAuditRequired
	}
	if app != nil {
		if err := app.Validate(); err != nil {
			audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
			return safeFailure(ErrInvalidPreview, err)
		}
	}
	if r.Store == nil || r.Executor == nil {
		audit(r.Auditor, AuditRecord{Action: "rollout", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (r Rollout) rememberDigest(ctx context.Context, record DeploymentRecord, app App, current, available string, existed bool) error {
	v := record.Value
	if existed && v.ImageDigest == current && v.AvailableDigest == available {
		return nil
	}
	if !existed {
		seed := Deployment{
			AppID: app.ID, Image: app.Image, RuleRef: app.RuleRef, Generation: app.Generation,
			Phase: PhaseActive, ImageDigest: current, AvailableDigest: available,
		}
		leased, err := r.Store.AcquireLease(ctx, app.ID, record.Version, seed, r.now().Add(r.leaseDuration()))
		if err != nil {
			return ErrReconcilePending
		}
		seeded := leased.Value
		seeded.Lease, seeded.LeaseUntil = "", time.Time{}
		if _, err := r.Store.CompareAndSwap(ctx, app.ID, leased.Version, leased.Value.FencingToken, seeded); err != nil {
			return ErrReconcilePending
		}
		return nil
	}
	v.ImageDigest, v.AvailableDigest = current, available
	if _, err := r.Store.CompareAndSwap(ctx, app.ID, record.Version, v.FencingToken, v); err != nil {
		return ErrReconcilePending
	}
	return nil
}

func priorInstanceAbsent(existed bool, instanceID string) bool {
	return !existed || instanceID == ""
}

func rolloutBusy(value Deployment, existed bool, now time.Time) bool {
	return existed && ((value.Phase != "" && value.Phase != PhaseActive) || (value.Lease != "" && value.LeaseUntil.After(now)))
}

func publishedHistory(value Deployment) []DeploymentRevision {
	if value.PriorAbsent || (value.PriorInstance == "" && value.PriorImage == "") {
		return cloneRevisions(value.History)
	}
	return []DeploymentRevision{{
		InstanceID:  value.PriorInstance,
		Image:       value.PriorImage,
		RuleRef:     value.PriorRuleRef,
		RuleTarget:  value.PriorRuleTarget,
		Generation:  value.PriorGeneration,
		ImageDigest: value.PriorDigest,
	}}
}

func cloneRevisions(history []DeploymentRevision) []DeploymentRevision {
	if len(history) == 0 {
		return nil
	}
	return append([]DeploymentRevision(nil), history...)
}

func pinImageDigest(image, digest string) string {
	if digest == "" || image == "" || strings.Contains(image, "@") {
		return image
	}
	pinned := image + "@" + digest
	if !boundedText(pinned, 512) {
		return image
	}
	return pinned
}

type ResourceOwner string

const (
	OwnerPlugin ResourceOwner = "plugin"
	OwnerCore   ResourceOwner = "core"
)

type ResourceImpact struct {
	Kind, ID string
	Owner    ResourceOwner
	Shared   bool
}
type DeletePreview struct {
	AppID, Generation, Digest string
	Impacts                   []ResourceImpact
}

func PreviewDelete(appID, generation string, impacts []ResourceImpact) (DeletePreview, error) {
	if !validID(appID) || !boundedText(generation, 128) || len(impacts) > MaxCollectionItems {
		return DeletePreview{}, ErrBoundExceeded
	}
	normalized := append([]ResourceImpact(nil), impacts...)
	for _, impact := range normalized {
		if !boundedText(impact.Kind, 64) || !boundedText(impact.ID, 128) || (impact.Owner != OwnerPlugin && impact.Owner != OwnerCore) {
			return DeletePreview{}, errors.New("delete impact is invalid")
		}
	}
	sort.Slice(normalized, func(i, j int) bool {
		a, b := normalized[i], normalized[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		return !a.Shared && b.Shared
	})
	for i := 1; i < len(normalized); i++ {
		if normalized[i-1].Kind == normalized[i].Kind && normalized[i-1].ID == normalized[i].ID {
			return DeletePreview{}, errors.New("delete impact identity is duplicated or conflicting")
		}
	}
	digest, err := canonicalDigest(struct {
		AppID, Generation string
		Impacts           []ResourceImpact
	}{appID, generation, normalized})
	if err != nil {
		return DeletePreview{}, ErrInvalidPreview
	}
	return DeletePreview{appID, generation, digest, normalized}, nil
}

type DeleteExecutor interface {
	DeleteOwned(context.Context, string, ResourceImpact) error
	ReleaseCoreRef(context.Context, string, ResourceImpact) error
}
type DeleteInventory interface {
	CurrentDelete(context.Context, string, string) ([]ResourceImpact, error)
}
type DeleteInventoryFunc func(context.Context, string, string) ([]ResourceImpact, error)

func (f DeleteInventoryFunc) CurrentDelete(ctx context.Context, a, g string) ([]ResourceImpact, error) {
	return f(ctx, a, g)
}
func ExecuteDelete(ctx context.Context, shown DeletePreview, authorization Authorization, inventory DeleteInventory, verifier AuthorizationVerifier, executor DeleteExecutor, journal ProgressJournal, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if inventory == nil || verifier == nil || executor == nil || journal == nil {
		audit(auditor, AuditRecord{Action: "delete", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	impacts, err := inventory.CurrentDelete(ctx, shown.AppID, shown.Generation)
	if err != nil {
		audit(auditor, AuditRecord{Action: "delete", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	trusted, err := PreviewDelete(shown.AppID, shown.Generation, impacts)
	if err != nil {
		audit(auditor, AuditRecord{Action: "delete", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	shownDigest, _ := canonicalDigest(struct {
		AppID, Generation string
		Impacts           []ResourceImpact
	}{shown.AppID, shown.Generation, shown.Impacts})
	if shownDigest != shown.Digest || shown.Digest != trusted.Digest || authorization.AppID != trusted.AppID || authorization.Generation != trusted.Generation || authorization.PreviewDigest != trusted.Digest {
		audit(auditor, AuditRecord{Action: "delete", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if err := verifier.Verify(ctx, authorization, trusted.AppID, trusted.Generation, trusted.Digest); err != nil {
		audit(auditor, AuditRecord{Action: "delete", Outcome: "denied", Detail: ErrUnauthorized.Error()})
		return safeFailure(ErrUnauthorized, err)
	}
	operation := trusted.Digest
	for _, impact := range trusted.Impacts {
		if impact.Shared {
			continue
		}
		effect, _ := canonicalDigest(impact)
		done, e := journal.Completed(ctx, operation, effect)
		if e != nil {
			audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, e)
		}
		if done {
			continue
		}
		audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "applying", Detail: effect})
		key, _ := canonicalDigest(struct{ Operation, Effect string }{operation, effect})
		if impact.Owner == OwnerCore {
			e = executor.ReleaseCoreRef(ctx, key, impact)
		} else {
			e = executor.DeleteOwned(ctx, key, impact)
		}
		if e != nil {
			audit(auditor, AuditRecord{Action: "delete", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, e)
		}
		if e = journal.MarkCompleted(ctx, operation, effect); e != nil {
			audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, e)
		}
		audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "completed", Detail: effect})
	}
	audit(auditor, AuditRecord{Action: "delete", Outcome: "succeeded", Detail: trusted.AppID})
	return nil
}
