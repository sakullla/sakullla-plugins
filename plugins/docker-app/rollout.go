package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Deployment struct {
	AppID, InstanceID, Image, RuleRef, RuleTarget, Generation string
	Phase                                                     RolloutPhase
	PendingInstance, DesiredRuleTarget, LastFailure, Lease    string
	LeaseUntil                                                time.Time
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
)

const DefaultCleanupTimeout = time.Second

type DeploymentRecord struct {
	Version uint64
	Value   Deployment
}

// DeploymentStateStore is the durable CAS boundary. Production adapters must
// persist records and versions across process restart. DeploymentStore is only
// the deterministic in-memory repository model.
type DeploymentStateStore interface {
	Load(context.Context, string) (DeploymentRecord, bool, error)
	CompareAndSwap(context.Context, string, uint64, Deployment) (DeploymentRecord, error)
}

type DeploymentStore struct {
	mu     sync.RWMutex
	values map[string]DeploymentRecord
}

func NewDeploymentStore() *DeploymentStore {
	return &DeploymentStore{values: make(map[string]DeploymentRecord)}
}
func (store *DeploymentStore) Load(_ context.Context, appID string) (DeploymentRecord, bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	record, ok := store.values[appID]
	return record, ok, nil
}
func (store *DeploymentStore) CompareAndSwap(_ context.Context, appID string, expected uint64, value Deployment) (DeploymentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.values[appID]
	if current.Version != expected {
		return DeploymentRecord{}, ErrStateConflict
	}
	value.AppID = appID
	next := DeploymentRecord{Version: expected + 1, Value: value}
	store.values[appID] = next
	return next, nil
}
func (store *DeploymentStore) Get(appID string) (Deployment, bool) {
	record, ok, _ := store.Load(context.Background(), appID)
	return record.Value, ok
}
func (store *DeploymentStore) Put(value Deployment) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.values[value.AppID]
	store.values[value.AppID] = DeploymentRecord{Version: current.Version + 1, Value: value}
}

type RuntimeState struct {
	RuleTarget string
	Instances  map[string]bool
}

// RolloutExecutor is a capability-backed business adapter. Production uses
// future typed public SDK handles; this is not a Host wire contract.
type RolloutExecutor interface {
	Pull(context.Context, string) error
	Start(context.Context, App) (string, error)
	Ready(context.Context, string) error
	Cutover(context.Context, string, string) error
	Drain(context.Context, string) error
	Remove(context.Context, string) error
	Inspect(context.Context, string, string) (RuntimeState, error)
}

type Rollout struct {
	Store          DeploymentStateStore
	Executor       RolloutExecutor
	Auditor        Auditor
	CleanupTimeout time.Duration
	LeaseDuration  time.Duration
	Clock          func() time.Time
}

var leaseSequence atomic.Uint64

func (rollout Rollout) Update(ctx context.Context, app App) error {
	if rollout.Auditor == nil {
		return ErrAuditRequired
	}
	if err := app.Validate(); err != nil {
		audit(rollout.Auditor, AuditRecord{Action: "rollout", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	if rollout.Store == nil || rollout.Executor == nil {
		audit(rollout.Auditor, AuditRecord{Action: "rollout", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	oldRecord, hadOld, err := rollout.Store.Load(ctx, app.ID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	old := oldRecord.Value
	now := rollout.now()
	if hadOld && (old.Phase == PhaseCleanupPending || old.Phase == PhaseRouteReconcile || (old.Lease != "" && old.LeaseUntil.After(now))) {
		return ErrReconcilePending
	}
	lease := fmt.Sprintf("rollout-%d", leaseSequence.Add(1))
	leased := old
	leased.AppID, leased.Lease, leased.LeaseUntil = app.ID, lease, now.Add(rollout.leaseDuration())
	leasedRecord, err := rollout.Store.CompareAndSwap(ctx, app.ID, oldRecord.Version, leased)
	if err != nil {
		return ErrReconcilePending
	}
	restoreOld := func() error {
		_, err := rollout.Store.CompareAndSwap(context.Background(), app.ID, leasedRecord.Version, old)
		return err
	}
	persistPending := func(phase RolloutPhase, pending, actualTarget, desiredTarget string, cause error) error {
		value := old
		value.AppID, value.Generation, value.PendingInstance, value.RuleTarget = app.ID, app.Generation, pending, actualTarget
		value.DesiredRuleTarget, value.Phase, value.LastFailure, value.Lease, value.LeaseUntil = desiredTarget, phase, ErrOperationFailed.Error(), "", time.Time{}
		_, err := rollout.Store.CompareAndSwap(context.Background(), app.ID, leasedRecord.Version, value)
		return errors.Join(cause, err)
	}
	fail := func(phase string, cause error) error {
		audit(rollout.Auditor, AuditRecord{Action: "rollout." + phase, Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return fmt.Errorf("rollout %s: %w", phase, safeFailure(ErrOperationFailed, cause))
	}
	rollout.progress(app, PhasePulling)
	if err := rollout.Executor.Pull(ctx, app.Image); err != nil {
		return fail("pull", errors.Join(err, restoreOld()))
	}
	rollout.progress(app, PhaseStarting)
	newInstance, err := rollout.Executor.Start(ctx, app)
	if err != nil {
		if newInstance == "" {
			return fail("start", errors.Join(err, restoreOld()))
		}
		removeErr := rollout.removeWithCleanup(newInstance)
		if removeErr != nil {
			return fail("start", persistPending(PhaseCleanupPending, newInstance, old.RuleTarget, old.RuleTarget, errors.Join(err, removeErr)))
		}
		return fail("start", errors.Join(err, restoreOld()))
	}
	rollout.progress(app, PhaseReadiness)
	if err := rollout.Executor.Ready(ctx, newInstance); err != nil {
		removeErr := rollout.removeWithCleanup(newInstance)
		if removeErr != nil {
			return fail("readiness", persistPending(PhaseCleanupPending, newInstance, old.RuleTarget, old.RuleTarget, errors.Join(err, removeErr)))
		}
		return fail("readiness", errors.Join(err, restoreOld()))
	}
	rollout.progress(app, PhaseCutover)
	if err := rollout.Executor.Cutover(ctx, app.RuleRef, newInstance); err != nil {
		if hadOld {
			restoreErr := rollout.restoreWithCleanup(old)
			if restoreErr != nil {
				return fail("cutover", persistPending(PhaseRouteReconcile, newInstance, newInstance, old.RuleTarget, errors.Join(err, restoreErr)))
			}
		}
		removeErr := rollout.removeWithCleanup(newInstance)
		if removeErr != nil {
			return fail("cutover", persistPending(PhaseCleanupPending, newInstance, old.RuleTarget, old.RuleTarget, errors.Join(err, removeErr)))
		}
		return fail("cutover", errors.Join(err, restoreOld()))
	}
	if hadOld && old.InstanceID != "" {
		rollout.progress(app, PhaseDraining)
		if err := rollout.Executor.Drain(ctx, old.InstanceID); err != nil {
			restoreErr := rollout.restoreWithCleanup(old)
			if restoreErr != nil {
				return fail("drain", persistPending(PhaseRouteReconcile, newInstance, newInstance, old.RuleTarget, errors.Join(err, restoreErr)))
			}
			removeErr := rollout.removeWithCleanup(newInstance)
			if removeErr != nil {
				return fail("drain", persistPending(PhaseCleanupPending, newInstance, old.RuleTarget, old.RuleTarget, errors.Join(err, removeErr)))
			}
			return fail("drain", errors.Join(err, restoreOld()))
		}
	}
	active := Deployment{AppID: app.ID, InstanceID: newInstance, Image: app.Image, RuleRef: app.RuleRef, RuleTarget: newInstance, Generation: app.Generation, Phase: PhaseActive}
	if _, err := rollout.Store.CompareAndSwap(ctx, app.ID, leasedRecord.Version, active); err != nil {
		return ErrReconcilePending
	}
	audit(rollout.Auditor, AuditRecord{Action: "rollout", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func (rollout Rollout) Reconcile(ctx context.Context, appID string) error {
	if rollout.Auditor == nil {
		return ErrAuditRequired
	}
	if rollout.Store == nil || rollout.Executor == nil {
		return ErrTypedHandlesUnavailable
	}
	record, ok, err := rollout.Store.Load(ctx, appID)
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if !ok || (record.Value.Phase != PhaseCleanupPending && record.Value.Phase != PhaseRouteReconcile) || (record.Value.Lease != "" && record.Value.LeaseUntil.After(rollout.now())) {
		return ErrReconcilePending
	}
	value := record.Value
	value.Lease, value.LeaseUntil = fmt.Sprintf("reconcile-%d", leaseSequence.Add(1)), rollout.now().Add(rollout.leaseDuration())
	leased, err := rollout.Store.CompareAndSwap(ctx, appID, record.Version, value)
	if err != nil {
		return ErrReconcilePending
	}
	state, err := rollout.Executor.Inspect(ctx, appID, value.RuleRef)
	if err != nil {
		rollout.releasePending(leased, record.Value)
		return safeFailure(ErrOperationFailed, err)
	}
	pending := value.PendingInstance
	if value.Phase == PhaseRouteReconcile || (pending != "" && state.RuleTarget == pending) {
		desired := value.DesiredRuleTarget
		if desired == "" || (value.InstanceID != "" && !state.Instances[value.InstanceID]) {
			rollout.releasePending(leased, record.Value)
			return ErrReconcilePending
		}
		if state.RuleTarget != desired {
			if err := rollout.restoreTarget(value.RuleRef, desired); err != nil {
				rollout.releasePending(leased, record.Value)
				return safeFailure(ErrOperationFailed, err)
			}
		}
	}
	if pending != "" && state.Instances[pending] {
		if err := rollout.removeWithCleanup(pending); err != nil {
			rollout.releasePending(leased, record.Value)
			return safeFailure(ErrOperationFailed, err)
		}
	}
	recovered := record.Value
	recovered.Phase, recovered.PendingInstance, recovered.DesiredRuleTarget, recovered.LastFailure, recovered.Lease, recovered.LeaseUntil = PhaseActive, "", "", "", "", time.Time{}
	recovered.RuleTarget = recovered.DesiredRuleTarget
	if record.Value.DesiredRuleTarget != "" {
		recovered.RuleTarget = record.Value.DesiredRuleTarget
	}
	if _, err := rollout.Store.CompareAndSwap(ctx, appID, leased.Version, recovered); err != nil {
		return ErrReconcilePending
	}
	audit(rollout.Auditor, AuditRecord{Action: "rollout.reconcile", Outcome: "succeeded", Detail: appID})
	return nil
}

func (rollout Rollout) releasePending(leased DeploymentRecord, pending Deployment) {
	pending.Lease, pending.LeaseUntil = "", time.Time{}
	_, _ = rollout.Store.CompareAndSwap(context.Background(), pending.AppID, leased.Version, pending)
}
func (rollout Rollout) now() time.Time {
	if rollout.Clock != nil {
		return rollout.Clock()
	}
	return time.Now()
}
func (rollout Rollout) leaseDuration() time.Duration {
	if rollout.LeaseDuration > 0 {
		return rollout.LeaseDuration
	}
	return 30 * time.Second
}
func (rollout Rollout) cleanupContext() (context.Context, context.CancelFunc) {
	timeout := rollout.CleanupTimeout
	if timeout <= 0 {
		timeout = DefaultCleanupTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}
func (rollout Rollout) restoreWithCleanup(old Deployment) error {
	return rollout.restoreTarget(old.RuleRef, old.RuleTarget)
}
func (rollout Rollout) restoreTarget(ruleRef, target string) error {
	ctx, cancel := rollout.cleanupContext()
	defer cancel()
	return rollout.Executor.Cutover(ctx, ruleRef, target)
}
func (rollout Rollout) removeWithCleanup(instance string) error {
	ctx, cancel := rollout.cleanupContext()
	defer cancel()
	return rollout.Executor.Remove(ctx, instance)
}
func (rollout Rollout) progress(app App, phase RolloutPhase) {
	audit(rollout.Auditor, AuditRecord{Action: "rollout.progress", Outcome: string(phase), Detail: app.ID})
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
	return DeletePreview{AppID: appID, Generation: generation, Digest: digest, Impacts: normalized}, nil
}

type DeleteExecutor interface {
	// operation is a canonical digest and must be capability-backed and
	// idempotent before durable journal acknowledgement.
	DeleteOwned(context.Context, string, ResourceImpact) error
	ReleaseCoreRef(context.Context, string, ResourceImpact) error
}
type DeleteInventory interface {
	CurrentDelete(context.Context, string, string) ([]ResourceImpact, error)
}
type DeleteInventoryFunc func(context.Context, string, string) ([]ResourceImpact, error)

func (f DeleteInventoryFunc) CurrentDelete(ctx context.Context, appID, generation string) ([]ResourceImpact, error) {
	return f(ctx, appID, generation)
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
		completed, journalErr := journal.Completed(ctx, operation, effect)
		if journalErr != nil {
			audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, journalErr)
		}
		if completed {
			continue
		}
		audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "applying", Detail: effect})
		idempotencyKey, _ := canonicalDigest(struct{ Operation, Effect string }{operation, effect})
		var effectErr error
		if impact.Owner == OwnerCore {
			effectErr = executor.ReleaseCoreRef(ctx, idempotencyKey, impact)
		} else {
			effectErr = executor.DeleteOwned(ctx, idempotencyKey, impact)
		}
		if effectErr != nil {
			audit(auditor, AuditRecord{Action: "delete", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, effectErr)
		}
		if journalErr := journal.MarkCompleted(ctx, operation, effect); journalErr != nil {
			audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
			return safeFailure(ErrOperationFailed, journalErr)
		}
		audit(auditor, AuditRecord{Action: "delete.progress", Outcome: "completed", Detail: effect})
	}
	audit(auditor, AuditRecord{Action: "delete", Outcome: "succeeded", Detail: trusted.AppID})
	return nil
}
