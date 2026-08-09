package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Deployment struct {
	AppID           string
	InstanceID      string
	Image           string
	RuleRef         string
	RuleTarget      string
	Generation      string
	Phase           RolloutPhase
	PendingInstance string
	LastFailure     string
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

type DeploymentStore struct {
	mu     sync.RWMutex
	values map[string]Deployment
}

func NewDeploymentStore() *DeploymentStore {
	return &DeploymentStore{values: make(map[string]Deployment)}
}
func (store *DeploymentStore) Get(appID string) (Deployment, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.values[appID]
	return value, ok
}
func (store *DeploymentStore) Put(value Deployment) {
	store.mu.Lock()
	store.values[value.AppID] = value
	store.mu.Unlock()
}

// RolloutExecutor is a deterministic business adapter only. A production
// adapter must be backed by future typed public SDK handles; this interface is
// neither serialized nor exposed as a Host contract.
type RolloutExecutor interface {
	Pull(context.Context, string) error
	Start(context.Context, App) (string, error)
	Ready(context.Context, string) error
	Cutover(context.Context, string, string) error
	Drain(context.Context, string) error
	Remove(context.Context, string) error
}

type Rollout struct {
	Store          *DeploymentStore
	Executor       RolloutExecutor
	Auditor        Auditor
	CleanupTimeout time.Duration
}

func (rollout Rollout) Update(ctx context.Context, app App) error {
	if rollout.Auditor == nil {
		return ErrAuditRequired
	}
	if err := app.Validate(); err != nil {
		audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout", Outcome: "denied", Detail: err.Error()})
		return safeFailure(ErrInvalidPreview, err, app.Secrets)
	}
	if rollout.Store == nil || rollout.Executor == nil {
		audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	old, hadOld := rollout.Store.Get(app.ID)
	rollout.progress(app, PhasePulling)
	if err := rollout.Executor.Pull(ctx, app.Image); err != nil {
		return rollout.fail(app, "pull", err)
	}
	rollout.progress(app, PhaseStarting)
	newInstance, err := rollout.Executor.Start(ctx, app)
	if err != nil {
		if newInstance != "" {
			err = errors.Join(err, rollout.removeWithCleanup(app, old, newInstance))
		}
		return rollout.fail(app, "start", err)
	}
	rollout.progress(app, PhaseReadiness)
	if err := rollout.Executor.Ready(ctx, newInstance); err != nil {
		err = errors.Join(err, rollout.removeWithCleanup(app, old, newInstance))
		return rollout.fail(app, "readiness", err)
	}
	rollout.progress(app, PhaseCutover)
	if err := rollout.Executor.Cutover(ctx, app.RuleRef, newInstance); err != nil {
		if hadOld {
			restoreErr := rollout.restoreWithCleanup(old)
			err = errors.Join(err, restoreErr)
			if restoreErr != nil {
				rollout.persistReconcile(app, old, newInstance, err)
				return rollout.fail(app, "cutover", err)
			}
		}
		err = errors.Join(err, rollout.removeWithCleanup(app, old, newInstance))
		return rollout.fail(app, "cutover", err)
	}
	if hadOld && old.InstanceID != "" {
		rollout.progress(app, PhaseDraining)
		if err := rollout.Executor.Drain(ctx, old.InstanceID); err != nil {
			restoreErr := rollout.restoreWithCleanup(old)
			combined := errors.Join(err, restoreErr)
			if restoreErr != nil {
				rollout.persistReconcile(app, old, newInstance, combined)
				return rollout.fail(app, "drain", combined)
			}
			combined = errors.Join(combined, rollout.removeWithCleanup(app, old, newInstance))
			return rollout.fail(app, "drain", combined)
		}
	}
	rollout.Store.Put(Deployment{AppID: app.ID, InstanceID: newInstance, Image: app.Image, RuleRef: app.RuleRef, RuleTarget: newInstance, Generation: app.Generation, Phase: PhaseActive})
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func (rollout Rollout) cleanupContext() (context.Context, context.CancelFunc) {
	timeout := rollout.CleanupTimeout
	if timeout <= 0 {
		timeout = DefaultCleanupTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (rollout Rollout) restoreWithCleanup(old Deployment) error {
	cleanupCtx, cancel := rollout.cleanupContext()
	defer cancel()
	return rollout.Executor.Cutover(cleanupCtx, old.RuleRef, old.RuleTarget)
}

func (rollout Rollout) removeWithCleanup(app App, old Deployment, newInstance string) error {
	cleanupCtx, cancel := rollout.cleanupContext()
	defer cancel()
	err := rollout.Executor.Remove(cleanupCtx, newInstance)
	if err != nil {
		pending := old
		pending.AppID, pending.Generation, pending.PendingInstance, pending.Phase = app.ID, app.Generation, newInstance, PhaseCleanupPending
		pending.LastFailure = redactText(err.Error(), app.Secrets)
		rollout.Store.Put(pending)
	}
	return err
}

func (rollout Rollout) persistReconcile(app App, old Deployment, newInstance string, failure error) {
	old.PendingInstance, old.RuleTarget, old.Phase = newInstance, newInstance, PhaseRouteReconcile
	old.LastFailure = redactText(failure.Error(), app.Secrets)
	rollout.Store.Put(old)
}

func (rollout Rollout) progress(app App, phase RolloutPhase) {
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout.progress", Outcome: string(phase), Detail: app.ID})
}

func (rollout Rollout) fail(app App, phase string, err error) error {
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout." + phase, Outcome: "failed", Detail: err.Error()})
	return fmt.Errorf("rollout %s: %w", phase, safeFailure(ErrOperationFailed, err, app.Secrets))
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
	copy := append([]ResourceImpact(nil), impacts...)
	for _, impact := range copy {
		if !boundedText(impact.Kind, 64) || !boundedText(impact.ID, 128) || (impact.Owner != OwnerPlugin && impact.Owner != OwnerCore) {
			return DeletePreview{}, errors.New("delete impact is invalid")
		}
	}
	sort.Slice(copy, func(i, j int) bool {
		if copy[i].Kind != copy[j].Kind {
			return copy[i].Kind < copy[j].Kind
		}
		return copy[i].ID < copy[j].ID
	})
	digest, err := canonicalDigest(struct {
		AppID, Generation string
		Impacts           []ResourceImpact
	}{appID, generation, copy})
	if err != nil {
		return DeletePreview{}, ErrInvalidPreview
	}
	return DeletePreview{AppID: appID, Generation: generation, Digest: digest, Impacts: copy}, nil
}

type DeleteExecutor interface {
	// operation is stable across retries; implementations must apply each
	// resource operation idempotently before durable journal acknowledgement.
	DeleteOwned(context.Context, string, ResourceImpact) error
	ReleaseCoreRef(context.Context, string, ResourceImpact) error
}

type DeleteInventory interface {
	CurrentDelete(context.Context, string, string) ([]ResourceImpact, error)
}
type DeleteInventoryFunc func(context.Context, string, string) ([]ResourceImpact, error)

func (function DeleteInventoryFunc) CurrentDelete(ctx context.Context, appID, generation string) ([]ResourceImpact, error) {
	return function(ctx, appID, generation)
}

func ExecuteDelete(ctx context.Context, shown DeletePreview, authorization Authorization, inventory DeleteInventory, verifier AuthorizationVerifier, executor DeleteExecutor, journal ProgressJournal, auditor Auditor, secrets []string) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if inventory == nil || verifier == nil || executor == nil || journal == nil {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	impacts, err := inventory.CurrentDelete(ctx, shown.AppID, shown.Generation)
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "failed", Detail: err.Error()})
		return safeFailure(ErrOperationFailed, err, secrets)
	}
	trusted, err := PreviewDelete(shown.AppID, shown.Generation, impacts)
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "denied", Detail: err.Error()})
		return safeFailure(ErrInvalidPreview, err, secrets)
	}
	shownDigest, _ := canonicalDigest(struct {
		AppID, Generation string
		Impacts           []ResourceImpact
	}{shown.AppID, shown.Generation, shown.Impacts})
	if shownDigest != shown.Digest || shown.Digest != trusted.Digest || authorization.AppID != trusted.AppID || authorization.Generation != trusted.Generation || authorization.PreviewDigest != trusted.Digest {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if err := verifier.Verify(ctx, authorization, trusted.AppID, trusted.Generation, trusted.Digest); err != nil {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "denied", Detail: err.Error()})
		return safeFailure(ErrUnauthorized, err, secrets)
	}
	operation := trusted.Digest
	for _, impact := range trusted.Impacts {
		if impact.Shared {
			continue
		}
		effect := string(impact.Owner) + ":" + impact.Kind + ":" + impact.ID
		completed, journalErr := journal.Completed(ctx, operation, effect)
		if journalErr != nil {
			audit(auditor, secrets, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: journalErr.Error()})
			return safeFailure(ErrOperationFailed, journalErr, secrets)
		}
		if completed {
			continue
		}
		audit(auditor, secrets, AuditRecord{Action: "delete.progress", Outcome: "applying", Detail: effect})
		var effectErr error
		if impact.Owner == OwnerCore {
			effectErr = executor.ReleaseCoreRef(ctx, operation+":"+effect, impact)
		} else {
			effectErr = executor.DeleteOwned(ctx, operation+":"+effect, impact)
		}
		if effectErr != nil {
			audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "failed", Detail: effectErr.Error()})
			return safeFailure(ErrOperationFailed, effectErr, secrets)
		}
		if journalErr := journal.MarkCompleted(ctx, operation, effect); journalErr != nil {
			audit(auditor, secrets, AuditRecord{Action: "delete.progress", Outcome: "failed", Detail: journalErr.Error()})
			return safeFailure(ErrOperationFailed, journalErr, secrets)
		}
		audit(auditor, secrets, AuditRecord{Action: "delete.progress", Outcome: "completed", Detail: effect})
	}
	audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "succeeded", Detail: trusted.AppID})
	return nil
}
