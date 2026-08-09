package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type Deployment struct {
	AppID      string
	InstanceID string
	Image      string
	RuleRef    string
	RuleTarget string
	Generation string
	Phase      RolloutPhase
}

type RolloutPhase string

const (
	PhasePulling   RolloutPhase = "pulling"
	PhaseStarting  RolloutPhase = "starting"
	PhaseReadiness RolloutPhase = "readiness"
	PhaseCutover   RolloutPhase = "cutover"
	PhaseDraining  RolloutPhase = "draining"
	PhaseActive    RolloutPhase = "active"
)

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
	Store    *DeploymentStore
	Executor RolloutExecutor
	Auditor  Auditor
}

func (rollout Rollout) Update(ctx context.Context, app App) error {
	if err := app.Validate(); err != nil {
		return err
	}
	if rollout.Store == nil || rollout.Executor == nil {
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
			_ = rollout.Executor.Remove(context.WithoutCancel(ctx), newInstance)
		}
		return rollout.fail(app, "start", err)
	}
	rollbackNew := func() { _ = rollout.Executor.Remove(context.WithoutCancel(ctx), newInstance) }
	rollout.progress(app, PhaseReadiness)
	if err := rollout.Executor.Ready(ctx, newInstance); err != nil {
		rollbackNew()
		return rollout.fail(app, "readiness", err)
	}
	rollout.progress(app, PhaseCutover)
	if err := rollout.Executor.Cutover(ctx, app.RuleRef, newInstance); err != nil {
		if hadOld {
			err = errors.Join(err, rollout.Executor.Cutover(context.WithoutCancel(ctx), old.RuleRef, old.RuleTarget))
		}
		rollbackNew()
		return rollout.fail(app, "cutover", err)
	}
	if hadOld && old.InstanceID != "" {
		rollout.progress(app, PhaseDraining)
		if err := rollout.Executor.Drain(ctx, old.InstanceID); err != nil {
			rollbackErr := rollout.Executor.Cutover(context.WithoutCancel(ctx), old.RuleRef, old.RuleTarget)
			rollbackNew()
			return rollout.fail(app, "drain", errors.Join(err, rollbackErr))
		}
	}
	rollout.Store.Put(Deployment{AppID: app.ID, InstanceID: newInstance, Image: app.Image, RuleRef: app.RuleRef, RuleTarget: newInstance, Generation: app.Generation, Phase: PhaseActive})
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func (rollout Rollout) progress(app App, phase RolloutPhase) {
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout.progress", Outcome: string(phase), Detail: app.ID})
}

func (rollout Rollout) fail(app App, phase string, err error) error {
	audit(rollout.Auditor, app.Secrets, AuditRecord{Action: "rollout." + phase, Outcome: "failed", Detail: err.Error()})
	return fmt.Errorf("rollout %s: %w", phase, redactFailure(err, app.Secrets))
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
	AppID   string
	Impacts []ResourceImpact
}

func PreviewDelete(appID string, impacts []ResourceImpact) (DeletePreview, error) {
	if !validID(appID) || len(impacts) > MaxCollectionItems {
		return DeletePreview{}, ErrBoundExceeded
	}
	copy := append([]ResourceImpact(nil), impacts...)
	for _, impact := range copy {
		if !boundedText(impact.Kind, 64) || !boundedText(impact.ID, 128) || (impact.Owner != OwnerPlugin && impact.Owner != OwnerCore) {
			return DeletePreview{}, errors.New("delete impact is invalid")
		}
	}
	return DeletePreview{AppID: appID, Impacts: copy}, nil
}

type DeleteExecutor interface {
	DeleteOwned(context.Context, ResourceImpact) error
	ReleaseCoreRef(context.Context, ResourceImpact) error
}

func ExecuteDelete(ctx context.Context, preview DeletePreview, authorized bool, executor DeleteExecutor, auditor Auditor, secrets []string) error {
	if !authorized {
		audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "denied", Detail: ErrUnauthorized.Error()})
		return ErrUnauthorized
	}
	if executor == nil {
		return ErrTypedHandlesUnavailable
	}
	for _, impact := range preview.Impacts {
		if impact.Shared {
			continue
		}
		var err error
		if impact.Owner == OwnerCore {
			err = executor.ReleaseCoreRef(ctx, impact)
		} else {
			err = executor.DeleteOwned(ctx, impact)
		}
		if err != nil {
			audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "failed", Detail: err.Error()})
			return redactFailure(err, secrets)
		}
	}
	audit(auditor, secrets, AuditRecord{Action: "delete", Outcome: "succeeded", Detail: preview.AppID})
	return nil
}
