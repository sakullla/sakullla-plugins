package dockerapp

import (
	"context"
	"errors"
	"sort"
)

type ComposeService struct {
	Name            string
	Privileged      bool
	HostMounts      []string
	AddCapabilities []string
	Networks        []string
	Volumes         []string
}

type ComposePlan struct {
	AppID       string
	Generation  string
	Project     string
	Services    []ComposeService
	RuleImpacts []string
}

type RiskKind string

const (
	RiskPrivileged RiskKind = "privileged"
	RiskHostMount  RiskKind = "host-mount"
	RiskCapability RiskKind = "capability"
	RiskNetwork    RiskKind = "network"
	RiskVolume     RiskKind = "volume"
	RiskRule       RiskKind = "rule"
)

type RiskItem struct {
	Kind   RiskKind
	Target string
}

type RiskPreview struct {
	AppID, Generation, Project, Digest string
	Items                              []RiskItem
}

func PreviewCompose(plan ComposePlan) (RiskPreview, error) {
	normalized, err := canonicalComposePlan(plan)
	if err != nil {
		return RiskPreview{}, err
	}
	plan = normalized
	preview := RiskPreview{AppID: plan.AppID, Generation: plan.Generation, Project: plan.Project}
	for _, service := range plan.Services {
		if service.Privileged {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskPrivileged, Target: service.Name})
		}
		for _, target := range service.HostMounts {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskHostMount, Target: service.Name + ":" + target})
		}
		for _, target := range service.AddCapabilities {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskCapability, Target: service.Name + ":" + target})
		}
		for _, target := range service.Networks {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskNetwork, Target: target})
		}
		for _, target := range service.Volumes {
			preview.Items = append(preview.Items, RiskItem{Kind: RiskVolume, Target: target})
		}
	}
	for _, target := range plan.RuleImpacts {
		preview.Items = append(preview.Items, RiskItem{Kind: RiskRule, Target: target})
	}
	if len(preview.Items) > MaxCollectionItems {
		return RiskPreview{}, ErrBoundExceeded
	}
	sort.Slice(preview.Items, func(i, j int) bool {
		if preview.Items[i].Kind == preview.Items[j].Kind {
			return preview.Items[i].Target < preview.Items[j].Target
		}
		return preview.Items[i].Kind < preview.Items[j].Kind
	})
	digest, err := canonicalDigest(struct {
		AppID, Generation, Project string
		Items                      []RiskItem
	}{preview.AppID, preview.Generation, preview.Project, preview.Items})
	if err != nil {
		return RiskPreview{}, ErrInvalidPreview
	}
	preview.Digest = digest
	return preview, nil
}

func canonicalComposePlan(plan ComposePlan) (ComposePlan, error) {
	if !validID(plan.AppID) || !boundedText(plan.Generation, 128) || !validID(plan.Project) || len(plan.Services) > MaxComposeServices || len(plan.RuleImpacts) > MaxCollectionItems {
		return ComposePlan{}, ErrBoundExceeded
	}
	normalized := plan
	normalized.Services = append([]ComposeService(nil), plan.Services...)
	for index := range normalized.Services {
		service := &normalized.Services[index]
		if !validID(service.Name) {
			return ComposePlan{}, errors.New("compose service is invalid")
		}
		var err error
		if service.HostMounts, err = sortedUnique(service.HostMounts, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.AddCapabilities, err = sortedUnique(service.AddCapabilities, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.Networks, err = sortedUnique(service.Networks, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
		if service.Volumes, err = sortedUnique(service.Volumes, MaxCollectionItems); err != nil {
			return ComposePlan{}, err
		}
	}
	sort.Slice(normalized.Services, func(i, j int) bool { return normalized.Services[i].Name < normalized.Services[j].Name })
	for index := 1; index < len(normalized.Services); index++ {
		if normalized.Services[index-1].Name == normalized.Services[index].Name {
			return ComposePlan{}, errors.New("compose service is duplicated")
		}
	}
	var err error
	if normalized.RuleImpacts, err = sortedUnique(plan.RuleImpacts, MaxCollectionItems); err != nil {
		return ComposePlan{}, err
	}
	return normalized, nil
}

// ComposeExecutor is an injectable business-test boundary. The operation key
// must be applied idempotently so a journal-write failure can safely resume.
// It is not a Host API or wire contract; production remains gated on future
// typed SDK handles.
type ComposeExecutor interface {
	ApplyCompose(context.Context, string, ComposePlan) error
}
type ComposeExecutorFunc func(context.Context, string, ComposePlan) error

func (function ComposeExecutorFunc) ApplyCompose(ctx context.Context, operation string, plan ComposePlan) error {
	return function(ctx, operation, plan)
}

type ComposeInventory interface {
	CurrentCompose(context.Context, string, string) (ComposePlan, error)
}
type ComposeInventoryFunc func(context.Context, string, string) (ComposePlan, error)

func (function ComposeInventoryFunc) CurrentCompose(ctx context.Context, appID, generation string) (ComposePlan, error) {
	return function(ctx, appID, generation)
}

type AuditRecord struct{ Action, Outcome, Detail string }
type Auditor interface{ Record(AuditRecord) }
type AuditorFunc func(AuditRecord)

func (function AuditorFunc) Record(record AuditRecord) { function(record) }

func ExecuteCompose(ctx context.Context, shown RiskPreview, authorization Authorization, inventory ComposeInventory, verifier AuthorizationVerifier, executor ComposeExecutor, journal ProgressJournal, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if inventory == nil || verifier == nil || executor == nil || journal == nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	plan, err := inventory.CurrentCompose(ctx, shown.AppID, shown.Generation)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	normalized, err := canonicalComposePlan(plan)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	trusted, err := PreviewCompose(normalized)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return safeFailure(ErrInvalidPreview, err)
	}
	shownDigest, _ := canonicalDigest(struct {
		AppID, Generation, Project string
		Items                      []RiskItem
	}{shown.AppID, shown.Generation, shown.Project, shown.Items})
	if shownDigest != shown.Digest || shown.AppID != trusted.AppID || shown.Generation != trusted.Generation || shown.Digest != trusted.Digest || authorization.AppID != trusted.AppID || authorization.Generation != trusted.Generation || authorization.PreviewDigest != trusted.Digest {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if err := verifier.Verify(ctx, authorization, trusted.AppID, trusted.Generation, trusted.Digest); err != nil {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrUnauthorized.Error()})
		return safeFailure(ErrUnauthorized, err)
	}
	operation, err := canonicalDigest(normalized)
	if err != nil {
		return ErrInvalidPreview
	}
	completed, err := journal.Completed(ctx, operation, "compose")
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	if completed {
		audit(auditor, AuditRecord{Action: "compose.apply", Outcome: "succeeded", Detail: "already completed"})
		return nil
	}
	audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "applying", Detail: operation})
	err = executor.ApplyCompose(ctx, operation, normalized)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	audit(auditor, AuditRecord{Action: "compose.apply", Outcome: outcome, Detail: map[bool]string{true: ErrOperationFailed.Error(), false: ""}[err != nil]})
	if err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if err := journal.MarkCompleted(ctx, operation, "compose"); err != nil {
		audit(auditor, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	return nil
}

func audit(auditor Auditor, record AuditRecord) {
	if auditor == nil {
		return
	}
	auditor.Record(record)
}
