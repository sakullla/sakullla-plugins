package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	if !validID(plan.AppID) || !boundedText(plan.Generation, 128) || !validID(plan.Project) || len(plan.Services) > MaxComposeServices || len(plan.RuleImpacts) > MaxCollectionItems {
		return RiskPreview{}, ErrBoundExceeded
	}
	preview := RiskPreview{AppID: plan.AppID, Generation: plan.Generation, Project: plan.Project}
	for _, service := range plan.Services {
		if !validID(service.Name) {
			return RiskPreview{}, errors.New("compose service is invalid")
		}
		for _, collection := range [][]string{service.HostMounts, service.AddCapabilities, service.Networks, service.Volumes} {
			if _, err := sortedUnique(collection, MaxCollectionItems); err != nil {
				return RiskPreview{}, err
			}
		}
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
	if _, err := sortedUnique(plan.RuleImpacts, MaxCollectionItems); err != nil {
		return RiskPreview{}, err
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

func ExecuteCompose(ctx context.Context, shown RiskPreview, authorization Authorization, inventory ComposeInventory, verifier AuthorizationVerifier, executor ComposeExecutor, journal ProgressJournal, auditor Auditor, secrets []string) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if inventory == nil || verifier == nil || executor == nil || journal == nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	plan, err := inventory.CurrentCompose(ctx, shown.AppID, shown.Generation)
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "failed", Detail: err.Error()})
		return safeFailure(ErrOperationFailed, err, secrets)
	}
	trusted, err := PreviewCompose(plan)
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: err.Error()})
		return safeFailure(ErrInvalidPreview, err, secrets)
	}
	shownDigest, _ := canonicalDigest(struct {
		AppID, Generation, Project string
		Items                      []RiskItem
	}{shown.AppID, shown.Generation, shown.Project, shown.Items})
	if shownDigest != shown.Digest || shown.AppID != trusted.AppID || shown.Generation != trusted.Generation || shown.Digest != trusted.Digest || authorization.AppID != trusted.AppID || authorization.Generation != trusted.Generation || authorization.PreviewDigest != trusted.Digest {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return ErrInvalidPreview
	}
	if err := verifier.Verify(ctx, authorization, trusted.AppID, trusted.Generation, trusted.Digest); err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: err.Error()})
		return safeFailure(ErrUnauthorized, err, secrets)
	}
	operation := trusted.Digest
	completed, err := journal.Completed(ctx, operation, "compose")
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: err.Error()})
		return safeFailure(ErrOperationFailed, err, secrets)
	}
	if completed {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "succeeded", Detail: "already completed"})
		return nil
	}
	audit(auditor, secrets, AuditRecord{Action: "compose.progress", Outcome: "applying", Detail: operation})
	err = executor.ApplyCompose(ctx, operation, plan)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: outcome, Detail: fmt.Sprint(err)})
	if err != nil {
		return safeFailure(ErrOperationFailed, err, secrets)
	}
	if err := journal.MarkCompleted(ctx, operation, "compose"); err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.progress", Outcome: "failed", Detail: err.Error()})
		return safeFailure(ErrOperationFailed, err, secrets)
	}
	return nil
}

func audit(auditor Auditor, secrets []string, record AuditRecord) {
	if auditor == nil {
		return
	}
	record.Action = redactText(record.Action, secrets)
	record.Outcome = redactText(record.Outcome, secrets)
	record.Detail = redactText(record.Detail, secrets)
	auditor.Record(record)
}

func redactText(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}
