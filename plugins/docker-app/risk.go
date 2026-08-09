package dockerapp

import (
	"context"
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
	Project string
	Items   []RiskItem
}

func PreviewCompose(plan ComposePlan) (RiskPreview, error) {
	if !validID(plan.Project) || len(plan.Services) > MaxComposeServices || len(plan.RuleImpacts) > MaxCollectionItems {
		return RiskPreview{}, ErrBoundExceeded
	}
	preview := RiskPreview{Project: plan.Project}
	for _, service := range plan.Services {
		if !validID(service.Name) {
			return RiskPreview{}, fmt.Errorf("compose service %q is invalid", service.Name)
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
	return preview, nil
}

type Authorization struct {
	Approved map[RiskKind]bool
}

func (authorization Authorization) Validate(preview RiskPreview) error {
	for _, item := range preview.Items {
		if !authorization.Approved[item.Kind] {
			return fmt.Errorf("%w: risk %s requires approval", ErrUnauthorized, item.Kind)
		}
	}
	return nil
}

// ComposeExecutor is an injectable business-test boundary. It is not a Host
// API or wire contract; production remains gated on future typed SDK handles.
type ComposeExecutor interface {
	ApplyCompose(context.Context, ComposePlan) error
}
type ComposeExecutorFunc func(context.Context, ComposePlan) error

func (function ComposeExecutorFunc) ApplyCompose(ctx context.Context, plan ComposePlan) error {
	return function(ctx, plan)
}

type AuditRecord struct{ Action, Outcome, Detail string }
type Auditor interface{ Record(AuditRecord) }
type AuditorFunc func(AuditRecord)

func (function AuditorFunc) Record(record AuditRecord) { function(record) }

func ExecuteCompose(ctx context.Context, plan ComposePlan, authorization Authorization, executor ComposeExecutor, auditor Auditor, secrets []string) error {
	preview, err := PreviewCompose(plan)
	if err == nil {
		err = authorization.Validate(preview)
	}
	if err != nil {
		audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: "denied", Detail: err.Error()})
		return err
	}
	if executor == nil {
		return ErrTypedHandlesUnavailable
	}
	err = executor.ApplyCompose(ctx, plan)
	outcome := "succeeded"
	if err != nil {
		outcome = "failed"
	}
	audit(auditor, secrets, AuditRecord{Action: "compose.apply", Outcome: outcome, Detail: fmt.Sprint(err)})
	return redactFailure(err, secrets)
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

type redactedFailure struct {
	cause   error
	message string
}

func (failure *redactedFailure) Error() string { return failure.message }
func (failure *redactedFailure) Unwrap() error { return failure.cause }
func redactFailure(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	return &redactedFailure{cause: err, message: redactText(err.Error(), secrets)}
}
