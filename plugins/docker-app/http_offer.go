package dockerapp

import (
	"context"
	"fmt"
	"sort"
)

// HTTPOffer is a managed app that may appear in the host HTTP rule
// backend-provider catalog. ID is the app id.
type HTTPOffer struct {
	ID, DisplayName, RuleRef, Generation string
}

// HTTPRuleHandle switches a rule target. Host http.rule implements this.
// It is not a Host wire contract; production stays fail-closed without a grant.
type HTTPRuleHandle interface {
	Cutover(context.Context, uint64, string, string) error
}

type HTTPRuleHandleFunc func(context.Context, uint64, string, string) error

func (function HTTPRuleHandleFunc) Cutover(ctx context.Context, fence uint64, ruleRef, target string) error {
	return function(ctx, fence, ruleRef, target)
}

// OffersHTTP reports whether a managed app should be listed as a backend
// provider. Apps without a rule binding are not HTTP publishers.
func OffersHTTP(app App) bool {
	return validID(app.ID) && boundedText(app.Image, 512) && boundedText(app.RuleRef, 128) && boundedText(app.Generation, 128)
}

// ProjectHTTPOffers lists HTTP-publishing managed apps as backend providers.
// Non-HTTP apps are omitted. The result is sorted by id.
func ProjectHTTPOffers(apps []App) ([]HTTPOffer, error) {
	if len(apps) > MaxApps {
		return nil, fmt.Errorf("%w: apps maximum is %d", ErrBoundExceeded, MaxApps)
	}
	offers := make([]HTTPOffer, 0, len(apps))
	for _, app := range apps {
		if !OffersHTTP(app) {
			continue
		}
		offers = append(offers, HTTPOffer{ID: app.ID, DisplayName: app.ID, RuleRef: app.RuleRef, Generation: app.Generation})
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].ID < offers[j].ID })
	return offers, nil
}

// ListHTTPBackendProviders is the backend-provider catalog projection.
func ListHTTPBackendProviders(apps []App) ([]HTTPOffer, error) {
	return ProjectHTTPOffers(apps)
}

// CutoverHTTPOffer switches the rule target through http.rule only after the
// new instance is ready. A failed switch leaves previous unchanged.
func CutoverHTTPOffer(ctx context.Context, handle HTTPRuleHandle, fence uint64, offer HTTPOffer, previous, next string, ready bool, auditor Auditor) (string, error) {
	if auditor == nil {
		return previous, ErrAuditRequired
	}
	if handle == nil {
		audit(auditor, AuditRecord{Action: "http.rule", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return previous, ErrTypedHandlesUnavailable
	}
	if !ready || !boundedText(offer.RuleRef, 128) || !boundedText(next, 128) {
		audit(auditor, AuditRecord{Action: "http.rule", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
		return previous, ErrInvalidPreview
	}
	if err := handle.Cutover(ctx, fence, offer.RuleRef, next); err != nil {
		audit(auditor, AuditRecord{Action: "http.rule", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return previous, safeFailure(ErrOperationFailed, err)
	}
	detail := offer.ID
	if detail == "" {
		detail = offer.RuleRef
	}
	audit(auditor, AuditRecord{Action: "http.rule", Outcome: "succeeded", Detail: detail})
	return next, nil
}

// HTTPRuleCutover adapts http.rule to RolloutExecutor.Cutover. Ready has
// already succeeded when rollout invokes this.
type HTTPRuleCutover struct {
	Handle  HTTPRuleHandle
	Auditor Auditor
}

func (cutover HTTPRuleCutover) Cutover(ctx context.Context, fence uint64, ruleRef, target string) error {
	_, err := CutoverHTTPOffer(ctx, cutover.Handle, fence, HTTPOffer{RuleRef: ruleRef}, "", target, true, cutover.Auditor)
	return err
}
