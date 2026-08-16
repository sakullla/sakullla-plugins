package dockerapp

import (
	"context"
	"fmt"
	"sort"
)

// HTTPOffer is a managed app that may appear in the host HTTP rule
// backend-provider catalog. ProviderID is the app id.
type HTTPOffer struct {
	AppID, ProviderID, RuleRef string
	Ports                      []uint16
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
// provider. Apps without an HTTP port on a labeled instance are omitted.
func OffersHTTP(app App, ports []uint16) bool {
	return validID(app.ID) && boundedText(app.Image, 512) && boundedText(app.Generation, 128) && len(ports) > 0
}

// ProjectHTTPOffers lists HTTP-publishing managed apps as backend providers.
// Missing http.rule grant, unlabeled candidates, and apps without exposed
// ports are omitted. The result is sorted by app id.
func ProjectHTTPOffers(apps []App, observations []ContainerObservation, granted bool) ([]HTTPOffer, error) {
	if len(apps) > MaxApps {
		return nil, fmt.Errorf("%w: apps maximum is %d", ErrBoundExceeded, MaxApps)
	}
	if !granted {
		return []HTTPOffer{}, nil
	}
	discoveries, err := Discover(observations)
	if err != nil {
		return nil, err
	}
	portsByApp := make(map[string][]uint16)
	for _, discovery := range discoveries {
		if discovery.Candidate || discovery.AppID == "" || len(discovery.Ports) == 0 {
			continue
		}
		portsByApp[discovery.AppID] = mergePorts(portsByApp[discovery.AppID], discovery.Ports)
	}
	offers := make([]HTTPOffer, 0, len(apps))
	for _, app := range apps {
		ports := portsByApp[app.ID]
		if !OffersHTTP(app, ports) {
			continue
		}
		offers = append(offers, HTTPOffer{
			AppID:      app.ID,
			ProviderID: app.ID,
			RuleRef:    app.RuleRef,
			Ports:      append([]uint16(nil), ports...),
		})
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].AppID < offers[j].AppID })
	return offers, nil
}

// ListHTTPBackendProviders is the backend-provider catalog projection.
func ListHTTPBackendProviders(apps []App, observations []ContainerObservation, granted bool) ([]HTTPOffer, error) {
	return ProjectHTTPOffers(apps, observations, granted)
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
	detail := offer.AppID
	if detail == "" {
		detail = offer.ProviderID
	}
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

func mergePorts(existing, extra []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(existing)+len(extra))
	merged := make([]uint16, 0, len(existing)+len(extra))
	for _, port := range append(append([]uint16(nil), existing...), extra...) {
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		merged = append(merged, port)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })
	return merged
}
