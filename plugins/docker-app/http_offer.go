package dockerapp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
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

// HTTPRuleSpec is the plugin-side create request for a host HTTP rule.
// The host owns the resulting rule object; backend is the published port.
type HTTPRuleSpec struct {
	AppID  string
	Domain string
	Port   uint16
}

// HostHTTPRule is one entry in the host HTTP rule list after a create request.
type HostHTTPRule struct {
	Ref, Domain, Backend, AppID string
	Port                        uint16
}

// AppHTTPIngress is the application-page projection of published host ports.
// Apps without a published port do not offer HTTP rule creation.
type AppHTTPIngress struct {
	AppID          string
	PublishedPorts []uint16
	CanCreate      bool
}

// HTTPRuleCreateHandle creates a host HTTP rule. Host http.rule implements this.
type HTTPRuleCreateHandle interface {
	Create(context.Context, HTTPRuleSpec) (HostHTTPRule, error)
}

type HTTPRuleCreateHandleFunc func(context.Context, HTTPRuleSpec) (HostHTTPRule, error)

func (function HTTPRuleCreateHandleFunc) Create(ctx context.Context, spec HTTPRuleSpec) (HostHTTPRule, error) {
	return function(ctx, spec)
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

// ListPublishedPorts returns host-published ports from compose YAML and from
// labeled runtime observations. Unlabeled candidates are omitted.
func ListPublishedPorts(app App, observations []ContainerObservation) ([]uint16, error) {
	if len(observations) > MaxDiscoveries {
		return nil, fmt.Errorf("%w: discoveries maximum is %d", ErrBoundExceeded, MaxDiscoveries)
	}
	ports := composePublishedPorts(app.Compose)
	discoveries, err := Discover(observations)
	if err != nil {
		return nil, err
	}
	for _, discovery := range discoveries {
		if discovery.Candidate || discovery.AppID != app.ID || len(discovery.Ports) == 0 {
			continue
		}
		ports = mergePorts(ports, discovery.Ports)
	}
	return ports, nil
}

// ProjectAppHTTPIngress lists published ports for the application page.
func ProjectAppHTTPIngress(app App, observations []ContainerObservation) (AppHTTPIngress, error) {
	ports, err := ListPublishedPorts(app, observations)
	if err != nil {
		return AppHTTPIngress{}, err
	}
	return AppHTTPIngress{AppID: app.ID, PublishedPorts: ports, CanCreate: len(ports) > 0}, nil
}

// CreateHTTPRuleFromPublishedPort asks the host to create an HTTP rule for a
// selected published port and ingress domain. Empty domain or missing ports
// leave the existing host rule list unchanged.
func CreateHTTPRuleFromPublishedPort(ctx context.Context, handle HTTPRuleCreateHandle, existing []HostHTTPRule, app App, observations []ContainerObservation, domain string, port uint16, auditor Auditor) ([]HostHTTPRule, error) {
	preserved := cloneHTTPRules(existing)
	if auditor == nil {
		return preserved, ErrAuditRequired
	}
	normalized, ok := normalizeIngressDomain(domain)
	if !ok {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "denied", Detail: ErrEmptyIngressDomain.Error()})
		return preserved, ErrEmptyIngressDomain
	}
	ports, err := ListPublishedPorts(app, observations)
	if err != nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return preserved, safeFailure(ErrOperationFailed, err)
	}
	if len(ports) == 0 || !containsPort(ports, port) {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "denied", Detail: ErrNoPublishedPort.Error()})
		return preserved, ErrNoPublishedPort
	}
	if handle == nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return preserved, ErrTypedHandlesUnavailable
	}
	created, err := handle.Create(ctx, HTTPRuleSpec{AppID: app.ID, Domain: normalized, Port: port})
	if err != nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return preserved, safeFailure(ErrOperationFailed, err)
	}
	created = normalizeCreatedHTTPRule(created, app.ID, normalized, port)
	audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "succeeded", Detail: app.ID})
	return append(preserved, created), nil
}

func normalizeCreatedHTTPRule(rule HostHTTPRule, appID, domain string, port uint16) HostHTTPRule {
	if rule.AppID == "" {
		rule.AppID = appID
	}
	if rule.Domain == "" {
		rule.Domain = domain
	}
	if rule.Port == 0 {
		rule.Port = port
	}
	if rule.Backend == "" {
		rule.Backend = ":" + strconv.Itoa(int(port))
	}
	return rule
}

func normalizeIngressDomain(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "https://"):
		value = value[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		value = value[len("http://"):]
	}
	if cut := strings.IndexAny(value, "/?#"); cut >= 0 {
		if cut == 0 {
			return "", false
		}
		value = value[:cut]
	}
	value = strings.TrimSpace(value)
	if !boundedText(value, 253) {
		return "", false
	}
	return value, true
}

func containsPort(ports []uint16, want uint16) bool {
	for _, port := range ports {
		if port == want {
			return true
		}
	}
	return false
}

func cloneHTTPRules(rules []HostHTTPRule) []HostHTTPRule {
	return append([]HostHTTPRule(nil), rules...)
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
