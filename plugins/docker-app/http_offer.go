package dockerapp

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const HTTPBackendOfferMaxEntries = 256

// HTTPOffer is a managed app that may appear in the host HTTP published-port
// catalog. ProviderID is the app id.
type HTTPOffer struct {
	AppID, ProviderID, RuleRef, AgentID, DisplayName string
	Ports                                            []uint16
	Available                                        bool
}

// HTTPBackendCatalogOffer is one http.backend-offer replace entry.
type HTTPBackendCatalogOffer struct {
	ResourceID  string `json:"resource_id"`
	AgentID     string `json:"agent_id"`
	Port        int    `json:"port"`
	DisplayName string `json:"display_name"`
	Available   bool   `json:"available"`
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
// The host owns the resulting rule object; backend is that Agent's published port.
type HTTPRuleSpec struct {
	AppID   string
	AgentID string
	Domain  string
	Port    uint16
}

// HostHTTPRule is one host-owned HTTP rule after list or create.
type HostHTTPRule struct {
	Ref     string `json:"ref,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Backend string `json:"backend,omitempty"`
	AppID   string `json:"app_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Enabled bool   `json:"enabled"`
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

// HTTPRuleListHandle lists host HTTP rules for one Agent. Host http.rule list
// implements this. Application-page success uses this list, not process memory.
type HTTPRuleListHandle interface {
	List(context.Context, string) ([]HostHTTPRule, error)
}

type HTTPRuleListHandleFunc func(context.Context, string) ([]HostHTTPRule, error)

func (function HTTPRuleListHandleFunc) List(ctx context.Context, agentID string) ([]HostHTTPRule, error) {
	return function(ctx, agentID)
}

// HTTPBackendOfferReplaceHandle replaces this plugin instance's published-port
// catalog. Host http.backend-offer implements this.
type HTTPBackendOfferReplaceHandle interface {
	ReplaceHTTPBackendOffers(context.Context, []HTTPBackendCatalogOffer) error
}

type HTTPBackendOfferReplaceHandleFunc func(context.Context, []HTTPBackendCatalogOffer) error

func (function HTTPBackendOfferReplaceHandleFunc) ReplaceHTTPBackendOffers(ctx context.Context, offers []HTTPBackendCatalogOffer) error {
	return function(ctx, offers)
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
		ports := mergePorts(composePublishedPorts(app.Compose), portsByApp[app.ID])
		if !OffersHTTP(app, ports) {
			continue
		}
		offers = append(offers, HTTPOffer{
			AppID:       app.ID,
			ProviderID:  app.ID,
			RuleRef:     app.RuleRef,
			AgentID:     app.AgentID,
			DisplayName: app.ID,
			Ports:       append([]uint16(nil), ports...),
			Available:   true,
		})
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].AppID < offers[j].AppID })
	return offers, nil
}

// ProjectHTTPBackendCatalog expands ProjectHTTPOffers into the public
// http.backend-offer replace payload. Stopped apps stay listed with
// available=false; apps without a port or agent are omitted.
func ProjectHTTPBackendCatalog(apps []App, observations []ContainerObservation, running map[string]bool, granted bool) ([]HTTPBackendCatalogOffer, error) {
	offers, err := ProjectHTTPOffers(apps, observations, granted)
	if err != nil {
		return nil, err
	}
	catalog := make([]HTTPBackendCatalogOffer, 0, len(offers))
	for _, offer := range offers {
		if !validID(offer.AppID) || !validAgentID(offer.AgentID) {
			continue
		}
		name := strings.TrimSpace(offer.DisplayName)
		if name == "" {
			name = offer.AppID
		}
		available := catalogOfferAvailable(offer, running)
		for _, port := range offer.Ports {
			if port == 0 {
				continue
			}
			catalog = append(catalog, HTTPBackendCatalogOffer{
				ResourceID:  offer.AppID,
				AgentID:     offer.AgentID,
				Port:        int(port),
				DisplayName: name,
				Available:   available,
			})
			if len(catalog) >= HTTPBackendOfferMaxEntries {
				break
			}
		}
		if len(catalog) >= HTTPBackendOfferMaxEntries {
			break
		}
	}
	sort.Slice(catalog, func(i, j int) bool {
		if catalog[i].AgentID != catalog[j].AgentID {
			return catalog[i].AgentID < catalog[j].AgentID
		}
		if catalog[i].ResourceID != catalog[j].ResourceID {
			return catalog[i].ResourceID < catalog[j].ResourceID
		}
		return catalog[i].Port < catalog[j].Port
	})
	return catalog, nil
}

func catalogOfferAvailable(offer HTTPOffer, running map[string]bool) bool {
	if running == nil {
		return offer.Available
	}
	stored, ok := running[offer.AppID]
	if !ok {
		return offer.Available
	}
	return stored
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
// selected published port and ingress domain. Success is the host list
// filtered by this app's Agent and published ports. Host rejection does not
// record a local success.
func CreateHTTPRuleFromPublishedPort(ctx context.Context, handle HTTPRuleCreateHandle, lister HTTPRuleListHandle, app App, observations []ContainerObservation, domain string, port uint16, auditor Auditor) ([]HostHTTPRule, error) {
	if auditor == nil {
		return nil, ErrAuditRequired
	}
	normalized, ok := normalizeIngressDomain(domain)
	if !ok {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "denied", Detail: ErrEmptyIngressDomain.Error()})
		return nil, ErrEmptyIngressDomain
	}
	ports, err := ListPublishedPorts(app, observations)
	if err != nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return nil, safeFailure(ErrOperationFailed, err)
	}
	if len(ports) == 0 || !containsPort(ports, port) {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "denied", Detail: ErrNoPublishedPort.Error()})
		return nil, ErrNoPublishedPort
	}
	if handle == nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return nil, ErrTypedHandlesUnavailable
	}
	if _, err := handle.Create(ctx, HTTPRuleSpec{AppID: app.ID, AgentID: app.AgentID, Domain: normalized, Port: port}); err != nil {
		audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return nil, safeFailure(ErrOperationFailed, err)
	}
	if lister == nil {
		audit(auditor, AuditRecord{Action: "http.rule.list", Outcome: "unavailable", Detail: ErrHTTPRuleListFailed.Error()})
		return nil, ErrHTTPRuleListFailed
	}
	listed, err := lister.List(ctx, app.AgentID)
	if err != nil {
		audit(auditor, AuditRecord{Action: "http.rule.list", Outcome: "failed", Detail: ErrHTTPRuleListFailed.Error()})
		return nil, safeFailure(ErrHTTPRuleListFailed, err)
	}
	audit(auditor, AuditRecord{Action: "http.rule.create", Outcome: "succeeded", Detail: app.ID})
	return FilterHTTPRulesForApp(listed, app, ports), nil
}

// FilterHTTPRulesForApp keeps host list entries that target this app's Agent
// and published ports.
func FilterHTTPRulesForApp(rules []HostHTTPRule, app App, ports []uint16) []HostHTTPRule {
	filtered := make([]HostHTTPRule, 0, len(rules))
	for _, rule := range rules {
		if rule.AgentID != "" && app.AgentID != "" && rule.AgentID != app.AgentID {
			continue
		}
		port := rule.Port
		if port == 0 {
			parsed, ok := parseBackendPort(rule.Backend)
			if !ok {
				continue
			}
			port = parsed
			rule.Port = port
		}
		if !containsPort(ports, port) {
			continue
		}
		if rule.AppID == "" {
			rule.AppID = app.ID
		}
		if rule.AgentID == "" {
			rule.AgentID = app.AgentID
		}
		if rule.Domain == "" && rule.Backend != "" {
			rule.Domain = rule.Backend
		}
		filtered = append(filtered, rule)
	}
	return filtered
}

func normalizeCreatedHTTPRule(rule HostHTTPRule, app App, domain string, port uint16) HostHTTPRule {
	if rule.AppID == "" {
		rule.AppID = app.ID
	}
	if rule.AgentID == "" {
		rule.AgentID = app.AgentID
	}
	if rule.Domain == "" {
		rule.Domain = domain
	}
	if rule.Port == 0 {
		rule.Port = port
	}
	if rule.Backend == "" {
		rule.Backend = publishedPortBackend(app.AgentID, port)
	}
	return rule
}

func publishedPortBackend(agentID string, port uint16) string {
	return strings.TrimSpace(agentID) + ":" + strconv.Itoa(int(port))
}

func normalizeIngressDomain(value string) (string, bool) {
	frontend, err := normalizeHTTPRuleFrontend(value)
	if err != nil {
		return "", false
	}
	return frontend, true
}

// normalizeHTTPRuleFrontend matches the host NormalizeHTTPRuleFrontend wire
// contract: hostname or http(s) URL, path stripped, https:// kept.
func normalizeHTTPRuleFrontend(domain string) (string, error) {
	if domain == "" || domain != strings.TrimSpace(domain) || strings.ContainsAny(domain, "\r\n\x00") {
		return "", ErrEmptyIngressDomain
	}
	scheme := "http"
	host := domain
	lower := strings.ToLower(domain)
	switch {
	case strings.HasPrefix(lower, "https://"):
		scheme = "https"
		host = domain[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		scheme = "http"
		host = domain[len("http://"):]
	case strings.Contains(domain, "://"):
		return "", ErrEmptyIngressDomain
	}
	if cut := strings.IndexAny(host, "/?#"); cut >= 0 {
		if cut == 0 {
			return "", ErrEmptyIngressDomain
		}
		host = host[:cut]
	}
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \r\n\x00/") {
		return "", ErrEmptyIngressDomain
	}
	frontend := scheme + "://" + host
	parsed, err := url.Parse(frontend)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil {
		return "", ErrEmptyIngressDomain
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", ErrEmptyIngressDomain
	}
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host, nil
}

func parseBackendPort(backend string) (uint16, bool) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return 0, false
	}
	if parsed, err := url.Parse(backend); err == nil && parsed != nil && parsed.Host != "" {
		if portText := parsed.Port(); portText != "" {
			return parsePortNumber(portText)
		}
		if parsed.Scheme == "" {
			if _, portText, ok := strings.Cut(parsed.Host, ":"); ok {
				return parsePortNumber(portText)
			}
		}
	}
	if index := strings.LastIndexByte(backend, ':'); index >= 0 {
		return parsePortNumber(backend[index+1:])
	}
	return 0, false
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
