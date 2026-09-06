package shadowsocksserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	RouteDirect                = "direct"
	RouteReject                = "reject"
	RouteUpstream              = "upstream"
	MaxUpstreams               = 16
	MaxRouteRules              = 64
	maxUDPAssociationResponses = 8
	maxUDPAssociationBytes     = 256 << 10
)

var (
	ErrRouteRejected            = errors.New("route rejected")
	ErrRouteDatasetUnavailable  = errors.New("route dataset unavailable")
	ErrRouteUpstreamUnavailable = errors.New("route upstream unavailable")
)

type Upstream struct {
	ID            string `json:"id"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Method        string `json:"method"`
	SecretRef     string `json:"secret_ref"`
	SecretVersion string `json:"secret_version"`
	Enabled       bool   `json:"enabled"`
	TCP           bool   `json:"tcp"`
	UDP           bool   `json:"udp"`
}

type RouteRule struct {
	ID             string                          `json:"id"`
	SourceID       string                          `json:"source_id"`
	Classification pluginsdk.DatasetClassification `json:"classification"`
	Action         string                          `json:"action"`
	UpstreamID     string                          `json:"upstream_id,omitempty"`
}

type RoutingConfiguration struct {
	Upstreams         []Upstream  `json:"upstreams"`
	Rules             []RouteRule `json:"rules"`
	DefaultAction     string      `json:"default_action"`
	DefaultUpstreamID string      `json:"default_upstream_id,omitempty"`
}

func (configuration RoutingConfiguration) effectiveDefault() string {
	if configuration.DefaultAction == "" {
		return RouteDirect
	}
	return configuration.DefaultAction
}

func (configuration RoutingConfiguration) Validate() error {
	if len(configuration.Upstreams) > MaxUpstreams || len(configuration.Rules) > MaxRouteRules {
		return ErrInvalid
	}
	upstreams := make(map[string]Upstream, len(configuration.Upstreams))
	for _, upstream := range configuration.Upstreams {
		endpoint := pluginsdk.ManagedNetworkEndpoint{Host: upstream.Host, Port: upstream.Port}
		if !refPattern.MatchString(upstream.ID) || endpoint.Validate() != nil || !SupportedMethod(upstream.Method) ||
			!refPattern.MatchString(upstream.SecretRef) || !refPattern.MatchString(upstream.SecretVersion) || (!upstream.TCP && !upstream.UDP) {
			return ErrInvalid
		}
		if _, duplicate := upstreams[upstream.ID]; duplicate {
			return ErrInvalid
		}
		upstreams[upstream.ID] = upstream
	}
	seen := map[string]bool{}
	for _, rule := range configuration.Rules {
		if !refPattern.MatchString(rule.ID) || seen[rule.ID] || pluginsdk.ValidatePolicyIdentity(rule.SourceID) != nil || rule.Classification.Validate() != nil {
			return ErrInvalid
		}
		seen[rule.ID] = true
		if err := validateRouteAction(rule.Action, rule.UpstreamID, upstreams); err != nil {
			return err
		}
	}
	return validateRouteAction(configuration.effectiveDefault(), configuration.DefaultUpstreamID, upstreams)
}

func validateRouteAction(action, upstreamID string, upstreams map[string]Upstream) error {
	switch action {
	case RouteDirect, RouteReject:
		if upstreamID != "" {
			return ErrInvalid
		}
	case RouteUpstream:
		if _, ok := upstreams[upstreamID]; !ok {
			return ErrRouteUpstreamUnavailable
		}
	default:
		return ErrInvalid
	}
	return nil
}

type datasetRoutingClient interface {
	ResolveDataset(context.Context, pluginsdk.DatasetResolveRequest) (pluginsdk.DatasetReference, error)
	QueryDatasets(context.Context, pluginsdk.DatasetQueryRequest) (pluginsdk.DatasetQueryResponse, error)
}

type routeSnapshot struct {
	configuration RoutingConfiguration
	references    map[string]pluginsdk.DatasetReference
	datasets      datasetRoutingClient
}

type routeDecision struct {
	Action        string
	RuleID        string
	Upstream      *Upstream
	VersionDigest string
}

type RouteStatus struct {
	RuleID         string `json:"rule_id"`
	SourceID       string `json:"source_id"`
	Classification string `json:"classification"`
	VersionDigest  string `json:"version_digest,omitempty"`
	Action         string `json:"action"`
	Exit           string `json:"exit,omitempty"`
	Failure        string `json:"failure,omitempty"`
}

type RouteSourceStatus struct {
	SourceID      string `json:"source_id"`
	VersionDigest string `json:"version_digest,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (snapshot *routeSnapshot) statuses() []RouteStatus {
	if snapshot == nil {
		return []RouteStatus{}
	}
	result := make([]RouteStatus, 0, len(snapshot.configuration.Rules))
	for _, rule := range snapshot.configuration.Rules {
		status := RouteStatus{RuleID: rule.ID, SourceID: rule.SourceID, Classification: rule.Classification.Name, Action: rule.Action, Exit: rule.Action}
		if rule.Action == RouteUpstream {
			status.Exit = rule.UpstreamID
		}
		status.VersionDigest = snapshot.references[rule.SourceID].VersionDigest
		if rule.Action == RouteUpstream {
			upstream := snapshot.upstream(rule.UpstreamID)
			if upstream == nil {
				status.Failure = "upstream-disabled-or-missing"
			} else if !upstream.TCP && !upstream.UDP {
				status.Failure = "protocol-unsupported"
			}
		}
		result = append(result, status)
	}
	return result
}

func prepareRouteSnapshot(ctx context.Context, configuration RoutingConfiguration, client datasetRoutingClient) (*routeSnapshot, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	snapshot := &routeSnapshot{configuration: cloneRouting(configuration), references: map[string]pluginsdk.DatasetReference{}, datasets: client}
	if len(configuration.Rules) == 0 {
		return snapshot, nil
	}
	if client == nil {
		return nil, ErrRouteDatasetUnavailable
	}
	for _, rule := range configuration.Rules {
		if _, ok := snapshot.references[rule.SourceID]; ok {
			continue
		}
		reference, err := client.ResolveDataset(ctx, pluginsdk.DatasetResolveRequest{SourceID: rule.SourceID})
		if err != nil {
			return nil, ErrRouteDatasetUnavailable
		}
		snapshot.references[rule.SourceID] = reference
	}
	return snapshot, nil
}

func (snapshot *routeSnapshot) decide(ctx context.Context, protocol, target string) (routeDecision, error) {
	if snapshot == nil {
		return routeDecision{Action: RouteDirect}, nil
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return routeDecision{}, ErrInvalid
	}
	host = strings.Trim(host, "[]")
	address, addressErr := netip.ParseAddr(host)
	for _, rule := range snapshot.configuration.Rules {
		isDomain := rule.Classification.Kind == pluginsdk.DatasetClassificationDomain
		if isDomain == (addressErr == nil) {
			continue
		}
		request := pluginsdk.DatasetQueryRequest{Reference: snapshot.references[rule.SourceID], Classifications: []pluginsdk.DatasetClassification{rule.Classification}, Budget: pluginsdk.DatasetQueryBudget{MaxDurationMicros: 2000, MaxResponseBytes: 32768}}
		if isDomain {
			request.Domain = strings.ToLower(host)
		} else {
			request.Address = address.String()
		}
		response, err := snapshot.datasets.QueryDatasets(ctx, request)
		if err != nil || response.Status != pluginsdk.DatasetQueryOK || len(response.Matches) != 1 {
			return routeDecision{RuleID: rule.ID, VersionDigest: request.Reference.VersionDigest}, ErrRouteDatasetUnavailable
		}
		if !response.Matches[0].Matched {
			continue
		}
		decision := routeDecision{Action: rule.Action, RuleID: rule.ID, VersionDigest: response.Reference.VersionDigest}
		if rule.Action == RouteUpstream {
			upstream := snapshot.upstream(rule.UpstreamID)
			if upstream == nil || !supportsProtocol(*upstream, protocol) {
				return decision, ErrRouteUpstreamUnavailable
			}
			decision.Upstream = upstream
		}
		return decision, nil
	}
	decision := routeDecision{Action: snapshot.configuration.effectiveDefault()}
	if decision.Action == RouteUpstream {
		decision.Upstream = snapshot.upstream(snapshot.configuration.DefaultUpstreamID)
		if decision.Upstream == nil || !supportsProtocol(*decision.Upstream, protocol) {
			return routeDecision{}, ErrRouteUpstreamUnavailable
		}
	}
	return decision, nil
}

func (snapshot *routeSnapshot) upstream(id string) *Upstream {
	for index := range snapshot.configuration.Upstreams {
		if snapshot.configuration.Upstreams[index].ID == id && snapshot.configuration.Upstreams[index].Enabled {
			value := snapshot.configuration.Upstreams[index]
			return &value
		}
	}
	return nil
}

func supportsProtocol(upstream Upstream, protocol string) bool {
	return protocol == "tcp" && upstream.TCP || protocol == "udp" && upstream.UDP
}

func cloneRouting(configuration RoutingConfiguration) RoutingConfiguration {
	configuration.Upstreams = append([]Upstream(nil), configuration.Upstreams...)
	configuration.Rules = append([]RouteRule(nil), configuration.Rules...)
	for index := range configuration.Rules {
		configuration.Rules[index].Classification.Attributes = append([]pluginsdk.DatasetAttribute(nil), configuration.Rules[index].Classification.Attributes...)
	}
	if configuration.Upstreams == nil {
		configuration.Upstreams = []Upstream{}
	}
	if configuration.Rules == nil {
		configuration.Rules = []RouteRule{}
	}
	if configuration.DefaultAction == "" {
		configuration.DefaultAction = RouteDirect
	}
	return configuration
}
