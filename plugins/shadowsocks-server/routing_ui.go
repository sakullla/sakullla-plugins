package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type upstreamWriteRequest struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
	TCP      bool   `json:"tcp"`
	UDP      bool   `json:"udp"`
}

type routingWriteRequest struct {
	Rules             []RouteRule `json:"rules"`
	DefaultAction     string      `json:"default_action"`
	DefaultUpstreamID string      `json:"default_upstream_id,omitempty"`
}

func decodeRoutingWrite(request *http.Request, target any) error {
	raw, err := io.ReadAll(io.LimitReader(request.Body, MaxConfigBytes+1))
	if err != nil || len(raw) > MaxConfigBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func (c *Controller) serveRouting(writer http.ResponseWriter, request *http.Request) {
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		routing := cloneRouting(c.directory().Routing)
		var status []RouteStatus
		if agentID := strings.TrimSpace(request.URL.Query().Get("agent_id")); validAgentID(agentID) {
			if report, err := c.ReportListen(request.Context(), agentID); err == nil {
				status = report.Routes
			}
		}
		sources := c.routeSourceStatuses(request.Context(), routing)
		status = mergeRouteStatuses(routing, sources, status)
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, RouteStatus: status, RouteSources: sources, Access: readWriteAccess()})
	case http.MethodPost:
		var body routingWriteRequest
		if err := decodeRoutingWrite(request, &body); err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(err)})
			return
		}
		current := c.directory().Routing
		next := RoutingConfiguration{Upstreams: current.Upstreams, Rules: body.Rules, DefaultAction: body.DefaultAction, DefaultUpstreamID: body.DefaultUpstreamID}
		if err := c.replaceRouting(request.Context(), next); err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		next = cloneRouting(next)
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &next, Access: readWriteAccess()})
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
	}
}

func (c *Controller) routeSourceStatuses(ctx context.Context, routing RoutingConfiguration) []RouteSourceStatus {
	result := make([]RouteSourceStatus, 0)
	seen := map[string]bool{}
	for _, rule := range routing.Rules {
		if seen[rule.SourceID] {
			continue
		}
		seen[rule.SourceID] = true
		status := RouteSourceStatus{SourceID: rule.SourceID}
		if c.managedRuntime == nil || c.managedRuntime.datasets == nil {
			status.Error = "dataset-unavailable"
		} else if reference, err := c.managedRuntime.datasets.ResolveDataset(ctx, pluginsdk.DatasetResolveRequest{SourceID: rule.SourceID}); err != nil {
			status.Error = "dataset-unavailable"
		} else {
			status.VersionDigest = reference.VersionDigest
		}
		result = append(result, status)
	}
	return result
}

func mergeRouteStatuses(routing RoutingConfiguration, sources []RouteSourceStatus, applied []RouteStatus) []RouteStatus {
	byRule := map[string]RouteStatus{}
	for _, status := range applied {
		byRule[status.RuleID] = status
	}
	bySource := map[string]RouteSourceStatus{}
	for _, source := range sources {
		bySource[source.SourceID] = source
	}
	upstreams := map[string]Upstream{}
	for _, upstream := range routing.Upstreams {
		upstreams[upstream.ID] = upstream
	}
	result := make([]RouteStatus, 0, len(routing.Rules))
	for _, rule := range routing.Rules {
		status, ok := byRule[rule.ID]
		if !ok {
			status = RouteStatus{RuleID: rule.ID, SourceID: rule.SourceID, Classification: rule.Classification.Name, Action: rule.Action, Exit: rule.Action, DomainSource: "none"}
			if rule.Action == RouteUpstream {
				status.Exit = rule.UpstreamID
			}
		}
		source := bySource[rule.SourceID]
		if status.VersionDigest == "" {
			status.VersionDigest = source.VersionDigest
		}
		if source.Error != "" {
			status.Failure = source.Error
		}
		if rule.Action == RouteUpstream {
			upstream, exists := upstreams[rule.UpstreamID]
			switch {
			case !exists:
				status.Failure = "upstream-missing"
			case !upstream.Enabled:
				status.Failure = "upstream-disabled"
			case !upstream.TCP:
				status.Failure = "tcp-unsupported"
			case !upstream.UDP:
				status.Failure = "udp-unsupported"
			}
		}
		result = append(result, status)
	}
	return result
}

func (c *Controller) serveUpstreamCollection(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	var body upstreamWriteRequest
	if err := decodeRoutingWrite(request, &body); err != nil {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(err)})
		return
	}
	routing, err := c.createUpstream(request.Context(), body)
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, Access: readWriteAccess()})
}

func (c *Controller) serveUpstreamItem(writer http.ResponseWriter, request *http.Request, id, action string) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	routing, err := c.mutateUpstream(request.Context(), id, action)
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, Access: readWriteAccess()})
}

func (c *Controller) createUpstream(ctx context.Context, body upstreamWriteRequest) (RoutingConfiguration, error) {
	if c.managedRuntime == nil || !refPattern.MatchString(body.ID) || strings.TrimSpace(body.Password) == "" {
		return RoutingConfiguration{}, ErrInvalid
	}
	engine, err := NewProtocolEngine(body.Method, []byte(body.Password))
	if err != nil {
		return RoutingConfiguration{}, ErrInvalid
	}
	engine.Destroy()
	current := cloneRouting(c.directory().Routing)
	for _, upstream := range current.Upstreams {
		if upstream.ID == body.ID {
			return RoutingConfiguration{}, ErrInvalid
		}
	}
	material := []byte(body.Password)
	reference, err := c.managedRuntime.importOpaqueSecret(ctx, "upstream", material)
	clear(material)
	if err != nil {
		return RoutingConfiguration{}, err
	}
	current.Upstreams = append(current.Upstreams, Upstream{ID: body.ID, Host: body.Host, Port: body.Port, Method: body.Method, SecretRef: reference.ID, SecretVersion: reference.Version, Enabled: true, TCP: body.TCP, UDP: body.UDP})
	if err := c.replaceRouting(ctx, current); err != nil {
		c.managedRuntime.revokeReferences(ctx, []pluginsdk.ScopedSecretReference{reference})
		return RoutingConfiguration{}, err
	}
	return cloneRouting(current), nil
}

func (c *Controller) mutateUpstream(ctx context.Context, id, action string) (RoutingConfiguration, error) {
	current := cloneRouting(c.directory().Routing)
	next := cloneRouting(current)
	index := -1
	for candidate := range next.Upstreams {
		if next.Upstreams[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 {
		return RoutingConfiguration{}, ErrInvalid
	}
	removed := next.Upstreams[index]
	switch action {
	case "enable":
		next.Upstreams[index].Enabled = true
	case "disable":
		next.Upstreams[index].Enabled = false
	case "delete":
		for _, rule := range next.Rules {
			if rule.UpstreamID == id {
				return RoutingConfiguration{}, ErrRouteUpstreamUnavailable
			}
		}
		if next.DefaultUpstreamID == id {
			return RoutingConfiguration{}, ErrRouteUpstreamUnavailable
		}
		next.Upstreams = append(next.Upstreams[:index], next.Upstreams[index+1:]...)
	default:
		return RoutingConfiguration{}, ErrInvalid
	}
	if err := c.replaceRouting(ctx, next); err != nil {
		return RoutingConfiguration{}, err
	}
	if action == "delete" && c.managedRuntime != nil {
		if err := c.managedRuntime.revokeSecret(ctx, removed.SecretRef, removed.SecretVersion); err != nil {
			return RoutingConfiguration{}, err
		}
	}
	return cloneRouting(next), nil
}

func (c *Controller) replaceRouting(ctx context.Context, routing RoutingConfiguration) error {
	if err := routing.Validate(); err != nil {
		return err
	}
	previous := c.directory()
	next := clone(previous)
	next.Routing = cloneRouting(routing)
	if store, ok := c.listenState.(RoutingCatalogStore); ok {
		if err := store.StoreRouting(ctx, next.Routing); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.configuration.Routing = cloneRouting(next.Routing)
	c.mu.Unlock()
	agents := map[string]bool{}
	for _, listener := range next.Listeners {
		agents[listener.AgentID] = true
	}
	for agentID := range agents {
		if err := c.applyAgentListens(ctx, agentID); err != nil {
			if store, ok := c.listenState.(RoutingCatalogStore); ok {
				_ = store.StoreRouting(ctx, previous.Routing)
			}
			c.mu.Lock()
			c.configuration.Routing = cloneRouting(previous.Routing)
			c.mu.Unlock()
			for restored := range agents {
				_ = c.applyAgentListens(ctx, restored)
			}
			return err
		}
	}
	return nil
}
