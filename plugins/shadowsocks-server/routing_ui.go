package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
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

// ErrDatasetRefreshFailed reports that every issued Host refresh control
// failed. In that case routing is never re-applied and the previously bound
// immutable versions keep serving.
var ErrDatasetRefreshFailed = errors.New("dataset refresh failed")

type datasetRefreshSource struct {
	SourceID     string `json:"source_id"`
	BeforeDigest string `json:"before_digest,omitempty"`
	AfterDigest  string `json:"after_digest,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

type datasetRefreshNode struct {
	AgentID        string `json:"agent_id"`
	RoutingApplied bool   `json:"routing_applied"`
	RoutingError   string `json:"routing_error,omitempty"`
}

type datasetRefreshReport struct {
	Mode    string                 `json:"mode"`
	Message string                 `json:"message,omitempty"`
	Sources []datasetRefreshSource `json:"sources"`
	Nodes   []datasetRefreshNode   `json:"nodes,omitempty"`
}

func (c *Controller) serveRoutingRefresh(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	var body struct {
		SourceID string `json:"source_id"`
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, MaxConfigBytes+1))
	if err != nil || len(raw) > MaxConfigBytes {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
		return
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
	}
	report, err := c.refreshDatasets(request.Context(), strings.TrimSpace(body.SourceID))
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	sources := c.routeSourceStatuses(request.Context(), c.directory().Routing)
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Refresh: report, RouteSources: sources, Access: readWriteAccess()})
}

// refreshDatasets triggers the Host refresh control for every dataset source
// referenced by routing rules (or only the requested source) and then
// re-applies routing so Agents re-resolve the pinned immutable references to
// the newest Host-prepared version. A denied dataset.manage grant degrades to
// re-apply only; a failed refresh control never re-applies, keeping the old
// version live. In-progress sessions keep their own snapshot either way.
func (c *Controller) refreshDatasets(ctx context.Context, onlySource string) (*datasetRefreshReport, error) {
	routing := c.directory().Routing
	sources := make([]string, 0, len(routing.Rules))
	referenced := false
	seen := map[string]bool{}
	for _, rule := range routing.Rules {
		if rule.SourceID == onlySource {
			referenced = true
		}
		if onlySource != "" && rule.SourceID != onlySource {
			continue
		}
		if seen[rule.SourceID] {
			continue
		}
		seen[rule.SourceID] = true
		sources = append(sources, rule.SourceID)
	}
	if onlySource != "" && !referenced {
		return nil, ErrInvalid
	}
	report := &datasetRefreshReport{Mode: "host-refresh", Sources: make([]datasetRefreshSource, 0, len(sources))}
	manageable := c.managedRuntime != nil && c.managedRuntime.client != nil
	failed := 0
	succeeded := 0
	for _, sourceID := range sources {
		entry := datasetRefreshSource{SourceID: sourceID, BeforeDigest: c.resolveDatasetDigest(ctx, sourceID)}
		switch {
		case !manageable:
			entry.Status = "skipped"
		default:
			err := c.managedRuntime.controlDatasetRefresh(ctx, sourceID)
			switch {
			case err == nil:
				succeeded++
			case datasetManageDenied(err):
				manageable = false
				entry.Status = "skipped"
			default:
				failed++
				entry.Status = "error"
				entry.Error = "refresh-failed"
			}
		}
		report.Sources = append(report.Sources, entry)
	}
	if !manageable && len(sources) > 0 {
		report.Mode = "reapply-only"
		report.Message = "宿主未授予 dataset.manage 或刷新控制不可用，已重新应用当前绑定；未获取新版本。"
	}
	if failed > 0 && succeeded == 0 {
		// Every issued refresh control failed: do not re-apply so no new
		// dataset can be silently selected; the old versions keep working.
		return nil, ErrDatasetRefreshFailed
	}
	agents := map[string]bool{}
	for _, listener := range c.directory().Listeners {
		agents[listener.AgentID] = true
	}
	ordered := make([]string, 0, len(agents))
	for agentID := range agents {
		ordered = append(ordered, agentID)
	}
	sort.Strings(ordered)
	for _, agentID := range ordered {
		node := datasetRefreshNode{AgentID: agentID}
		if err := c.applyAgentListens(ctx, agentID); err != nil {
			node.RoutingError = publicListenError(err)
		} else {
			node.RoutingApplied = true
		}
		report.Nodes = append(report.Nodes, node)
	}
	updated := 0
	for index := range report.Sources {
		entry := &report.Sources[index]
		entry.AfterDigest = c.resolveDatasetDigest(ctx, entry.SourceID)
		if entry.Status != "" {
			continue
		}
		switch {
		case entry.AfterDigest == "":
			entry.Status = "unresolved"
		case entry.AfterDigest != entry.BeforeDigest:
			entry.Status = "updated"
			updated++
		default:
			entry.Status = "latest"
		}
	}
	if report.Message == "" {
		switch {
		case len(report.Sources) == 0:
			report.Message = "没有引用数据集的分流规则，已重新应用当前路由。"
		case failed > 0:
			report.Message = "部分数据源刷新失败，已应用成功刷新的版本，失败源保留当前版本。"
		case updated > 0:
			report.Message = "数据源已更新到新版本并重新应用分流。"
		default:
			report.Message = "数据源已是最新版本，已重新应用分流。"
		}
	}
	return report, nil
}

func (c *Controller) resolveDatasetDigest(ctx context.Context, sourceID string) string {
	if c.managedRuntime == nil || c.managedRuntime.datasets == nil {
		return ""
	}
	reference, err := c.managedRuntime.datasets.ResolveDataset(ctx, pluginsdk.DatasetResolveRequest{SourceID: sourceID})
	if err != nil {
		return ""
	}
	return reference.VersionDigest
}

func datasetManageDenied(err error) bool {
	var runtimeError *pluginsdk.RuntimeError
	return errors.As(err, &runtimeError) && runtimeError.Code == pluginsdk.ErrorPermissionDenied
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
		var routingApplied *bool
		routingError := ""
		if agentID := strings.TrimSpace(request.URL.Query().Get("agent_id")); validAgentID(agentID) {
			applied := false
			routingApplied = &applied
			if report, err := c.ReportListen(request.Context(), agentID); err == nil {
				status = report.Routes
				applied = report.Online && report.RoutingDigest == routingDigest(routing)
				if !applied {
					routingError = "分流配置已保存，等待该节点应用"
				}
			} else {
				routingError = publicListenError(err)
			}
		}
		sources := c.routeSourceStatuses(request.Context(), routing)
		// Execution faces resolve their own scoped dataset handles. A control
		// face without that handle must not overwrite a node's applied evidence.
		for index := range sources {
			for _, applied := range status {
				if applied.SourceID == sources[index].SourceID && applied.VersionDigest != "" {
					sources[index].VersionDigest, sources[index].Error = applied.VersionDigest, ""
					break
				}
			}
		}
		status = mergeRouteStatuses(routing, sources, status)
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, RoutingApplied: routingApplied, RoutingError: routingError, RouteStatus: status, RouteSources: sources, Access: readWriteAccess()})
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
	if action == "test" {
		c.serveUpstreamTest(writer, request, id)
		return
	}
	var body upstreamWriteRequest
	if action == "update" {
		if err := decodeRoutingWrite(request, &body); err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(err)})
			return
		}
	}
	routing, err := c.mutateUpstream(request.Context(), id, action, body)
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, Access: readWriteAccess()})
}

// serveUpstreamTest probes one saved upstream from the selected Agent. The
// target node comes from the request body (agent_id) or the agent_id query
// parameter; the probe is read-only against the saved configuration.
func (c *Controller) serveUpstreamTest(writer http.ResponseWriter, request *http.Request, id string) {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, MaxConfigBytes+1))
	if err != nil || len(raw) > MaxConfigBytes {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
		return
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
	}
	agentID := strings.TrimSpace(body.AgentID)
	if agentID == "" {
		agentID = strings.TrimSpace(request.URL.Query().Get("agent_id"))
	}
	if !validAgentID(agentID) {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: agentRequiredText})
		return
	}
	result, err := c.testUpstream(request.Context(), id, agentID)
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Test: result, Access: readWriteAccess()})
}

// testUpstream routes a read-only connectivity probe for the saved upstream
// to the selected Agent. Disabled upstreams stay testable because the probe
// does not depend on routing decisions. An offline node or a failed plugin
// call degrades to a classified failure in the result instead of an HTTP
// error, keeping the routing_error-style reporting; saved configuration and
// in-flight sessions are never touched.
func (c *Controller) testUpstream(ctx context.Context, id, agentID string) (*upstreamTestResult, error) {
	if c.listenHost == nil {
		return nil, ErrExecutionUnavailable
	}
	var upstream *Upstream
	routing := c.directory().Routing
	for index := range routing.Upstreams {
		if routing.Upstreams[index].ID == id {
			upstream = &routing.Upstreams[index]
			break
		}
	}
	if upstream == nil {
		return nil, ErrInvalid
	}
	result, err := c.listenHost.TestUpstream(ctx, agentID, *upstream)
	if err != nil {
		result.Failure = "probe-failed"
		if errors.Is(err, ErrAgentOffline) {
			result.Failure = "agent-offline"
		}
	}
	if result.AgentID == "" {
		result.AgentID = agentID
	}
	if result.UpstreamID == "" {
		result.UpstreamID = upstream.ID
	}
	return &result, nil
}

// routingExportVersion is the only routing file layout the importer accepts.
// Bumping it lets future schema changes reject stale or foreign files instead
// of silently misreading them.
const routingExportVersion = 1

// upstreamExportEntry is the non-secret projection of an upstream. Secret
// references stay inside the instance: they are meaningless elsewhere and the
// export must not reveal which scoped-secret IDs exist.
type upstreamExportEntry struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Method  string `json:"method"`
	Enabled bool   `json:"enabled"`
	TCP     bool   `json:"tcp"`
	UDP     bool   `json:"udp"`
}

type routingExportDocument struct {
	Version           int                   `json:"version"`
	Rules             []RouteRule           `json:"rules"`
	DefaultAction     string                `json:"default_action"`
	DefaultUpstreamID string                `json:"default_upstream_id,omitempty"`
	Upstreams         []upstreamExportEntry `json:"upstreams"`
}

// upstreamImportEntry accepts the export shape plus a per-upstream password
// the admin fills in the import dialog. The password is never echoed back; it
// only flows into the scoped-secret mint path.
type upstreamImportEntry struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
	TCP      bool   `json:"tcp"`
	UDP      bool   `json:"udp"`
}

type routingImportRequest struct {
	Version           int                   `json:"version"`
	Rules             []RouteRule           `json:"rules"`
	DefaultAction     string                `json:"default_action"`
	DefaultUpstreamID string                `json:"default_upstream_id,omitempty"`
	Upstreams         []upstreamImportEntry `json:"upstreams"`
}

// routingImportError carries a readable per-upstream rejection message for
// failures the generic "请求无效" text cannot explain, such as a missing or
// incompatible credential.
type routingImportError struct{ message string }

func (err *routingImportError) Error() string { return err.message }

func routingImportRejected(message string) error {
	return &routingImportError{message: message}
}

func (c *Controller) serveRoutingExport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	routing := cloneRouting(c.directory().Routing)
	document := routingExportDocument{
		Version:           routingExportVersion,
		Rules:             routing.Rules,
		DefaultAction:     routing.effectiveDefault(),
		DefaultUpstreamID: routing.DefaultUpstreamID,
		Upstreams:         make([]upstreamExportEntry, 0, len(routing.Upstreams)),
	}
	for _, upstream := range routing.Upstreams {
		document.Upstreams = append(document.Upstreams, upstreamExportEntry{ID: upstream.ID, Host: upstream.Host, Port: upstream.Port, Method: upstream.Method, Enabled: upstream.Enabled, TCP: upstream.TCP, UDP: upstream.UDP})
	}
	wire, err := json.Marshal(document)
	if err != nil {
		writeListenJSON(writer, http.StatusInternalServerError, listenAPIResponse{Error: "导出失败"})
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="shadowsocks-routing.json"`)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(wire)
	}
}

func (c *Controller) serveRoutingImport(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	var body routingImportRequest
	if err := decodeRoutingWrite(request, &body); err != nil {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(err)})
		return
	}
	routing, err := c.importRouting(request.Context(), body)
	if err != nil {
		var rejected *routingImportError
		if errors.As(err, &rejected) {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: rejected.message})
			return
		}
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, Access: readWriteAccess()})
}

// importRouting validates the whole file before anything is committed:
// structure, limits, and credentials are checked first, new secrets are minted
// through the scoped-secret path, and replaceRouting is the single commit
// point. On any failure the current configuration stays untouched and every
// secret minted for the attempt is revoked; secrets minted for upstreams that
// keep their credential are never rolled back. An upstream without a password
// may reuse the credential of the existing upstream with the same ID, provided
// the stored material still validates against the imported method.
func (c *Controller) importRouting(ctx context.Context, body routingImportRequest) (RoutingConfiguration, error) {
	if body.Version != routingExportVersion {
		return RoutingConfiguration{}, routingImportRejected("配置文件版本不兼容或已损坏，请重新导出后再试")
	}
	if len(body.Upstreams) > MaxUpstreams || len(body.Rules) > MaxRouteRules {
		return RoutingConfiguration{}, ErrInvalid
	}
	if len(body.Upstreams) > 0 && c.managedRuntime == nil {
		return RoutingConfiguration{}, ErrInvalid
	}
	current := cloneRouting(c.directory().Routing)
	existing := make(map[string]Upstream, len(current.Upstreams))
	for _, upstream := range current.Upstreams {
		existing[upstream.ID] = upstream
	}
	next := RoutingConfiguration{
		Rules:             append([]RouteRule(nil), body.Rules...),
		DefaultAction:     body.DefaultAction,
		DefaultUpstreamID: body.DefaultUpstreamID,
		Upstreams:         make([]Upstream, 0, len(body.Upstreams)),
	}
	minted := make([]pluginsdk.ScopedSecretReference, 0, len(body.Upstreams))
	fail := func(err error) (RoutingConfiguration, error) {
		if c.managedRuntime != nil {
			c.managedRuntime.revokeReferences(ctx, minted)
		}
		return RoutingConfiguration{}, err
	}
	seen := make(map[string]bool, len(body.Upstreams))
	missing := make([]string, 0)
	for _, entry := range body.Upstreams {
		endpoint := pluginsdk.ManagedNetworkEndpoint{Host: entry.Host, Port: entry.Port}
		if !refPattern.MatchString(entry.ID) || seen[entry.ID] || endpoint.Validate() != nil || !SupportedMethod(entry.Method) || (!entry.TCP && !entry.UDP) {
			return fail(ErrInvalid)
		}
		seen[entry.ID] = true
		upstream := Upstream{ID: entry.ID, Host: entry.Host, Port: entry.Port, Method: entry.Method, Enabled: entry.Enabled, TCP: entry.TCP, UDP: entry.UDP}
		if password := strings.TrimSpace(entry.Password); password != "" {
			engine, err := NewProtocolEngine(entry.Method, []byte(entry.Password))
			if err != nil {
				return fail(routingImportRejected(fmt.Sprintf("上游 %q 的连接密钥与加密方式不匹配，请核对后重试", entry.ID)))
			}
			engine.Destroy()
			material := []byte(entry.Password)
			reference, err := c.managedRuntime.importOpaqueSecret(ctx, "upstream", material)
			clear(material)
			if err != nil {
				return fail(err)
			}
			minted = append(minted, reference)
			upstream.SecretRef, upstream.SecretVersion = reference.ID, reference.Version
		} else if previous, ok := existing[entry.ID]; ok {
			material, err := c.managedRuntime.Resolve(ctx, previous.SecretRef, previous.SecretVersion)
			if err != nil {
				return fail(routingImportRejected(fmt.Sprintf("上游 %q 无法沿用现有凭据，请补填连接密钥", entry.ID)))
			}
			engine, err := NewProtocolEngine(entry.Method, material)
			clear(material)
			if err != nil {
				return fail(routingImportRejected(fmt.Sprintf("上游 %q 的现有凭据与加密方式不兼容，请补填连接密钥", entry.ID)))
			}
			engine.Destroy()
			upstream.SecretRef, upstream.SecretVersion = previous.SecretRef, previous.SecretVersion
		} else {
			missing = append(missing, fmt.Sprintf("%q", entry.ID))
			continue
		}
		next.Upstreams = append(next.Upstreams, upstream)
	}
	if len(missing) > 0 {
		return fail(routingImportRejected(fmt.Sprintf("上游 %s 缺少连接密钥，请补填后重试", strings.Join(missing, "、"))))
	}
	if err := next.Validate(); err != nil {
		return fail(err)
	}
	if err := c.replaceRouting(ctx, next); err != nil {
		return fail(err)
	}
	// Credentials the imported configuration no longer references are dropped.
	// Revocation stays best-effort: an orphaned secret has no consumer and does
	// not change the committed configuration.
	retired := make([]pluginsdk.ScopedSecretReference, 0, len(current.Upstreams))
	kept := make(map[string]bool, len(next.Upstreams))
	for _, upstream := range next.Upstreams {
		kept[upstream.SecretRef+"\x00"+upstream.SecretVersion] = true
	}
	for _, upstream := range current.Upstreams {
		if !kept[upstream.SecretRef+"\x00"+upstream.SecretVersion] {
			retired = append(retired, pluginsdk.ScopedSecretReference{ID: upstream.SecretRef, Version: upstream.SecretVersion})
		}
	}
	if c.managedRuntime != nil {
		c.managedRuntime.revokeReferences(ctx, retired)
	}
	return cloneRouting(next), nil
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

func (c *Controller) mutateUpstream(ctx context.Context, id, action string, body upstreamWriteRequest) (RoutingConfiguration, error) {
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
	previous := next.Upstreams[index]
	var minted pluginsdk.ScopedSecretReference
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
	case "update":
		endpoint := pluginsdk.ManagedNetworkEndpoint{Host: body.Host, Port: body.Port}
		if endpoint.Validate() != nil || !SupportedMethod(body.Method) || (!body.TCP && !body.UDP) {
			return RoutingConfiguration{}, ErrInvalid
		}
		if strings.TrimSpace(body.Password) != "" {
			if c.managedRuntime == nil {
				return RoutingConfiguration{}, ErrInvalid
			}
			engine, err := NewProtocolEngine(body.Method, []byte(body.Password))
			if err != nil {
				return RoutingConfiguration{}, ErrInvalid
			}
			engine.Destroy()
			material := []byte(body.Password)
			reference, err := c.managedRuntime.importOpaqueSecret(ctx, "upstream", material)
			clear(material)
			if err != nil {
				return RoutingConfiguration{}, err
			}
			minted = reference
		} else if body.Method != previous.Method {
			// A method change must still accept the kept credential.
			if c.managedRuntime == nil {
				return RoutingConfiguration{}, ErrInvalid
			}
			material, err := c.managedRuntime.Resolve(ctx, previous.SecretRef, previous.SecretVersion)
			if err != nil {
				return RoutingConfiguration{}, err
			}
			engine, err := NewProtocolEngine(body.Method, material)
			clear(material)
			if err != nil {
				return RoutingConfiguration{}, ErrInvalid
			}
			engine.Destroy()
		}
		updated := &next.Upstreams[index]
		updated.Host, updated.Port, updated.Method = body.Host, body.Port, body.Method
		updated.TCP, updated.UDP = body.TCP, body.UDP
		if minted.ID != "" {
			updated.SecretRef, updated.SecretVersion = minted.ID, minted.Version
		}
	default:
		return RoutingConfiguration{}, ErrInvalid
	}
	if err := c.replaceRouting(ctx, next); err != nil {
		if minted.ID != "" {
			c.managedRuntime.revokeReferences(ctx, []pluginsdk.ScopedSecretReference{minted})
		}
		return RoutingConfiguration{}, err
	}
	switch {
	case action == "delete" && c.managedRuntime != nil:
		if err := c.managedRuntime.revokeSecret(ctx, previous.SecretRef, previous.SecretVersion); err != nil {
			return RoutingConfiguration{}, err
		}
	case action == "update" && minted.ID != "":
		if err := c.managedRuntime.revokeSecret(ctx, previous.SecretRef, previous.SecretVersion); err != nil {
			// Mirror finishSecretReplacement: restore the previous routing so
			// the still-live secret keeps its consumer, then drop the minted ref.
			if restoreErr := c.replaceRouting(ctx, current); restoreErr != nil {
				return RoutingConfiguration{}, ErrExecutionUnavailable
			}
			c.managedRuntime.revokeReferences(ctx, []pluginsdk.ScopedSecretReference{minted})
			return RoutingConfiguration{}, ErrExecutionUnavailable
		}
	}
	return cloneRouting(next), nil
}

func (c *Controller) replaceRouting(ctx context.Context, routing RoutingConfiguration) error {
	if err := routing.Validate(); err != nil {
		return err
	}
	next := c.directory()
	next.Routing = cloneRouting(routing)
	if store, ok := c.listenState.(RoutingCatalogStore); ok {
		if err := store.StoreRouting(ctx, next.Routing); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.configuration.Routing = cloneRouting(next.Routing)
	published := c.published
	c.mu.Unlock()
	if published != nil {
		if err := published.commitDirectory(next); err != nil {
			return err
		}
	}
	agents := map[string]bool{}
	for _, listener := range next.Listeners {
		agents[listener.AgentID] = true
	}
	for agentID := range agents {
		// Desired routing is durable. A missing or failing execution face must
		// not roll back healthy nodes; reconciliation retries its own state.
		_ = c.applyAgentListens(ctx, agentID)
	}
	return nil
}
