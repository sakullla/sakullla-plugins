package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

// maxRemoteSources bounds the panel-side registry of remote dataset sources.
const maxRemoteSources = 32

// remoteSourceRecord is the durable panel-side mirror of one remote dataset
// source registration. The Host owns the source inside the plugin's resource
// group but exposes no list operation to plugins, so the registration
// parameters are kept under the plugin's own state key to render the list,
// refresh, and remove entries. Records never carry credentials: the remote
// URL cannot contain userinfo and no credential field exists.
type remoteSourceRecord struct {
	Source    pluginsdk.DatasetSource          `json:"source"`
	Retrieval pluginsdk.DatasetSourceRetrieval `json:"retrieval"`
}

func (record remoteSourceRecord) validate() error {
	if record.Source.Validate() != nil || record.Source.URL == "" || record.Retrieval.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

// RemoteSourceCatalogStore persists the remote-source registry alongside the
// other plugin catalogs.
type RemoteSourceCatalogStore interface {
	LoadRemoteSources(context.Context) ([]remoteSourceRecord, bool, error)
	StoreRemoteSources(context.Context, []remoteSourceRecord) error
}

// remoteSourceView projects a registered remote source for the panel,
// including the version the Host currently resolves and the fetch time the
// catalog exposes. Referenced tells the panel a rule still names the source
// so removal can warn about the resulting fail-closed state.
type remoteSourceView struct {
	SourceID               string `json:"source_id"`
	Name                   string `json:"name"`
	URL                    string `json:"url"`
	Format                 string `json:"format"`
	Mode                   string `json:"mode"`
	ChecksumURL            string `json:"checksum_url,omitempty"`
	Revision               string `json:"revision,omitempty"`
	ExpectedDigest         string `json:"expected_digest,omitempty"`
	RefreshIntervalSeconds int64  `json:"refresh_interval_seconds"`
	VersionDigest          string `json:"version_digest,omitempty"`
	FetchedAt              string `json:"fetched_at,omitempty"`
	Referenced             bool   `json:"referenced"`
	Error                  string `json:"error,omitempty"`
}

type datasetSourceWriteRequest struct {
	SourceID               string `json:"source_id"`
	Name                   string `json:"name,omitempty"`
	URL                    string `json:"url"`
	Format                 string `json:"format"`
	Mode                   string `json:"mode"`
	ChecksumURL            string `json:"checksum_url,omitempty"`
	Revision               string `json:"revision,omitempty"`
	ExpectedDigest         string `json:"expected_digest,omitempty"`
	RefreshIntervalSeconds int64  `json:"refresh_interval_seconds,omitempty"`
}

// datasetSourceError carries a readable rejection or failure message for
// registration input and Host answers the generic "请求无效" text cannot
// explain; status overrides the default 400 when the cause is a denied grant.
type datasetSourceError struct {
	message string
	status  int
}

func (err *datasetSourceError) Error() string { return err.message }

func datasetSourceRejected(message string) error {
	return &datasetSourceError{message: message}
}

func datasetSourceDenied(message string) error {
	return &datasetSourceError{message: message, status: http.StatusForbidden}
}

var datasetDigestWirePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// remoteSourceIDPattern keeps panel-registered source ids to the same
// lowercase identifier style the built-in geosite/geoip ids use, so rules and
// Host datasets refer to them consistently. The SDK identity bound only
// rejects empty or delimitered text, which is too loose for a source name.
// "/" and ":" stay excluded because the id is embedded as a single URL path
// segment in the panel API (for example /api/dataset-sources/{id}/delete);
// a "/" would split the route and make a registered source impossible to
// remove.
var remoteSourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// upstreamIDPattern keeps panel-created upstream ids inside the same
// URL-safe identifier set remoteSourceIDPattern uses. The wider refPattern
// also admits "/" and ":", but the panel API embeds the id as a single path
// segment (/api/upstreams/{id}/{action}); a "/" would split the route and a
// ":" id created through the API would be unaddressable the same way, so a
// laxer id would be creatable yet permanently unmanageable. Stored routing
// state is not revalidated against this pattern on load, so an upstream
// saved under the older bound still applies.
var upstreamIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// upstreamRequestError carries a readable rejection message for upstream
// write input the generic "请求无效" text cannot explain, such as an id that
// cannot appear inside the item route.
type upstreamRequestError struct{ message string }

func (err *upstreamRequestError) Error() string { return err.message }

func upstreamRejected(message string) error {
	return &upstreamRequestError{message: message}
}

func writeUpstreamError(writer http.ResponseWriter, err error) {
	var rejected *upstreamRequestError
	if errors.As(err, &rejected) {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: rejected.message})
		return
	}
	writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
}

// remoteDatasetURLError mirrors the early, readable half of the Host's remote
// URL bound: literal https only, no credentials, no fragment. The Host still
// re-authorizes private addresses, DNS, redirects and budgets on its side.
func remoteDatasetURLError(label, raw string) string {
	if raw == "" {
		return label + "不能为空"
	}
	if len(raw) > 2048 {
		return label + "长度不能超过 2048 字符"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return label + "不是合法 URL"
	}
	if parsed.Scheme != "https" {
		return label + "必须使用 https"
	}
	if parsed.User != nil {
		return label + "不能携带用户名或口令"
	}
	if parsed.Fragment != "" {
		return label + "不能包含 # 片段"
	}
	return ""
}

// datasetSourceRegisterRequest turns the panel form into a validated SDK
// request. Every rejection happens before the Host call so nothing is created
// for invalid input; the SDK request validation still runs as the final gate.
func datasetSourceRegisterRequest(body datasetSourceWriteRequest) (pluginsdk.DatasetSourceRegisterRequest, error) {
	var request pluginsdk.DatasetSourceRegisterRequest
	sourceID := strings.TrimSpace(body.SourceID)
	if pluginsdk.ValidatePolicyIdentity(sourceID) != nil || !remoteSourceIDPattern.MatchString(sourceID) {
		return request, datasetSourceRejected("数据源标识无效：需以小写字母或数字开头，仅含小写字母、数字与 . _ -")
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = sourceID
	}
	if len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
		return request, datasetSourceRejected("显示名称过长或包含非法字符")
	}
	rawURL := strings.TrimSpace(body.URL)
	if errText := remoteDatasetURLError("远程规则集地址", rawURL); errText != "" {
		return request, datasetSourceRejected(errText)
	}
	format := pluginsdk.DatasetFormat(strings.TrimSpace(body.Format))
	if format.Validate() != nil {
		return request, datasetSourceRejected("内容格式不受支持，请选择 geosite、geoip、cidr、community 或 geo-mmdb")
	}
	interval := body.RefreshIntervalSeconds
	if interval != 0 && (interval < 3600 || interval > 366*24*3600) {
		return request, datasetSourceRejected("自动刷新间隔需为 0（仅手动刷新）或 3600–31622400 秒")
	}
	retrieval := pluginsdk.DatasetSourceRetrieval{Mode: strings.TrimSpace(body.Mode)}
	switch retrieval.Mode {
	case pluginsdk.DatasetRetrievalPinned:
		retrieval.Revision = strings.TrimSpace(body.Revision)
		retrieval.ExpectedDigest = strings.TrimSpace(body.ExpectedDigest)
		if retrieval.Revision == "" || len(retrieval.Revision) > 256 || strings.ContainsAny(retrieval.Revision, "\r\n\x00") {
			return request, datasetSourceRejected("固定版本模式需要填写版本标识（revision）")
		}
		if !datasetDigestWirePattern.MatchString(retrieval.ExpectedDigest) {
			return request, datasetSourceRejected("固定版本模式需要 sha256: 前缀加 64 位十六进制的内容摘要")
		}
	case pluginsdk.DatasetRetrievalRollingSHA256:
		retrieval.ChecksumURL = strings.TrimSpace(body.ChecksumURL)
		if errText := remoteDatasetURLError("校验和地址", retrieval.ChecksumURL); errText != "" {
			return request, datasetSourceRejected(errText)
		}
	default:
		return request, datasetSourceRejected("更新方式需为 pinned（固定版本）或 rolling-sha256（滚动校验）")
	}
	request = pluginsdk.DatasetSourceRegisterRequest{
		Source: pluginsdk.DatasetSource{
			ID:                     sourceID,
			Name:                   name,
			URL:                    rawURL,
			Format:                 format,
			RefreshIntervalSeconds: interval,
		},
		Retrieval: retrieval,
	}
	if err := request.Validate(); err != nil {
		return request, datasetSourceRejected("登记参数未通过校验，请核对地址、更新方式与刷新间隔")
	}
	return request, nil
}

func (c *Controller) remoteSourceRecords() []remoteSourceRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]remoteSourceRecord(nil), c.remoteSources...)
}

func (c *Controller) remoteSourceRegistered(sourceID string) bool {
	for _, record := range c.remoteSourceRecords() {
		if record.Source.ID == sourceID {
			return true
		}
	}
	return false
}

// commitRemoteSources validates and persists the registry before publishing it
// to memory, matching the store-then-commit order used for routing.
func (c *Controller) commitRemoteSources(ctx context.Context, next []remoteSourceRecord) error {
	if len(next) > maxRemoteSources {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(next))
	for _, record := range next {
		if record.validate() != nil || seen[record.Source.ID] {
			return ErrInvalid
		}
		seen[record.Source.ID] = true
	}
	c.mu.Lock()
	state := c.listenState
	c.mu.Unlock()
	if store, ok := state.(RemoteSourceCatalogStore); ok {
		if err := store.StoreRemoteSources(ctx, next); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.remoteSources = append([]remoteSourceRecord(nil), next...)
	c.mu.Unlock()
	return nil
}

func (c *Controller) remoteSourceViews(ctx context.Context) []remoteSourceView {
	records := c.remoteSourceRecords()
	referenced := map[string]bool{}
	for _, rule := range c.directory().Routing.Rules {
		referenced[rule.SourceID] = true
	}
	views := make([]remoteSourceView, 0, len(records))
	for _, record := range records {
		source := record.Source
		view := remoteSourceView{
			SourceID:               source.ID,
			Name:                   source.Name,
			URL:                    source.URL,
			Format:                 string(source.Format),
			Mode:                   record.Retrieval.Mode,
			ChecksumURL:            record.Retrieval.ChecksumURL,
			Revision:               record.Retrieval.Revision,
			ExpectedDigest:         record.Retrieval.ExpectedDigest,
			RefreshIntervalSeconds: source.RefreshIntervalSeconds,
			Referenced:             referenced[source.ID],
		}
		digest := c.resolveDatasetDigest(ctx, source.ID)
		if digest == "" {
			view.Error = "dataset-unavailable"
		} else {
			view.VersionDigest = digest
			if c.managedRuntime != nil {
				view.FetchedAt = c.managedRuntime.datasetSourceFetchedAt(ctx, source.ID, digest)
			}
		}
		views = append(views, view)
	}
	return views
}

// registerRemoteSource validates the form, issues dataset.source-register on
// the control-plane face, then records the registration locally. The Host
// call is the single creation point: a rejected request or failed control
// leaves both the Host state and the registry untouched. Registering the same
// source ID again replaces the earlier registration, which is how a changed
// URL or update policy is applied.
func (c *Controller) registerRemoteSource(ctx context.Context, body datasetSourceWriteRequest) ([]remoteSourceView, error) {
	request, err := datasetSourceRegisterRequest(body)
	if err != nil {
		return nil, err
	}
	if c.managedRuntime == nil || c.managedRuntime.client == nil {
		return nil, ErrExecutionUnavailable
	}
	if !c.remoteSourceRegistered(request.Source.ID) && len(c.remoteSourceRecords()) >= maxRemoteSources {
		return nil, datasetSourceRejected(fmt.Sprintf("远程规则集数量已达上限（%d 个）", maxRemoteSources))
	}
	if _, err := c.managedRuntime.registerDatasetSource(ctx, request); err != nil {
		if datasetGrantDenied(err) {
			return nil, datasetSourceDenied("宿主未授予远程规则集登记权限（dataset.source-register），请在插件授权中开启后重试")
		}
		return nil, datasetSourceRejected("远程规则集登记失败：宿主未能获取或校验该地址的内容，未确认创建数据源")
	}
	record := remoteSourceRecord{Source: request.Source, Retrieval: request.Retrieval}
	next := make([]remoteSourceRecord, 0, len(c.remoteSourceRecords())+1)
	replaced := false
	for _, existing := range c.remoteSourceRecords() {
		if existing.Source.ID == record.Source.ID {
			next = append(next, record)
			replaced = true
			continue
		}
		next = append(next, existing)
	}
	if !replaced {
		next = append(next, record)
	}
	if err := c.commitRemoteSources(ctx, next); err != nil {
		return nil, err
	}
	return c.remoteSourceViews(ctx), nil
}

// removeRemoteSource deletes the Host-side source then drops the local
// registry record. Rules still referencing the source are not rewritten: they
// lose resolution and report dataset-unavailable, which is the fail-closed
// boundary the removal must keep.
func (c *Controller) removeRemoteSource(ctx context.Context, sourceID string) ([]remoteSourceView, error) {
	if c.managedRuntime == nil || c.managedRuntime.client == nil {
		return nil, ErrExecutionUnavailable
	}
	records := c.remoteSourceRecords()
	index := -1
	for i, record := range records {
		if record.Source.ID == sourceID {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, datasetSourceRejected("该远程规则集不存在或已被移除")
	}
	if err := c.managedRuntime.controlDatasetDeleteSource(ctx, sourceID); err != nil {
		if datasetGrantDenied(err) {
			return nil, datasetSourceDenied("宿主未授予数据集管理权限（dataset.manage），无法移除远程规则集")
		}
		return nil, datasetSourceRejected("远程规则集移除失败：宿主拒绝了删除请求，登记信息保持不变")
	}
	next := append(append([]remoteSourceRecord(nil), records[:index]...), records[index+1:]...)
	if err := c.commitRemoteSources(ctx, next); err != nil {
		return nil, err
	}
	return c.remoteSourceViews(ctx), nil
}

func (c *Controller) serveDatasetSources(writer http.ResponseWriter, request *http.Request) {
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, RemoteSources: c.remoteSourceViews(request.Context()), Access: readWriteAccess()})
	case http.MethodPost:
		var body datasetSourceWriteRequest
		if err := decodeRoutingWrite(request, &body); err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(err)})
			return
		}
		views, err := c.registerRemoteSource(request.Context(), body)
		if err != nil {
			writeDatasetSourceError(writer, err)
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, RemoteSources: views, Access: readWriteAccess()})
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
	}
}

func (c *Controller) serveDatasetSourceDelete(writer http.ResponseWriter, request *http.Request, sourceID string) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	views, err := c.removeRemoteSource(request.Context(), sourceID)
	if err != nil {
		writeDatasetSourceError(writer, err)
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, RemoteSources: views, Access: readWriteAccess()})
}

func writeDatasetSourceError(writer http.ResponseWriter, err error) {
	var rejected *datasetSourceError
	if errors.As(err, &rejected) {
		status := rejected.status
		if status == 0 {
			status = http.StatusBadRequest
		}
		writeListenJSON(writer, status, listenAPIResponse{Error: rejected.message})
		return
	}
	writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
}

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
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Refresh: report, RouteSources: sources, RemoteSources: c.remoteSourceViews(request.Context()), Access: readWriteAccess()})
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
	if onlySource != "" && !referenced && c.remoteSourceRegistered(onlySource) {
		// A registered remote source can be refreshed before any rule cites it;
		// the Host re-fetches and prepares its newest version the same way.
		referenced = true
		sources = append(sources, onlySource)
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
			case datasetGrantDenied(err):
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

// datasetGrantDenied reports a refused Host capability grant on any dataset
// operation (manage refresh/delete, catalog, or source-register).
func datasetGrantDenied(err error) bool {
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
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Routing: &routing, RoutingApplied: routingApplied, RoutingError: routingError, RouteStatus: status, RouteSources: sources, RemoteSources: c.remoteSourceViews(request.Context()), Access: readWriteAccess()})
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
		writeUpstreamError(writer, err)
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
		writeUpstreamError(writer, err)
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
		if !upstreamIDPattern.MatchString(entry.ID) {
			return fail(routingImportRejected(fmt.Sprintf("上游 %q 的标识无效：需以小写字母或数字开头，仅含小写字母、数字与 . _ -", entry.ID)))
		}
		endpoint := pluginsdk.ManagedNetworkEndpoint{Host: entry.Host, Port: entry.Port}
		if seen[entry.ID] || endpoint.Validate() != nil || !SupportedMethod(entry.Method) || (!entry.TCP && !entry.UDP) {
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
	if !upstreamIDPattern.MatchString(body.ID) {
		return RoutingConfiguration{}, upstreamRejected("上游标识无效：需以小写字母或数字开头，仅含小写字母、数字与 . _ -")
	}
	if c.managedRuntime == nil || strings.TrimSpace(body.Password) == "" {
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
