package ippolicy

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var uiAssets embed.FS

type APIResponse struct {
	Ready        bool                               `json:"ready"`
	Config       Configuration                      `json:"config"`
	Policy       *pluginsdk.PolicyControlResponse   `json:"policy,omitempty"`
	Entry        *pluginsdk.PolicyControlResponse   `json:"entry,omitempty"`
	Entries      []pluginsdk.PolicyEntrySnapshot    `json:"entries"`
	EntryOverlay *EntryOverlay                      `json:"entry_overlay,omitempty"`
	Bindings     []pluginsdk.DatasetBindingResponse `json:"bindings"`
	Datasets     []DatasetView                      `json:"datasets"`
	Events       []pluginsdk.PolicyEvent            `json:"events"`
	Provinces    []ProvinceOption                   `json:"provinces"`
	Issues       []string                           `json:"issues"`
	Error        string                             `json:"error,omitempty"`
	Access       APIAccess                          `json:"access"`
}

type APIAccess struct {
	CanRead  bool `json:"can_read"`
	CanWrite bool `json:"can_write"`
}

type DatasetView struct {
	Definition      DatasetDefinition                `json:"definition"`
	Versions        []pluginsdk.DatasetVersion       `json:"versions"`
	Classifications []pluginsdk.DatasetCatalogEntry  `json:"classifications"`
	Status          *pluginsdk.DatasetStatusResponse `json:"status,omitempty"`
	Error           string                           `json:"error,omitempty"`
}

type writeRequest struct {
	Mode    string                       `json:"mode"`
	Config  Configuration                `json:"config"`
	Entry   *pluginsdk.PolicyEntryTarget `json:"entry,omitempty"`
	Reset   bool                         `json:"reset,omitempty"`
	Binding *BindingMutation             `json:"binding,omitempty"`
	Dataset *DatasetMutation             `json:"dataset,omitempty"`
	Rules   []Rule                       `json:"rules,omitempty"`
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	if pluginsdk.ServePluginUIAsset(writer, request, uiAssets, "assets/ui") {
		return
	}
	if !controller.uiReady() {
		writeJSON(writer, http.StatusServiceUnavailable, APIResponse{Ready: false, Config: DefaultConfiguration(), Bindings: []pluginsdk.DatasetBindingResponse{}, Datasets: []DatasetView{}, Events: []pluginsdk.PolicyEvent{}, Provinces: Provinces(), Issues: []string{"管理进程尚未激活"}, Error: ErrUnavailable.Error()})
		return
	}
	switch request.URL.Path {
	case "/api/state":
		controller.serveState(writer, request)
	case "/api/config":
		controller.serveConfig(writer, request)
	case "/api/entry-mode":
		controller.serveEntryMode(writer, request)
	case "/api/binding":
		controller.serveBinding(writer, request)
	case "/api/dataset":
		controller.serveDataset(writer, request)
	case "/api/entry-rules":
		controller.serveEntryRules(writer, request)
	default:
		http.Error(writer, "IP 策略页面未找到", http.StatusNotFound)
	}
}

func (controller *Controller) serveState(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeJSON(writer, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !uiAuthorized(request) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": ErrUnauthorized.Error()})
		return
	}
	response := controller.state(request)
	status := http.StatusOK
	if response.Error == ErrUnauthorized.Error() {
		status = http.StatusForbidden
	} else if !response.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(writer, status, response)
}

func (controller *Controller) state(request *http.Request) APIResponse {
	config := controller.currentConfig()
	response := APIResponse{Ready: true, Config: config, Entries: []pluginsdk.PolicyEntrySnapshot{}, Bindings: []pluginsdk.DatasetBindingResponse{}, Datasets: []DatasetView{}, Events: []pluginsdk.PolicyEvent{}, Provinces: Provinces(), Issues: []string{}, Access: APIAccess{CanRead: true, CanWrite: true}}
	policyState, err := controller.inspectPolicy(request.Context(), nil)
	if err != nil {
		response.Ready, response.Error = false, publicError(err)
		return response
	}
	response.Policy = &policyState
	listed, listErr := controller.listPolicyEntries(request.Context())
	if listErr != nil {
		response.Issues = append(response.Issues, "入口列表不可用")
	} else {
		response.Entries = make([]pluginsdk.PolicyEntrySnapshot, len(listed.Entries))
		copy(response.Entries, listed.Entries)
	}
	entryToken := strings.TrimSpace(request.URL.Query().Get("entry_token"))
	if entryToken != "" && listErr == nil {
		found := false
		for _, snapshot := range listed.Entries {
			if snapshot.Entry.Token != entryToken {
				continue
			}
			found = true
			entryState, entryErr := controller.inspectPolicyTarget(request.Context(), listed.InstanceID, listed.Stage, &snapshot.Entry)
			if entryErr != nil {
				response.Issues = append(response.Issues, "入口状态不可用")
				break
			}
			response.Entry = &entryState
			overlay := EntryOverlay{Schema: OverlaySchema, Rules: []Rule{}}
			if len(entryState.Overlay) != 0 {
				parsed, overlayErr := ParseEntryOverlay(entryState.Overlay, config)
				if overlayErr != nil {
					response.Issues = append(response.Issues, "入口规则不可用")
					break
				}
				overlay = parsed
			}
			response.EntryOverlay = &overlay
			break
		}
		if !found {
			response.Issues = append(response.Issues, "入口已不存在")
		}
	}
	nodeID := cleanIdentity(request.URL.Query().Get("node_id"))
	for _, definition := range config.Datasets {
		view := DatasetView{Definition: definition, Versions: []pluginsdk.DatasetVersion{}, Classifications: []pluginsdk.DatasetCatalogEntry{}}
		bindingRequest := pluginsdk.DatasetBindingRequest{Action: pluginsdk.DatasetBindingInspect, InstanceID: policyState.InstanceID, SourceID: definition.SourceID, Targets: pluginsdk.ExecutionTargetSelection{Mode: pluginsdk.ExecutionTargetsEffective}}
		binding, bindingErr := controller.runtime.ManageDatasetBinding(request.Context(), bindingRequest)
		if bindingErr != nil {
			view.Error = "数据绑定状态不可用"
		} else {
			response.Bindings = append(response.Bindings, binding)
		}
		history, historyErr := controller.runtime.DatasetCatalog(request.Context(), pluginsdk.DatasetCatalogRequest{SourceID: definition.SourceID, Limit: pluginsdk.DatasetMaxCatalogPage})
		if historyErr != nil {
			view.Error = joinIssue(view.Error, "版本目录不可用")
		} else {
			view.Versions = history.Versions
			version := ""
			if binding.Desired != nil {
				version = binding.Desired.Spec.VersionDigest
			} else if len(history.Versions) > 0 {
				version = history.Versions[0].Digest
			}
			if version != "" {
				catalog, catalogErr := controller.runtime.DatasetCatalog(request.Context(), pluginsdk.DatasetCatalogRequest{SourceID: definition.SourceID, VersionDigest: version, Limit: pluginsdk.DatasetMaxCatalogPage})
				if catalogErr != nil {
					view.Error = joinIssue(view.Error, "分类目录不可用")
				} else {
					view.Classifications = catalog.Classifications
				}
			}
		}
		if nodeID != "" {
			status, statusErr := controller.runtime.DatasetStatus(request.Context(), pluginsdk.DatasetStatusRequest{SourceID: definition.SourceID, NodeID: nodeID})
			if statusErr != nil {
				view.Error = joinIssue(view.Error, "节点数据状态不可用")
			} else {
				view.Status = &status
			}
		}
		response.Datasets = append(response.Datasets, view)
	}
	if nodeID != "" {
		var events pluginsdk.EventListResponse
		if err := controller.runtime.Call(request.Context(), pluginsdk.HostRuntimeCall{Operation: pluginsdk.HostRuntimeEventList, Payload: mustJSON(pluginsdk.EventListRequest{AgentID: nodeID})}, &events); err != nil {
			response.Issues = append(response.Issues, "诊断事件暂时不可用")
		} else {
			response.Events = events.Events
		}
	}
	return response
}

func (controller *Controller) serveEntryRules(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	if body.Entry == nil || body.Rules == nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "入口身份或规则列表缺失"})
		return
	}
	result, err := controller.setEntryRules(request.Context(), *body.Entry, body.Rules)
	writeMutation(writer, result, err)
}

func (controller *Controller) serveConfig(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	result, err := controller.replacePolicy(request.Context(), body.Config, pluginsdk.PolicyMode(body.Mode))
	writeMutation(writer, result, err)
}

func (controller *Controller) serveEntryMode(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	if body.Entry == nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "入口身份缺失"})
		return
	}
	result, err := controller.setEntryMode(request.Context(), *body.Entry, pluginsdk.PolicyMode(body.Mode), body.Reset)
	writeMutation(writer, result, err)
}

func (controller *Controller) serveBinding(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	if body.Binding == nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "数据绑定参数缺失"})
		return
	}
	result, err := controller.bindDatasetAtomic(request.Context(), *body.Binding)
	writeMutation(writer, result, err)
}

func (controller *Controller) serveDataset(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	if body.Dataset == nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "数据源操作缺失"})
		return
	}
	result, err := controller.controlDataset(request.Context(), *body.Dataset)
	writeMutation(writer, result, err)
}

func (controller *Controller) setEntryRules(ctx context.Context, claimed pluginsdk.PolicyEntryTarget, rules []Rule) (any, error) {
	if claimed.Validate() != nil || claimed.Token == "" || len(rules) > MaxOverlayRules {
		return nil, fmt.Errorf("%w: 入口身份或规则数量无效", ErrInvalidConfig)
	}
	config := controller.currentConfig()
	ownedRules := make([]Rule, len(rules))
	copy(ownedRules, rules)
	overlay := EntryOverlay{Schema: OverlaySchema, Rules: ownedRules}
	parsed, err := ParseEntryOverlay(mustJSON(overlay), config)
	if err != nil {
		return nil, err
	}
	current, err := controller.inspectResolvedEntry(ctx, claimed)
	if err != nil {
		return nil, err
	}
	mode, err := pluginsdk.ResolvePolicyMode(current.Desired.Settings)
	if err != nil || mode.Validate() != nil {
		return nil, ErrUnavailable
	}
	encoded := mustJSON(parsed)
	return controller.replaceEntry(ctx, current, mode, encoded)
}

func (controller *Controller) decodeWrite(writer http.ResponseWriter, request *http.Request) (writeRequest, bool) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeJSON(writer, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return writeRequest{}, false
	}
	if !uiAuthorized(request) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": ErrUnauthorized.Error()})
		return writeRequest{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, pluginsdk.PluginHostPayloadMaxBytes+1))
	if err != nil || len(raw) > pluginsdk.PluginHostPayloadMaxBytes {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "请求超过边界"})
		return writeRequest{}, false
	}
	var body writeRequest
	if err := decodeStrictJSON(raw, &body); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "请求 JSON 无效"})
		return writeRequest{}, false
	}
	return body, true
}

func uiAuthorized(request *http.Request) bool {
	_, ok := pluginsdk.PluginUIActor(request)
	return ok
}

func writeMutation(writer http.ResponseWriter, result any, err error) {
	if err == nil {
		writeJSON(writer, http.StatusOK, result)
		return
	}
	status := http.StatusServiceUnavailable
	if errors.Is(err, ErrUnauthorized) {
		status = http.StatusForbidden
	} else if errors.Is(err, ErrInvalidConfig) {
		status = http.StatusBadRequest
	}
	writeJSON(writer, status, map[string]string{"error": publicError(err)})
}

func publicError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidConfig), errors.Is(err, ErrUnauthorized), errors.Is(err, ErrUnavailable):
		return err.Error()
	default:
		return ErrUnavailable.Error()
	}
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	_ = pluginsdk.WritePluginUIJSON(writer, status, payload)
}
func mustJSON(value any) json.RawMessage { encoded, _ := json.Marshal(value); return encoded }
func joinIssue(left, right string) string {
	if left == "" {
		return right
	}
	return left + "；" + right
}
