package ippolicy

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var uiAssets embed.FS

type APIResponse struct {
	Ready     bool                               `json:"ready"`
	Config    Configuration                      `json:"config"`
	Policy    *pluginsdk.PolicyControlResponse   `json:"policy,omitempty"`
	Entry     *pluginsdk.PolicyControlResponse   `json:"entry,omitempty"`
	Bindings  []pluginsdk.DatasetBindingResponse `json:"bindings"`
	Datasets  []DatasetView                      `json:"datasets"`
	Events    []pluginsdk.PolicyEvent            `json:"events"`
	Provinces []ProvinceOption                   `json:"provinces"`
	Issues    []string                           `json:"issues"`
	Error     string                             `json:"error,omitempty"`
	Access    APIAccess                          `json:"access"`
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
	RuleRef string                       `json:"rule_ref,omitempty"`
	Overlay *EntryOverlay                `json:"overlay,omitempty"`
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
	case "/api/http-overlay":
		controller.serveHTTPOverlay(writer, request)
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
	if !response.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(writer, status, response)
}

func (controller *Controller) state(request *http.Request) APIResponse {
	config := controller.currentConfig()
	response := APIResponse{Ready: true, Config: config, Bindings: []pluginsdk.DatasetBindingResponse{}, Datasets: []DatasetView{}, Events: []pluginsdk.PolicyEvent{}, Provinces: Provinces(), Issues: []string{}, Access: APIAccess{CanRead: true, CanWrite: true}}
	policyState, err := controller.inspectPolicy(request.Context(), nil)
	if err != nil {
		response.Ready, response.Error = false, publicError(err)
		return response
	}
	response.Policy = &policyState
	entry := entryFromQuery(request)
	if entry != nil {
		entryState, entryErr := controller.inspectPolicy(request.Context(), entry)
		if entryErr != nil {
			response.Issues = append(response.Issues, "入口状态不可用")
		} else {
			response.Entry = &entryState
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

func (controller *Controller) serveHTTPOverlay(writer http.ResponseWriter, request *http.Request) {
	body, ok := controller.decodeWrite(writer, request)
	if !ok {
		return
	}
	if body.Overlay == nil || strings.TrimSpace(body.RuleRef) == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "HTTP 入口规则缺失"})
		return
	}
	config := controller.currentConfig()
	if _, err := ParseEntryOverlay(mustJSON(*body.Overlay), config); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": publicError(err)})
		return
	}
	policyState, err := controller.inspectPolicy(request.Context(), nil)
	if err != nil {
		writeMutation(writer, nil, err)
		return
	}
	overlay, err := encodeOverlay(*body.Overlay, policyState.InstanceID)
	if err == nil {
		requestBody := pluginsdk.HTTPRuleRequest{Action: pluginsdk.HTTPRuleActionCutover, RuleRef: body.RuleRef, Overlay: overlay}
		err = controller.runtime.Call(request.Context(), pluginsdk.HostRuntimeCall{Operation: pluginsdk.HostRuntimeHTTPRule, OperationID: operationIDFor("overlay", requestBody), Payload: mustJSON(requestBody)}, nil)
	}
	writeMutation(writer, map[string]bool{"stored": err == nil}, publicRuntimeError(err))
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

func entryFromQuery(request *http.Request) *pluginsdk.PolicyEntryTarget {
	kind, id, node := cleanIdentity(request.URL.Query().Get("entry_kind")), cleanIdentity(request.URL.Query().Get("entry_id")), cleanIdentity(request.URL.Query().Get("node_id"))
	if kind == "" || id == "" || node == "" {
		return nil
	}
	entry := &pluginsdk.PolicyEntryTarget{NodeID: node, Kind: kind, ID: id}
	if entry.Validate() != nil {
		return nil
	}
	return entry
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
