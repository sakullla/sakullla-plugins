package waf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"embed"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var appUIAssets embed.FS

const (
	unavailableMessage   = "暂时无法管理 Web 防火墙。"
	deniedMessage        = "无权管理 Web 防火墙。"
	emptyEntriesNotice   = "还没有 HTTP 入口。"
	invalidOverlayNotice = "覆盖无效，已按失败关闭处理。"
	notAttachedNotice    = "该入口尚未挂上 Web 防火墙。"
)

type wafAPIResponse struct {
	Ready       bool            `json:"ready"`
	DefaultMode string          `json:"default_mode,omitempty"`
	Entries     []HTTPEntry     `json:"entries,omitempty"`
	CustomRules []CustomRule    `json:"custom_rules,omitempty"`
	Exclusions  []Exclusion     `json:"exclusions,omitempty"`
	Events      []SecurityEvent `json:"events,omitempty"`
	Error       string          `json:"error,omitempty"`
	Notice      string          `json:"notice,omitempty"`
	Access      struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	} `json:"access,omitempty"`
}

type wafWriteRequest struct {
	AgentID    string `json:"agent_id"`
	RuleRef    string `json:"rule_ref"`
	Mode       string `json:"mode"`
	ID         string `json:"id"`
	Target     string `json:"target"`
	Needle     string `json:"needle"`
	RuleID     string `json:"rule_id"`
	PathPrefix string `json:"path_prefix"`
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	if pluginsdk.ServePluginUIAsset(writer, request, appUIAssets, "assets/ui") {
		return
	}
	if !controller.uiReady() {
		writeWAFJSON(writer, http.StatusServiceUnavailable, wafAPIResponse{Error: unavailableMessage})
		return
	}
	switch request.URL.Path {
	case "/api/state":
		controller.serveState(writer, request)
	case "/api/mode":
		controller.serveGlobalMode(writer, request)
	case "/api/entries/mode":
		controller.serveEntryMode(writer, request)
	case "/api/custom-rules":
		controller.serveCustomRules(writer, request)
	case "/api/exclusions":
		controller.serveExclusions(writer, request)
	default:
		http.Error(writer, "Web 防火墙页未找到", http.StatusNotFound)
	}
}

func (controller *Controller) serveState(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
	response := controller.stateResponse(request.Context(), agentID, "")
	status := http.StatusOK
	if !response.Ready && response.Error != "" {
		status = http.StatusServiceUnavailable
		if response.Error == deniedMessage {
			status = http.StatusForbidden
		}
	}
	writeWAFJSON(writer, status, response)
}

func (controller *Controller) serveGlobalMode(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	body, err := decodeWAFWrite(request)
	if err != nil {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: ErrInvalidConfig.Error()})
		return
	}
	if err := controller.setGlobalMode(request.Context(), body.AgentID, body.Mode); err != nil {
		writeWAFJSON(writer, wafStatus(err), controller.stateResponse(request.Context(), body.AgentID, publicWAFError(err)))
		return
	}
	writeWAFJSON(writer, http.StatusOK, controller.stateResponse(request.Context(), body.AgentID, ""))
}

func (controller *Controller) serveEntryMode(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	body, err := decodeWAFWrite(request)
	if err != nil {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: ErrInvalidConfig.Error()})
		return
	}
	if err := controller.setEntryMode(request.Context(), body.AgentID, body.RuleRef, body.Mode); err != nil {
		writeWAFJSON(writer, wafStatus(err), controller.stateResponse(request.Context(), body.AgentID, publicWAFError(err)))
		return
	}
	writeWAFJSON(writer, http.StatusOK, controller.stateResponse(request.Context(), body.AgentID, ""))
}

func (controller *Controller) serveCustomRules(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	body, err := decodeWAFWrite(request)
	if err != nil {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: ErrInvalidRule.Error()})
		return
	}
	agentID := strings.TrimSpace(body.AgentID)
	if err := controller.addCustomRule(request.Context(), CustomRule{ID: body.ID, Target: body.Target, Needle: body.Needle}); err != nil {
		writeWAFJSON(writer, wafStatus(err), controller.stateResponse(request.Context(), agentID, publicWAFError(err)))
		return
	}
	writeWAFJSON(writer, http.StatusOK, controller.stateResponse(request.Context(), agentID, ""))
}

func (controller *Controller) serveExclusions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeWAFJSON(writer, http.StatusMethodNotAllowed, wafAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeWAFJSON(writer, http.StatusForbidden, wafAPIResponse{Error: deniedMessage})
		return
	}
	body, err := decodeWAFWrite(request)
	if err != nil {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: ErrInvalidExclusion.Error()})
		return
	}
	agentID := strings.TrimSpace(body.AgentID)
	if err := controller.addExclusion(request.Context(), Exclusion{RuleID: body.RuleID, PathPrefix: body.PathPrefix}); err != nil {
		writeWAFJSON(writer, wafStatus(err), controller.stateResponse(request.Context(), agentID, publicWAFError(err)))
		return
	}
	writeWAFJSON(writer, http.StatusOK, controller.stateResponse(request.Context(), agentID, ""))
}

func (controller *Controller) stateResponse(ctx context.Context, agentID, failed string) wafAPIResponse {
	config := controller.currentConfig()
	response := wafAPIResponse{Ready: true, DefaultMode: config.Mode, CustomRules: config.CustomRules, Exclusions: config.Exclusions}
	response.Access.CanRead = true
	response.Access.CanWrite = true
	if failed != "" {
		response.Error = failed
		response.Ready = false
	}
	if strings.TrimSpace(agentID) == "" {
		response.Notice = ErrAgentRequired.Error()
		return response
	}
	entries, err := controller.listEntries(ctx, agentID)
	if err != nil {
		response.Ready = false
		response.Error = publicWAFError(err)
		return response
	}
	response.Entries = entries
	if len(entries) == 0 {
		response.Notice = emptyEntriesNotice
	}
	if controller.events != nil {
		events, eventErr := controller.events.ListEvents(ctx, agentID)
		if eventErr != nil {
			if response.Error == "" {
				response.Error = publicWAFError(eventErr)
			}
		} else {
			response.Events = events
		}
	}
	return response
}

func (controller *Controller) listEntries(ctx context.Context, agentID string) ([]HTTPEntry, error) {
	if !validAgentID(agentID) {
		return nil, ErrAgentRequired
	}
	if controller.catalog == nil {
		return nil, ErrPolicyUnavailable
	}
	listed, err := controller.catalog.List(ctx, agentID)
	if err != nil {
		return nil, err
	}
	defaultMode := controller.currentConfig().Mode
	entries := make([]HTTPEntry, 0, len(listed))
	for _, entry := range listed {
		projected := entry
		if projected.OverlayInvalid {
			projected.Mode = ""
			if projected.Notice == "" {
				projected.Notice = invalidOverlayNotice
			}
			entries = append(entries, projected)
			continue
		}
		if overlay, ok := controller.overlayMode(agentID, projected.RuleRef); ok && validMode(overlay) {
			projected.Mode = overlay
		} else if !validMode(projected.Mode) {
			projected.Mode = defaultMode
		}
		if !projected.Attached {
			projected.Notice = notAttachedNotice
		}
		entries = append(entries, projected)
	}
	return entries, nil
}

func (controller *Controller) setEntryMode(ctx context.Context, agentID, ruleRef, mode string) error {
	if !validAgentID(agentID) {
		return ErrAgentRequired
	}
	if strings.TrimSpace(ruleRef) == "" {
		return ErrUnknownEntry
	}
	if !validMode(mode) {
		return ErrInvalidMode
	}
	entries, err := controller.listEntries(ctx, agentID)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range entries {
		if entry.RuleRef == ruleRef {
			found = true
			if entry.OverlayInvalid {
				return ErrInvalidConfig
			}
			break
		}
	}
	if !found {
		return ErrUnknownEntry
	}
	if controller.overlaysW != nil {
		if err := controller.overlaysW.SetMode(ctx, agentID, ruleRef, mode); err != nil {
			return err
		}
	}
	next := controller.snapshotOverlays()
	next[overlayKey(agentID, ruleRef)] = mode
	return controller.replaceOverlays(ctx, next)
}

func (controller *Controller) setGlobalMode(ctx context.Context, agentID, mode string) error {
	if !validMode(mode) {
		return ErrInvalidMode
	}
	config := controller.currentConfig()
	config.Mode = mode
	if err := controller.replaceConfig(ctx, config); err != nil {
		return err
	}
	if strings.TrimSpace(agentID) == "" {
		return nil
	}
	entries, err := controller.listEntries(ctx, agentID)
	if err != nil {
		return err
	}
	next := controller.snapshotOverlays()
	for _, entry := range entries {
		if entry.OverlayInvalid || strings.TrimSpace(entry.RuleRef) == "" {
			continue
		}
		if controller.overlaysW != nil {
			if err := controller.overlaysW.SetMode(ctx, agentID, entry.RuleRef, mode); err != nil {
				return err
			}
		}
		next[overlayKey(agentID, entry.RuleRef)] = mode
	}
	return controller.replaceOverlays(ctx, next)
}

func (controller *Controller) addCustomRule(ctx context.Context, rule CustomRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	config := controller.currentConfig()
	if len(config.CustomRules) >= MaxRules {
		return ErrBoundExceeded
	}
	for _, existing := range config.CustomRules {
		if existing.ID == rule.ID {
			return ErrDuplicateRule
		}
	}
	config.CustomRules = append(config.CustomRules, rule)
	return controller.replaceConfig(ctx, config)
}

func (controller *Controller) addExclusion(ctx context.Context, exclusion Exclusion) error {
	if err := exclusion.Validate(); err != nil {
		return err
	}
	config := controller.currentConfig()
	if len(config.Exclusions) >= MaxExclusions {
		return ErrBoundExceeded
	}
	config.Exclusions = append(config.Exclusions, exclusion)
	return controller.replaceConfig(ctx, config)
}

func (controller *Controller) uiIdentity(request *http.Request) (string, error) {
	actor, ok := pluginsdk.PluginUIActor(request)
	if !ok {
		return "", ErrUnauthorized
	}
	return actor, nil
}

func decodeWAFWrite(request *http.Request) (wafWriteRequest, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil {
		return wafWriteRequest{}, err
	}
	var decoded wafWriteRequest
	if len(strings.TrimSpace(string(body))) == 0 {
		return decoded, nil
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return wafWriteRequest{}, err
	}
	return decoded, nil
}

func writeWAFJSON(writer http.ResponseWriter, status int, payload wafAPIResponse) {
	_ = pluginsdk.WritePluginUIJSON(writer, status, payload)
}

func wafStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalidMode), errors.Is(err, ErrInvalidRule), errors.Is(err, ErrInvalidExclusion),
		errors.Is(err, ErrInvalidConfig), errors.Is(err, ErrBoundExceeded), errors.Is(err, ErrDuplicateRule),
		errors.Is(err, ErrUnknownEntry), errors.Is(err, ErrAgentRequired):
		return http.StatusBadRequest
	default:
		return http.StatusServiceUnavailable
	}
}

func publicWAFError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnauthorized):
		return deniedMessage
	case errors.Is(err, ErrPolicyUnavailable), errors.Is(err, ErrUnavailable):
		return err.Error()
	case errors.Is(err, ErrInvalidMode), errors.Is(err, ErrInvalidRule), errors.Is(err, ErrInvalidExclusion),
		errors.Is(err, ErrInvalidConfig), errors.Is(err, ErrBoundExceeded), errors.Is(err, ErrDuplicateRule),
		errors.Is(err, ErrUnknownEntry), errors.Is(err, ErrAgentRequired):
		return err.Error()
	default:
		return unavailableMessage
	}
}
