package waf

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	ManagedRules    []CustomRule    `json:"managed_rules"`
	Coverage        map[string]int  `json:"coverage"`
	Ready           bool            `json:"ready"`
	DefaultMode     string          `json:"default_mode,omitempty"`
	Entries         []HTTPEntry     `json:"entries,omitempty"`
	CustomRules     []CustomRule    `json:"custom_rules,omitempty"`
	Exclusions      []Exclusion     `json:"exclusions,omitempty"`
	Events          []SecurityEvent `json:"events,omitempty"`
	EventsAvailable bool            `json:"events_available"`
	EventSummary    map[string]int  `json:"event_summary,omitempty"`
	RecentEvents    []SecurityEvent `json:"recent_events,omitempty"`
	EntriesPage     *wafPage        `json:"entries_page,omitempty"`
	EventsPage      *wafPage        `json:"events_page,omitempty"`
	Error           string          `json:"error,omitempty"`
	Notice          string          `json:"notice,omitempty"`
	Access          struct {
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
	case "/api/entries/mode-all":
		controller.serveEntryModes(writer, request)
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
	response := controller.stateResponseWithEvents(request.Context(), agentID, "", request.URL.Query().Get("include_events") != "false")
	if err := paginateWAFState(&response, request.URL.Query()); err != nil {
		writeWAFJSON(writer, http.StatusBadRequest, wafAPIResponse{Error: "分页或筛选参数无效。"})
		return
	}
	status := http.StatusOK
	if !response.Ready && response.Error != "" {
		status = http.StatusServiceUnavailable
		if response.Error == deniedMessage {
			status = http.StatusForbidden
		}
	}
	writeWAFJSON(writer, status, response)
}

type wafPage struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// Pagination covers the current catalog and the events retained by the host.
// Callers without page_size keep the original state response contract.
func paginateWAFState(response *wafAPIResponse, query url.Values) error {
	if !query.Has("page_size") {
		return nil
	}
	positiveInt := func(key string, fallback int) (int, error) {
		if !query.Has(key) {
			return fallback, nil
		}
		value, err := strconv.Atoi(query.Get(key))
		if err != nil || value < 1 {
			return 0, ErrInvalidConfig
		}
		return value, nil
	}
	size, err := positiveInt("page_size", 10)
	if err != nil || size > 100 {
		return ErrInvalidConfig
	}
	entryPage, err := positiveInt("entry_page", 1)
	if err != nil {
		return err
	}
	eventPage, err := positiveInt("event_page", 1)
	if err != nil {
		return err
	}
	entryMode, eventMode := query.Get("entry_mode"), query.Get("event_mode")
	for _, mode := range []string{entryMode, eventMode} {
		if mode != "" && mode != ModeObserve && mode != ModeDeny && mode != "skip" {
			return ErrInvalidMode
		}
	}
	entryQuery := strings.ToLower(strings.TrimSpace(query.Get("entry_query")))
	eventQuery := strings.ToLower(strings.TrimSpace(query.Get("event_query")))
	entries := make([]HTTPEntry, 0, len(response.Entries))
	for _, entry := range response.Entries {
		mode := entry.Mode
		if entry.OverlayInvalid || !entry.Attached {
			mode = "skip"
		}
		text := strings.ToLower(strings.Join([]string{entry.FrontendURL, entry.Backend, entry.RuleRef}, " "))
		if (entryMode == "" || mode == entryMode) && strings.Contains(text, entryQuery) {
			entries = append(entries, entry)
		}
	}
	events := make([]SecurityEvent, 0, len(response.Events))
	for _, event := range response.Events {
		mode := event.Disposition
		if mode != ModeDeny {
			mode = ModeObserve
			if event.Reason != "" && event.Reason != "rule_matched" {
				mode = "skip"
			}
		}
		text := strings.ToLower(strings.Join([]string{event.Site, event.RuleID, event.Reason, event.Digest}, " "))
		if (eventMode == "" || mode == eventMode) && strings.Contains(text, eventQuery) {
			events = append(events, event)
		}
	}
	pageBounds := func(total, page int) (*wafPage, int, int) {
		pages := max(1, (total+size-1)/size)
		page = min(page, pages)
		start := (page - 1) * size
		return &wafPage{Page: page, PageSize: size, Total: total}, start, min(start+size, total)
	}
	var start, end int
	response.EntriesPage, start, end = pageBounds(len(entries), entryPage)
	response.Entries = entries[start:end]
	response.EventsPage, start, end = pageBounds(len(events), eventPage)
	response.Events = events[start:end]
	return nil
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
	if request.Method != http.MethodPost && request.Method != http.MethodDelete {
		writer.Header().Set("Allow", "POST, DELETE")
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
	if request.Method == http.MethodDelete {
		if err := controller.removeCustomRule(request.Context(), body.ID); err != nil {
			writeWAFJSON(writer, wafStatus(err), wafAPIResponse{Error: publicWAFError(err)})
			return
		}
		writeWAFJSON(writer, http.StatusOK, wafAPIResponse{Ready: true})
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
	if request.Method != http.MethodPost && request.Method != http.MethodDelete {
		writer.Header().Set("Allow", "POST, DELETE")
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
	if request.Method == http.MethodDelete {
		if err := controller.removeExclusion(request.Context(), body.RuleID, body.PathPrefix); err != nil {
			writeWAFJSON(writer, wafStatus(err), wafAPIResponse{Error: publicWAFError(err)})
			return
		}
		writeWAFJSON(writer, http.StatusOK, wafAPIResponse{Ready: true})
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
	return controller.stateResponseWithEvents(ctx, agentID, failed, true)
}

func (controller *Controller) stateResponseWithEvents(ctx context.Context, agentID, failed string, includeEvents bool) wafAPIResponse {
	config := controller.currentConfig()
	response := wafAPIResponse{Ready: true, DefaultMode: config.Mode, CustomRules: config.CustomRules, Exclusions: config.Exclusions, ManagedRules: managedRuleCatalog(), Coverage: map[string]int{"total": 0, "deny": 0, "observe": 0, "unprotected": 0, "disabled": 0}}
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
	for _, entry := range entries {
		response.Coverage["total"]++
		if !entry.Enabled {
			response.Coverage["disabled"]++
			continue
		}
		if !entry.Attached || entry.OverlayInvalid {
			response.Coverage["unprotected"]++
			continue
		}
		response.Coverage[entry.Mode]++
	}
	if len(entries) == 0 {
		response.Notice = emptyEntriesNotice
	}
	if !includeEvents {
		return response
	}
	if controller.events == nil {
		response.Error = publicWAFError(ErrUnavailable)
		return response
	}
	events, eventErr := controller.events.ListEvents(ctx, agentID)
	if eventErr != nil {
		response.Error = publicWAFError(eventErr)
		return response
	}
	response.Events = events
	response.EventsAvailable = true
	response.EventSummary = map[string]int{"deny": 0, "observe": 0, "skip": 0}
	for _, event := range events {
		mode := ModeObserve
		if event.Disposition == ModeDeny {
			mode = ModeDeny
		} else if event.Reason != "" && event.Reason != "rule_matched" {
			mode = "skip"
		}
		response.EventSummary[mode]++
	}
	response.RecentEvents = events[:min(5, len(events))]
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
		if projected.Attached && !validMode(projected.Mode) {
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
	if controller.overlaysW == nil {
		return ErrUnavailable
	}
	return controller.overlaysW.SetMode(ctx, agentID, ruleRef, mode)
}

func (controller *Controller) setGlobalMode(ctx context.Context, agentID, mode string) error {
	if !validMode(mode) {
		return ErrInvalidMode
	}
	if controller.overlaysW == nil {
		return ErrUnavailable
	}
	if strings.TrimSpace(agentID) != "" {
		entries, err := controller.listEntries(ctx, agentID)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.OverlayInvalid || !entry.Attached || strings.TrimSpace(entry.RuleRef) == "" {
				continue
			}
			if err := controller.overlaysW.SetMode(ctx, agentID, entry.RuleRef, mode); err != nil {
				return err
			}
		}
	}
	config := controller.currentConfig()
	config.Mode = mode
	return controller.replaceConfig(ctx, config)
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
