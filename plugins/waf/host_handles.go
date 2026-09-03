package waf

import (
	"context"
	"encoding/json"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	hostHTTPRuleOperation  = pluginsdk.HostRuntimeHTTPRule
	hostHTTPRuleActionList = pluginsdk.HTTPRuleActionList
	hostInstanceConfigOp   = "instance.config"
	hostEventListOp        = "event.list"
	hostWAFRuleMatchCode   = "waf.rule_match"
)

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type hostCapabilityRuntime struct {
	client hostRuntimeCaller
}

type hostHTTPRuleListItem struct {
	RuleRef     string         `json:"rule_ref"`
	FrontendURL string         `json:"frontend_url"`
	Backend     string         `json:"backend"`
	Enabled     bool           `json:"enabled"`
	PolicyRef   *hostPolicyRef `json:"policy_ref"`
}

type hostPolicyRef struct {
	ID      string          `json:"id"`
	Overlay json.RawMessage `json:"overlay"`
}

type hostHTTPRuleListResponse struct {
	Rules []hostHTTPRuleListItem `json:"rules"`
}

type hostPolicyEvent struct {
	Site        string `json:"site"`
	RuleID      string `json:"rule_id"`
	Digest      string `json:"digest"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
	Code        string `json:"code"`
	Action      string `json:"action"`
}

type hostEventListResponse struct {
	Events []hostPolicyEvent `json:"events"`
}

func newHostCapabilityRuntime(client hostRuntimeCaller) *hostCapabilityRuntime {
	if client == nil {
		return nil
	}
	return &hostCapabilityRuntime{client: client}
}

func (runtime *hostCapabilityRuntime) List(ctx context.Context, agentID string) ([]HTTPEntry, error) {
	if runtime == nil || runtime.client == nil {
		return nil, ErrUnavailable
	}
	if !validAgentID(agentID) {
		return nil, ErrAgentRequired
	}
	var response hostHTTPRuleListResponse
	if err := callHost(ctx, runtime.client, "", hostHTTPRuleOperation, pluginsdk.HTTPRuleRequest{
		Action: hostHTTPRuleActionList, AgentID: agentID,
	}, &response); err != nil {
		return nil, ErrUnavailable
	}
	entries := make([]HTTPEntry, 0, len(response.Rules))
	for _, item := range response.Rules {
		ref := strings.TrimSpace(item.RuleRef)
		if ref == "" {
			continue
		}
		entries = append(entries, projectHostHTTPEntry(item, ref))
	}
	return entries, nil
}

func projectHostHTTPEntry(item hostHTTPRuleListItem, ref string) HTTPEntry {
	entry := HTTPEntry{
		RuleRef:     ref,
		FrontendURL: strings.TrimSpace(item.FrontendURL),
		Backend:     strings.TrimSpace(item.Backend),
		Enabled:     item.Enabled,
	}
	if item.PolicyRef == nil || strings.TrimSpace(item.PolicyRef.ID) == "" {
		return entry
	}
	entry.Attached = true
	mode, ok := parseOverlayMode(item.PolicyRef.Overlay)
	if !ok {
		entry.OverlayInvalid = true
		entry.Notice = invalidOverlayNotice
		return entry
	}
	entry.Mode = mode
	return entry
}

func (runtime *hostCapabilityRuntime) SetMode(ctx context.Context, agentID, ruleRef, mode string) error {
	if runtime == nil || runtime.client == nil {
		return ErrUnavailable
	}
	if !validAgentID(agentID) {
		return ErrAgentRequired
	}
	if strings.TrimSpace(ruleRef) == "" {
		return ErrUnknownEntry
	}
	if !validMode(mode) {
		return ErrInvalidMode
	}
	overlay, err := json.Marshal(struct {
		Mode string `json:"mode"`
	}{Mode: mode})
	if err != nil {
		return ErrUnavailable
	}
	payload := struct {
		Action  string          `json:"action"`
		AgentID string          `json:"agent_id"`
		RuleRef string          `json:"rule_ref"`
		Overlay json.RawMessage `json:"overlay"`
	}{
		Action:  pluginsdk.HTTPRuleActionCutover,
		AgentID: agentID,
		RuleRef: ruleRef,
		Overlay: overlay,
	}
	if err := callHost(ctx, runtime.client, overlayOperationID(agentID, ruleRef, mode), hostHTTPRuleOperation, payload, nil); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) StoreConfig(ctx context.Context, config Configuration) error {
	if runtime == nil || runtime.client == nil {
		return ErrUnavailable
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return ErrUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	payload := struct {
		Config json.RawMessage `json:"config"`
	}{Config: encoded}
	if err := callHost(ctx, runtime.client, configOperationID(), hostInstanceConfigOp, payload, &response); err != nil {
		return ErrUnavailable
	}
	if !response.Stored {
		return ErrUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) ListEvents(ctx context.Context, agentID string) ([]SecurityEvent, error) {
	if runtime == nil || runtime.client == nil {
		return nil, ErrUnavailable
	}
	if !validAgentID(agentID) {
		return nil, ErrAgentRequired
	}
	var response hostEventListResponse
	payload := struct {
		AgentID string `json:"agent_id"`
		Code    string `json:"code"`
	}{AgentID: agentID, Code: hostWAFRuleMatchCode}
	if err := callHost(ctx, runtime.client, "", hostEventListOp, payload, &response); err != nil {
		return nil, ErrUnavailable
	}
	events := make([]SecurityEvent, 0, len(response.Events))
	for _, item := range response.Events {
		if event, ok := projectHostPolicyEvent(item); ok {
			events = append(events, event)
		}
	}
	return events, nil
}

func projectHostPolicyEvent(item hostPolicyEvent) (SecurityEvent, bool) {
	code := strings.TrimSpace(item.Code)
	if code != "" && code != hostWAFRuleMatchCode {
		return SecurityEvent{}, false
	}
	disposition := strings.TrimSpace(item.Disposition)
	if disposition == "" {
		disposition = strings.TrimSpace(item.Action)
	}
	if disposition != "" && !validMode(disposition) {
		return SecurityEvent{}, false
	}
	return SecurityEvent{
		Site:        strings.TrimSpace(item.Site),
		RuleID:      strings.TrimSpace(item.RuleID),
		Digest:      strings.TrimSpace(item.Digest),
		Disposition: disposition,
		Reason:      strings.TrimSpace(item.Reason),
	}, true
}

func bindProductionHostCapabilities(config ControllerConfig) ControllerConfig {
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err != nil || client == nil {
		return config
	}
	runtime := newHostCapabilityRuntime(client)
	if config.Catalog == nil {
		config.Catalog = runtime
	}
	if config.Overlays == nil {
		config.Overlays = runtime
	}
	if config.Events == nil {
		config.Events = runtime
	}
	if config.Configs == nil {
		config.Configs = runtime
	}
	return config
}

func overlayOperationID(agentID, ruleRef, mode string) string {
	return "waf.overlay." + strings.TrimSpace(agentID) + "." + strings.TrimSpace(ruleRef) + "." + strings.TrimSpace(mode)
}

func configOperationID() string {
	return "waf.instance.config"
}

func callHost(ctx context.Context, client hostRuntimeCaller, operationID, operation string, payload any, result any) error {
	if client == nil {
		return ErrUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ErrUnavailable
	}
	var raw json.RawMessage
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, OperationID: operationID, Payload: encoded}, &raw); err != nil {
		return ErrUnavailable
	}
	if result == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return ErrUnavailable
	}
	return nil
}
