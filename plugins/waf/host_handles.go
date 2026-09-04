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
	hostInstanceConfigOp   = pluginsdk.HostRuntimeInstanceConfig
	hostEventListOp        = pluginsdk.HostRuntimeEventList
	hostWAFRuleMatchCode   = "waf.rule_match"
)

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type hostCapabilityRuntime struct {
	client hostRuntimeCaller
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
	request := pluginsdk.HTTPRuleRequest{Action: hostHTTPRuleActionList, AgentID: agentID}
	if err := request.Validate(); err != nil {
		return nil, ErrUnavailable
	}
	var response pluginsdk.HTTPRuleListResponse
	if err := callHost(ctx, runtime.client, "", hostHTTPRuleOperation, request, &response); err != nil {
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

func projectHostHTTPEntry(item pluginsdk.HTTPRuleListItem, ref string) HTTPEntry {
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
	request := pluginsdk.HTTPRuleRequest{
		Action:  pluginsdk.HTTPRuleActionCutover,
		AgentID: agentID,
		RuleRef: ruleRef,
		Overlay: overlay,
	}
	if err := request.Validate(); err != nil {
		return ErrUnavailable
	}
	if err := callHost(ctx, runtime.client, overlayOperationID(agentID, ruleRef, mode), hostHTTPRuleOperation, request, nil); err != nil {
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
	request := pluginsdk.InstanceConfigRequest{Config: encoded}
	if err := request.Validate(); err != nil {
		return ErrUnavailable
	}
	var response pluginsdk.InstanceConfigResponse
	if err := callHost(ctx, runtime.client, configOperationID(), hostInstanceConfigOp, request, &response); err != nil {
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
	request := pluginsdk.EventListRequest{AgentID: agentID, Code: hostWAFRuleMatchCode}
	if err := request.Validate(); err != nil {
		return nil, ErrUnavailable
	}
	var response pluginsdk.EventListResponse
	if err := callHost(ctx, runtime.client, "", hostEventListOp, request, &response); err != nil {
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

func projectHostPolicyEvent(item pluginsdk.PolicyEvent) (SecurityEvent, bool) {
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
