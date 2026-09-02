package waf

import (
	"context"
	"encoding/json"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	pluginConfigStateKey   = "waf-config"
	pluginOverlayStateKey  = "waf-overlays"
	hostHTTPRuleOperation  = pluginsdk.HostRuntimeHTTPRule
	hostHTTPRuleActionList = pluginsdk.HTTPRuleActionList
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

func (runtime *hostCapabilityRuntime) LoadConfig(ctx context.Context) (Configuration, bool, error) {
	raw, found, err := runtime.loadState(ctx, pluginConfigStateKey)
	if err != nil || !found {
		return Configuration{}, found, err
	}
	config, err := ParseConfiguration(raw)
	if err != nil {
		return Configuration{}, false, ErrUnavailable
	}
	return config, true, nil
}

func (runtime *hostCapabilityRuntime) StoreConfig(ctx context.Context, config Configuration) error {
	return runtime.storeState(ctx, pluginConfigStateKey, config)
}

func (runtime *hostCapabilityRuntime) LoadOverlays(ctx context.Context) (map[string]string, bool, error) {
	raw, found, err := runtime.loadState(ctx, pluginOverlayStateKey)
	if err != nil || !found {
		return nil, found, err
	}
	var overlays map[string]string
	if json.Unmarshal(raw, &overlays) != nil {
		return nil, false, ErrUnavailable
	}
	return cloneOverlays(overlays), true, nil
}

func (runtime *hostCapabilityRuntime) StoreOverlays(ctx context.Context, overlays map[string]string) error {
	return runtime.storeState(ctx, pluginOverlayStateKey, cloneOverlays(overlays))
}

func (runtime *hostCapabilityRuntime) List(ctx context.Context, agentID string) ([]HTTPEntry, error) {
	if runtime == nil || runtime.client == nil {
		return nil, ErrUnavailable
	}
	if !validAgentID(agentID) {
		return nil, ErrAgentRequired
	}
	var response pluginsdk.HTTPRuleListResponse
	if err := callHost(ctx, runtime.client, hostHTTPRuleOperation, pluginsdk.HTTPRuleRequest{
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
		entries = append(entries, HTTPEntry{
			RuleRef:     ref,
			FrontendURL: strings.TrimSpace(item.FrontendURL),
			Backend:     strings.TrimSpace(item.Backend),
			Enabled:     item.Enabled,
			Mode:        ModeObserve,
			Attached:    true,
		})
	}
	return entries, nil
}

func (runtime *hostCapabilityRuntime) loadState(ctx context.Context, key string) (json.RawMessage, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": key}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	return response.Value, true, nil
}

func (runtime *hostCapabilityRuntime) storeState(ctx context.Context, key string, value any) error {
	if runtime == nil || runtime.client == nil {
		return ErrUnavailable
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": key, "value": json.RawMessage(encoded)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrUnavailable
	}
	return nil
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
	if config.State == nil {
		config.State = runtime
	}
	return config
}

func callHost(ctx context.Context, client hostRuntimeCaller, operation string, payload any, result any) error {
	if client == nil {
		return ErrUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ErrUnavailable
	}
	var raw json.RawMessage
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, Payload: encoded}, &raw); err != nil {
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
