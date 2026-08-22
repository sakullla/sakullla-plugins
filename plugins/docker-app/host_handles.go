package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	hostAgentEngineOperation  = "agent.engine.report"
	hostAgentComposeOperation = "agent.compose"
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

func (runtime *hostCapabilityRuntime) Report(ctx context.Context, agentID string) (AgentEngineReport, error) {
	if !validAgentID(agentID) {
		return AgentEngineReport{}, errors.New("agent id is invalid")
	}
	if runtime == nil || runtime.client == nil {
		return AgentEngineReport{}, ErrTypedHandlesUnavailable
	}
	var raw map[string]any
	if err := callHost(ctx, runtime.client, hostAgentEngineOperation, map[string]any{"agent_id": agentID}, &raw); err != nil {
		return AgentEngineReport{}, err
	}
	encoded, err := json.Marshal(raw)
	if err != nil || localDockerEngineTarget(encoded) {
		return AgentEngineReport{}, ErrTypedHandlesUnavailable
	}
	report, err := DecodeAgentEngineReport(encoded)
	if err != nil {
		return AgentEngineReport{}, ErrTypedHandlesUnavailable
	}
	if report.AgentID != agentID {
		return AgentEngineReport{}, ErrTypedHandlesUnavailable
	}
	return normalizeAgentEngineReport(report), nil
}

func (runtime *hostCapabilityRuntime) ApplyApp(ctx context.Context, app App) error {
	if !validAgentID(app.AgentID) {
		return ErrAgentOffline
	}
	return runtime.compose(ctx, map[string]any{
		"action": "apply", "agent_id": app.AgentID, "app_id": app.ID,
		"compose": app.Compose, "workdir": app.WorkDir,
	}, nil)
}

func (runtime *hostCapabilityRuntime) Start(ctx context.Context, appID string) error {
	return runtime.compose(ctx, map[string]any{"action": "start", "app_id": appID}, nil)
}

func (runtime *hostCapabilityRuntime) Stop(ctx context.Context, appID string) error {
	return runtime.compose(ctx, map[string]any{"action": "stop", "app_id": appID}, nil)
}

func (runtime *hostCapabilityRuntime) Restart(ctx context.Context, appID string) error {
	return runtime.compose(ctx, map[string]any{"action": "restart", "app_id": appID}, nil)
}

func (runtime *hostCapabilityRuntime) ReadLogs(ctx context.Context, appID, service string) (string, error) {
	var result struct {
		Logs string `json:"logs"`
	}
	if err := runtime.compose(ctx, map[string]any{"action": "logs", "app_id": appID, "service": service}, &result); err != nil {
		return "", err
	}
	return result.Logs, nil
}

func (runtime *hostCapabilityRuntime) RemoveApp(ctx context.Context, appID string) error {
	return runtime.compose(ctx, map[string]any{"action": "remove", "app_id": appID}, nil)
}

func (runtime *hostCapabilityRuntime) compose(ctx context.Context, payload map[string]any, result any) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	return callHost(ctx, runtime.client, hostAgentComposeOperation, payload, result)
}

func bindProductionHostCapabilities(config ControllerConfig) ControllerConfig {
	return bindHostCapabilityClient(config, func() (hostRuntimeCaller, error) {
		return pluginsdk.NewHostRuntimeClientFromEnvironment()
	})
}

func bindHostCapabilityClient(config ControllerConfig, factory func() (hostRuntimeCaller, error)) ControllerConfig {
	if config.Admission == nil {
		config.Admission = TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		})
	}
	if config.UIEngineSource == nil {
		config.UIEngineSource = NewReportedEngineCatalog()
	}
	if factory == nil {
		return config
	}
	client, err := factory()
	if err != nil || client == nil {
		return config
	}
	runtime := newHostCapabilityRuntime(client)
	config.UIEngineSource = runtime
	config.UIApply = runtime
	config.UIStart = runtime
	config.UIStop = runtime
	config.UIRestart = runtime
	config.UILogs = runtime
	config.UIRemove = runtime
	return config
}

func callHost(ctx context.Context, client hostRuntimeCaller, operation string, payload any, result any) error {
	if client == nil {
		return ErrTypedHandlesUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil || localDockerEngineTarget(encoded) {
		return ErrTypedHandlesUnavailable
	}
	var raw json.RawMessage
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, Payload: encoded}, &raw); err != nil {
		return ErrTypedHandlesUnavailable
	}
	if localDockerEngineTarget(raw) {
		return ErrTypedHandlesUnavailable
	}
	if result == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func localDockerEngineTarget(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return containsLocalDockerMarker(strings.ToLower(string(raw)))
	}
	return localDockerEngineValue(document, "")
}

func localDockerEngineValue(node any, key string) bool {
	switch typed := node.(type) {
	case map[string]any:
		for childKey, child := range typed {
			if strings.EqualFold(childKey, "compose") {
				continue
			}
			if localDockerEngineValue(child, childKey) {
				return true
			}
		}
		return false
	case []any:
		for _, child := range typed {
			if localDockerEngineValue(child, key) {
				return true
			}
		}
		return false
	case string:
		if isLocalDockerHandleKey(key) {
			return true
		}
		return containsLocalDockerMarker(strings.ToLower(typed))
	default:
		return isLocalDockerHandleKey(key)
	}
}

func isLocalDockerHandleKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "docker_host", "unix_socket", "docker_socket", "npipe":
		return true
	default:
		return false
	}
}

func containsLocalDockerMarker(lower string) bool {
	for _, marker := range []string{"docker.socket", "docker.sock", "unix://", "npipe:"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
