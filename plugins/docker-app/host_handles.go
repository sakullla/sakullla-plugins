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
	hostAgentImageOperation   = "agent.image"
	hostHTTPRuleOperation     = "http.rule"
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

func (runtime *hostCapabilityRuntime) Start(ctx context.Context, app App) error {
	return runtime.composeApp(ctx, app, map[string]any{"action": "start"}, nil)
}

func (runtime *hostCapabilityRuntime) Stop(ctx context.Context, app App) error {
	return runtime.composeApp(ctx, app, map[string]any{"action": "stop"}, nil)
}

func (runtime *hostCapabilityRuntime) Restart(ctx context.Context, app App) error {
	return runtime.composeApp(ctx, app, map[string]any{"action": "restart"}, nil)
}

func (runtime *hostCapabilityRuntime) ReadLogs(ctx context.Context, app App, service string) (string, error) {
	var result struct {
		Logs string `json:"logs"`
	}
	if err := runtime.composeApp(ctx, app, map[string]any{"action": "logs", "service": service}, &result); err != nil {
		return "", err
	}
	return result.Logs, nil
}

func (runtime *hostCapabilityRuntime) RemoveApp(ctx context.Context, app App) error {
	return runtime.composeApp(ctx, app, map[string]any{"action": "remove"}, nil)
}

func (runtime *hostCapabilityRuntime) Create(ctx context.Context, spec HTTPRuleSpec) (HostHTTPRule, error) {
	if runtime == nil || runtime.client == nil {
		return HostHTTPRule{}, ErrTypedHandlesUnavailable
	}
	if !validAgentID(spec.AgentID) {
		return HostHTTPRule{}, ErrAgentOffline
	}
	var created HostHTTPRule
	if err := callHost(ctx, runtime.client, hostHTTPRuleOperation, map[string]any{
		"action": "create", "app_id": spec.AppID, "agent_id": spec.AgentID,
		"domain": spec.Domain, "port": spec.Port,
	}, &created); err != nil {
		return HostHTTPRule{}, err
	}
	return created, nil
}

func (runtime *hostCapabilityRuntime) ObserveImage(ctx context.Context, app App) (UpdateObservation, error) {
	if runtime == nil || runtime.client == nil {
		return UpdateObservation{}, ErrTypedHandlesUnavailable
	}
	if !validAgentID(app.AgentID) {
		return UpdateObservation{}, ErrAgentOffline
	}
	var result struct {
		CurrentDigest string `json:"current_digest"`
		LatestDigest  string `json:"latest_digest"`
	}
	if err := callHost(ctx, runtime.client, hostAgentImageOperation, map[string]any{
		"action": "observe", "agent_id": app.AgentID, "app_id": app.ID, "image": app.Image,
	}, &result); err != nil {
		return UpdateObservation{}, err
	}
	return UpdateObservation{CurrentDigest: result.CurrentDigest, LatestDigest: result.LatestDigest}, nil
}

type hostRolloutRuntime struct {
	runtime *hostCapabilityRuntime
}

func (rollout hostRolloutRuntime) Pull(ctx context.Context, fence uint64, app App) error {
	return rollout.runtime.composeApp(ctx, app, map[string]any{"action": "pull", "fence": fence, "image": app.Image}, nil)
}

func (rollout hostRolloutRuntime) Start(ctx context.Context, fence uint64, app App) (string, error) {
	var result struct {
		InstanceID string `json:"instance_id"`
	}
	if err := rollout.runtime.composeApp(ctx, app, map[string]any{"action": "start-instance", "fence": fence, "image": app.Image}, &result); err != nil {
		return "", err
	}
	if strings.TrimSpace(result.InstanceID) == "" {
		return "", ErrTypedHandlesUnavailable
	}
	return result.InstanceID, nil
}

func (rollout hostRolloutRuntime) Ready(ctx context.Context, fence uint64, app App, instanceID string) error {
	return rollout.runtime.composeApp(ctx, app, map[string]any{"action": "ready", "fence": fence, "instance_id": instanceID}, nil)
}

func (rollout hostRolloutRuntime) Cutover(ctx context.Context, fence uint64, ruleRef, target string) error {
	if rollout.runtime == nil || rollout.runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	return callHost(ctx, rollout.runtime.client, hostHTTPRuleOperation, map[string]any{
		"action": "cutover", "fence": fence, "rule_ref": ruleRef, "target": target,
	}, nil)
}

func (rollout hostRolloutRuntime) Drain(ctx context.Context, fence uint64, app App, instanceID string) error {
	return rollout.runtime.composeApp(ctx, app, map[string]any{"action": "drain", "fence": fence, "instance_id": instanceID}, nil)
}

func (rollout hostRolloutRuntime) Remove(ctx context.Context, fence uint64, app App, instanceID string) error {
	return rollout.runtime.composeApp(ctx, app, map[string]any{"action": "remove-instance", "fence": fence, "instance_id": instanceID}, nil)
}

func (rollout hostRolloutRuntime) Inspect(ctx context.Context, fence uint64, app App, ruleRef string) (RuntimeState, error) {
	var state RuntimeState
	if err := rollout.runtime.composeApp(ctx, app, map[string]any{
		"action": "inspect", "fence": fence, "rule_ref": ruleRef,
	}, &state); err != nil {
		return RuntimeState{}, err
	}
	return state, nil
}

func (runtime *hostCapabilityRuntime) composeApp(ctx context.Context, app App, payload map[string]any, result any) error {
	if !validAgentID(app.AgentID) {
		return ErrAgentOffline
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["agent_id"] = app.AgentID
	payload["app_id"] = app.ID
	return runtime.compose(ctx, payload, result)
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
	config.UIHTTPRule = runtime
	config.UIImageObserver = runtime
	config.UIRolloutExecutor = hostRolloutRuntime{runtime: runtime}
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
