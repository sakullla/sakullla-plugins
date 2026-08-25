package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	pluginCallEngineName          = "engine.report"
	pluginCallComposeName         = "compose"
	pluginCallImageName           = "image"
	pluginCallFilesName           = "files"
	hostHTTPRuleOperation         = pluginsdk.HostRuntimeHTTPRule
	hostHTTPBackendOfferOperation = "http.backend-offer"
	hostHTTPRuleActionCreate      = pluginsdk.HTTPRuleActionCreate
	hostHTTPRuleActionList        = "list"
	hostHTTPRuleActionDelete      = "delete"
	pluginAppsStateKey            = "apps"
	pluginRuntimeStateKey         = "app-runtime"
)

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type hostCapabilityRuntime struct {
	client hostRuntimeCaller
}

type hostOperationKeyContextKey struct{}

func withHostOperationKey(ctx context.Context, operationID string) context.Context {
	operationID = strings.TrimSpace(operationID)
	if ctx == nil || operationID == "" {
		return ctx
	}
	return context.WithValue(ctx, hostOperationKeyContextKey{}, operationID)
}

func hostOperationKeyFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(hostOperationKeyContextKey{}).(string)
	return strings.TrimSpace(value)
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
	if err := runtime.pluginCall(ctx, agentID, pluginCallEngineName, map[string]any{"agent_id": agentID}, &raw); err != nil {
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

func (runtime *hostCapabilityRuntime) LoadApps(ctx context.Context) ([]App, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginAppsStateKey}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	var apps []App
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &apps) != nil || len(apps) > MaxApps {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return cloneApps(apps), true, nil
}

func (runtime *hostCapabilityRuntime) StoreApps(ctx context.Context, apps []App) error {
	if runtime == nil || runtime.client == nil || len(apps) > MaxApps {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloneApps(apps))
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginAppsStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) LoadRuntime(ctx context.Context) (map[string]bool, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginRuntimeStateKey}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	var values map[string]bool
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &values) != nil || len(values) > MaxApps {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return cloneAppRuntime(values), true, nil
}

func (runtime *hostCapabilityRuntime) StoreRuntime(ctx context.Context, values map[string]bool) error {
	if runtime == nil || runtime.client == nil || len(values) > MaxApps {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloneAppRuntime(values))
	if err != nil {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginRuntimeStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) ApplyApp(ctx context.Context, app App) error {
	if !validAgentID(app.AgentID) {
		return ErrAgentOffline
	}
	return runtime.compose(ctx, map[string]any{
		"action": "apply", "agent_id": app.AgentID, "app_id": app.ID,
		"compose": app.Compose, "workdir": app.WorkDir, "env": app.Env,
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
	var created hostHTTPRuleWire
	if err := callHostWithOperation(ctx, runtime.client, hostHTTPRuleOperation, hostOperationKeyFromContext(ctx), map[string]any{
		"action": hostHTTPRuleActionCreate, "agent_id": spec.AgentID,
		"domain": spec.Domain, "port": int(spec.Port),
	}, &created); err != nil {
		return HostHTTPRule{}, err
	}
	return created.asHostHTTPRule(spec.AgentID), nil
}

func (runtime *hostCapabilityRuntime) List(ctx context.Context, agentID string) ([]HostHTTPRule, error) {
	if runtime == nil || runtime.client == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	if !validAgentID(agentID) {
		return nil, ErrAgentOffline
	}
	var response struct {
		Rules []hostHTTPRuleWire `json:"rules"`
	}
	if err := callHost(ctx, runtime.client, hostHTTPRuleOperation, map[string]any{
		"action": hostHTTPRuleActionList, "agent_id": agentID,
	}, &response); err != nil {
		return nil, err
	}
	rules := make([]HostHTTPRule, 0, len(response.Rules))
	for _, item := range response.Rules {
		rules = append(rules, item.asHostHTTPRule(agentID))
	}
	return rules, nil
}

func (runtime *hostCapabilityRuntime) Delete(ctx context.Context, agentID, ruleRef string) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	ruleRef = strings.TrimSpace(ruleRef)
	if ruleRef == "" {
		return ErrEmptyHTTPRuleRef
	}
	return callHostWithOperation(ctx, runtime.client, hostHTTPRuleOperation, hostOperationKeyFromContext(ctx), map[string]any{
		"action": hostHTTPRuleActionDelete, "agent_id": agentID, "rule_ref": ruleRef,
	}, nil)
}

func (runtime *hostCapabilityRuntime) ReplaceHTTPBackendOffers(ctx context.Context, offers []HTTPBackendCatalogOffer) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	if offers == nil {
		offers = []HTTPBackendCatalogOffer{}
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, hostHTTPBackendOfferOperation, map[string]any{"offers": offers}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

type hostHTTPRuleWire struct {
	RuleRef     string `json:"rule_ref,omitempty"`
	Ref         string `json:"ref,omitempty"`
	FrontendURL string `json:"frontend_url,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Backend     string `json:"backend,omitempty"`
	BackendURL  string `json:"backend_url,omitempty"`
	AppID       string `json:"app_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Port        int    `json:"port,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

func (wire hostHTTPRuleWire) asHostHTTPRule(agentID string) HostHTTPRule {
	ref := strings.TrimSpace(wire.RuleRef)
	if ref == "" {
		ref = strings.TrimSpace(wire.Ref)
	}
	domain := strings.TrimSpace(wire.FrontendURL)
	if domain == "" {
		domain = strings.TrimSpace(wire.Domain)
	}
	backend := strings.TrimSpace(wire.Backend)
	if backend == "" {
		backend = strings.TrimSpace(wire.BackendURL)
	}
	rule := HostHTTPRule{
		Ref:     ref,
		Domain:  domain,
		Backend: backend,
		AppID:   strings.TrimSpace(wire.AppID),
		AgentID: strings.TrimSpace(wire.AgentID),
		Enabled: true,
	}
	if rule.AgentID == "" {
		rule.AgentID = agentID
	}
	if wire.Enabled != nil {
		rule.Enabled = *wire.Enabled
	}
	if wire.Port > 0 && wire.Port <= 65535 {
		rule.Port = uint16(wire.Port)
	} else if port, ok := parseBackendPort(backend); ok {
		rule.Port = port
	}
	return rule
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
	if err := runtime.pluginCall(ctx, app.AgentID, pluginCallImageName, map[string]any{
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
	if strings.TrimSpace(ruleRef) == "" {
		return nil
	}
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
	payload["compose"] = app.Compose
	return runtime.compose(ctx, payload, result)
}

func (runtime *hostCapabilityRuntime) compose(ctx context.Context, payload map[string]any, result any) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	agentID, _ := payload["agent_id"].(string)
	return runtime.pluginCall(ctx, agentID, pluginCallComposeName, payload, result)
}

func (runtime *hostCapabilityRuntime) Files(ctx context.Context, app App, payload map[string]any, result any) error {
	if !validAgentID(app.AgentID) {
		return ErrAgentOffline
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["agent_id"] = app.AgentID
	payload["app_id"] = app.ID
	return runtime.files(ctx, payload, result)
}

func (runtime *hostCapabilityRuntime) files(ctx context.Context, payload map[string]any, result any) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	agentID, _ := payload["agent_id"].(string)
	return runtime.pluginCall(ctx, agentID, pluginCallFilesName, payload, result)
}

func (runtime *hostCapabilityRuntime) pluginCall(ctx context.Context, agentID, name string, inner any, result any) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	payload, err := marshalPluginCallPayload(inner)
	if err != nil {
		return ErrTypedHandlesUnavailable
	}
	request := pluginsdk.PluginCallRequest{AgentID: agentID, Name: name, Payload: payload}
	if err := request.Validate(); err != nil {
		return ErrTypedHandlesUnavailable
	}
	return callHost(ctx, runtime.client, pluginsdk.HostRuntimePluginCall, request, result)
}

func marshalPluginCallPayload(inner any) (json.RawMessage, error) {
	switch typed := inner.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return typed, nil
	case []byte:
		return typed, nil
	default:
		return json.Marshal(typed)
	}
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
	config.UIAppState = runtime
	config.UIApply = runtime
	config.UIStart = runtime
	config.UIStop = runtime
	config.UIRestart = runtime
	config.UILogs = runtime
	config.UIRemove = runtime
	config.UIHTTPRule = runtime
	config.UIHTTPRuleList = runtime
	config.UIHTTPRuleDelete = runtime
	config.UIHTTPBackendOffer = runtime
	config.UIImageObserver = runtime
	config.UIRolloutExecutor = hostRolloutRuntime{runtime: runtime}
	return config
}

func callHost(ctx context.Context, client hostRuntimeCaller, operation string, payload any, result any) error {
	return callHostWithOperation(ctx, client, operation, "", payload, result)
}

func callHostWithOperation(ctx context.Context, client hostRuntimeCaller, operation, operationID string, payload any, result any) error {
	if client == nil {
		return ErrTypedHandlesUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil || localDockerEngineTarget(encoded) {
		return ErrTypedHandlesUnavailable
	}
	var raw json.RawMessage
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, OperationID: strings.TrimSpace(operationID), Payload: encoded}, &raw); err != nil {
		return safeFailure(ErrTypedHandlesUnavailable, err)
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
			if skipLocalDockerValueKey(childKey) {
				continue
			}
			if strings.EqualFold(childKey, "payload") {
				child = decodePluginCallPayload(child)
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

func decodePluginCallPayload(node any) any {
	switch typed := node.(type) {
	case string:
		var decoded any
		if err := json.Unmarshal([]byte(typed), &decoded); err == nil {
			return decoded
		}
	case json.RawMessage:
		var decoded any
		if err := json.Unmarshal(typed, &decoded); err == nil {
			return decoded
		}
	case []byte:
		var decoded any
		if err := json.Unmarshal(typed, &decoded); err == nil {
			return decoded
		}
	}
	return node
}

func skipLocalDockerValueKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "compose", "content", "path", "name", "entries":
		return true
	default:
		return false
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
