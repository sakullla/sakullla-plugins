package shadowsocksserver

import (
	"context"
	"encoding/json"
	"sync"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type hostCapabilityRuntime struct {
	client hostRuntimeCaller
	mu     sync.Mutex
	live   map[string][]ListenPortStatus
}

func (c *Controller) ReportListen(ctx context.Context, agentID string) (ListenReport, error) {
	if !validAgentID(agentID) {
		return ListenReport{}, ErrAgentOffline
	}
	if c == nil || c.listenHost == nil {
		return ListenReport{}, ErrTypedHandlesUnavailable
	}
	return c.listenHost.Report(ctx, agentID)
}

func (c *Controller) ApplyListen(ctx context.Context, agentID string, listens []ListenApplyItem) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	if c == nil || c.listenHost == nil {
		return ErrTypedHandlesUnavailable
	}
	return c.listenHost.Apply(ctx, agentID, listens)
}

func (c *Controller) StopListen(ctx context.Context, agentID string, listenIDs []string) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	if c == nil || c.listenHost == nil {
		return ErrTypedHandlesUnavailable
	}
	return c.listenHost.Stop(ctx, agentID, listenIDs)
}

func newHostCapabilityRuntime(client hostRuntimeCaller) *hostCapabilityRuntime {
	if client == nil {
		return nil
	}
	return &hostCapabilityRuntime{client: client, live: map[string][]ListenPortStatus{}}
}

func (runtime *hostCapabilityRuntime) Report(ctx context.Context, agentID string) (ListenReport, error) {
	if !validAgentID(agentID) {
		return ListenReport{}, ErrAgentOffline
	}
	if runtime == nil || runtime.client == nil {
		return ListenReport{}, ErrTypedHandlesUnavailable
	}
	var report ListenReport
	if err := runtime.pluginCall(ctx, agentID, pluginCallListenReport, map[string]any{"agent_id": agentID}, &report); err != nil {
		return ListenReport{}, err
	}
	if report.AgentID != "" && report.AgentID != agentID {
		return ListenReport{}, ErrTypedHandlesUnavailable
	}
	report.AgentID = agentID
	return report, nil
}

func (runtime *hostCapabilityRuntime) Apply(ctx context.Context, agentID string, listens []ListenApplyItem) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	var result listenApplyResult
	if err := runtime.pluginCall(ctx, agentID, pluginCallListenApply, map[string]any{
		"agent_id": agentID,
		"listens":  listens,
	}, &result); err != nil {
		runtime.refreshLive(ctx, agentID)
		return err
	}
	if !result.Accepted {
		runtime.refreshLive(ctx, agentID)
		return ErrListenBind
	}
	runtime.setLive(agentID, result.Listens)
	return nil
}

func (runtime *hostCapabilityRuntime) refreshLive(ctx context.Context, agentID string) {
	if runtime == nil {
		return
	}
	report, err := runtime.Report(ctx, agentID)
	if err != nil {
		runtime.setLive(agentID, nil)
		return
	}
	runtime.setLive(agentID, report.Listens)
}

func (runtime *hostCapabilityRuntime) Stop(ctx context.Context, agentID string, listenIDs []string) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	var result listenApplyResult
	if err := runtime.pluginCall(ctx, agentID, pluginCallListenStop, map[string]any{
		"agent_id":   agentID,
		"listen_ids": listenIDs,
	}, &result); err != nil {
		return err
	}
	runtime.setLive(agentID, result.Listens)
	return nil
}

func (runtime *hostCapabilityRuntime) LiveListens(agentID string) []ListenPortStatus {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]ListenPortStatus(nil), runtime.live[agentID]...)
}

func (runtime *hostCapabilityRuntime) HasLiveListen(agentID, listenID string) bool {
	for _, item := range runtime.LiveListens(agentID) {
		if item.ID == listenID {
			return true
		}
	}
	return false
}

func (runtime *hostCapabilityRuntime) setLive(agentID string, listens []ListenPortStatus) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.live == nil {
		runtime.live = map[string][]ListenPortStatus{}
	}
	runtime.live[agentID] = append([]ListenPortStatus(nil), listens...)
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
		config.Admission = TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return RuntimeAdapters{}, nil
			}}, nil
		})
	}
	if factory == nil {
		return config
	}
	client, err := factory()
	if err != nil || client == nil {
		return config
	}
	config.ListenRuntime = newHostCapabilityRuntime(client)
	return config
}

func callHost(ctx context.Context, client hostRuntimeCaller, operation string, payload any, result any) error {
	if client == nil {
		return ErrTypedHandlesUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ErrTypedHandlesUnavailable
	}
	var raw json.RawMessage
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, Payload: encoded}, &raw); err != nil {
		return err
	}
	if result == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return ErrTypedHandlesUnavailable
	}
	return nil
}
