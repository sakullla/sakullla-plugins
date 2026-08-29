package shadowsocksserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	pluginListensStateKey = "listens"
	pluginSecretsStateKey = "secrets"
	pluginNodesStateKey   = "agent-nodes"
	pluginNodeAddressesOp = "node.addresses"
	maxAgentNodes         = 512
)

type persistedSecret struct {
	Ref      string `json:"ref"`
	Version  string `json:"version"`
	Material string `json:"material"`
}

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type hostCapabilityRuntime struct {
	client hostRuntimeCaller
	mu     sync.Mutex
	live   map[string][]ListenPortStatus
	nodes  map[string]NodeAddresses
	hints  map[string]NodeAddresses
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
	return &hostCapabilityRuntime{
		client: client,
		live:   map[string][]ListenPortStatus{},
		nodes:  map[string]NodeAddresses{},
		hints:  map[string]NodeAddresses{},
	}
}

func (runtime *hostCapabilityRuntime) LoadListens(ctx context.Context) ([]ListenRule, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginListensStateKey}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	var listeners []ListenRule
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &listeners) != nil || len(listeners) > MaxListeners {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return cloneListeners(listeners), true, nil
}

func (runtime *hostCapabilityRuntime) StoreListens(ctx context.Context, listeners []ListenRule) error {
	if runtime == nil || runtime.client == nil || len(listeners) > MaxListeners {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloneListeners(listeners))
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginListensStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) LoadSecrets(ctx context.Context) (map[string]string, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginSecretsStateKey}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	var stored []persistedSecret
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &stored) != nil || len(stored) > MaxUsers+MaxListeners {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return secretsFromPersisted(stored), true, nil
}

func (runtime *hostCapabilityRuntime) StoreSecrets(ctx context.Context, secrets map[string]string) error {
	if runtime == nil || runtime.client == nil || len(secrets) > MaxUsers+MaxListeners {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(persistedFromSecrets(secrets))
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginSecretsStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) LoadNodes(ctx context.Context) (map[string]NodeAddresses, bool, error) {
	if runtime == nil || runtime.client == nil {
		return nil, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginNodesStateKey}, &response); err != nil {
		return nil, false, err
	}
	if !response.Found {
		return nil, false, nil
	}
	var nodes map[string]NodeAddresses
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &nodes) != nil || len(nodes) > maxAgentNodes {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return cloneAgentNodes(nodes), true, nil
}

func (runtime *hostCapabilityRuntime) StoreNodes(ctx context.Context, nodes map[string]NodeAddresses) error {
	if runtime == nil || runtime.client == nil || len(nodes) > maxAgentNodes {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloneAgentNodes(nodes))
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginNodesStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (runtime *hostCapabilityRuntime) snapshotNodes() map[string]NodeAddresses {
	if runtime == nil {
		return map[string]NodeAddresses{}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return cloneAgentNodes(runtime.nodes)
}

func cloneAgentNodes(nodes map[string]NodeAddresses) map[string]NodeAddresses {
	out := make(map[string]NodeAddresses, len(nodes))
	for agentID, node := range nodes {
		out[agentID] = node
	}
	return out
}

func secretsFromPersisted(stored []persistedSecret) map[string]string {
	out := make(map[string]string, len(stored))
	for _, item := range stored {
		if item.Ref == "" || item.Version == "" {
			continue
		}
		out[issuedSecretKey(item.Ref, item.Version)] = item.Material
	}
	return out
}

func persistedFromSecrets(secrets map[string]string) []persistedSecret {
	out := make([]persistedSecret, 0, len(secrets))
	for key, material := range secrets {
		ref, version, ok := strings.Cut(key, "\x00")
		if !ok || ref == "" || version == "" {
			continue
		}
		out = append(out, persistedSecret{Ref: ref, Version: version, Material: material})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref == out[j].Ref {
			return out[i].Version < out[j].Version
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

func (runtime *hostCapabilityRuntime) SetAgentNode(agentID string, node NodeAddresses) {
	runtime.rememberNode(agentID, node)
}

func (runtime *hostCapabilityRuntime) AgentNode(_ context.Context, agentID string) NodeAddresses {
	return runtime.overrideNode(agentID)
}

func (runtime *hostCapabilityRuntime) overrideNode(agentID string) NodeAddresses {
	if runtime == nil || !validAgentID(agentID) {
		return NodeAddresses{}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.nodes[agentID]
}

func (runtime *hostCapabilityRuntime) CatalogNode(ctx context.Context, agentID string) NodeAddresses {
	if runtime == nil || !validAgentID(agentID) || runtime.client == nil {
		return NodeAddresses{}
	}
	var result struct {
		DDNS         string `json:"ddns_domain"`
		IPv4         string `json:"ipv4"`
		IPv6         string `json:"ipv6"`
		LastSeenIPv4 string `json:"last_seen_ipv4"`
		LastSeenIPv6 string `json:"last_seen_ipv6"`
	}
	if err := callHost(ctx, runtime.client, pluginNodeAddressesOp, map[string]any{"agent_id": agentID}, &result); err != nil {
		return NodeAddresses{}
	}
	node := NodeAddresses{
		DDNS: strings.TrimSpace(result.DDNS),
		IPv4: strings.TrimSpace(result.IPv4),
		IPv6: strings.TrimSpace(result.IPv6),
	}
	if node.IPv4 == "" {
		node.IPv4 = strings.TrimSpace(result.LastSeenIPv4)
	}
	if node.IPv6 == "" {
		node.IPv6 = strings.TrimSpace(result.LastSeenIPv6)
	}
	return node
}

func (runtime *hostCapabilityRuntime) rememberNode(agentID string, node NodeAddresses) {
	if runtime == nil || !validAgentID(agentID) || !nodeHasAddr(node) {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.nodes == nil {
		runtime.nodes = map[string]NodeAddresses{}
	}
	runtime.nodes[agentID] = node
}

func (runtime *hostCapabilityRuntime) clearOverride(agentID string) {
	if runtime == nil || !validAgentID(agentID) {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	delete(runtime.nodes, agentID)
}

func (runtime *hostCapabilityRuntime) setHint(agentID string, node NodeAddresses) {
	if runtime == nil || !validAgentID(agentID) || !nodeHasAddr(node) {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.hints == nil {
		runtime.hints = map[string]NodeAddresses{}
	}
	runtime.hints[agentID] = node
}

func (runtime *hostCapabilityRuntime) hintNode(agentID string) NodeAddresses {
	if runtime == nil || !validAgentID(agentID) {
		return NodeAddresses{}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.hints[agentID]
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
	request, err := pluginsdk.NewPluginCallRequest(agentID, name, inner)
	if err != nil {
		return ErrTypedHandlesUnavailable
	}
	return callHost(ctx, runtime.client, pluginsdk.HostRuntimePluginCall, request, result)
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
	runtime := newHostCapabilityRuntime(client)
	config.ListenRuntime = runtime
	config.ListenState = runtime
	return config
}

type loopbackRuntimeCaller struct {
	controller *Controller
}

func (caller loopbackRuntimeCaller) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	if caller.controller == nil {
		return ErrTypedHandlesUnavailable
	}
	if call.Operation != pluginsdk.HostRuntimePluginCall {
		return ErrTypedHandlesUnavailable
	}
	var request pluginsdk.PluginCallRequest
	if err := json.Unmarshal(call.Payload, &request); err != nil {
		return ErrTypedHandlesUnavailable
	}
	raw, err := caller.controller.Call(ctx, "", request.Name, request.Payload)
	if err != nil {
		return err
	}
	if target == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, target)
}

// BindLoopbackListenHost routes plugin.call back to this process so a control
// plane and Agent can share one Controller in tests.
func (c *Controller) BindLoopbackListenHost() {
	if c == nil {
		return
	}
	c.listenHost = newHostCapabilityRuntime(loopbackRuntimeCaller{controller: c})
	if c.listenExec != nil {
		c.listenExec.bindHost = "127.0.0.1"
	}
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
