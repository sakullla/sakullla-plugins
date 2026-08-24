package reversel4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// hostRuntimeCaller is the public SDK host runtime transport. Every host
// effect of this plugin goes through it; there is no private host contract.
type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

// pluginsdkPayloadBound mirrors the canonical host runtime payload ceiling.
const pluginsdkPayloadBound = pluginsdk.PluginHostPayloadMaxBytes

// hostRuntime wraps the generic host runtime client with the typed l4.rule,
// channel.reverse, and durable-state operations this plugin orchestrates.
type hostRuntime struct {
	client hostRuntimeCaller
}

type mutationOperationContextKey struct{}

func withMutationOperationKey(ctx context.Context, operationKey string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, mutationOperationContextKey{}, strings.TrimSpace(operationKey))
}

func mutationRequestOperationKey(ctx context.Context) string {
	if ctx != nil {
		if key, ok := ctx.Value(mutationOperationContextKey{}).(string); ok && key != "" {
			return key
		}
	}
	return "internal"
}

// newProductionHostRuntime binds the canonical host runtime client from the
// plugin process environment. A missing endpoint means the host did not
// provision the runtime surface; orchestration then reports the explicit
// unavailable error instead of gating plugin startup.
func newProductionHostRuntime() *hostRuntime {
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err != nil || client == nil {
		return nil
	}
	return &hostRuntime{client: client}
}

func bindHostRuntime(client hostRuntimeCaller) *hostRuntime {
	if client == nil {
		return nil
	}
	return &hostRuntime{client: client}
}

func (runtime *hostRuntime) available() bool {
	return runtime != nil && runtime.client != nil
}

// channelSession is the wire result of a channel.reverse action.
type channelSession struct {
	SessionRef string `json:"session_ref"`
	State      string `json:"state"`
	BridgeHost string `json:"bridge_host,omitempty"`
	BridgePort int    `json:"bridge_port,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

// l4RuleResult is the wire result of an l4.rule mutation. It mirrors the host
// result, which reports the owning agent alongside the SDK rule reference.
type l4RuleResult struct {
	RuleRef string `json:"rule_ref"`
	AgentID string `json:"agent_id"`
	Enabled bool   `json:"enabled"`
}

func (runtime *hostRuntime) ensureChannel(ctx context.Context, operationID string, request pluginsdk.ChannelReverseRequest) (channelSession, error) {
	request.Action = pluginsdk.ChannelReverseActionEnsure
	var result channelSession
	err := runtime.call(ctx, operationID, pluginsdk.HostRuntimeChannelReverse, request, &result)
	if err != nil {
		return channelSession{}, err
	}
	if result.State != pluginsdk.ChannelReverseStateOnline && result.State != pluginsdk.ChannelReverseStateOffline {
		return channelSession{}, fmt.Errorf("%w: channel session reported unsupported state %q", ErrHostOperationFailed, result.State)
	}
	return result, nil
}

// channelStatus is a live read-only lookup. It never sends an operation id,
// so the host cannot pin the result to a cached mutation outcome.
func (runtime *hostRuntime) channelStatus(ctx context.Context, sessionRef string) (channelSession, error) {
	request := pluginsdk.ChannelReverseRequest{Action: pluginsdk.ChannelReverseActionStatus, SessionRef: sessionRef}
	var result channelSession
	err := runtime.call(ctx, "", pluginsdk.HostRuntimeChannelReverse, request, &result)
	if err != nil {
		return channelSession{}, err
	}
	return result, nil
}

func (runtime *hostRuntime) teardownChannel(ctx context.Context, operationID, sessionRef string) error {
	request := pluginsdk.ChannelReverseRequest{Action: pluginsdk.ChannelReverseActionTeardown, SessionRef: sessionRef}
	return runtime.call(ctx, operationID, pluginsdk.HostRuntimeChannelReverse, request, nil)
}

func (runtime *hostRuntime) createRule(ctx context.Context, operationID string, request pluginsdk.L4RuleRequest) (l4RuleResult, error) {
	request.Action = pluginsdk.L4RuleActionCreate
	var result l4RuleResult
	err := runtime.call(ctx, operationID, pluginsdk.HostRuntimeL4Rule, request, &result)
	if err != nil {
		return l4RuleResult{}, err
	}
	if result.RuleRef == "" {
		return l4RuleResult{}, fmt.Errorf("%w: l4 rule creation returned no rule reference", ErrHostOperationFailed)
	}
	return result, nil
}

func (runtime *hostRuntime) updateRule(ctx context.Context, operationID string, request pluginsdk.L4RuleRequest) (l4RuleResult, error) {
	request.Action = pluginsdk.L4RuleActionUpdate
	var result l4RuleResult
	err := runtime.call(ctx, operationID, pluginsdk.HostRuntimeL4Rule, request, &result)
	if err != nil {
		return l4RuleResult{}, err
	}
	return result, nil
}

func (runtime *hostRuntime) setRuleEnabled(ctx context.Context, operationID string, request pluginsdk.L4RuleRequest, enabled bool) (l4RuleResult, error) {
	request.Action = pluginsdk.L4RuleActionDisable
	if enabled {
		request.Action = pluginsdk.L4RuleActionEnable
	}
	var result l4RuleResult
	err := runtime.call(ctx, operationID, pluginsdk.HostRuntimeL4Rule, request, &result)
	if err != nil {
		return l4RuleResult{}, err
	}
	return result, nil
}

func (runtime *hostRuntime) deleteRule(ctx context.Context, operationID string, request pluginsdk.L4RuleRequest) error {
	request.Action = pluginsdk.L4RuleActionDelete
	return runtime.call(ctx, operationID, pluginsdk.HostRuntimeL4Rule, request, nil)
}

type stateGetResult struct {
	Found bool            `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
}

type statePutResult struct {
	Stored bool `json:"stored"`
}

// stateGet reads one durable plugin state key. State reads never carry an
// operation id, so they are never pinned to a cached durable outcome.
func (runtime *hostRuntime) stateGet(ctx context.Context, key string) ([]byte, bool, error) {
	var result stateGetResult
	err := runtime.call(ctx, "", "state.get", map[string]string{"key": key}, &result)
	if err != nil {
		return nil, false, err
	}
	if !result.Found {
		return nil, false, nil
	}
	return result.Value, true, nil
}

func (runtime *hostRuntime) statePut(ctx context.Context, key string, value []byte) error {
	var result statePutResult
	err := runtime.call(ctx, "", "state.put", struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}{Key: key, Value: json.RawMessage(value)}, &result)
	if err != nil {
		return err
	}
	if !result.Stored {
		return fmt.Errorf("%w: durable state was not stored", ErrStateUnavailable)
	}
	return nil
}

// call performs one host runtime operation. operationID is required for the
// mutating l4.rule and channel.reverse operations: the host turns the id into
// a durable idempotent claim, so retries of one logical mutation replay the
// stored outcome instead of duplicating host effects.
func (runtime *hostRuntime) call(ctx context.Context, operationID, operation string, payload, result any) error {
	if !runtime.available() {
		return ErrHostRuntimeUnavailable
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: encode %s request", ErrHostOperationFailed, operation)
	}
	call := pluginsdk.HostRuntimeCall{Operation: operation, Payload: encoded}
	if operationID != "" {
		call.OperationID = operationID
	}
	if err := call.Validate(); err != nil {
		return fmt.Errorf("%w: %s request is invalid: %v", ErrHostOperationFailed, operation, err)
	}
	if err := runtime.client.Call(ctx, call, result); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if ctx != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
		}
		var runtimeErr *pluginsdk.RuntimeError
		if errors.As(err, &runtimeErr) {
			switch runtimeErr.Code {
			case pluginsdk.ErrorUnavailable:
				return fmt.Errorf("%w: %s", ErrHostRuntimeUnavailable, safeHostText(runtimeErr.Message))
			case pluginsdk.ErrorPermissionDenied:
				return fmt.Errorf("%w: host denied the %s operation", ErrHostRejectedRequest, operation)
			case pluginsdk.ErrorInvalidArgument:
				return fmt.Errorf("%w: %s rejected the %s operation: %s", ErrHostRejectedRequest, "host", operation, safeHostText(runtimeErr.Message))
			}
		}
		return fmt.Errorf("%w: %s operation failed: %v", ErrHostOperationFailed, operation, err)
	}
	return nil
}

// mutationOperationKey derives the stable host operation id for one logical
// mapping mutation. Retrying the same intent reuses the id and payload, while
// a changed intent at the same uncommitted revision mints a new id instead of
// attaching to a stale pending or unknown host outcome.
func mutationOperationKey(ctx context.Context, action string, mapping Mapping, revision uint64) string {
	fields := []string{
		"reverse-l4", "mutation", mutationRequestOperationKey(ctx), action, mapping.ID, revisionString(revision),
		mapping.Name, mapping.EntryAgentID, mapping.ExitAgentID, mapping.Protocol,
		fmt.Sprintf("listen-%d", mapping.ListenPort), mapping.BackendHost,
		fmt.Sprintf("backend-%d", mapping.BackendPort),
	}
	for _, hop := range mapping.RelayChain {
		fields = append(fields, fmt.Sprintf("relay-%d", hop))
	}
	fields = append(fields,
		fmt.Sprintf("enabled-%t", mapping.Enabled), mapping.RuleRef, mapping.SessionRef,
		mapping.BridgeHost, fmt.Sprintf("bridge-%d", mapping.BridgePort),
		generationString(mapping.RecoveryGeneration),
	)
	return stableOperationKey(fields...)
}

func stableOperationKey(fields ...string) string {
	digest := sha256.New()
	for _, field := range fields {
		_, _ = digest.Write([]byte(field))
		_, _ = digest.Write([]byte{0})
	}
	return "reverse-l4:" + hex.EncodeToString(digest.Sum(nil))
}

func revisionString(revision uint64) string {
	return fmt.Sprintf("rev-%d", revision)
}

// safeHostText keeps host-provided messages bounded and single-line.
func safeHostText(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 200 {
		message = message[:200]
	}
	return strings.ReplaceAll(strings.ReplaceAll(message, "\r", " "), "\n", " ")
}
