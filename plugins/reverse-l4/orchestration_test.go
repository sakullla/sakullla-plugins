package reversel4

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// fakeHostRuntime mirrors the host-side semantics the plugin orchestrates
// against: durable operation-id idempotency for l4.rule and channel.reverse,
// instance-keyed plugin state, host-minted reverse channel sessions with an
// entry-side bridge endpoint, and agent-owned L4 rules addressed by rule_ref.
type fakeHostRuntime struct {
	mu sync.Mutex

	calls         []fakeHostCall
	executedCalls []fakeHostCall    // calls that ran host effects instead of replaying an outcome
	outcomes      map[string]string // durable operation key -> committed payload
	pending       map[string]string // durable operation key -> retryable failure fingerprint
	claimed       map[string]string // durable operation key -> last fingerprint

	state          map[string]json.RawMessage
	sessions       map[string]*fakeSession
	rules          map[string]*fakeRule
	nextRuleID     int
	nextBridgePort int

	failRuleCreateAttempts    int
	failRuleUpdateAttempts    int
	failChannelEnsureAttempts int

	blockStatusRefs map[string]struct{}
	statusEntered   map[string]chan struct{}
	statusExited    map[string]chan struct{}

	operationBlocks map[string]*operationBlock
}

type operationBlock struct {
	entered chan struct{}
	hold    chan struct{}
}

type fakeHostCall struct {
	Operation   string
	OperationID string
	Payload     string
}

type fakeSession struct {
	entry, exit, protocol, backendHost string
	backendPort                        int
	relayChain                         []int
	bridgeHost                         string
	bridgePort                         int
	entryLost                          bool
	exitLost                           bool
}

type fakeRule struct {
	id         string
	agentID    string
	name       string
	protocol   string
	listenPort int
	backends   []pluginsdk.L4RuleBackend
	tags       []string
	enabled    bool
}

func newFakeHostRuntime(t *testing.T) *fakeHostRuntime {
	t.Helper()
	return &fakeHostRuntime{
		outcomes:       map[string]string{},
		pending:        map[string]string{},
		claimed:        map[string]string{},
		state:          map[string]json.RawMessage{},
		sessions:       map[string]*fakeSession{},
		rules:          map[string]*fakeRule{},
		nextBridgePort: 6000,
	}
}

func (host *fakeHostRuntime) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, result any) error {
	if err := call.Validate(); err != nil {
		return err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	host.mu.Lock()
	host.calls = append(host.calls, fakeHostCall{Operation: call.Operation, OperationID: call.OperationID, Payload: string(call.Payload)})
	sessionRef, isStatus := channelStatusSessionRef(call)
	_, block := host.blockStatusRefs[sessionRef]
	opBlock := host.operationBlocks[call.OperationID]
	host.mu.Unlock()
	if isStatus && block {
		return host.waitBlockedStatus(ctx, sessionRef)
	}
	if opBlock != nil {
		if err := waitOperationBlock(ctx, opBlock); err != nil {
			return err
		}
	}

	host.mu.Lock()
	defer host.mu.Unlock()

	if call.OperationID != "" {
		fingerprint := call.Operation + "\x00" + string(call.Payload)
		if committed, ok := host.outcomes[call.OperationID]; ok {
			if host.claimed[call.OperationID] != fingerprint {
				return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInvalidArgument, Message: "host resource operation id was reused"}
			}
			return decodeInto(committed, result)
		}
		if pending, ok := host.pending[call.OperationID]; ok && host.claimed[call.OperationID] != pending {
			return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInvalidArgument, Message: "host resource operation id was reused"}
		}
		host.claimed[call.OperationID] = fingerprint
	}

	// Past this point the call executes real (fake) host effects.
	host.executedCalls = append(host.executedCalls, fakeHostCall{Operation: call.Operation, OperationID: call.OperationID, Payload: string(call.Payload)})

	payload, err := host.dispatch(call)
	if err != nil {
		var runtimeErr *pluginsdk.RuntimeError
		if errors.As(err, &runtimeErr) && runtimeErr.Retryable {
			host.pending[call.OperationID] = call.Operation + "\x00" + string(call.Payload)
			return err
		}
		if call.OperationID != "" {
			host.outcomes[call.OperationID] = fmt.Sprintf(`{"error":%q}`, err.Error())
		}
		return err
	}
	if call.OperationID != "" {
		delete(host.pending, call.OperationID)
		host.outcomes[call.OperationID] = payload
	}
	return decodeInto(payload, result)
}

func (host *fakeHostRuntime) dispatch(call pluginsdk.HostRuntimeCall) (string, error) {
	switch call.Operation {
	case "state.get":
		var request struct {
			Key string `json:"key"`
		}
		if err := strictDecode(call.Payload, &request); err != nil {
			return "", invalidRequest(err)
		}
		value, found := host.state[request.Key]
		if !found {
			return `{"found":false}`, nil
		}
		return fmt.Sprintf(`{"found":true,"value":%s}`, value), nil
	case "state.put":
		var request struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := strictDecode(call.Payload, &request); err != nil {
			return "", invalidRequest(err)
		}
		host.state[request.Key] = append(json.RawMessage(nil), request.Value...)
		return `{"stored":true}`, nil
	case pluginsdk.HostRuntimeChannelReverse:
		var request pluginsdk.ChannelReverseRequest
		if err := strictDecode(call.Payload, &request); err != nil || request.Validate() != nil {
			return "", invalidRequest(err)
		}
		return host.dispatchChannel(request)
	case pluginsdk.HostRuntimeL4Rule:
		var request pluginsdk.L4RuleRequest
		if err := strictDecode(call.Payload, &request); err != nil || request.Validate() != nil {
			return "", invalidRequest(err)
		}
		return host.dispatchRule(request)
	default:
		return "", &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInvalidArgument, Message: "host resource operation is unsupported"}
	}
}

func (host *fakeHostRuntime) dispatchChannel(request pluginsdk.ChannelReverseRequest) (string, error) {
	switch request.Action {
	case pluginsdk.ChannelReverseActionEnsure:
		if host.failChannelEnsureAttempts > 0 {
			host.failChannelEnsureAttempts--
			return "", &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "injected channel failure", Retryable: true}
		}
		sessionRef := request.SessionRef
		if sessionRef == "" {
			sessionRef = fmt.Sprintf("channel/%s/%s", request.EntryAgentID, request.ExitAgentID)
		}
		session, ok := host.sessions[sessionRef]
		if !ok {
			host.nextBridgePort++
			session = &fakeSession{bridgeHost: "127.0.0.1", bridgePort: host.nextBridgePort}
			host.sessions[sessionRef] = session
		} else if session.entryLost {
			host.nextBridgePort++
			session.bridgeHost = "127.0.0.1"
			session.bridgePort = host.nextBridgePort
			session.entryLost = false
		}
		session.exitLost = false
		session.entry, session.exit = request.EntryAgentID, request.ExitAgentID
		session.protocol, session.backendHost, session.backendPort = request.Protocol, request.BackendHost, request.BackendPort
		session.relayChain = append([]int(nil), request.RelayChain...)
		return fmt.Sprintf(`{"session_ref":%q,"state":"online","bridge_host":%q,"bridge_port":%d}`, sessionRef, session.bridgeHost, session.bridgePort), nil
	case pluginsdk.ChannelReverseActionStatus:
		session, ok := host.sessions[request.SessionRef]
		if !ok {
			return fmt.Sprintf(`{"session_ref":%q,"state":"offline","last_error":"reverse channel is not established"}`, request.SessionRef), nil
		}
		if session.entryLost || session.exitLost {
			lastError := "reverse channel is not established"
			switch {
			case session.entryLost && !session.exitLost:
				lastError = "entry session is gone"
			case session.exitLost && !session.entryLost:
				lastError = "exit session is gone"
			}
			if !session.entryLost {
				return fmt.Sprintf(`{"session_ref":%q,"state":"offline","last_error":%q,"bridge_host":%q,"bridge_port":%d}`, request.SessionRef, lastError, session.bridgeHost, session.bridgePort), nil
			}
			return fmt.Sprintf(`{"session_ref":%q,"state":"offline","last_error":%q}`, request.SessionRef, lastError), nil
		}
		return fmt.Sprintf(`{"session_ref":%q,"state":"online","bridge_host":%q,"bridge_port":%d}`, request.SessionRef, session.bridgeHost, session.bridgePort), nil
	case pluginsdk.ChannelReverseActionTeardown:
		delete(host.sessions, request.SessionRef)
		return fmt.Sprintf(`{"session_ref":%q,"state":"offline"}`, request.SessionRef), nil
	default:
		return "", invalidRequest(nil)
	}
}

func (host *fakeHostRuntime) dispatchRule(request pluginsdk.L4RuleRequest) (string, error) {
	switch request.Action {
	case pluginsdk.L4RuleActionCreate:
		if host.failRuleCreateAttempts > 0 {
			host.failRuleCreateAttempts--
			return "", &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "injected rule failure", Retryable: true}
		}
		host.nextRuleID++
		rule := &fakeRule{
			id: strconv.Itoa(host.nextRuleID), agentID: request.AgentID, name: request.Name,
			protocol: request.Protocol, listenPort: request.ListenPort,
			backends: append([]pluginsdk.L4RuleBackend(nil), request.Backends...),
			tags:     append([]string(nil), request.Tags...), enabled: true,
		}
		if request.Enabled != nil {
			rule.enabled = *request.Enabled
		}
		host.rules[rule.id] = rule
		return ruleResult(rule), nil
	case pluginsdk.L4RuleActionUpdate, pluginsdk.L4RuleActionEnable, pluginsdk.L4RuleActionDisable:
		if host.failRuleUpdateAttempts > 0 {
			host.failRuleUpdateAttempts--
			return "", &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "injected rule failure", Retryable: true}
		}
		rule, ok := host.rules[request.RuleRef]
		if !ok || rule.agentID != request.AgentID {
			return "", invalidRequest(errors.New("rule not found"))
		}
		if request.Name != "" {
			rule.name = request.Name
		}
		if request.Protocol != "" {
			rule.protocol = request.Protocol
		}
		if request.ListenPort > 0 {
			rule.listenPort = request.ListenPort
		}
		if request.Backends != nil {
			rule.backends = append([]pluginsdk.L4RuleBackend(nil), request.Backends...)
		}
		if request.Tags != nil {
			rule.tags = append([]string(nil), request.Tags...)
		}
		if request.Action == pluginsdk.L4RuleActionEnable {
			rule.enabled = true
		} else if request.Action == pluginsdk.L4RuleActionDisable {
			rule.enabled = false
		} else if request.Enabled != nil {
			rule.enabled = *request.Enabled
		}
		return ruleResult(rule), nil
	case pluginsdk.L4RuleActionDelete:
		rule, ok := host.rules[request.RuleRef]
		if !ok || rule.agentID != request.AgentID {
			return "", invalidRequest(errors.New("rule not found"))
		}
		delete(host.rules, request.RuleRef)
		return ruleResult(rule), nil
	default:
		return "", invalidRequest(nil)
	}
}

func ruleResult(rule *fakeRule) string {
	return fmt.Sprintf(`{"rule_ref":%q,"agent_id":%q,"enabled":%t}`, rule.id, rule.agentID, rule.enabled)
}

func (host *fakeHostRuntime) rule(ruleRef string) *fakeRule {
	host.mu.Lock()
	defer host.mu.Unlock()
	if rule, ok := host.rules[ruleRef]; ok {
		return &fakeRule{id: rule.id, agentID: rule.agentID, name: rule.name, protocol: rule.protocol,
			listenPort: rule.listenPort, backends: append([]pluginsdk.L4RuleBackend(nil), rule.backends...),
			tags: append([]string(nil), rule.tags...), enabled: rule.enabled}
	}
	return nil
}

func (host *fakeHostRuntime) session(sessionRef string) *fakeSession {
	host.mu.Lock()
	defer host.mu.Unlock()
	if session, ok := host.sessions[sessionRef]; ok {
		return &fakeSession{entry: session.entry, exit: session.exit, protocol: session.protocol,
			backendHost: session.backendHost, backendPort: session.backendPort,
			relayChain: append([]int(nil), session.relayChain...), bridgeHost: session.bridgeHost, bridgePort: session.bridgePort,
			entryLost: session.entryLost, exitLost: session.exitLost}
	}
	return nil
}

func (host *fakeHostRuntime) dropChannel(sessionRef string) {
	host.mu.Lock()
	defer host.mu.Unlock()
	delete(host.sessions, sessionRef)
}

func (host *fakeHostRuntime) dropEntry(sessionRef string) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if session, ok := host.sessions[sessionRef]; ok {
		session.entryLost = true
	}
}

func (host *fakeHostRuntime) dropExit(sessionRef string) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if session, ok := host.sessions[sessionRef]; ok {
		session.exitLost = true
	}
}

func (host *fakeHostRuntime) sessionCount() int {
	host.mu.Lock()
	defer host.mu.Unlock()
	return len(host.sessions)
}

func (host *fakeHostRuntime) ruleCount() int {
	host.mu.Lock()
	defer host.mu.Unlock()
	return len(host.rules)
}

func (host *fakeHostRuntime) forgetRule(ruleRef string) {
	host.mu.Lock()
	defer host.mu.Unlock()
	delete(host.rules, ruleRef)
}

func (host *fakeHostRuntime) resetCalls() {
	host.mu.Lock()
	defer host.mu.Unlock()
	host.calls = nil
	host.executedCalls = nil
}

func (host *fakeHostRuntime) blockChannelStatus(sessionRef string) (entered, exited <-chan struct{}) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.blockStatusRefs == nil {
		host.blockStatusRefs = map[string]struct{}{}
		host.statusEntered = map[string]chan struct{}{}
		host.statusExited = map[string]chan struct{}{}
	}
	enteredCh := make(chan struct{})
	exitedCh := make(chan struct{})
	host.blockStatusRefs[sessionRef] = struct{}{}
	host.statusEntered[sessionRef] = enteredCh
	host.statusExited[sessionRef] = exitedCh
	return enteredCh, exitedCh
}

func (host *fakeHostRuntime) blockOperationID(operationID string) (entered <-chan struct{}, unblock func()) {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.operationBlocks == nil {
		host.operationBlocks = map[string]*operationBlock{}
	}
	enteredCh := make(chan struct{})
	hold := make(chan struct{})
	host.operationBlocks[operationID] = &operationBlock{entered: enteredCh, hold: hold}
	return enteredCh, func() { closeSignal(hold) }
}

func waitOperationBlock(ctx context.Context, block *operationBlock) error {
	closeSignal(block.entered)
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-block.hold:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (host *fakeHostRuntime) waitBlockedStatus(ctx context.Context, sessionRef string) error {
	host.mu.Lock()
	entered := host.statusEntered[sessionRef]
	exited := host.statusExited[sessionRef]
	host.mu.Unlock()
	closeSignal(entered)
	defer closeSignal(exited)
	if ctx == nil {
		ctx = context.Background()
	}
	<-ctx.Done()
	return ctx.Err()
}

func (host *fakeHostRuntime) outcomeKeys() []string {
	host.mu.Lock()
	defer host.mu.Unlock()
	keys := make([]string, 0, len(host.outcomes))
	for key := range host.outcomes {
		keys = append(keys, key)
	}
	return keys
}

func (host *fakeHostRuntime) statusLookups() []fakeHostCall {
	host.mu.Lock()
	defer host.mu.Unlock()
	matched := make([]fakeHostCall, 0, len(host.calls))
	for _, call := range host.calls {
		if _, ok := channelStatusSessionRef(pluginsdk.HostRuntimeCall{Operation: call.Operation, OperationID: call.OperationID, Payload: json.RawMessage(call.Payload)}); ok {
			matched = append(matched, call)
		}
	}
	return matched
}

func channelStatusSessionRef(call pluginsdk.HostRuntimeCall) (string, bool) {
	if call.Operation != pluginsdk.HostRuntimeChannelReverse {
		return "", false
	}
	var request pluginsdk.ChannelReverseRequest
	if json.Unmarshal(call.Payload, &request) != nil {
		return "", false
	}
	if request.Action != pluginsdk.ChannelReverseActionStatus {
		return "", false
	}
	return request.SessionRef, true
}

func closeSignal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func assertBoundedLastError(t *testing.T, lastError string) {
	t.Helper()
	if lastError == "" {
		t.Fatal("LastError is empty")
	}
	if strings.ContainsAny(lastError, "\r\n") {
		t.Fatalf("LastError contains a newline: %q", lastError)
	}
	if len(lastError) > 200 {
		t.Fatalf("LastError length %d exceeds 200: %q", len(lastError), lastError)
	}
}

func (host *fakeHostRuntime) callCount(operation string) int {
	host.mu.Lock()
	defer host.mu.Unlock()
	count := 0
	for _, call := range host.calls {
		if call.Operation == operation {
			count++
		}
	}
	return count
}

func (host *fakeHostRuntime) onlyCall(t *testing.T, operation, action string) fakeHostCall {
	t.Helper()
	host.mu.Lock()
	defer host.mu.Unlock()
	var matched []fakeHostCall
	for _, call := range host.calls {
		if call.Operation != operation {
			continue
		}
		if action != "" && !strings.Contains(call.Payload, `"action":`+strconv.Quote(action)) {
			continue
		}
		matched = append(matched, call)
	}
	if len(matched) != 1 {
		t.Fatalf("operation %s action %s calls = %d, want exactly one", operation, action, len(matched))
	}
	return matched[0]
}

// executions counts calls that ran host effects for one operation and JSON
// action, excluding durable-outcome replays.
func (host *fakeHostRuntime) executions(operation, action string) int {
	host.mu.Lock()
	defer host.mu.Unlock()
	count := 0
	for _, call := range host.executedCalls {
		if call.Operation != operation {
			continue
		}
		if action != "" && !strings.Contains(call.Payload, `"action":`+strconv.Quote(action)) {
			continue
		}
		count++
	}
	return count
}

func strictDecode(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func decodeInto(payload string, result any) error {
	if result == nil || payload == "" {
		return nil
	}
	if strings.HasPrefix(payload, `{"error":`) {
		return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInvalidArgument, Message: payload}
	}
	return json.Unmarshal([]byte(payload), result)
}

func invalidRequest(err error) *pluginsdk.RuntimeError {
	message := "host resource request is invalid"
	if err != nil {
		message = err.Error()
	}
	return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInvalidArgument, Message: message}
}

func newOrchestrationService(t *testing.T, host *fakeHostRuntime) *Service {
	t.Helper()
	runtime := bindHostRuntime(host)
	service, err := NewService(newDurableMappingState(runtime), runtime)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func orchestrationMapping(id, protocol string) Mapping {
	return Mapping{
		ID: id, EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: protocol, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
	}
}

func TestCreateOrchestratesChannelThenRule(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)

	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if !created.Enabled || created.RuleRef == "" || created.SessionRef != "channel/entry-agent/exit-agent" {
		t.Fatalf("created mapping = %#v", created)
	}
	if created.BridgeHost != "127.0.0.1" || created.BridgePort == 0 {
		t.Fatalf("created bridge endpoint = %s:%d", created.BridgeHost, created.BridgePort)
	}

	rule := host.rule(created.RuleRef)
	if rule.agentID != "entry-agent" || rule.protocol != ProtocolTCP || rule.listenPort != 8443 {
		t.Fatalf("host rule = %#v", rule)
	}
	if len(rule.backends) != 1 || rule.backends[0].Host != created.BridgeHost || rule.backends[0].Port != created.BridgePort {
		t.Fatalf("host rule backends = %#v, want the channel bridge endpoint", rule.backends)
	}
	for _, tag := range []string{"mapping/tcp-map", "reverse-l4"} {
		if !containsTag(rule.tags, tag) {
			t.Fatalf("host rule tags = %v, missing %q", rule.tags, tag)
		}
	}
	if !rule.enabled {
		t.Fatal("host rule was not enabled on create")
	}

	session := host.session(created.SessionRef)
	if session.entry != "entry-agent" || session.exit != "exit-agent" || session.protocol != ProtocolTCP {
		t.Fatalf("host session = %#v", session)
	}
	if session.backendHost != "127.0.0.1" || session.backendPort != 9443 {
		t.Fatalf("host session backend = %s:%d", session.backendHost, session.backendPort)
	}

	persisted, err := service.List(t.Context())
	if err != nil || len(persisted) != 1 || persisted[0].ID != "tcp-map" || persisted[0].RuleRef != created.RuleRef {
		t.Fatalf("persisted mappings = %#v err=%v", persisted, err)
	}

	ensure, ruleCreate := host.onlyCall(t, "channel.reverse", "ensure"), host.onlyCall(t, "l4.rule", "create")
	if ensure.OperationID == "" || ruleCreate.OperationID == "" {
		t.Fatalf("mutating host calls must carry durable operation ids: %#v %#v", ensure, ruleCreate)
	}
	if host.callCount("state.put") != 1 {
		t.Fatalf("state.put calls = %d", host.callCount("state.put"))
	}
}

func TestDisableEnableDeleteLifecycle(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("udp-map", ProtocolUDP))
	if err != nil {
		t.Fatal(err)
	}

	disabled, err := service.SetEnabled(t.Context(), "udp-map", false)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled || disabled.RuleRef != created.RuleRef || disabled.SessionRef != created.SessionRef {
		t.Fatalf("disabled mapping = %#v", disabled)
	}
	if session := host.session(created.SessionRef); session != nil {
		t.Fatalf("disable left the reverse channel established: %#v", session)
	}
	if rule := host.rule(created.RuleRef); rule == nil || rule.enabled {
		t.Fatalf("disable left the host rule accepting traffic: %#v", rule)
	}
	if kept, err := service.List(t.Context()); err != nil || len(kept) != 1 {
		t.Fatalf("disable must keep the record: %#v err=%v", kept, err)
	}
	if status, err := service.Status(t.Context(), "udp-map"); err != nil || status.ChannelState != ChannelOffline {
		t.Fatalf("disabled status = %#v err=%v", status, err)
	}

	reenabled, err := service.SetEnabled(t.Context(), "udp-map", true)
	if err != nil {
		t.Fatal(err)
	}
	if !reenabled.Enabled || reenabled.RuleRef != created.RuleRef || reenabled.SessionRef != created.SessionRef {
		t.Fatalf("reenabled mapping = %#v", reenabled)
	}
	if session := host.session(created.SessionRef); session == nil {
		t.Fatal("enable did not re-establish the reverse channel")
	}
	reenabledRule := host.rule(created.RuleRef)
	if reenabledRule == nil || !reenabledRule.enabled {
		t.Fatalf("reenabled host rule = %#v", reenabledRule)
	}
	if len(reenabledRule.backends) != 1 || reenabledRule.backends[0].Port != reenabled.BridgePort {
		t.Fatalf("reenabled rule backends = %#v", reenabledRule.backends)
	}
	status, err := service.Status(t.Context(), "udp-map")
	if err != nil || status.ChannelState != ChannelOnline {
		t.Fatalf("reenabled status = %#v err=%v", status, err)
	}

	if err := service.Delete(t.Context(), "udp-map"); err != nil {
		t.Fatal(err)
	}
	if rule := host.rule(created.RuleRef); rule != nil {
		t.Fatalf("delete left an orphan host rule: %#v", rule)
	}
	if session := host.session(created.SessionRef); session != nil {
		t.Fatalf("delete left an orphan reverse channel: %#v", session)
	}
	if remaining, err := service.List(t.Context()); err != nil || len(remaining) != 0 {
		t.Fatalf("remaining mappings = %#v err=%v", remaining, err)
	}
	if err := service.Delete(t.Context(), "udp-map"); err != nil {
		t.Fatalf("repeated delete error = %v", err)
	}
}

func TestUpdateRepointsRuleAndMovesEntryAgent(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}

	updated := orchestrationMapping("tcp-map", ProtocolTCP)
	updated.ListenPort = 9443
	updated.BackendPort = 8080
	if _, err := service.Update(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	rule := host.rule(created.RuleRef)
	if rule.listenPort != 9443 {
		t.Fatalf("updated host rule listen port = %d", rule.listenPort)
	}
	if session := host.session(created.SessionRef); session.backendPort != 8080 {
		t.Fatalf("updated channel backend port = %d", session.backendPort)
	}

	moved := updated
	moved.EntryAgentID = "edge-agent"
	moved.ListenPort = 9543
	if _, err := service.Update(t.Context(), moved); err != nil {
		t.Fatal(err)
	}
	if stale := host.rule(created.RuleRef); stale != nil {
		t.Fatalf("entry move left the rule on the old agent: %#v", stale)
	}
	if session := host.session(created.SessionRef); session != nil {
		t.Fatalf("entry move left the old channel established: %#v", session)
	}
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed mappings = %#v err=%v", listed, err)
	}
	current := listed[0]
	if current.EntryAgentID != "edge-agent" || current.RuleRef == "" || current.RuleRef == created.RuleRef {
		t.Fatalf("moved mapping = %#v", current)
	}
	rule = host.rule(current.RuleRef)
	if rule == nil || rule.agentID != "edge-agent" || rule.listenPort != 9543 {
		t.Fatalf("moved host rule = %#v", rule)
	}
	if session := host.session(current.SessionRef); session == nil || session.entry != "edge-agent" {
		t.Fatalf("moved channel = %#v", session)
	}
}

func TestCreateRetryReplaysDurableChannelOutcome(t *testing.T) {
	host := newFakeHostRuntime(t)
	host.failRuleCreateAttempts = 1
	service := newOrchestrationService(t, host)

	if _, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP)); !errors.Is(err, ErrHostRuntimeUnavailable) {
		t.Fatalf("injected rule failure error = %v", err)
	}
	if listed, err := service.List(t.Context()); err != nil || len(listed) != 0 {
		t.Fatalf("failed create persisted a mapping: %#v err=%v", listed, err)
	}

	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if host.executions("channel.reverse", "ensure") != 1 {
		t.Fatalf("channel ensure executions = %d, want one durable execution replayed on retry", host.executions("channel.reverse", "ensure"))
	}
	if host.executions("l4.rule", "create") != 2 {
		t.Fatalf("rule create executions = %d, want the failed step retried", host.executions("l4.rule", "create"))
	}
	if session := host.session(created.SessionRef); session == nil {
		t.Fatal("retried create did not attach the durable channel session")
	}
	if rule := host.rule(created.RuleRef); rule == nil {
		t.Fatal("retried create did not create the host rule")
	}
}

func TestDeleteContinuesWhenHostTargetAlreadyGone(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate host-side cleanup having already removed both effects, as the
	// resource-group cleanup path would after a partial delete.
	host.dropChannel(created.SessionRef)
	host.forgetRule(created.RuleRef)
	if err := service.Delete(t.Context(), "tcp-map"); err != nil {
		t.Fatalf("delete with already-removed targets error = %v", err)
	}
	if remaining, err := service.List(t.Context()); err != nil || len(remaining) != 0 {
		t.Fatalf("remaining mappings = %#v err=%v", remaining, err)
	}
}

func TestStatusDistinguishesChannelConnectivity(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	outcomeCount := len(host.outcomeKeys())
	online, err := service.Status(t.Context(), "tcp-map")
	if err != nil || online.ChannelState != ChannelOnline {
		t.Fatalf("online status = %#v err=%v", online, err)
	}
	before := host.callCount("channel.reverse")
	offline, err := service.Status(t.Context(), "tcp-map")
	if err != nil || offline.ChannelState != ChannelOnline {
		t.Fatalf("repeated status = %#v err=%v", offline, err)
	}
	if host.callCount("channel.reverse") <= before {
		t.Fatal("status polls must not be pinned to one cached durable outcome")
	}
	listed, err := service.Statuses(t.Context())
	if err != nil || len(listed) != 1 || listed[0].ChannelState != ChannelOnline {
		t.Fatalf("catalog statuses = %#v err=%v", listed, err)
	}
	host.dropChannel(created.SessionRef)
	gone, err := service.Status(t.Context(), "tcp-map")
	if err != nil || gone.ChannelState != ChannelOffline || gone.LastError == "" {
		t.Fatalf("offline status = %#v err=%v", gone, err)
	}
	repeated, err := service.Statuses(t.Context())
	if err != nil || len(repeated) != 1 || repeated[0].ChannelState != ChannelOffline || repeated[0].LastError == "" {
		t.Fatalf("repeated statuses after drop = %#v err=%v", repeated, err)
	}
	for _, call := range host.statusLookups() {
		if call.OperationID != "" {
			t.Fatalf("status lookup carried operation id %#v", call)
		}
	}
	if got := len(host.outcomeKeys()); got != outcomeCount {
		t.Fatalf("status lookup created mutation outcomes: before=%d after=%d", outcomeCount, got)
	}
	if _, err := service.Status(t.Context(), "missing-map"); !errors.Is(err, ErrMappingNotFound) {
		t.Fatalf("unknown mapping status error = %v", err)
	}
}

func TestStatusesBoundsConcurrentLookupsAndDegradesBlockedMapping(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)

	disabledSpec := orchestrationMapping("alpha-disabled", ProtocolTCP)
	disabledSpec.EntryAgentID = "disabled-entry"
	disabledSpec.ExitAgentID = "disabled-exit"
	disabledSpec.ListenPort = 8441
	if _, err := service.Create(t.Context(), disabledSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetEnabled(t.Context(), "alpha-disabled", false); err != nil {
		t.Fatal(err)
	}

	onlineSpec := orchestrationMapping("beta-online", ProtocolTCP)
	onlineSpec.EntryAgentID = "online-entry"
	onlineSpec.ExitAgentID = "online-exit"
	onlineSpec.ListenPort = 8442
	online, err := service.Create(t.Context(), onlineSpec)
	if err != nil {
		t.Fatal(err)
	}

	blockedSpec := orchestrationMapping("gamma-blocked", ProtocolTCP)
	blockedSpec.EntryAgentID = "blocked-entry"
	blockedSpec.ExitAgentID = "blocked-exit"
	blockedSpec.ListenPort = 8443
	blocked, err := service.Create(t.Context(), blockedSpec)
	if err != nil {
		t.Fatal(err)
	}
	_, exited := host.blockChannelStatus(blocked.SessionRef)
	host.resetCalls()

	started := time.Now()
	statuses, err := service.Statuses(t.Context())
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > statusCollectionTimeout+time.Second {
		t.Fatalf("Statuses took %s, want within the 5s collection budget", elapsed)
	}
	if elapsed < statusCollectionTimeout-250*time.Millisecond {
		t.Fatalf("Statuses returned in %s, want to wait the 5s budget for the blocked lookup", elapsed)
	}
	if len(statuses) != 3 {
		t.Fatalf("statuses = %#v", statuses)
	}
	if statuses[0].ID != "alpha-disabled" || statuses[0].ChannelState != ChannelOffline || statuses[0].LastError != "" {
		t.Fatalf("disabled status = %#v", statuses[0])
	}
	if statuses[1].ID != "beta-online" || statuses[1].ChannelState != ChannelOnline || statuses[1].SessionRef != online.SessionRef {
		t.Fatalf("online status = %#v", statuses[1])
	}
	if statuses[2].ID != "gamma-blocked" || statuses[2].ChannelState != ChannelUnknown || statuses[2].SessionRef != blocked.SessionRef {
		t.Fatalf("blocked status = %#v", statuses[2])
	}
	assertBoundedLastError(t, statuses[2].LastError)
	if !strings.HasPrefix(statuses[2].LastError, "timeout:") {
		t.Fatalf("blocked LastError = %q, want timeout prefix", statuses[2].LastError)
	}

	lookups := host.statusLookups()
	if len(lookups) != 2 {
		t.Fatalf("channel status calls = %d, want 2 enabled lookups: %#v", len(lookups), lookups)
	}
	for _, lookup := range lookups {
		if lookup.OperationID != "" {
			t.Fatalf("status lookup carried operation id %q", lookup.OperationID)
		}
		ref, _ := channelStatusSessionRef(pluginsdk.HostRuntimeCall{Operation: lookup.Operation, Payload: json.RawMessage(lookup.Payload)})
		if ref == "" || strings.Contains(ref, "disabled") {
			t.Fatalf("disabled mapping triggered a status lookup: %#v", lookup)
		}
	}
	waitClosed(t, exited, time.Second, "blocked status worker did not exit after the collection deadline")
}

func TestStatusesStopsWhenRequestContextCanceled(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)

	firstSpec := orchestrationMapping("alpha-map", ProtocolTCP)
	firstSpec.EntryAgentID = "alpha-entry"
	firstSpec.ExitAgentID = "alpha-exit"
	firstSpec.ListenPort = 8441
	first, err := service.Create(t.Context(), firstSpec)
	if err != nil {
		t.Fatal(err)
	}
	secondSpec := orchestrationMapping("beta-map", ProtocolTCP)
	secondSpec.EntryAgentID = "beta-entry"
	secondSpec.ExitAgentID = "beta-exit"
	secondSpec.ListenPort = 8442
	second, err := service.Create(t.Context(), secondSpec)
	if err != nil {
		t.Fatal(err)
	}
	enteredFirst, exitedFirst := host.blockChannelStatus(first.SessionRef)
	enteredSecond, exitedSecond := host.blockChannelStatus(second.SessionRef)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct {
		statuses []MappingStatus
		err      error
	}, 1)
	go func() {
		statuses, err := service.Statuses(ctx)
		done <- struct {
			statuses []MappingStatus
			err      error
		}{statuses, err}
	}()
	waitClosed(t, enteredFirst, 2*time.Second, "first status worker did not start")
	waitClosed(t, enteredSecond, 2*time.Second, "second status worker did not start")
	cancel()

	var result struct {
		statuses []MappingStatus
		err      error
	}
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("Statuses kept waiting after the request context was canceled")
	}
	if result.err != nil {
		t.Fatalf("canceled Statuses error = %v", result.err)
	}
	if len(result.statuses) != 2 {
		t.Fatalf("canceled statuses = %#v", result.statuses)
	}
	for _, status := range result.statuses {
		if status.ChannelState != ChannelUnknown {
			t.Fatalf("canceled status = %#v", status)
		}
		assertBoundedLastError(t, status.LastError)
		if !strings.HasPrefix(status.LastError, "cancel:") {
			t.Fatalf("canceled LastError = %q, want cancel prefix", status.LastError)
		}
	}
	waitClosed(t, exitedFirst, time.Second, "first status worker did not exit after cancel")
	waitClosed(t, exitedSecond, time.Second, "second status worker did not exit after cancel")
}

func TestStatusesObservesLiveHostStateWithoutMutationOutcome(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	beforeOutcomes := append([]string(nil), host.outcomeKeys()...)
	host.resetCalls()

	first, err := service.Statuses(t.Context())
	if err != nil || len(first) != 1 || first[0].ChannelState != ChannelOnline || first[0].SessionRef != created.SessionRef || first[0].RuleRef != created.RuleRef {
		t.Fatalf("live statuses = %#v err=%v", first, err)
	}
	if lookups := host.statusLookups(); len(lookups) != 1 || lookups[0].OperationID != "" {
		t.Fatalf("first status lookups = %#v", lookups)
	}
	if after := host.outcomeKeys(); !sameStrings(beforeOutcomes, after) {
		t.Fatalf("status lookup mutated outcomes: before=%v after=%v", beforeOutcomes, after)
	}

	host.dropChannel(created.SessionRef)
	second, err := service.Statuses(t.Context())
	if err != nil || len(second) != 1 || second[0].ChannelState != ChannelOffline || second[0].LastError == "" {
		t.Fatalf("dropped-session statuses = %#v err=%v", second, err)
	}
	if second[0].SessionRef != created.SessionRef || second[0].RuleRef != created.RuleRef {
		t.Fatalf("status lookup changed mapping refs: %#v", second[0])
	}
	if lookups := host.statusLookups(); len(lookups) != 2 {
		t.Fatalf("repeated status lookups = %d, want a fresh host read", len(lookups))
	}
	if after := host.outcomeKeys(); !sameStrings(beforeOutcomes, after) {
		t.Fatalf("repeated status lookup mutated outcomes: before=%v after=%v", beforeOutcomes, after)
	}
}

func TestStatusesDoesNotWaitOnInFlightRecoveryHostLookup(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	entered, exited := host.blockChannelStatus(created.SessionRef)

	done := make(chan error, 1)
	go func() {
		done <- service.recoverMapping(t.Context(), created.ID)
	}()
	waitClosed(t, entered, 2*time.Second, "recovery status lookup did not start")

	started := time.Now()
	statuses, err := service.Statuses(t.Context())
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > statusCollectionTimeout+time.Second {
		t.Fatalf("Statuses waited %s on recovery host I/O, want within the 5s collection budget", elapsed)
	}
	if elapsed < statusCollectionTimeout-250*time.Millisecond {
		t.Fatalf("Statuses returned in %s, want to wait the 5s budget for the blocked lookup", elapsed)
	}
	if len(statuses) != 1 || statuses[0].ID != created.ID || statuses[0].ChannelState != ChannelUnknown {
		t.Fatalf("statuses during blocked recovery = %#v", statuses)
	}
	assertBoundedLastError(t, statuses[0].LastError)

	select {
	case recErr := <-done:
		if !errors.Is(recErr, context.DeadlineExceeded) {
			t.Fatalf("blocked recovery error = %v", recErr)
		}
	case <-time.After(recoveryAttemptTimeout + time.Second):
		t.Fatal("recovery did not observe its attempt deadline")
	}
	waitClosed(t, exited, time.Second, "recovery status worker did not exit after the attempt deadline")
}

func waitClosed(t *testing.T, ch <-chan struct{}, timeout time.Duration, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatal(message)
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func TestCreateGeneratesMappingIDAndKeepsRelayOrder(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)

	spec := orchestrationMapping("", ProtocolTCP)
	spec.Name = "内网 Web"
	spec.RelayChain = []int{4, 5, 7}
	created, err := service.Create(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !validMappingID(created.ID) {
		t.Fatalf("generated id %q is invalid", created.ID)
	}
	if created.Name != "内网 Web" {
		t.Fatalf("created name = %q", created.Name)
	}
	session := host.session(created.SessionRef)
	if session == nil || len(session.relayChain) != 3 || session.relayChain[0] != 4 || session.relayChain[1] != 5 || session.relayChain[2] != 7 {
		t.Fatalf("host relay chain = %#v", session)
	}

	direct := orchestrationMapping("", ProtocolTCP)
	direct.ListenPort = 8444
	second, err := service.Create(t.Context(), direct)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == created.ID || !validMappingID(second.ID) {
		t.Fatalf("second generated id = %q first = %q", second.ID, created.ID)
	}
	if len(second.RelayChain) != 0 {
		t.Fatalf("empty relay create = %#v", second)
	}

	same := orchestrationMapping("same-agents", ProtocolTCP)
	same.ExitAgentID = same.EntryAgentID
	if _, err := service.Create(t.Context(), same); !errors.Is(err, ErrInvalidMapping) {
		t.Fatalf("same-agent create error = %v", err)
	}

	kept := created
	kept.ListenPort = 9543
	updated, err := service.Update(t.Context(), kept)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID {
		t.Fatalf("update changed id from %q to %q", created.ID, updated.ID)
	}
}

func TestCreateRejectsDuplicatesAndBound(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	if _, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolUDP)); !errors.Is(err, ErrMappingExists) {
		t.Fatalf("duplicate create error = %v", err)
	}
	for count := 1; count < MaxMappings; count++ {
		mapping := orchestrationMapping(fmt.Sprintf("map-%04d", count), ProtocolTCP)
		mapping.ListenPort = 10000 + count
		if _, err := service.Create(t.Context(), mapping); err != nil {
			t.Fatalf("fill mapping %d error = %v", count, err)
		}
	}
	if _, err := service.Create(t.Context(), func() Mapping {
		mapping := orchestrationMapping("overflow-map", ProtocolTCP)
		mapping.ListenPort = 20000
		return mapping
	}()); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("overflow create error = %v", err)
	}
}

func TestUpdateWhileDisabledOnlyPersistsSpec(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetEnabled(t.Context(), "tcp-map", false); err != nil {
		t.Fatal(err)
	}
	host.resetCalls()
	spec := orchestrationMapping("tcp-map", ProtocolUDP)
	spec.BackendPort = 5353
	updated, err := service.Update(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.Protocol != ProtocolUDP || updated.RuleRef != created.RuleRef {
		t.Fatalf("disabled update = %#v", updated)
	}
	if host.callCount("channel.reverse") != 0 || host.callCount("l4.rule") != 0 {
		t.Fatalf("disabled update touched host effects: channel=%d rule=%d", host.callCount("channel.reverse"), host.callCount("l4.rule"))
	}
	reenabled, err := service.SetEnabled(t.Context(), "tcp-map", true)
	if err != nil {
		t.Fatal(err)
	}
	if reenabled.Protocol != ProtocolUDP || reenabled.BackendPort != 5353 {
		t.Fatalf("enable did not apply the updated spec: %#v", reenabled)
	}
	rule := host.rule(reenabled.RuleRef)
	if rule == nil || rule.protocol != ProtocolUDP || rule.listenPort != 8443 {
		t.Fatalf("rule after disabled update = %#v", rule)
	}
}

func TestUpdateWhileDisabledMovesEntryWithoutOrphanRule(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetEnabled(t.Context(), "tcp-map", false); err != nil {
		t.Fatal(err)
	}
	spec := orchestrationMapping("tcp-map", ProtocolTCP)
	spec.EntryAgentID = "edge-agent"
	if _, err := service.Update(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if stale := host.rule(created.RuleRef); stale != nil {
		t.Fatalf("disabled entry move left the rule on the old agent: %#v", stale)
	}
	reenabled, err := service.SetEnabled(t.Context(), "tcp-map", true)
	if err != nil {
		t.Fatal(err)
	}
	rule := host.rule(reenabled.RuleRef)
	if rule == nil || rule.agentID != "edge-agent" {
		t.Fatalf("rule after disabled entry move = %#v", rule)
	}
	if session := host.session(reenabled.SessionRef); session == nil || session.entry != "edge-agent" {
		t.Fatalf("channel after disabled entry move = %#v", session)
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func recoveryMappingSpec() Mapping {
	spec := orchestrationMapping("tcp-map", ProtocolTCP)
	spec.Name = "内网 Web"
	spec.RelayChain = []int{4, 5, 7}
	return spec
}

func assertMappingUserSpec(t *testing.T, got, want Mapping) {
	t.Helper()
	if got.ID != want.ID || got.Name != want.Name || got.EntryAgentID != want.EntryAgentID || got.ExitAgentID != want.ExitAgentID {
		t.Fatalf("mapping identity = %#v, want %#v", got, want)
	}
	if got.Protocol != want.Protocol || got.ListenPort != want.ListenPort || got.BackendHost != want.BackendHost || got.BackendPort != want.BackendPort {
		t.Fatalf("mapping spec = %#v, want %#v", got, want)
	}
	if len(got.RelayChain) != len(want.RelayChain) {
		t.Fatalf("relay chain = %v, want %v", got.RelayChain, want.RelayChain)
	}
	for index, hop := range want.RelayChain {
		if got.RelayChain[index] != hop {
			t.Fatalf("relay chain = %v, want %v", got.RelayChain, want.RelayChain)
		}
	}
}

func assertRecoveredOnline(t *testing.T, host *fakeHostRuntime, mapping Mapping) {
	t.Helper()
	session := host.session(mapping.SessionRef)
	if session == nil || session.entryLost || session.exitLost {
		t.Fatalf("recovered session = %#v", session)
	}
	if session.entry != mapping.EntryAgentID || session.exit != mapping.ExitAgentID || session.protocol != mapping.Protocol {
		t.Fatalf("recovered session owners = %#v", session)
	}
	if session.backendHost != mapping.BackendHost || session.backendPort != mapping.BackendPort {
		t.Fatalf("recovered session backend = %s:%d", session.backendHost, session.backendPort)
	}
	if len(session.relayChain) != len(mapping.RelayChain) {
		t.Fatalf("recovered relay chain = %v, want %v", session.relayChain, mapping.RelayChain)
	}
	for index, hop := range mapping.RelayChain {
		if session.relayChain[index] != hop {
			t.Fatalf("recovered relay chain = %v, want %v", session.relayChain, mapping.RelayChain)
		}
	}
	rule := host.rule(mapping.RuleRef)
	if rule == nil || !rule.enabled || rule.agentID != mapping.EntryAgentID || rule.protocol != mapping.Protocol || rule.listenPort != mapping.ListenPort {
		t.Fatalf("recovered rule = %#v", rule)
	}
	if len(rule.backends) != 1 || rule.backends[0].Host != mapping.BridgeHost || rule.backends[0].Port != mapping.BridgePort {
		t.Fatalf("recovered rule backends = %#v, want %s:%d", rule.backends, mapping.BridgeHost, mapping.BridgePort)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(message)
}

func TestRecoveryRestoresLostEntryOrExitSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop func(*fakeHostRuntime, string)
	}{
		{name: "entry", drop: (*fakeHostRuntime).dropEntry},
		{name: "exit", drop: (*fakeHostRuntime).dropExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newFakeHostRuntime(t)
			service := newOrchestrationService(t, host)

			disabledSpec := orchestrationMapping("disabled-map", ProtocolTCP)
			disabledSpec.EntryAgentID = "disabled-entry"
			disabledSpec.ExitAgentID = "disabled-exit"
			disabledSpec.ListenPort = 8444
			disabled, err := service.Create(t.Context(), disabledSpec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.SetEnabled(t.Context(), disabled.ID, false); err != nil {
				t.Fatal(err)
			}

			created, err := service.Create(t.Context(), recoveryMappingSpec())
			if err != nil {
				t.Fatal(err)
			}
			originalBridge := created.BridgePort
			tc.drop(host, created.SessionRef)
			offline, err := service.Status(t.Context(), created.ID)
			if err != nil || offline.ChannelState != ChannelOffline {
				t.Fatalf("dropped status = %#v err=%v", offline, err)
			}

			if err := service.recoverMapping(t.Context(), created.ID); err != nil {
				t.Fatal(err)
			}
			listed, err := service.List(t.Context())
			if err != nil || len(listed) != 2 {
				t.Fatalf("listed mappings = %#v err=%v", listed, err)
			}
			var recovered, keptDisabled Mapping
			for _, mapping := range listed {
				switch mapping.ID {
				case created.ID:
					recovered = mapping
				case disabled.ID:
					keptDisabled = mapping
				}
			}
			assertMappingUserSpec(t, recovered, created)
			if recovered.Revision != created.Revision {
				t.Fatalf("recovery changed user revision from %d to %d", created.Revision, recovered.Revision)
			}
			if recovered.SessionRef != created.SessionRef {
				t.Fatalf("recovery changed logical session from %q to %q", created.SessionRef, recovered.SessionRef)
			}
			if recovered.RecoveryGeneration == 0 {
				t.Fatal("recovery did not advance generation")
			}
			online, err := service.Status(t.Context(), created.ID)
			if err != nil || online.ChannelState != ChannelOnline {
				t.Fatalf("recovered status = %#v err=%v", online, err)
			}
			assertRecoveredOnline(t, host, recovered)
			if tc.name == "entry" && recovered.BridgePort == originalBridge {
				t.Fatal("entry recovery kept the lost entry bridge")
			}
			if tc.name == "exit" && recovered.BridgePort != originalBridge {
				t.Fatalf("exit recovery changed bridge from %d to %d", originalBridge, recovered.BridgePort)
			}
			if host.sessionCount() != 1 || host.ruleCount() != 2 {
				t.Fatalf("host sessions=%d rules=%d, want one channel and the disabled mapping's kept rule", host.sessionCount(), host.ruleCount())
			}
			if keptDisabled.ID != disabled.ID || keptDisabled.Enabled {
				t.Fatalf("disabled mapping = %#v", keptDisabled)
			}
			if session := host.session(disabled.SessionRef); session != nil {
				t.Fatalf("disabled mapping was rebuilt: %#v", session)
			}
			if err := service.recoverMapping(t.Context(), disabled.ID); err != nil {
				t.Fatal(err)
			}
			if session := host.session(disabled.SessionRef); session != nil {
				t.Fatalf("disabled mapping recovered after explicit tick: %#v", session)
			}
		})
	}
}

func TestRecoveryRepeatsKeepSingleLogicalSessionAndRule(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), recoveryMappingSpec())
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		host.dropEntry(created.SessionRef)
		if err := service.recoverMapping(t.Context(), created.ID); err != nil {
			t.Fatalf("recovery round %d: %v", round, err)
		}
	}
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed mappings = %#v err=%v", listed, err)
	}
	recovered := listed[0]
	assertMappingUserSpec(t, recovered, created)
	if recovered.SessionRef != created.SessionRef {
		t.Fatalf("repeated recovery changed session ref from %q to %q", created.SessionRef, recovered.SessionRef)
	}
	if host.sessionCount() != 1 || host.ruleCount() != 1 {
		t.Fatalf("host sessions=%d rules=%d after repeated recovery", host.sessionCount(), host.ruleCount())
	}
	assertRecoveredOnline(t, host, recovered)
	if recovered.RuleRef != created.RuleRef {
		t.Fatalf("repeated recovery created a new rule %q, want %q", recovered.RuleRef, created.RuleRef)
	}
}

func TestRecoveryFailureKeepsMappingAndRetryEligibility(t *testing.T) {
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), recoveryMappingSpec())
	if err != nil {
		t.Fatal(err)
	}
	host.dropExit(created.SessionRef)
	host.failChannelEnsureAttempts = 1
	if err := service.recoverMapping(t.Context(), created.ID); !errors.Is(err, ErrHostRuntimeUnavailable) {
		t.Fatalf("injected recovery failure = %v", err)
	}
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("failed recovery listed = %#v err=%v", listed, err)
	}
	failed := listed[0]
	if !failed.Enabled {
		t.Fatalf("recovery failure disabled the mapping: %#v", failed)
	}
	assertMappingUserSpec(t, failed, created)
	if failed.SessionRef != created.SessionRef || failed.RuleRef != created.RuleRef {
		t.Fatalf("recovery failure rewrote refs: %#v", failed)
	}
	if failed.RecoveryGeneration == 0 {
		t.Fatal("failed recovery did not keep the advanced generation")
	}
	offline, err := service.Status(t.Context(), created.ID)
	if err != nil || offline.ChannelState != ChannelOffline {
		t.Fatalf("failed recovery status = %#v err=%v", offline, err)
	}

	if err := service.recoverMapping(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	retried, err := service.List(t.Context())
	if err != nil || len(retried) != 1 {
		t.Fatalf("retried recovery listed = %#v err=%v", retried, err)
	}
	if retried[0].RecoveryGeneration <= failed.RecoveryGeneration {
		t.Fatalf("retry reused generation %d", retried[0].RecoveryGeneration)
	}
	online, err := service.Status(t.Context(), created.ID)
	if err != nil || online.ChannelState != ChannelOnline {
		t.Fatalf("retried recovery status = %#v err=%v", online, err)
	}
	assertRecoveredOnline(t, host, retried[0])
}

func TestRecoveryRacesWithUpdateDisableAndDelete(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		host := newFakeHostRuntime(t)
		service := newOrchestrationService(t, host)
		created, err := service.Create(t.Context(), recoveryMappingSpec())
		if err != nil {
			t.Fatal(err)
		}
		host.dropEntry(created.SessionRef)
		spec := created
		spec.ListenPort = 9543
		spec.BackendPort = 8080
		spec.Name = "更新后的 Web"
		spec.RelayChain = []int{8, 9}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = service.recoverMapping(t.Context(), created.ID)
		}()
		go func() {
			defer wg.Done()
			_, _ = service.Update(t.Context(), spec)
		}()
		wg.Wait()

		listed, err := service.List(t.Context())
		if err != nil || len(listed) != 1 {
			t.Fatalf("listed mappings = %#v err=%v", listed, err)
		}
		final := listed[0]
		assertMappingUserSpec(t, final, spec)
		if !final.Enabled {
			t.Fatalf("update race disabled the mapping: %#v", final)
		}
		assertRecoveredOnline(t, host, final)
		if host.sessionCount() != 1 || host.ruleCount() != 1 {
			t.Fatalf("update race host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
		}
		service.recoverAll(t.Context())
		after, err := service.List(t.Context())
		if err != nil || len(after) != 1 {
			t.Fatalf("post-tick mappings = %#v err=%v", after, err)
		}
		assertMappingUserSpec(t, after[0], spec)
	})

	t.Run("disable", func(t *testing.T) {
		host := newFakeHostRuntime(t)
		service := newOrchestrationService(t, host)
		created, err := service.Create(t.Context(), recoveryMappingSpec())
		if err != nil {
			t.Fatal(err)
		}
		host.dropExit(created.SessionRef)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = service.recoverMapping(t.Context(), created.ID)
		}()
		go func() {
			defer wg.Done()
			_, _ = service.SetEnabled(t.Context(), created.ID, false)
		}()
		wg.Wait()

		listed, err := service.List(t.Context())
		if err != nil || len(listed) != 1 || listed[0].Enabled {
			t.Fatalf("disabled race listed = %#v err=%v", listed, err)
		}
		assertMappingUserSpec(t, listed[0], created)
		if session := host.session(listed[0].SessionRef); session != nil {
			t.Fatalf("disabled mapping left a live session: %#v", session)
		}
		rule := host.rule(listed[0].RuleRef)
		if rule == nil || rule.enabled {
			t.Fatalf("disabled mapping host rule = %#v", rule)
		}
		if err := service.recoverMapping(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		service.recoverAll(t.Context())
		if session := host.session(listed[0].SessionRef); session != nil {
			t.Fatalf("later tick rebuilt a disabled mapping: %#v", session)
		}
		kept, err := service.List(t.Context())
		if err != nil || len(kept) != 1 || kept[0].Enabled {
			t.Fatalf("later tick listed = %#v err=%v", kept, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		host := newFakeHostRuntime(t)
		service := newOrchestrationService(t, host)
		created, err := service.Create(t.Context(), recoveryMappingSpec())
		if err != nil {
			t.Fatal(err)
		}
		host.dropEntry(created.SessionRef)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = service.recoverMapping(t.Context(), created.ID)
		}()
		go func() {
			defer wg.Done()
			_ = service.Delete(t.Context(), created.ID)
		}()
		wg.Wait()

		listed, err := service.List(t.Context())
		if err != nil || len(listed) != 0 {
			t.Fatalf("deleted race listed = %#v err=%v", listed, err)
		}
		if host.sessionCount() != 0 || host.ruleCount() != 0 {
			t.Fatalf("deleted race left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
		}
		if err := service.recoverMapping(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		service.recoverAll(t.Context())
		if remaining, err := service.List(t.Context()); err != nil || len(remaining) != 0 {
			t.Fatalf("later tick rebuilt a deleted mapping: %#v err=%v", remaining, err)
		}
		if host.sessionCount() != 0 || host.ruleCount() != 0 {
			t.Fatalf("later tick left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
		}
	})
}

func TestRecoveryRacesWithOwnerMoveUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		move func(*Mapping)
	}{
		{
			name: "entry",
			move: func(spec *Mapping) {
				spec.EntryAgentID = "edge-agent"
				spec.ListenPort = 9543
			},
		},
		{
			name: "exit",
			move: func(spec *Mapping) {
				spec.ExitAgentID = "core-agent"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, service, created, unblockEnsure, done := startRecoveryEnsureBlocked(t)
			spec := created
			tc.move(&spec)
			if _, err := service.Update(t.Context(), spec); err != nil {
				t.Fatal(err)
			}
			unblockEnsure()
			waitRecoveryDone(t, done)

			listed, err := service.List(t.Context())
			if err != nil || len(listed) != 1 {
				t.Fatalf("listed mappings = %#v err=%v", listed, err)
			}
			final := listed[0]
			assertMappingUserSpec(t, final, spec)
			if !final.Enabled {
				t.Fatalf("owner-move race disabled the mapping: %#v", final)
			}
			if final.SessionRef == "" || final.SessionRef == created.SessionRef {
				t.Fatalf("owner-move race reused the old session: %#v", final)
			}
			if tc.name == "entry" && (final.RuleRef == "" || final.RuleRef == created.RuleRef) {
				t.Fatalf("entry move reused the old rule: %#v", final)
			}
			assertRecoveredOnline(t, host, final)
			if host.sessionCount() != 1 || host.ruleCount() != 1 {
				t.Fatalf("owner-move race host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
			}
			if stale := host.session(created.SessionRef); stale != nil {
				t.Fatalf("owner-move left the old channel established: %#v", stale)
			}
			if tc.name == "entry" {
				if stale := host.rule(created.RuleRef); stale != nil {
					t.Fatalf("entry move left the rule on the old agent: %#v", stale)
				}
			}
			service.recoverAll(t.Context())
			after, err := service.List(t.Context())
			if err != nil || len(after) != 1 {
				t.Fatalf("post-tick mappings = %#v err=%v", after, err)
			}
			assertMappingUserSpec(t, after[0], spec)
			assertRecoveredOnline(t, host, after[0])
			if host.sessionCount() != 1 || host.ruleCount() != 1 {
				t.Fatalf("post-tick host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
			}
		})
	}
}

func TestClaimedRecoveryAbandonsStaleHostEffectsOnTimeoutAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ruleOp    string
		failRule  func(*fakeHostRuntime)
		mutate    func(*testing.T, *Service, Mapping)
		assertEnd func(*testing.T, *fakeHostRuntime, *Service, Mapping)
	}{
		{
			name:   "delete",
			ruleOp: "rule.create",
			failRule: func(host *fakeHostRuntime) {
				host.failRuleCreateAttempts = 1
			},
			mutate: func(t *testing.T, service *Service, created Mapping) {
				t.Helper()
				if err := service.Delete(t.Context(), created.ID); err != nil {
					t.Fatal(err)
				}
			},
			assertEnd: assertDeletedMappingNotRebuilt,
		},
		{
			name:   "disable",
			ruleOp: "rule.update",
			failRule: func(host *fakeHostRuntime) {
				host.failRuleUpdateAttempts = 1
			},
			mutate: func(t *testing.T, service *Service, created Mapping) {
				t.Helper()
				if _, err := service.SetEnabled(t.Context(), created.ID, false); err != nil {
					t.Fatal(err)
				}
			},
			assertEnd: assertDisabledMappingNotRebuilt,
		},
	} {
		t.Run(tc.name+"/timeout", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			host, service, created, unblockEnsure, done := startRecoveryEnsureBlockedWith(t, ctx)
			enteredRule, _ := host.blockOperationID(recoveryOperationKey(tc.ruleOp, created.ID, created.Revision, created.RecoveryGeneration+1))
			tc.mutate(t, service, created)
			unblockEnsure()
			waitClosed(t, enteredRule, 2*time.Second, "recovery rule alignment did not start")
			waitRecoveryDone(t, done)
			tc.assertEnd(t, host, service, created)
		})
		t.Run(tc.name+"/failure", func(t *testing.T) {
			host, service, created, unblockEnsure, done := startRecoveryEnsureBlocked(t)
			tc.mutate(t, service, created)
			tc.failRule(host)
			unblockEnsure()
			waitRecoveryDone(t, done)
			tc.assertEnd(t, host, service, created)
		})
	}
}

func TestStaleUpdateRealignDiscardsLaterDeleteAndDisable(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		host, service, created, unblockFirst, done := startRecoveryEnsureBlocked(t)
		spec := created
		spec.ListenPort = 9543
		spec.BackendPort = 8080
		spec.Name = "更新后的 Web"
		spec.RelayChain = []int{8, 9}
		updated, err := service.Update(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		if err := service.Delete(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		unblockSecond()
		waitRecoveryDone(t, done)
		listed, err := service.List(t.Context())
		if err != nil || len(listed) != 0 {
			t.Fatalf("deleted after realign listed = %#v err=%v", listed, err)
		}
		if host.sessionCount() != 0 || host.ruleCount() != 0 {
			t.Fatalf("stale realign after delete left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
		}
		service.recoverAll(t.Context())
		if remaining, err := service.List(t.Context()); err != nil || len(remaining) != 0 {
			t.Fatalf("later tick rebuilt a deleted mapping: %#v err=%v", remaining, err)
		}
		if host.sessionCount() != 0 || host.ruleCount() != 0 {
			t.Fatalf("later tick left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
		}
	})

	t.Run("disable", func(t *testing.T) {
		host, service, created, unblockFirst, done := startRecoveryEnsureBlocked(t)
		spec := created
		spec.ListenPort = 9543
		spec.BackendPort = 8080
		spec.Name = "更新后的 Web"
		spec.RelayChain = []int{8, 9}
		updated, err := service.Update(t.Context(), spec)
		if err != nil {
			t.Fatal(err)
		}
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		disabled, err := service.SetEnabled(t.Context(), created.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		unblockSecond()
		waitRecoveryDone(t, done)
		listed, err := service.List(t.Context())
		if err != nil || len(listed) != 1 || listed[0].Enabled {
			t.Fatalf("disabled after realign listed = %#v err=%v", listed, err)
		}
		assertMappingUserSpec(t, listed[0], disabled)
		if session := host.session(listed[0].SessionRef); session != nil {
			t.Fatalf("stale realign after disable left a live session: %#v", session)
		}
		rule := host.rule(listed[0].RuleRef)
		if rule == nil || rule.enabled {
			t.Fatalf("stale realign after disable host rule = %#v", rule)
		}
		if err := service.recoverMapping(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		service.recoverAll(t.Context())
		if session := host.session(listed[0].SessionRef); session != nil {
			t.Fatalf("later tick rebuilt a disabled mapping: %#v", session)
		}
		kept, err := service.List(t.Context())
		if err != nil || len(kept) != 1 || kept[0].Enabled {
			t.Fatalf("later tick listed = %#v err=%v", kept, err)
		}
	})

	t.Run("delete/timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		host, service, created, unblockFirst, done := startRecoveryEnsureBlockedWith(t, ctx)
		updated := updateMappingDuringBlockedRecovery(t, service, created)
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		if err := service.Delete(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		enteredCreate, _ := host.blockOperationID(recoveryOperationKey("rule.create", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockSecond()
		waitClosed(t, enteredCreate, 2*time.Second, "stale realign rule create did not start")
		waitRecoveryDone(t, done)
		assertDeletedMappingNotRebuilt(t, host, service, created)
	})

	t.Run("delete/failure", func(t *testing.T) {
		host, service, created, unblockFirst, done := startRecoveryEnsureBlocked(t)
		updated := updateMappingDuringBlockedRecovery(t, service, created)
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		if err := service.Delete(t.Context(), created.ID); err != nil {
			t.Fatal(err)
		}
		host.failRuleCreateAttempts = 1
		unblockSecond()
		waitRecoveryDone(t, done)
		assertDeletedMappingNotRebuilt(t, host, service, created)
	})

	t.Run("disable/timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		host, service, created, unblockFirst, done := startRecoveryEnsureBlockedWith(t, ctx)
		updated := updateMappingDuringBlockedRecovery(t, service, created)
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		if _, err := service.SetEnabled(t.Context(), created.ID, false); err != nil {
			t.Fatal(err)
		}
		enteredUpdate, _ := host.blockOperationID(recoveryOperationKey("rule.update", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockSecond()
		waitClosed(t, enteredUpdate, 2*time.Second, "stale realign rule update did not start")
		waitRecoveryDone(t, done)
		assertDisabledMappingNotRebuilt(t, host, service, updated)
	})

	t.Run("disable/failure", func(t *testing.T) {
		host, service, created, unblockFirst, done := startRecoveryEnsureBlocked(t)
		updated := updateMappingDuringBlockedRecovery(t, service, created)
		enteredSecond, unblockSecond := host.blockOperationID(recoveryOperationKey("channel.ensure", updated.ID, updated.Revision, updated.RecoveryGeneration))
		unblockFirst()
		waitClosed(t, enteredSecond, 2*time.Second, "update-compensation realign ensure did not start")
		if _, err := service.SetEnabled(t.Context(), created.ID, false); err != nil {
			t.Fatal(err)
		}
		host.failRuleUpdateAttempts = 1
		unblockSecond()
		waitRecoveryDone(t, done)
		assertDisabledMappingNotRebuilt(t, host, service, updated)
	})
}

func startRecoveryEnsureBlocked(t *testing.T) (*fakeHostRuntime, *Service, Mapping, func(), <-chan error) {
	t.Helper()
	return startRecoveryEnsureBlockedWith(t, t.Context())
}

func startRecoveryEnsureBlockedWith(t *testing.T, ctx context.Context) (*fakeHostRuntime, *Service, Mapping, func(), <-chan error) {
	t.Helper()
	host := newFakeHostRuntime(t)
	service := newOrchestrationService(t, host)
	created, err := service.Create(t.Context(), recoveryMappingSpec())
	if err != nil {
		t.Fatal(err)
	}
	host.dropEntry(created.SessionRef)
	entered, unblock := host.blockOperationID(recoveryOperationKey("channel.ensure", created.ID, created.Revision, created.RecoveryGeneration+1))
	done := make(chan error, 1)
	go func() {
		done <- service.recoverMapping(ctx, created.ID)
	}()
	waitClosed(t, entered, 2*time.Second, "recovery ensure did not start")
	return host, service, created, unblock, done
}

func updateMappingDuringBlockedRecovery(t *testing.T, service *Service, created Mapping) Mapping {
	t.Helper()
	spec := created
	spec.ListenPort = 9543
	spec.BackendPort = 8080
	spec.Name = "更新后的 Web"
	spec.RelayChain = []int{8, 9}
	updated, err := service.Update(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func waitRecoveryDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case recErr := <-done:
		if recErr != nil {
			t.Fatalf("stale realign recovery error = %v", recErr)
		}
	case <-time.After(recoveryAttemptTimeout + 2*time.Second):
		t.Fatal("recovery did not finish after the competing mutation")
	}
}

func assertDeletedMappingNotRebuilt(t *testing.T, host *fakeHostRuntime, service *Service, created Mapping) {
	t.Helper()
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 0 {
		t.Fatalf("deleted race listed = %#v err=%v", listed, err)
	}
	if host.sessionCount() != 0 || host.ruleCount() != 0 {
		t.Fatalf("deleted race left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
	}
	if err := service.recoverMapping(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	service.recoverAll(t.Context())
	if remaining, err := service.List(t.Context()); err != nil || len(remaining) != 0 {
		t.Fatalf("later tick rebuilt a deleted mapping: %#v err=%v", remaining, err)
	}
	if host.sessionCount() != 0 || host.ruleCount() != 0 {
		t.Fatalf("later tick left host sessions=%d rules=%d", host.sessionCount(), host.ruleCount())
	}
}

func assertDisabledMappingNotRebuilt(t *testing.T, host *fakeHostRuntime, service *Service, created Mapping) {
	t.Helper()
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 || listed[0].Enabled {
		t.Fatalf("disabled race listed = %#v err=%v", listed, err)
	}
	assertMappingUserSpec(t, listed[0], created)
	if session := host.session(listed[0].SessionRef); session != nil {
		t.Fatalf("disabled mapping left a live session: %#v", session)
	}
	rule := host.rule(listed[0].RuleRef)
	if rule == nil || rule.enabled {
		t.Fatalf("disabled mapping host rule = %#v", rule)
	}
	if err := service.recoverMapping(t.Context(), created.ID); err != nil {
		t.Fatal(err)
	}
	service.recoverAll(t.Context())
	if session := host.session(listed[0].SessionRef); session != nil {
		t.Fatalf("later tick rebuilt a disabled mapping: %#v", session)
	}
	kept, err := service.List(t.Context())
	if err != nil || len(kept) != 1 || kept[0].Enabled {
		t.Fatalf("later tick listed = %#v err=%v", kept, err)
	}
}

func TestControllerActivateRecoversLostSessionsAndStopHaltsTicks(t *testing.T) {
	host := newFakeHostRuntime(t)
	runtime := bindHostRuntime(host)
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		State:       newDurableMappingState(runtime),
		Runtime:     runtime,
		BindRuntime: func() *hostRuntime { return runtime },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.stop(t.Context(), nil) })
	if err := controller.prepare(t.Context(), nil, nil); err != nil {
		t.Fatal(err)
	}
	service := controller.Service()
	if service == nil {
		t.Fatal("prepared controller exposes no orchestration service")
	}
	created, err := service.Create(t.Context(), recoveryMappingSpec())
	if err != nil {
		t.Fatal(err)
	}
	host.dropEntry(created.SessionRef)

	started := time.Now()
	if err := controller.activate(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("activate blocked on recovery host I/O for %s", elapsed)
	}

	waitUntil(t, 2*time.Second, func() bool {
		status, err := service.Status(t.Context(), created.ID)
		return err == nil && status.ChannelState == ChannelOnline
	}, "activate scan did not restore the lost entry session")
	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed mappings = %#v err=%v", listed, err)
	}
	assertMappingUserSpec(t, listed[0], created)
	assertRecoveredOnline(t, host, listed[0])

	if err := controller.stop(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if controller.Service() != nil {
		t.Fatal("stop left the orchestration service mounted")
	}
	host.dropExit(listed[0].SessionRef)
	time.Sleep(2 * recoveryScanInterval)
	offline, err := service.Status(t.Context(), created.ID)
	if err != nil || offline.ChannelState != ChannelOffline {
		t.Fatalf("stopped controller kept recovering: %#v err=%v", offline, err)
	}
}
