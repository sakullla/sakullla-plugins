package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const backupNodeTestSHA256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

const backupNodeTestArtifact = "media-20261022t030405.tar.zst"

func backupNodeTestSettings(enabled bool) BackupSettings {
	return BackupSettings{Node: BackupNodeSettings{Enabled: enabled}}
}

func backupNodeTestApps() []App {
	return []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRunTestCompose, Generation: "generation-1"},
		{ID: "git", AgentID: "agent-2", Compose: backupRunTestCompose, Generation: "generation-1"},
	}
}

func backupNodeTestTransfer() NodeBackupTransfer {
	return NodeBackupTransfer{
		AppID:         "media",
		SourceAgentID: "agent-1",
		TargetAgentID: "agent-2",
		ArtifactName:  backupNodeTestArtifact,
		SizeBytes:     4096,
		SHA256:        backupNodeTestSHA256,
	}
}

// backupNodeStub stands in for the Host transport: it serves the apps state,
// engine-report observe calls, and the node-transfer control plane, recording
// every dispatch for assertions.
type backupNodeStub struct {
	t    *testing.T
	mu   sync.Mutex
	apps []App

	online    map[string]bool
	reportErr map[string]error

	calls        []pluginsdk.HostRuntimeCall
	sendRequests []pluginsdk.NodeTransferRequest
	sendErr      error
	sendResponse pluginsdk.NodeTransferResponse

	statusRequests int
	statusOnceErr  error
	statusStates   []pluginsdk.NodeTransferResponse
}

func (stub *backupNodeStub) call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.t.Helper()
	stub.calls = append(stub.calls, call)
	switch call.Operation {
	case "state.get":
		var request struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			stub.t.Fatalf("state.get payload: %v", err)
		}
		if request.Key != pluginAppsStateKey {
			stub.t.Fatalf("unexpected state.get key %q", request.Key)
		}
		return copyHostResult(map[string]any{"found": true, "value": stub.apps}, target)
	case pluginsdk.HostRuntimePluginCall:
		request := decodePluginCallRequest(stub.t, call)
		payload := decodePluginCallInner(stub.t, request)
		if request.Name != pluginCallEngineName {
			stub.t.Fatalf("unexpected plugin.call name %q", request.Name)
		}
		agentID, _ := payload["agent_id"].(string)
		if err := stub.reportErr[agentID]; err != nil {
			return err
		}
		online := true
		if value, exists := stub.online[agentID]; exists {
			online = value
		}
		return copyHostResult(map[string]any{"agent_id": agentID, "online": online}, target)
	case pluginsdk.HostRuntimeNodeTransfer:
		var request pluginsdk.NodeTransferRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			stub.t.Fatalf("node.transfer payload: %v", err)
		}
		switch request.Action {
		case pluginsdk.NodeTransferActionSend:
			stub.sendRequests = append(stub.sendRequests, request)
			if stub.sendErr != nil {
				return stub.sendErr
			}
			response := stub.sendResponse
			if response.TransferID == "" {
				response = pluginsdk.NodeTransferResponse{TransferID: "nt-media-1", State: pluginsdk.NodeTransferStatePending}
			}
			return copyHostResult(response, target)
		case pluginsdk.NodeTransferActionStatus:
			stub.statusRequests++
			if stub.statusOnceErr != nil {
				err := stub.statusOnceErr
				stub.statusOnceErr = nil
				return err
			}
			if len(stub.statusStates) == 0 {
				stub.t.Fatalf("node.transfer status without a scripted response")
			}
			response := stub.statusStates[0]
			if len(stub.statusStates) > 1 {
				stub.statusStates = stub.statusStates[1:]
			}
			return copyHostResult(response, target)
		default:
			stub.t.Fatalf("node.transfer action = %q", request.Action)
		}
	default:
		stub.t.Fatalf("unexpected host operation %q", call.Operation)
	}
	return nil
}

func (stub *backupNodeStub) hostCallsByOperation(operation string) []pluginsdk.HostRuntimeCall {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	calls := make([]pluginsdk.HostRuntimeCall, 0, len(stub.calls))
	for _, call := range stub.calls {
		if call.Operation == operation {
			calls = append(calls, call)
		}
	}
	return calls
}

func newBackupNodeRuntime(t *testing.T, apps []App) (*hostCapabilityRuntime, *backupNodeStub) {
	t.Helper()
	stub := &backupNodeStub{t: t, apps: apps}
	runtime := newHostCapabilityRuntime(hostCallFunc(stub.call))
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	return runtime, stub
}

func shrinkBackupNodePollInterval(t *testing.T) {
	t.Helper()
	previous := backupNodePollInterval
	backupNodePollInterval = time.Millisecond
	t.Cleanup(func() { backupNodePollInterval = previous })
}

func newFatalBackupNodeRuntime(t *testing.T) *hostCapabilityRuntime {
	t.Helper()
	runtime := newHostCapabilityRuntime(hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		t.Fatal("dispatched to the host while the transfer must stay unreachable")
		return nil
	}))
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	return runtime
}

// The disabled destination is the default and rejects server-side before any
// host dispatch: no entry, no inter-node transfer.
func TestPushBackupArtifactDisabledRejectsBeforeHostUse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings BackupSettings
	}{
		{name: "default off", settings: BackupSettings{}},
		{name: "s3 configured, node off", settings: backupRunTestSettings(true, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime := newFatalBackupNodeRuntime(t)
			result, err := runtime.PushBackupArtifact(context.Background(), test.settings, backupNodeTestTransfer())
			if !errors.Is(err, ErrBackupNodeDisabled) {
				t.Fatalf("err = %v want %v", err, ErrBackupNodeDisabled)
			}
			if result != (NodeBackupTransferResult{}) {
				t.Fatalf("result = %#v", result)
			}
			if !strings.Contains(err.Error(), nodeStageDisabled) {
				t.Fatalf("err text = %q", err.Error())
			}
		})
	}
}

func TestPushBackupArtifactRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mutate    func(*NodeBackupTransfer)
		wantStage string
	}{
		{name: "same agent", mutate: func(t *NodeBackupTransfer) { t.TargetAgentID = t.SourceAgentID }, wantStage: nodeStageInvalid},
		{name: "empty app", mutate: func(t *NodeBackupTransfer) { t.AppID = "" }, wantStage: nodeStageInvalid},
		{name: "invalid app", mutate: func(t *NodeBackupTransfer) { t.AppID = "Bad_ID" }, wantStage: nodeStageInvalid},
		{name: "empty source", mutate: func(t *NodeBackupTransfer) { t.SourceAgentID = "" }, wantStage: nodeStageInvalid},
		{name: "path in artifact name", mutate: func(t *NodeBackupTransfer) { t.ArtifactName = "nested/media.tar.zst" }, wantStage: nodeStageInvalid},
		{name: "traversal in artifact name", mutate: func(t *NodeBackupTransfer) { t.ArtifactName = "media..tar.zst" }, wantStage: nodeStageInvalid},
		{name: "zero size", mutate: func(t *NodeBackupTransfer) { t.SizeBytes = 0 }, wantStage: nodeStageInvalid},
		{name: "short digest", mutate: func(t *NodeBackupTransfer) { t.SHA256 = "abcd" }, wantStage: nodeStageInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime := newFatalBackupNodeRuntime(t)
			transfer := backupNodeTestTransfer()
			test.mutate(&transfer)
			result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), transfer)
			if err == nil || !strings.Contains(err.Error(), test.wantStage) {
				t.Fatalf("err = %v want stage %q", err, test.wantStage)
			}
			if result != (NodeBackupTransferResult{}) {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

// Only managed Agents are selectable: an unknown source or target is rejected
// before the observe probe and before any transfer dispatch.
func TestPushBackupArtifactRejectsUnmanagedAgents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*NodeBackupTransfer)
	}{
		{name: "unmanaged target", mutate: func(t *NodeBackupTransfer) { t.TargetAgentID = "agent-9" }},
		{name: "unmanaged source", mutate: func(t *NodeBackupTransfer) { t.SourceAgentID = "agent-9" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
			transfer := backupNodeTestTransfer()
			test.mutate(&transfer)
			result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), transfer)
			if err == nil || !strings.Contains(err.Error(), nodeStageTargetUnmanaged) {
				t.Fatalf("err = %v want stage %q", err, nodeStageTargetUnmanaged)
			}
			if result != (NodeBackupTransferResult{}) {
				t.Fatalf("result = %#v", result)
			}
			if len(stub.hostCallsByOperation(pluginsdk.HostRuntimeNodeTransfer)) != 0 {
				t.Fatal("unmanaged agent still dispatched node.transfer")
			}
			if len(stub.hostCallsByOperation(pluginsdk.HostRuntimePluginCall)) != 0 {
				t.Fatal("unmanaged agent still probed the engine report")
			}
		})
	}
}

func TestPushBackupArtifactRejectsOfflineTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
	}{
		{name: "report offline"},
		{name: "report unreachable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
			if test.name == "report offline" {
				stub.online = map[string]bool{"agent-2": false}
			} else {
				stub.reportErr = map[string]error{"agent-2": errors.New("agent tunnel is down")}
			}
			result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer())
			if err == nil || !strings.Contains(err.Error(), nodeStageTargetOffline) {
				t.Fatalf("err = %v want stage %q", err, nodeStageTargetOffline)
			}
			if result != (NodeBackupTransferResult{}) {
				t.Fatalf("result = %#v", result)
			}
			if len(stub.hostCallsByOperation(pluginsdk.HostRuntimeNodeTransfer)) != 0 {
				t.Fatal("offline target still dispatched node.transfer")
			}
		})
	}
}

// A send-side transport failure is fail-closed: staged error, no fallback, no
// degraded local copy path.
func TestPushBackupArtifactSendFailureFailsClosed(t *testing.T) {
	shrinkBackupNodePollInterval(t)
	runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
	stub.sendErr = errors.New("agent tunnel entry ensure failed")
	result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer())
	if err == nil || !strings.Contains(err.Error(), nodeStageUnreachable) {
		t.Fatalf("err = %v want stage %q", err, nodeStageUnreachable)
	}
	if result != (NodeBackupTransferResult{}) {
		t.Fatalf("result = %#v", result)
	}
	if len(stub.sendRequests) != 1 {
		t.Fatalf("send requests = %d", len(stub.sendRequests))
	}
}

func TestPushBackupArtifactClassifiesFailedTerminalStates(t *testing.T) {
	shrinkBackupNodePollInterval(t)
	tests := []struct {
		name      string
		lastError string
		wantStage string
	}{
		{name: "credential handshake", lastError: "tunnel credential handshake was rejected", wantStage: nodeStageAuthFailed},
		{name: "agent identity mismatch", lastError: "agent tunnel identity mismatch", wantStage: nodeStageAuthFailed},
		{name: "permission denied", lastError: "permission denied for node transfer", wantStage: nodeStageAuthFailed},
		{name: "connection reset", lastError: "connection reset by peer", wantStage: nodeStageInterrupted},
		{name: "stream closed", lastError: "stream closed mid transfer", wantStage: nodeStageInterrupted},
		{name: "deadline exceeded", lastError: "context deadline exceeded while transferring", wantStage: nodeStageTimeout},
		{name: "unknown failure", lastError: "internal error 500", wantStage: nodeStageFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
			stub.statusStates = []pluginsdk.NodeTransferResponse{{
				TransferID: "nt-media-1", State: pluginsdk.NodeTransferStateFailed, LastError: test.lastError,
			}}
			result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer())
			if err == nil || !strings.Contains(err.Error(), test.wantStage) {
				t.Fatalf("err = %v want stage %q", err, test.wantStage)
			}
			if result != (NodeBackupTransferResult{}) {
				t.Fatalf("result = %#v", result)
			}
			if stub.statusRequests != 1 {
				t.Fatalf("status requests = %d", stub.statusRequests)
			}
		})
	}
}

func TestPushBackupArtifactSuccessPollsToCompleted(t *testing.T) {
	shrinkBackupNodePollInterval(t)
	runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
	stub.statusStates = []pluginsdk.NodeTransferResponse{
		{TransferID: "nt-media-1", State: pluginsdk.NodeTransferStateTransferring, BytesTransferred: 1024},
		{TransferID: "nt-media-1", State: pluginsdk.NodeTransferStateCompleted, BytesTransferred: 4096},
	}
	result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer())
	if err != nil {
		t.Fatal(err)
	}
	want := NodeBackupTransferResult{
		TransferID:       "nt-media-1",
		TargetAgentID:    "agent-2",
		TargetPath:       "media/backups/" + backupNodeTestArtifact,
		BytesTransferred: 4096,
	}
	if result != want {
		t.Fatalf("result = %#v want %#v", result, want)
	}
	transferCalls := stub.hostCallsByOperation(pluginsdk.HostRuntimeNodeTransfer)
	if len(transferCalls) != 3 {
		t.Fatalf("node.transfer calls = %d want 1 send + 2 status", len(transferCalls))
	}
	send := transferCalls[0]
	if send.OperationID == "" {
		t.Fatal("send carried no operation id")
	}
	if want := nodeTransferOperationID(stub.sendRequests[0]); send.OperationID != want {
		t.Fatalf("send operation id = %q want %q", send.OperationID, want)
	}
	if len(stub.sendRequests) != 1 {
		t.Fatalf("send requests = %d", len(stub.sendRequests))
	}
	request := stub.sendRequests[0]
	if request.Action != pluginsdk.NodeTransferActionSend ||
		request.SourceAgentID != "agent-1" || request.TargetAgentID != "agent-2" ||
		request.AppID != "media" || request.ArtifactName != backupNodeTestArtifact ||
		request.SizeBytes != 4096 || request.SHA256 != backupNodeTestSHA256 {
		t.Fatalf("send request = %#v", request)
	}
	var statusPayload pluginsdk.NodeTransferRequest
	if err := json.Unmarshal(transferCalls[1].Payload, &statusPayload); err != nil {
		t.Fatalf("status payload: %v", err)
	}
	if statusPayload.Action != pluginsdk.NodeTransferActionStatus || statusPayload.TransferID != "nt-media-1" ||
		statusPayload.SourceAgentID != "" || statusPayload.ArtifactName != "" || statusPayload.SHA256 != "" {
		t.Fatalf("status request = %#v", statusPayload)
	}
	if stub.statusRequests != 2 {
		t.Fatalf("status requests = %d want 2", stub.statusRequests)
	}
}

// Retrying the same logical push reuses the host-side idempotent send: the
// operation id (and payload) stay identical, so the host returns the same
// transfer instead of duplicating bytes.
func TestPushBackupArtifactRetryReusesOperationID(t *testing.T) {
	shrinkBackupNodePollInterval(t)
	runtime, stub := newBackupNodeRuntime(t, backupNodeTestApps())
	// First attempt: the send is accepted, one status poll fails on transport.
	stub.statusOnceErr = errors.New("control plane momentarily unavailable")
	if _, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer()); err == nil ||
		!strings.Contains(err.Error(), nodeStageUnreachable) {
		t.Fatalf("first attempt err = %v want stage %q", err, nodeStageUnreachable)
	}
	// Second attempt with identical inputs completes.
	stub.statusStates = []pluginsdk.NodeTransferResponse{
		{TransferID: "nt-media-1", State: pluginsdk.NodeTransferStateCompleted, BytesTransferred: 4096},
	}
	result, err := runtime.PushBackupArtifact(context.Background(), backupNodeTestSettings(true), backupNodeTestTransfer())
	if err != nil {
		t.Fatal(err)
	}
	if result.TransferID != "nt-media-1" || result.BytesTransferred != 4096 {
		t.Fatalf("retry result = %#v", result)
	}
	if len(stub.sendRequests) != 2 {
		t.Fatalf("send requests = %d", len(stub.sendRequests))
	}
	first, second := stub.sendRequests[0], stub.sendRequests[1]
	if first != second {
		t.Fatalf("retry payload changed: %#v vs %#v", first, second)
	}
	transferCalls := stub.hostCallsByOperation(pluginsdk.HostRuntimeNodeTransfer)
	var sendIDs []string
	for _, call := range transferCalls {
		var request pluginsdk.NodeTransferRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			t.Fatalf("node.transfer payload: %v", err)
		}
		if request.Action == pluginsdk.NodeTransferActionSend {
			sendIDs = append(sendIDs, call.OperationID)
		}
	}
	if len(sendIDs) != 2 || sendIDs[0] != sendIDs[1] || sendIDs[0] == "" {
		t.Fatalf("send operation ids = %v", sendIDs)
	}
}

func TestManagedBackupAgentsReturnsSortedUniqueAgents(t *testing.T) {
	t.Parallel()
	runtime, stub := newBackupNodeRuntime(t, []App{
		{ID: "media", AgentID: "agent-2", Compose: backupRunTestCompose, Generation: "generation-1"},
		{ID: "git", AgentID: "agent-1", Compose: backupRunTestCompose, Generation: "generation-1"},
		{ID: "wiki", AgentID: "agent-2", Compose: backupRunTestCompose, Generation: "generation-1"},
		{ID: "orphans", Generation: "generation-1"},
	})
	agents, err := runtime.ManagedBackupAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 || agents[0] != "agent-1" || agents[1] != "agent-2" {
		t.Fatalf("agents = %#v", agents)
	}
	if len(stub.hostCallsByOperation(pluginsdk.HostRuntimeNodeTransfer)) != 0 {
		t.Fatal("agent listing dispatched node.transfer")
	}
}
