package dockerapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// Node backup destination transfer. The control plane pushes one finished
// backup artifact from a source Agent's workspace to a target Agent's
// plugin-managed directory through the SDK node-transfer host operation: only
// small control messages cross plugin.call/HostRuntimeCall payloads, the bytes
// ride the host-managed agent tunnel (agent-identity PKI, mutual TLS), and the
// receiver lands them under its <workspace>/<appID>/backups/ tree. There is no
// plaintext or unauthenticated fallback: a missing tunnel credential, a failed
// handshake, or an unreachable target fails the push with a staged error, and
// no local degraded copy is ever written. The destination switch defaults to
// off; a single gate function keeps every transfer path unreachable while it
// stays off, so the UI hiding the entry (T8) is cosmetic and the server-side
// rejection is authoritative.

// Node-transfer failure stages. Closed strings: host-controlled text never
// reaches them, it is only classified onto this set.
const (
	nodeStageDisabled        = "node backup is not enabled"
	nodeStageInvalid         = "transfer request is invalid"
	nodeStageTargetUnmanaged = "target agent is not managed"
	nodeStageTargetOffline   = "target agent is offline"
	nodeStageUnreachable     = "target agent is unreachable through the host tunnel"
	nodeStageAuthFailed      = "tunnel authentication failed"
	nodeStageInterrupted     = "transfer was interrupted"
	nodeStageTimeout         = "transfer timed out"
	nodeStageFailed          = "transfer failed"
)

var (
	// ErrBackupNodeDisabled is the server-side rejection every node-transfer
	// entry returns while the node backup destination stays off.
	ErrBackupNodeDisabled = errors.New(nodeStageDisabled)
)

const backupNodeTransferTimeout = 30 * time.Minute

// backupNodePollInterval spaces node-transfer status polls. Tests shrink it.
var backupNodePollInterval = 2 * time.Second

// NodeBackupTransfer names one artifact push between two managed Agents. The
// artifact is addressed by its flat name inside the app's backups/ tree on
// both sides; size and digest travel with the control message so the receiver
// can verify what the tunnel delivered.
type NodeBackupTransfer struct {
	AppID         string
	SourceAgentID string
	TargetAgentID string
	ArtifactName  string
	SizeBytes     int64
	SHA256        string
}

// NodeBackupTransferResult reports one completed push. TargetPath is the
// receiver-side landing convention enforced by the host: the artifact name
// below the target plugin-managed <appID>/backups/ directory.
type NodeBackupTransferResult struct {
	TransferID       string
	TargetAgentID    string
	TargetPath       string
	BytesTransferred int64
}

// gateBackupNode is the single gate for the node backup destination. Every
// node-transfer entry funnels through it before any host call, so a disabled
// configuration leaves no reachable transfer path.
func gateBackupNode(settings BackupSettings) error {
	if !settings.Node.Enabled {
		return fmt.Errorf("backup node transfer rejected: %w", ErrBackupNodeDisabled)
	}
	return nil
}

// ManagedBackupAgents returns the sorted set of Agents this plugin manages
// (every Agent with a stored app). Node-backup target selection is limited to
// this set; anything else is rejected as unmanaged.
func (runtime *hostCapabilityRuntime) ManagedBackupAgents(ctx context.Context) ([]string, error) {
	if runtime == nil || runtime.client == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	apps, _, err := runtime.LoadApps(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(apps))
	agents := make([]string, 0, len(apps))
	for index := range apps {
		agentID := strings.TrimSpace(apps[index].AgentID)
		if agentID == "" {
			continue
		}
		if _, exists := seen[agentID]; exists {
			continue
		}
		seen[agentID] = struct{}{}
		agents = append(agents, agentID)
	}
	sort.Strings(agents)
	return agents, nil
}

// PushPackedBackupArtifact adapts one packed run artifact (T5 pack result)
// into a node push. It is the seam the backup orchestration (node destination
// with an optional target Agent) and the cross-node restore fetch (T6) call;
// neither orchestrates transfers on its own.
func (runtime *hostCapabilityRuntime) PushPackedBackupArtifact(ctx context.Context, settings BackupSettings, app App, targetAgentID string, packed packedBackupArtifact) (NodeBackupTransferResult, error) {
	return runtime.PushBackupArtifact(ctx, settings, NodeBackupTransfer{
		AppID:         app.ID,
		SourceAgentID: app.AgentID,
		TargetAgentID: targetAgentID,
		ArtifactName:  packed.Name,
		SizeBytes:     packed.Size,
		SHA256:        packed.SHA256,
	})
}

// PushBackupArtifact transfers one finished backup artifact from the source
// Agent workspace to the target Agent's plugin-managed backups/ directory over
// the SDK node-transfer host operation. The destination gate is checked first,
// then the request shape, then target membership in the managed Agent set and
// its online state (engine-report observe precedent). Send is asynchronous and
// idempotent by operation id; the push then polls status to a terminal state.
// Every failure returns a staged error and leaves no usable artifact at the
// target: the receiver-side landing is host-enforced and this side never
// degrades to an unauthenticated or local copy.
func (runtime *hostCapabilityRuntime) PushBackupArtifact(ctx context.Context, settings BackupSettings, transfer NodeBackupTransfer) (NodeBackupTransferResult, error) {
	if err := gateBackupNode(settings); err != nil {
		return NodeBackupTransferResult{}, err
	}
	if runtime == nil || runtime.client == nil {
		return NodeBackupTransferResult{}, ErrTypedHandlesUnavailable
	}
	request, err := buildNodeTransferSendRequest(transfer)
	if err != nil {
		return NodeBackupTransferResult{}, err
	}
	managed, err := runtime.ManagedBackupAgents(ctx)
	if err != nil {
		return NodeBackupTransferResult{}, err
	}
	if !managedAgentContains(managed, request.SourceAgentID) || !managedAgentContains(managed, request.TargetAgentID) {
		return NodeBackupTransferResult{}, backupNodeFailure(nodeStageTargetUnmanaged)
	}
	report, err := runtime.Report(ctx, request.TargetAgentID)
	if err != nil || !report.Online {
		return NodeBackupTransferResult{}, backupNodeFailure(nodeStageTargetOffline)
	}
	accepted, err := runtime.nodeTransferCall(ctx, nodeTransferOperationID(request), request)
	if err != nil {
		return NodeBackupTransferResult{}, err
	}
	if accepted.State == pluginsdk.NodeTransferStateFailed {
		return NodeBackupTransferResult{}, backupNodeFailure(classifyNodeTransferText(accepted.LastError))
	}
	if accepted.State != pluginsdk.NodeTransferStateCompleted {
		pollCtx, cancel := context.WithTimeout(ctx, backupNodeTransferTimeout)
		defer cancel()
		accepted, err = runtime.awaitNodeTransfer(pollCtx, accepted.TransferID)
		if err != nil {
			return NodeBackupTransferResult{}, err
		}
	}
	return NodeBackupTransferResult{
		TransferID:       accepted.TransferID,
		TargetAgentID:    request.TargetAgentID,
		TargetPath:       path.Join(request.AppID, backupArtifactDir, request.ArtifactName),
		BytesTransferred: accepted.BytesTransferred,
	}, nil
}

// buildNodeTransferSendRequest validates the push shape against the same rules
// the SDK enforces server-side. It performs no host calls.
func buildNodeTransferSendRequest(transfer NodeBackupTransfer) (pluginsdk.NodeTransferRequest, error) {
	request := pluginsdk.NodeTransferRequest{
		Action:        pluginsdk.NodeTransferActionSend,
		SourceAgentID: strings.TrimSpace(transfer.SourceAgentID),
		TargetAgentID: strings.TrimSpace(transfer.TargetAgentID),
		AppID:         strings.TrimSpace(transfer.AppID),
		ArtifactName:  strings.TrimSpace(transfer.ArtifactName),
		SizeBytes:     transfer.SizeBytes,
		SHA256:        strings.ToLower(strings.TrimSpace(transfer.SHA256)),
	}
	if !validID(request.AppID) || !validAgentID(request.SourceAgentID) || !validAgentID(request.TargetAgentID) || !sha256Hex(request.SHA256) {
		return pluginsdk.NodeTransferRequest{}, backupNodeFailure(nodeStageInvalid)
	}
	if err := request.Validate(); err != nil {
		return pluginsdk.NodeTransferRequest{}, backupNodeFailure(nodeStageInvalid)
	}
	return request, nil
}

// nodeTransferOperationID derives the deterministic idempotency key of one
// push: retries of the same transfer reuse the host-side result instead of
// duplicating bytes. The key is a bounded hash so long agent or artifact names
// cannot overflow the operation identity budget.
func nodeTransferOperationID(request pluginsdk.NodeTransferRequest) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		request.SourceAgentID, request.TargetAgentID, request.AppID,
		request.ArtifactName, fmt.Sprintf("%d", request.SizeBytes), request.SHA256,
	}, "\x1f")))
	return "node-backup-" + hex.EncodeToString(digest[:16])
}

// nodeTransferCall performs one node-transfer host operation and validates the
// wire shape on both directions.
func (runtime *hostCapabilityRuntime) nodeTransferCall(ctx context.Context, operationID string, request pluginsdk.NodeTransferRequest) (pluginsdk.NodeTransferResponse, error) {
	if err := request.Validate(); err != nil {
		return pluginsdk.NodeTransferResponse{}, backupNodeFailure(nodeStageInvalid)
	}
	var response pluginsdk.NodeTransferResponse
	if err := callHostWithOperation(ctx, runtime.client, pluginsdk.HostRuntimeNodeTransfer, operationID, request, &response); err != nil {
		return pluginsdk.NodeTransferResponse{}, backupNodeFailure(classifyNodeTransferFailure(err))
	}
	if err := response.Validate(); err != nil {
		return pluginsdk.NodeTransferResponse{}, backupNodeFailure(nodeStageFailed)
	}
	return response, nil
}

// awaitNodeTransfer polls one accepted transfer until it completes. A failed
// terminal state, a tunnel-level transport failure, or the poll budget expiry
// returns a staged error; nothing is retried past the host-side idempotent
// send.
func (runtime *hostCapabilityRuntime) awaitNodeTransfer(ctx context.Context, transferID string) (pluginsdk.NodeTransferResponse, error) {
	request := pluginsdk.NodeTransferRequest{Action: pluginsdk.NodeTransferActionStatus, TransferID: transferID}
	ticker := time.NewTicker(backupNodePollInterval)
	defer ticker.Stop()
	for {
		response, err := runtime.nodeTransferCall(ctx, "", request)
		if err != nil {
			return pluginsdk.NodeTransferResponse{}, err
		}
		switch response.State {
		case pluginsdk.NodeTransferStateCompleted:
			return response, nil
		case pluginsdk.NodeTransferStateFailed:
			return pluginsdk.NodeTransferResponse{}, backupNodeFailure(classifyNodeTransferText(response.LastError))
		}
		select {
		case <-ctx.Done():
			return pluginsdk.NodeTransferResponse{}, backupNodeFailure(nodeStageTimeout)
		case <-ticker.C:
		}
	}
}

// classifyNodeTransferFailure maps a transport-level error onto the closed
// stage set. The host transport is fail-closed: any plugin-unavailable class
// means the tunnel path could not be used and never degrades.
func classifyNodeTransferFailure(err error) string {
	if err == nil {
		return nodeStageFailed
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nodeStageTimeout
	}
	if errors.Is(err, ErrTypedHandlesUnavailable) {
		return nodeStageUnreachable
	}
	return classifyNodeTransferText(err.Error())
}

// classifyNodeTransferText maps host-reported failure text onto the closed
// stage set. The text itself is never forwarded.
func classifyNodeTransferText(text string) string {
	lower := strings.ToLower(strings.TrimSpace(text))
	switch {
	case lower == "":
		return nodeStageFailed
	case strings.Contains(lower, "permission"):
		return nodeStageAuthFailed
	case strings.Contains(lower, "auth"), strings.Contains(lower, "credential"),
		strings.Contains(lower, "handshake"), strings.Contains(lower, "tls"),
		strings.Contains(lower, "identity"):
		return nodeStageAuthFailed
	case strings.Contains(lower, "unreachable"), strings.Contains(lower, "unavailable"),
		strings.Contains(lower, "offline"), strings.Contains(lower, "no route"),
		strings.Contains(lower, "tunnel"), strings.Contains(lower, "refused"):
		return nodeStageUnreachable
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "timed out"),
		strings.Contains(lower, "deadline"):
		return nodeStageTimeout
	case strings.Contains(lower, "cancel"), strings.Contains(lower, "interrupt"),
		strings.Contains(lower, "reset"), strings.Contains(lower, "closed"):
		return nodeStageInterrupted
	default:
		return nodeStageFailed
	}
}

func managedAgentContains(agents []string, agentID string) bool {
	for _, agent := range agents {
		if agent == agentID {
			return true
		}
	}
	return false
}

func backupNodeFailure(stage string) error {
	return fmt.Errorf("backup node transfer failed: %s", stage)
}
