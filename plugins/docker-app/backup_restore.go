package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Backup restore and delete orchestration. The heavy restore work runs on the
// target Agent execution face through the "backup-restore" plugin call: the
// Agent retrieves the artifact (S3 download through its own scoped-secret
// backed client, or the workspace backups/ tree of a node destination),
// verifies it against the record and the packed manifest, rebuilds the
// workspace and compose document, and restores named volumes. The control
// plane only gates (record exists, target managed, overwrite confirm), routes
// the artifact to the target (S3 parameters, or a node-transfer push when a
// node-destination artifact is not already present on the target), and then
// applies, starts, and records the restored app; it never unpacks artifacts
// locally. Same-node node-destination restores keep the direct workspace read:
// the artifact already lives where the restore runs. Every stage failure
// returns a stage-named error, leaves the record untouched, and removes
// restore residue best-effort so no half-built workspace survives. Delete
// removes the destination object first and the record second: a failed record
// removal keeps the record as the single authority while both removal steps
// stay retry-safe.

// Control-plane restore/delete failure stages. Closed strings; wrapped with
// the failing sub-call error where one exists.
const (
	backupRestoreStageRecord    = "backup record is invalid"
	backupRestoreStageAgent     = "target agent is not managed"
	backupRestoreStageRetrieve  = "artifact could not be retrieved"
	backupRestoreStageChecksum  = "artifact does not match its record"
	backupRestoreStageCorrupt   = "artifact is corrupt"
	backupRestoreStageWorkspace = "workspace could not be rebuilt"
	backupRestoreStageVolume    = "volume could not be restored"
	backupRestoreStageApply     = "app could not be applied"
	backupRestoreStageStart     = "app could not be started"
	backupRestoreStageAdopt     = "app could not be recorded as managed"
	backupRestoreStageTransfer  = "artifact could not be transferred to the target agent"

	backupDeleteStageDestination = "destination object could not be removed"
	backupDeleteStageRecord      = "backup record could not be removed"
)

// pluginCallBackupRestoreName is the Agent execution-face restore entry,
// following the backup-pack call convention.
const pluginCallBackupRestoreName = "backup-restore"

const (
	backupRestoreActionProbe   = "probe"
	backupRestoreActionRestore = "restore"
)

// Agent execution-face restore failure stages. Closed strings; local paths and
// OS errors never reach them.
const (
	backupRestoreFaceStageInvalid   = "restore request is invalid"
	backupRestoreFaceStageRetrieve  = "artifact could not be retrieved"
	backupRestoreFaceStageChecksum  = "artifact does not match its record"
	backupRestoreFaceStageCorrupt   = "artifact is corrupt"
	backupRestoreFaceStageWorkspace = "workspace could not be rebuilt"
	backupRestoreFaceStageVolume    = "volume could not be restored"
)

func backupRestoreFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup restore failed: %s", stage)
	}
	return fmt.Errorf("backup restore failed: %s (%s)", stage, fmt.Sprint(args...))
}

func backupRestoreFaceFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup-restore failed: %s", stage)
	}
	return fmt.Errorf("backup-restore failed: %s (%s)", stage, fmt.Sprint(args...))
}

func backupDeleteFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup delete failed: %s", stage)
	}
	return fmt.Errorf("backup delete failed: %s (%s)", stage, fmt.Sprint(args...))
}

// backupRestoreCallRequest is the wire shape of the agent-face restore call.
// The S3 fields carry reference strings only; credentials material never
// crosses the call boundary.
type backupRestoreCallRequest struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	AppID   string `json:"app_id"`
	WorkDir string `json:"workdir"`
	Source  string `json:"source"`
	Path    string `json:"path"`

	Endpoint          string `json:"endpoint,omitempty"`
	Bucket            string `json:"bucket,omitempty"`
	Prefix            string `json:"prefix,omitempty"`
	CredentialsSecret string `json:"credentials_secret,omitempty"`
	Object            string `json:"object,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	SizeBytes         int64  `json:"size,omitempty"`
}

// callBackupRestore is the Agent execution-face restore entry. "probe" only
// reports whether the referenced workspace artifact is already present with
// the recorded checksum; "restore" performs the full local restore pipeline.
func (controller *Controller) callBackupRestore(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request backupRestoreCallRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
	}
	if !validID(request.AppID) || !sha256Hex(strings.TrimSpace(request.SHA256)) || request.SizeBytes <= 0 {
		return nil, backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
	}
	switch strings.TrimSpace(request.Action) {
	case backupRestoreActionProbe:
		return controller.backupRestoreProbe(request)
	case backupRestoreActionRestore:
		return controller.backupRestoreRun(ctx, request)
	default:
		return nil, fmt.Errorf("backup-restore action %q is unknown", strings.TrimSpace(request.Action))
	}
}

// backupRestoreArtifactPath validates the workspace-relative artifact
// reference and resolves it under the app workspace.
func (controller *Controller) backupRestoreArtifactPath(request backupRestoreCallRequest) (root, workdir, artifactPath string, err error) {
	rel, ok := safeBackupEntryName(strings.TrimSpace(request.Path))
	if !ok || path.Base(rel) == rel || path.Dir(rel) != backupArtifactDir || !strings.HasSuffix(rel, backupArtifactSuffix) {
		return "", "", "", backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
	}
	root = controller.callWorkDirRoot(request.WorkDir)
	workdir, workErr := AppWorkDir(root, request.AppID)
	if workErr != nil {
		return "", "", "", backupRestoreFaceFailure(backupRestoreFaceStageWorkspace)
	}
	return root, workdir, filepath.Join(workdir, filepath.FromSlash(rel)), nil
}

func (controller *Controller) backupRestoreProbe(request backupRestoreCallRequest) ([]byte, error) {
	if strings.TrimSpace(request.Source) != BackupDestinationNode {
		return nil, backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
	}
	_, _, artifactPath, err := controller.backupRestoreArtifactPath(request)
	if err != nil {
		return nil, err
	}
	present := false
	if digest, size, hashErr := hashFileContents(artifactPath); hashErr == nil {
		present = size == request.SizeBytes && digest == strings.ToLower(strings.TrimSpace(request.SHA256))
	}
	return json.Marshal(map[string]any{"present": present})
}

func (controller *Controller) backupRestoreRun(ctx context.Context, request backupRestoreCallRequest) ([]byte, error) {
	root, workdir, artifactPath, err := controller.backupRestoreArtifactPath(request)
	if err != nil {
		return nil, err
	}
	workdirExisted := false
	if _, statErr := os.Lstat(workdir); statErr == nil {
		workdirExisted = true
	}
	downloaded := strings.TrimSpace(request.Source) == BackupDestinationS3
	if retrieveErr := controller.backupRestoreRetrieve(ctx, request, artifactPath); retrieveErr != nil {
		controller.backupRestoreCleanResidue(root, request.AppID, artifactPath, workdir, workdirExisted, downloaded)
		return nil, retrieveErr
	}
	digest, size, hashErr := hashFileContents(artifactPath)
	if hashErr != nil || size != request.SizeBytes || digest != strings.ToLower(strings.TrimSpace(request.SHA256)) {
		controller.backupRestoreCleanResidue(root, request.AppID, artifactPath, workdir, workdirExisted, downloaded)
		return nil, backupRestoreFaceFailure(backupRestoreFaceStageChecksum)
	}
	compose, rebuildErr := controller.rebuildFromBackupArtifact(ctx, root, request, artifactPath)
	if rebuildErr != nil {
		controller.backupRestoreCleanResidue(root, request.AppID, artifactPath, workdir, workdirExisted, downloaded)
		return nil, rebuildErr
	}
	return json.Marshal(map[string]any{
		"accepted": true, "compose": compose, "sha256": digest, "size": size,
	})
}

// backupRestoreRetrieve lands the artifact in the target workspace: S3
// sources download through the scoped-secret backed client (which verifies
// the checksum itself); node sources must already hold the file.
func (controller *Controller) backupRestoreRetrieve(ctx context.Context, request backupRestoreCallRequest, artifactPath string) error {
	switch strings.TrimSpace(request.Source) {
	case BackupDestinationNode:
		if info, statErr := os.Lstat(artifactPath); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return backupRestoreFaceFailure(backupRestoreFaceStageChecksum)
		}
		return nil
	case BackupDestinationS3:
		inner, err := json.Marshal(backupS3CallRequest{
			Action: backupS3ActionDownload, AgentID: request.AgentID, AppID: request.AppID,
			WorkDir: request.WorkDir, Endpoint: request.Endpoint, Bucket: request.Bucket,
			Prefix: request.Prefix, CredentialsSecret: request.CredentialsSecret,
			Object: request.Object, Path: request.Path, SHA256: strings.TrimSpace(request.SHA256),
		})
		if err != nil {
			return backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
		}
		if _, err := controller.callBackupS3(ctx, inner); err != nil {
			return fmt.Errorf("backup-restore failed: %s: %w", backupRestoreFaceStageRetrieve, err)
		}
		return nil
	default:
		return backupRestoreFaceFailure(backupRestoreFaceStageInvalid)
	}
}

// rebuildFromBackupArtifact verifies the packed artifact, rebuilds the
// workspace and compose document, and restores every named volume from the
// artifact members through the local execution face.
func (controller *Controller) rebuildFromBackupArtifact(ctx context.Context, root string, request backupRestoreCallRequest, artifactPath string) (string, error) {
	reader, err := OpenBackupArtifact(artifactPath)
	if err != nil {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageCorrupt)
	}
	if reader.Manifest().AppID != request.AppID {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageCorrupt, "artifact app id does not match the record")
	}
	compose, err := reader.ReadCompose()
	if err != nil {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageCorrupt)
	}
	workspace, err := PrepareAppWorkspace(root, request.AppID, compose)
	if err != nil {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageWorkspace)
	}
	// Workspace members (including workspace-relative bind contents) are
	// restored over the rebuilt workspace; the dedicated bind volume members
	// stay unused here.
	if err := reader.ExtractWorkspace(workspace.Dir); err != nil {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageWorkspace)
	}
	plans, err := planBackupVolumes(compose)
	if err != nil {
		return "", backupRestoreFaceFailure(backupRestoreFaceStageWorkspace)
	}
	for _, plan := range plans {
		if classifyBindSource(volumeSource(plan.Spec)) != bindNamed {
			continue
		}
		if err := stageBackupVolumeMember(reader, root, request.AppID, plan); err != nil {
			return "", err
		}
		if _, err := controller.runVolumeOp(ctx, volumeActionRestore, volumeCallRequest{
			Action: volumeActionRestore, AgentID: request.AgentID, AppID: request.AppID,
			WorkDir: root, Volume: plan.Spec,
		}); err != nil {
			return "", fmt.Errorf("backup-restore failed: %s (%s): %w", backupRestoreFaceStageVolume, plan.Spec, err)
		}
	}
	return compose, nil
}

// backupRestoreCleanResidue removes restore residue of a failed agent-face
// run: staged volume archives always, a retrieved artifact copy (never a
// node-destination origin artifact), and a rebuilt workspace that did not
// exist before this restore.
func (controller *Controller) backupRestoreCleanResidue(root, appID, artifactPath, workdir string, workdirExisted, downloaded bool) {
	_ = os.RemoveAll(filepath.Dir(volumeStagedArchivePath(root, appID, "restore")))
	if !downloaded {
		return
	}
	if !workdirExisted {
		_ = os.RemoveAll(workdir)
		return
	}
	_ = os.Remove(artifactPath)
}

// RestoreBackup restores one stored backup record onto targetAgentID.
// Gating: the runtime must be bound, the record must exist, the target must
// be a managed Agent (some stored app is bound to it), and overwriting a
// managed app with the same id requires confirm == appID (the app-delete
// confirm precedent). The restore itself runs on the target Agent execution
// face; same-node node-destination restores read the workspace artifact
// directly. Any stage failure leaves the record, the managed app list, and
// (best-effort) the target workspace without restore residue.
// workDirRoot is the managed workspace root used for same-node direct reads;
// an empty value falls back to the execution-face default.
func (runtime *hostCapabilityRuntime) RestoreBackup(ctx context.Context, recordID, targetAgentID, confirm string, settings BackupSettings, workDirRoot string) (App, error) {
	if runtime == nil || runtime.client == nil {
		return App{}, ErrTypedHandlesUnavailable
	}
	recordID = strings.TrimSpace(recordID)
	if !boundedText(recordID, 160) {
		return App{}, backupRestoreFailure(backupRestoreStageRecord)
	}
	if !validAgentID(targetAgentID) {
		return App{}, ErrAgentOffline
	}
	record, found, err := runtime.backups.Get(ctx, recordID)
	if err != nil {
		return App{}, err
	}
	if !found {
		return App{}, ErrBackupRecordUnknown
	}
	apps, _, err := runtime.LoadApps(ctx)
	if err != nil {
		return App{}, err
	}
	generation := ""
	targetManaged := false
	existing := App{}
	overwrite := false
	for index := range apps {
		if apps[index].AgentID == targetAgentID {
			targetManaged = true
			if generation == "" {
				generation = apps[index].Generation
			}
		}
		if apps[index].ID == record.AppID {
			existing, overwrite = cloneApp(apps[index]), true
		}
	}
	if !targetManaged {
		return App{}, backupRestoreFailure(backupRestoreStageAgent)
	}
	// Overwriting a managed app of the same name requires the app id as the
	// confirm token. Checked before any retrieval, dispatch, or write so an
	// unconfirmed restore has zero side effects.
	if overwrite && strings.TrimSpace(confirm) != existing.ID {
		return App{}, ErrDeleteUnconfirmed
	}
	var compose string
	switch record.Destination.Type {
	case BackupDestinationS3:
		if !settings.S3Configured() {
			return App{}, ErrBackupDestinationUnconfigured
		}
		result, err := runtime.dispatchAgentBackupRestore(ctx, record, settings, targetAgentID, existing, true)
		if err != nil {
			return App{}, err
		}
		compose = result.Compose
	case BackupDestinationNode:
		if record.Destination.Location == targetAgentID {
			root := strings.TrimSpace(workDirRoot)
			if root == "" {
				root = defaultExecutionWorkDirRoot()
			}
			compose, err = runtime.restoreLocalNodeArtifact(ctx, record, targetAgentID, existing, root)
			if err != nil {
				return App{}, err
			}
		} else {
			// Cross-node node destination: reuse an artifact already present on
			// the target (the transfer is idempotent but not free), otherwise
			// push it there over the node-transfer channel, then restore on the
			// target Agent face.
			present, err := runtime.probeTargetBackupArtifact(ctx, record, targetAgentID, existing)
			if err != nil {
				return App{}, err
			}
			if !present {
				if _, err := runtime.PushBackupArtifact(ctx, settings, NodeBackupTransfer{
					AppID: record.AppID, SourceAgentID: record.OriginAgentID, TargetAgentID: targetAgentID,
					ArtifactName: record.ID, SizeBytes: record.SizeBytes, SHA256: record.SHA256,
				}); err != nil {
					return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageTransfer, err)
				}
			}
			result, err := runtime.dispatchAgentBackupRestore(ctx, record, settings, targetAgentID, existing, false)
			if err != nil {
				return App{}, err
			}
			compose = result.Compose
		}
	default:
		return App{}, backupRestoreFailure(backupRunStageObjectReference)
	}
	return runtime.adoptRestoredApp(ctx, apps, record, existing, overwrite, targetAgentID, generation, compose)
}

// adoptRestoredApp applies, starts, and records the restored app. It runs
// only after the target Agent face reported a verified restore.
func (runtime *hostCapabilityRuntime) adoptRestoredApp(ctx context.Context, apps []App, record BackupRecord, existing App, overwrite bool, targetAgentID, generation, compose string) (App, error) {
	restored := App{ID: record.AppID, Generation: generation, Compose: compose}
	if overwrite {
		// Preserve the managed app's generation, environment, bound secrets,
		// and update policies; only the compose document is replaced.
		restored = existing
		restored.Compose = compose
	}
	if err := restored.bindCompose(); err != nil {
		return App{}, backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	restored.AgentID = targetAgentID
	if err := runtime.ApplyApp(ctx, restored); err != nil {
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageApply, err)
	}
	if err := runtime.Start(ctx, restored); err != nil {
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageStart, err)
	}
	next, err := UpsertManaged(apps, restored)
	if err != nil {
		return App{}, backupRestoreFailure(backupRestoreStageAdopt, err)
	}
	if err := runtime.StoreApps(ctx, next); err != nil {
		return App{}, backupRestoreFailure(backupRestoreStageAdopt, err)
	}
	return restored, nil
}

// restoreLocalNodeArtifact is the same-node direct path: the artifact already
// lives in the workspace the restore runs against, so the control plane reads
// it in place and drives the existing staged-volume restore operations.
func (runtime *hostCapabilityRuntime) restoreLocalNodeArtifact(ctx context.Context, record BackupRecord, targetAgentID string, existing App, root string) (string, error) {
	workdir, err := AppWorkDir(root, record.AppID)
	if err != nil {
		return "", backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	artifactPath := filepath.Join(workdir, backupArtifactDir, record.ID)
	digest, size, err := hashFileContents(artifactPath)
	if err != nil {
		return "", backupRestoreFailure(backupRestoreStageRetrieve, err)
	}
	if size != record.SizeBytes || digest != record.SHA256 {
		return "", fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageChecksum, ErrBackupArtifactCorrupt)
	}
	reader, err := OpenBackupArtifact(artifactPath)
	if err != nil {
		return "", fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageCorrupt, err)
	}
	if reader.Manifest().AppID != record.AppID {
		return "", backupRestoreFailure(backupRestoreStageCorrupt, "artifact app id does not match the record")
	}
	compose, err := reader.ReadCompose()
	if err != nil {
		return "", fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageCorrupt, err)
	}
	workspace, err := PrepareAppWorkspace(root, record.AppID, compose)
	if err != nil {
		return "", backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	if err := reader.ExtractWorkspace(workspace.Dir); err != nil {
		return "", fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageWorkspace, err)
	}
	plans, err := planBackupVolumes(compose)
	if err != nil {
		return "", backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	restoreApp := App{ID: record.AppID, AgentID: targetAgentID, WorkDir: existing.WorkDir}
	for _, plan := range plans {
		if classifyBindSource(volumeSource(plan.Spec)) != bindNamed {
			continue
		}
		if err := stageBackupVolumeMember(reader, root, record.AppID, plan); err != nil {
			return "", err
		}
		if err := runtime.VolumeRestore(ctx, restoreApp, plan.Spec); err != nil {
			return "", fmt.Errorf("backup restore failed: %s (%s): %w", backupRestoreStageVolume, plan.Spec, err)
		}
	}
	return compose, nil
}

// agentBackupRestoreResult is the verified agent-face restore answer the
// control plane builds the adoption from.
type agentBackupRestoreResult struct {
	Accepted bool   `json:"accepted"`
	Compose  string `json:"compose"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// dispatchAgentBackupRestore runs the restore pipeline on the target Agent
// execution face and checks the reported artifact against the record.
func (runtime *hostCapabilityRuntime) dispatchAgentBackupRestore(ctx context.Context, record BackupRecord, settings BackupSettings, targetAgentID string, existing App, s3Source bool) (agentBackupRestoreResult, error) {
	payload := map[string]any{
		"action": backupRestoreActionRestore, "agent_id": targetAgentID, "app_id": record.AppID,
		"workdir": existing.WorkDir, "path": backupArtifactDir + "/" + record.ID,
		"sha256": record.SHA256, "size": record.SizeBytes,
	}
	if s3Source {
		object := backupObjectName(record.Destination.Location, settings.S3.Prefix)
		if object == "" {
			return agentBackupRestoreResult{}, backupRestoreFailure(backupRunStageObjectReference)
		}
		payload["source"] = BackupDestinationS3
		payload["endpoint"] = settings.S3.Endpoint
		payload["bucket"] = settings.S3.Bucket
		payload["prefix"] = settings.S3.Prefix
		payload["credentials_secret"] = settings.S3.CredentialsSecret
		payload["object"] = object
	} else {
		payload["source"] = BackupDestinationNode
	}
	var result agentBackupRestoreResult
	if err := runtime.pluginCall(ctx, targetAgentID, pluginCallBackupRestoreName, payload, &result); err != nil {
		return agentBackupRestoreResult{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageRetrieve, err)
	}
	if !result.Accepted || !boundedCompose(result.Compose, MaxConfigBytes) ||
		result.SHA256 != record.SHA256 || result.Size != record.SizeBytes {
		return agentBackupRestoreResult{}, backupRestoreFailure(backupRestoreStageChecksum)
	}
	return result, nil
}

// probeTargetBackupArtifact reports whether the target Agent workspace
// already holds the exact recorded artifact, so a cross-node restore can skip
// the transfer (whose operation identity would otherwise replay the original
// push for up to the host idempotency window).
func (runtime *hostCapabilityRuntime) probeTargetBackupArtifact(ctx context.Context, record BackupRecord, targetAgentID string, existing App) (bool, error) {
	payload := map[string]any{
		"action": backupRestoreActionProbe, "agent_id": targetAgentID, "app_id": record.AppID,
		"workdir": existing.WorkDir, "source": BackupDestinationNode,
		"path": backupArtifactDir + "/" + record.ID, "sha256": record.SHA256, "size": record.SizeBytes,
	}
	var result struct {
		Present bool `json:"present"`
	}
	if err := runtime.pluginCall(ctx, targetAgentID, pluginCallBackupRestoreName, payload, &result); err != nil {
		return false, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageRetrieve, err)
	}
	return result.Present, nil
}

// stageBackupVolumeMember streams one artifact volume member onto the SDK
// staging path the volume-restore proxy operation reads, re-verifying the
// member checksum while copying and committing atomically.
func stageBackupVolumeMember(reader *BackupArtifactReader, root, appID string, plan backupVolumePlan) error {
	staged := volumeStagedArchivePath(root, appID, plan.Staged)
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		return backupRestoreFailure(backupRestoreStageVolume, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(staged), ".restore-stage-*")
	if err != nil {
		return backupRestoreFailure(backupRestoreStageVolume, err)
	}
	tempName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	err = reader.withMember(backupVolumeMember(plan.Member), func(content io.Reader) error {
		_, err := io.Copy(temporary, content)
		return err
	})
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		if errors.Is(err, ErrBackupArtifactCorrupt) {
			return fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageCorrupt, err)
		}
		return backupRestoreFailure(backupRestoreStageVolume, err)
	}
	if err := os.Rename(tempName, staged); err != nil {
		return backupRestoreFailure(backupRestoreStageVolume, err)
	}
	committed = true
	return nil
}

// DeleteBackup removes one stored backup record and its destination object.
// Deletion follows the app-delete confirm precedent (confirm == appID). The
// destination object is removed first and the record second: a record-removal
// failure keeps the record as the single authority while both steps stay
// retry-safe (an S3 delete of a missing object and a workspace artifact
// discard of a missing file both succeed), so no half-deleted state survives.
func (runtime *hostCapabilityRuntime) DeleteBackup(ctx context.Context, recordID, confirm string, settings BackupSettings) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	recordID = strings.TrimSpace(recordID)
	if !boundedText(recordID, 160) {
		return backupDeleteFailure(backupRestoreStageRecord)
	}
	record, found, err := runtime.backups.Get(ctx, recordID)
	if err != nil {
		return err
	}
	if !found {
		return ErrBackupRecordUnknown
	}
	if strings.TrimSpace(confirm) != record.AppID {
		return ErrDeleteUnconfirmed
	}
	if err := runtime.removeBackupDestination(ctx, record, settings); err != nil {
		return err
	}
	if err := runtime.backups.Remove(ctx, recordID); err != nil {
		return backupDeleteFailure(backupDeleteStageRecord, err.Error()+"; the destination object is already removed and the delete can be retried")
	}
	return nil
}

// removeBackupDestination deletes the destination object of one record: the
// S3 object through the origin Agent's backup-s3 execution face, or the
// workspace artifact of a node destination through the backup-pack discard
// face.
func (runtime *hostCapabilityRuntime) removeBackupDestination(ctx context.Context, record BackupRecord, settings BackupSettings) error {
	origin := App{ID: record.AppID, AgentID: record.OriginAgentID}
	switch record.Destination.Type {
	case BackupDestinationS3:
		if !settings.S3Configured() {
			return ErrBackupDestinationUnconfigured
		}
		if err := runtime.deleteBackupObject(ctx, origin, settings, record); err != nil {
			return fmt.Errorf("backup delete failed: %s: %w", backupDeleteStageDestination, err)
		}
		return nil
	case BackupDestinationNode:
		payload := map[string]any{
			"action": backupPackActionDiscard, "agent_id": record.OriginAgentID, "app_id": record.AppID,
			"workdir": origin.WorkDir, "path": backupArtifactDir + "/" + record.ID,
		}
		if err := runtime.pluginCall(ctx, record.OriginAgentID, pluginCallBackupPackName, payload, nil); err != nil {
			return fmt.Errorf("backup delete failed: %s: %w", backupDeleteStageDestination, err)
		}
		if location := strings.TrimSpace(record.Destination.Location); location != "" && location != record.OriginAgentID {
			// A pushed node artifact also lives on the target Agent; remove it
			// so no unrecorded copy survives the delete.
			pushed := map[string]any{
				"action": backupPackActionDiscard, "agent_id": location, "app_id": record.AppID,
				"workdir": origin.WorkDir, "path": backupArtifactDir + "/" + record.ID,
			}
			if err := runtime.pluginCall(ctx, location, pluginCallBackupPackName, pushed, nil); err != nil {
				return fmt.Errorf("backup delete failed: %s: %w", backupDeleteStageDestination, err)
			}
		}
		return nil
	default:
		return backupDeleteFailure(backupRunStageObjectReference)
	}
}
