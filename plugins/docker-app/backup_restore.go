package dockerapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Backup restore and delete orchestration. Restore retrieves the recorded
// artifact onto the target Agent (S3 download through the Agent execution
// face, or the origin Agent workspace backups/ tree for same-node node
// destinations), verifies it against the record and the packed manifest,
// rebuilds the workspace and compose document, restores volumes, adopts the
// app under the target Agent, starts it, and only then records the managed
// state change. Every stage failure returns a stage-named error, leaves the
// record untouched, and removes restore residue best-effort so no half-built
// workspace survives. Delete removes the destination object first and the
// record second: a failed record removal keeps the record as the single
// authority while both removal steps stay retry-safe.

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

	backupDeleteStageDestination = "destination object could not be removed"
	backupDeleteStageRecord      = "backup record could not be removed"
)

// ErrBackupRestoreCrossNode reports a node-destination restore onto an Agent
// other than the origin: cross-node artifact retrieval is provided by the
// node-transfer entry (T7) and is explicitly unavailable until it lands.
var ErrBackupRestoreCrossNode = errors.New("node destination cross-node retrieval is not available")

func backupRestoreFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup restore failed: %s", stage)
	}
	return fmt.Errorf("backup restore failed: %s (%s)", stage, fmt.Sprint(args...))
}

func backupDeleteFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup delete failed: %s", stage)
	}
	return fmt.Errorf("backup delete failed: %s (%s)", stage, fmt.Sprint(args...))
}

// RestoreBackup restores one stored backup record onto targetAgentID.
// Gating: the runtime must be bound, the record must exist, the target must
// be a managed Agent (some stored app is bound to it), and overwriting a
// managed app with the same id requires confirm == appID (the app-delete
// confirm precedent). Any stage failure leaves the record, the managed app
// list, and (best-effort) the target workspace without restore residue.
// workDirRoot is the managed workspace root the artifact is staged under; an
// empty value falls back to the execution-face default.
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
	root := strings.TrimSpace(workDirRoot)
	if root == "" {
		root = defaultExecutionWorkDirRoot()
	}
	workdir, err := AppWorkDir(root, record.AppID)
	if err != nil {
		return App{}, backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	artifactPath := filepath.Join(workdir, backupArtifactDir, record.ID)
	workdirExisted := false
	if _, statErr := os.Lstat(workdir); statErr == nil {
		workdirExisted = true
	}
	downloaded := false
	switch record.Destination.Type {
	case BackupDestinationS3:
		downloaded, err = runtime.downloadBackupArtifact(ctx, record, settings, targetAgentID, existing, artifactPath)
		if err != nil {
			// A dispatched download may have committed a mismatched copy before
			// the result check failed; remove retrieval residue best-effort.
			if !workdirExisted {
				_ = os.RemoveAll(workdir)
			} else {
				_ = os.Remove(artifactPath)
			}
			return App{}, err
		}
	case BackupDestinationNode:
		// Same-node restore reads the origin Agent workspace artifact directly;
		// cross-node retrieval is the node-transfer entry's concern (T7).
		if record.Destination.Location != targetAgentID {
			return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageRetrieve, ErrBackupRestoreCrossNode)
		}
	default:
		return App{}, backupRestoreFailure(backupRunStageObjectReference)
	}
	// cleanup removes restore residue of a failed run, best-effort: staged
	// volume archives always, the downloaded artifact copy (never the origin
	// node artifact), and a workspace that did not exist before this restore.
	cleanup := func() {
		_ = os.RemoveAll(filepath.Dir(volumeStagedArchivePath(root, record.AppID, "restore")))
		if downloaded && !workdirExisted {
			_ = os.RemoveAll(workdir)
		} else if downloaded {
			_ = os.Remove(artifactPath)
		}
	}
	digest, size, err := hashFileContents(artifactPath)
	if err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageRetrieve, err)
	}
	if size != record.SizeBytes || digest != record.SHA256 {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageChecksum, ErrBackupArtifactCorrupt)
	}
	reader, err := OpenBackupArtifact(artifactPath)
	if err != nil {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageCorrupt, err)
	}
	if reader.Manifest().AppID != record.AppID {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageCorrupt, "artifact app id does not match the record")
	}
	compose, err := reader.ReadCompose()
	if err != nil {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageCorrupt, err)
	}
	workspace, err := PrepareAppWorkspace(root, record.AppID, compose)
	if err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	// Workspace members (including workspace-relative bind contents) are
	// restored over the rebuilt workspace; the dedicated bind volume members
	// stay unused here.
	if err := reader.ExtractWorkspace(workspace.Dir); err != nil {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageWorkspace, err)
	}
	plans, err := planBackupVolumes(compose)
	if err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	restoreApp := App{ID: record.AppID, AgentID: targetAgentID, WorkDir: existing.WorkDir}
	for _, plan := range plans {
		if classifyBindSource(volumeSource(plan.Spec)) != bindNamed {
			continue
		}
		if err := stageBackupVolumeMember(reader, root, record.AppID, plan); err != nil {
			cleanup()
			return App{}, err
		}
		if err := runtime.VolumeRestore(ctx, restoreApp, plan.Spec); err != nil {
			cleanup()
			return App{}, fmt.Errorf("backup restore failed: %s (%s): %w", backupRestoreStageVolume, plan.Spec, err)
		}
	}
	restored := App{ID: record.AppID, Generation: generation, Compose: compose}
	if overwrite {
		// Preserve the managed app's generation, environment, bound secrets,
		// and update policies; only the compose document is replaced.
		restored = existing
		restored.Compose = compose
	}
	if err := restored.bindCompose(); err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageWorkspace, err)
	}
	restored.AgentID = targetAgentID
	if err := runtime.ApplyApp(ctx, restored); err != nil {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageApply, err)
	}
	if err := runtime.Start(ctx, restored); err != nil {
		cleanup()
		return App{}, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageStart, err)
	}
	next, err := UpsertManaged(apps, restored)
	if err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageAdopt, err)
	}
	if err := runtime.StoreApps(ctx, next); err != nil {
		cleanup()
		return App{}, backupRestoreFailure(backupRestoreStageAdopt, err)
	}
	return restored, nil
}

// downloadBackupArtifact retrieves one s3-destination artifact onto the
// target Agent workspace backups/ tree through the backup-s3 execution-face
// call and checks the reported size and checksum against the record.
func (runtime *hostCapabilityRuntime) downloadBackupArtifact(ctx context.Context, record BackupRecord, settings BackupSettings, targetAgentID string, existing App, artifactPath string) (bool, error) {
	if !settings.S3Configured() {
		return false, ErrBackupDestinationUnconfigured
	}
	object := backupObjectName(record.Destination.Location, settings.S3.Prefix)
	if object == "" {
		return false, backupRestoreFailure(backupRunStageObjectReference)
	}
	payload := map[string]any{
		"action": backupS3ActionDownload, "agent_id": targetAgentID, "app_id": record.AppID,
		"workdir": existing.WorkDir, "endpoint": settings.S3.Endpoint, "bucket": settings.S3.Bucket,
		"prefix": settings.S3.Prefix, "credentials_secret": settings.S3.CredentialsSecret,
		"object": object, "path": backupArtifactDir + "/" + record.ID, "sha256": record.SHA256,
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if err := runtime.pluginCall(ctx, targetAgentID, pluginCallBackupS3Name, payload, &result); err != nil {
		return false, fmt.Errorf("backup restore failed: %s: %w", backupRestoreStageRetrieve, err)
	}
	if !result.Accepted || !boundedText(result.Path, 512) || result.Size != record.SizeBytes || result.SHA256 != record.SHA256 {
		return false, backupRestoreFailure(backupRestoreStageChecksum)
	}
	return true, nil
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
		return nil
	default:
		return backupDeleteFailure(backupRunStageObjectReference)
	}
}
