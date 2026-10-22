package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

// Backup run orchestration. The control plane (hostCapabilityRuntime) gates on
// a configured destination and a managed app, then drives the Agent execution
// face: one volume-archive plugin call per operable volume (T3 entry), one
// backup-pack call that bundles compose + workspace + staged volume archives
// into a .tar.zst artifact under the workspace backups/ directory (T2), and
// one backup-s3 upload call when the S3 destination is configured (T4). With
// only the node destination enabled the artifact stays in the origin Agent's
// workspace. The backups state record is written last, so any earlier stage
// failure leaves no record, no staging residue, and no partial artifact.
// Running apps are never stopped or started: crash consistency relies on the
// artifact library's file-level snapshot copy.

const (
	// backupPackActionPack bundles one artifact from staged inputs.
	backupPackActionPack = "pack"
	// backupPackActionClean removes the workspace staging tree of a failed run.
	backupPackActionClean = "clean"
	// backupPackActionDiscard removes one partial artifact of a failed run.
	backupPackActionDiscard = "discard"
)

const (
	// backupArtifactDir is the app-workspace directory holding finished
	// artifacts; it matches the host node-transfer backup landing directory.
	backupArtifactDir = "backups"
	// backupStagingDir is the workspace-local staging tree root written by
	// volume archive operations (SDK staging convention).
	backupStagingDir = "backup-staging"
)

// Agent execution-face pack failure stages. Closed strings: local paths and
// OS errors never reach them.
const (
	backupPackStageInvalid        = "pack request is invalid"
	backupPackStageUnavailable    = "workspace is not available"
	backupPackStageArchiveMissing = "staged volume archive is missing"
	backupPackStageArtifactFailed = "artifact could not be created"
)

// Control-plane run failure stages. Closed strings, wrapped with the failing
// sub-call error where one exists.
const (
	backupRunStageAppInvalid         = "app id is invalid"
	backupRunStageVolumeInvalid      = "volume name is invalid"
	backupRunStageUnmanagedBind      = "relative bind is not operable"
	backupRunStageStagingSource      = "bind source is inside the staging tree"
	backupRunStageConflict           = "volume archive names conflict"
	backupRunStageVolumeLimit        = "volume count exceeds limit"
	backupRunStageRecordStore        = "backup record could not be stored"
	backupRunStageObjectMismatch     = "uploaded object does not match the artifact"
	backupRunStageObjectReference    = "backup object reference is invalid"
	backupRunStageDestinationInvalid = "backup destination selection is invalid"
)

const backupRunCleanupTimeout = 15 * time.Second

var (
	// ErrBackupRunAppUnknown rejects backups for apps that are not stored.
	ErrBackupRunAppUnknown = errors.New("app is not managed")
)

// isBackupOwnedWorkspaceTree reports whether one top-level workspace entry is
// a plugin-owned backup tree: finished artifacts under backups/ and staged
// volume archives under backup-staging/. They never become workspace members.
func isBackupOwnedWorkspaceTree(rel string) bool {
	return rel == backupArtifactDir || rel == backupStagingDir
}

func backupRunFailure(stage string, args ...any) error {
	if len(args) == 0 {
		return fmt.Errorf("backup run failed: %s", stage)
	}
	return fmt.Errorf("backup run failed: %s (%s)", stage, fmt.Sprint(args...))
}

func backupPackFailure(stage string) error {
	return fmt.Errorf("backup pack failed: %s", stage)
}

// backupVolumePlan is one operable compose volume: the compose source spec,
// the staged archive member name (flatten form, T3 staging convention), and
// the artifact member base name. Member names are prefixed per volume class
// (vol- for named volumes, bind- for relative binds) so a named volume and a
// relative bind can never collapse onto the same artifact member even when
// their staged names match.
type backupVolumePlan struct {
	Spec   string `json:"spec"`
	Staged string `json:"staged"`
	Member string `json:"member"`
}

// planBackupVolumes extracts the backup-operable volumes from a compose
// document: named volumes and workspace-relative binds. Host binds are host
// state, not app state, and stay outside the backup. Before anything runs,
// staged-name collisions across volume classes ("data" vs "./data",
// "configs/app" vs "configs_app") and binds whose source points into the
// staging tree fail explicitly instead of silently overwriting staged
// archives or archiving plugin-owned staging state.
func planBackupVolumes(document string) ([]backupVolumePlan, error) {
	if strings.TrimSpace(document) == "" {
		return nil, nil
	}
	var file composeBindDocument
	if err := yaml.Unmarshal([]byte(document), &file); err != nil {
		return nil, ErrInvalidCompose
	}
	sources := make([]string, 0, len(file.Services))
	for _, service := range file.Services {
		for _, entry := range service.Volumes {
			source := strings.TrimSpace(entry.Source)
			if source == "" {
				continue
			}
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	stagedOwner := map[string]string{}
	plans := make([]backupVolumePlan, 0, len(sources))
	for index, source := range sources {
		if index > 0 && sources[index-1] == source {
			continue
		}
		switch classifyBindSource(source) {
		case bindHost:
			continue
		case bindNamed:
			if !validBackupVolumeName(source) || len(stagedNameWithSuffix(source)) > backupVolumeNameMax {
				return nil, backupRunFailure(backupRunStageVolumeInvalid, source)
			}
			plans = append(plans, backupVolumePlan{Spec: source, Staged: source, Member: "vol-" + source})
		default:
			flattened, ok := stagedVolumeMemberName(source)
			if !ok {
				return nil, backupRunFailure(backupRunStageUnmanagedBind, source)
			}
			if backupSourceInsideStaging(source) {
				return nil, backupRunFailure(backupRunStageStagingSource, source)
			}
			if len(stagedNameWithSuffix(flattened)) > backupVolumeNameMax {
				return nil, backupRunFailure(backupRunStageVolumeInvalid, source)
			}
			plans = append(plans, backupVolumePlan{Spec: source, Staged: flattened, Member: "bind-" + flattened})
		}
	}
	for _, plan := range plans {
		if owner, exists := stagedOwner[plan.Staged]; exists {
			return nil, backupRunFailure(backupRunStageConflict, owner+" and "+plan.Spec)
		}
		stagedOwner[plan.Staged] = plan.Spec
	}
	if len(plans) > backupVolumeMax {
		return nil, backupRunFailure(backupRunStageVolumeLimit)
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Member < plans[j].Member })
	return plans, nil
}

// backupSourceInsideStaging reports whether a workspace-relative bind source
// resolves inside the plugin-owned staging tree.
func backupSourceInsideStaging(source string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(source), "\\", "/")
	normalized = strings.TrimPrefix(normalized, "./")
	cleaned := path.Clean(normalized)
	return cleaned == backupStagingDir || strings.HasPrefix(cleaned, backupStagingDir+"/")
}

// stagedNameWithSuffix is the staged archive file name (member plus ".tar")
// the execution face writes for one planned volume. The SDK staging name
// budget matches the artifact volume-name budget, so a staged name whose file
// name would exceed it is rejected during planning instead of failing the
// agent-side archive step after work has started.
func stagedNameWithSuffix(staged string) string {
	return staged + ".tar"
}

type backupPackRequest struct {
	Action  string             `json:"action"`
	AgentID string             `json:"agent_id"`
	AppID   string             `json:"app_id"`
	WorkDir string             `json:"workdir"`
	Compose string             `json:"compose"`
	Created string             `json:"created"`
	Path    string             `json:"path"`
	Volumes []backupVolumePlan `json:"volumes"`
}

// callBackupPack is the Agent execution-face entry for backup packing: it
// bundles the staged volume archives, the compose document, and the workspace
// into one artifact under the workspace backups/ directory, or removes run
// residue (staging tree, partial artifact) for failed control-plane runs.
func (controller *Controller) callBackupPack(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request backupPackRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, backupPackFailure(backupPackStageInvalid)
	}
	if !validID(request.AppID) {
		return nil, backupPackFailure(backupPackStageInvalid)
	}
	switch strings.TrimSpace(request.Action) {
	case backupPackActionPack:
		return controller.backupPackArtifact(request)
	case backupPackActionClean:
		return controller.backupPackClean(request)
	case backupPackActionDiscard:
		return controller.backupPackDiscard(request)
	default:
		return nil, fmt.Errorf("backup-pack action %q is unknown", strings.TrimSpace(request.Action))
	}
}

// backupPackArtifact packs one artifact from the staged volume archives and
// the workspace. Staged archives are consumed and removed whether the run
// succeeds or fails, and the artifact library guarantees no partial product.
func (controller *Controller) backupPackArtifact(request backupPackRequest) ([]byte, error) {
	if !boundedCompose(request.Compose, MaxConfigBytes) {
		return nil, backupPackFailure(backupPackStageInvalid)
	}
	created := time.Now().UTC()
	if trimmed := strings.TrimSpace(request.Created); trimmed != "" {
		parsed, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return nil, backupPackFailure(backupPackStageInvalid)
		}
		created = parsed.UTC()
	}
	if len(request.Volumes) > backupVolumeMax {
		return nil, backupPackFailure(backupPackStageInvalid)
	}
	root := controller.callWorkDirRoot(request.WorkDir)
	workdir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	files := make([]*os.File, 0, len(request.Volumes))
	defer func() {
		for _, file := range files {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()
	stagedSeen := make(map[string]struct{}, len(request.Volumes))
	memberSeen := make(map[string]struct{}, len(request.Volumes))
	volumes := make([]BackupVolumeSource, 0, len(request.Volumes))
	for _, volume := range request.Volumes {
		staged := strings.TrimSpace(volume.Staged)
		member := strings.TrimSpace(volume.Member)
		if staged == "" || !validBackupVolumeName(staged) || !validBackupVolumeName(member) {
			return nil, backupPackFailure(backupPackStageInvalid)
		}
		if _, duplicate := stagedSeen[staged]; duplicate {
			return nil, backupPackFailure(backupPackStageInvalid)
		}
		if _, duplicate := memberSeen[member]; duplicate {
			return nil, backupPackFailure(backupPackStageInvalid)
		}
		stagedSeen[staged] = struct{}{}
		memberSeen[member] = struct{}{}
		stagedPath := volumeStagedArchivePath(root, request.AppID, staged)
		file, err := os.Open(stagedPath)
		if err != nil {
			return nil, backupPackFailure(backupPackStageArchiveMissing)
		}
		info, statErr := file.Stat()
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			file.Close()
			return nil, backupPackFailure(backupPackStageArchiveMissing)
		}
		files = append(files, file)
		volumes = append(volumes, BackupVolumeSource{Name: member, Tar: file})
	}
	destDir := filepath.Join(workdir, backupArtifactDir)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	info, err := CreateBackupArtifact(destDir, BackupSource{
		AppID: request.AppID, Compose: request.Compose, Workdir: workdir,
		Volumes: volumes, CreatedAt: created,
	})
	if err != nil {
		return nil, backupPackFailure(backupPackStageArtifactFailed)
	}
	display, err := workspaceDisplayPath(workdir, info.Path)
	if err != nil {
		return nil, backupPackFailure(backupPackStageArtifactFailed)
	}
	return json.Marshal(map[string]any{
		"accepted": true, "path": display, "name": filepath.Base(info.Path),
		"size": info.Size, "sha256": info.SHA256, "created": info.Manifest.CreatedAt,
	})
}

// backupPackClean removes the workspace staging tree of one app.
func (controller *Controller) backupPackClean(request backupPackRequest) ([]byte, error) {
	workdir, err := AppWorkDir(controller.callWorkDirRoot(request.WorkDir), request.AppID)
	if err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	if err := os.RemoveAll(filepath.Join(workdir, backupStagingDir)); err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	return json.Marshal(map[string]any{"accepted": true})
}

// backupPackDiscard removes one artifact of a failed run. Only files inside
// the workspace backups/ tree with the artifact suffix are removable.
func (controller *Controller) backupPackDiscard(request backupPackRequest) ([]byte, error) {
	workdir, err := AppWorkDir(controller.callWorkDirRoot(request.WorkDir), request.AppID)
	if err != nil {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	rel, ok := safeBackupEntryName(strings.TrimSpace(request.Path))
	if !ok || path.Base(rel) == rel || path.Dir(rel) != backupArtifactDir || !strings.HasSuffix(rel, backupArtifactSuffix) {
		return nil, backupPackFailure(backupPackStageInvalid)
	}
	if err := os.Remove(filepath.Join(workdir, filepath.FromSlash(rel))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, backupPackFailure(backupPackStageUnavailable)
	}
	return json.Marshal(map[string]any{"accepted": true})
}

// packedBackupArtifact is the verified pack result the control plane builds
// the record from.
type packedBackupArtifact struct {
	Name    string
	Path    string
	Size    int64
	SHA256  string
	Created string
}

// RunBackup orchestrates one app backup. Gating: a destination must be
// chosen and configured (S3 endpoint+bucket or the node destination enabled)
// and the app must be stored and bound to an online Agent. destination is one
// of BackupDestinationS3, BackupDestinationNode, or "" (the first configured
// one, S3 first). A node destination with a non-empty targetAgentID pushes
// the finished artifact to that managed Agent over the node-transfer channel;
// without one the artifact stays in the origin Agent workspace. The app
// lifecycle is never touched; every stage failure returns a stage-named error
// and leaves no record, no staging residue, and no partial artifact. If the
// record cannot be stored after a successful destination write, the
// destination object is removed best-effort so no unrecorded object remains.
// Runs of one app are serialized: a second concurrent run fails fast instead
// of interleaving staging trees of the same workspace.
func (runtime *hostCapabilityRuntime) RunBackup(ctx context.Context, appID string, settings BackupSettings, destination, targetAgentID string) (BackupRecord, error) {
	if runtime == nil || runtime.client == nil {
		return BackupRecord{}, ErrTypedHandlesUnavailable
	}
	appID = strings.TrimSpace(appID)
	if !validID(appID) {
		return BackupRecord{}, backupRunFailure(backupRunStageAppInvalid)
	}
	switch destination {
	case "", BackupDestinationS3, BackupDestinationNode:
	default:
		return BackupRecord{}, backupRunFailure(backupRunStageDestinationInvalid)
	}
	useS3 := destination == BackupDestinationS3 || destination == "" && settings.S3Configured()
	if useS3 && !settings.S3Configured() {
		return BackupRecord{}, ErrBackupDestinationUnconfigured
	}
	if destination == BackupDestinationNode && !settings.Node.Enabled {
		return BackupRecord{}, fmt.Errorf("backup run failed: %w", ErrBackupNodeDisabled)
	}
	if destination == "" && !useS3 && !settings.Node.Enabled {
		return BackupRecord{}, ErrBackupDestinationUnconfigured
	}
	targetAgentID = strings.TrimSpace(targetAgentID)
	if targetAgentID != "" && (useS3 || !validAgentID(targetAgentID)) {
		return BackupRecord{}, backupRunFailure(backupRunStageDestinationInvalid)
	}
	unlock, busy := runtime.lockBackupRun(appID)
	defer unlock()
	if busy {
		return BackupRecord{}, ErrBackupRunBusy
	}
	apps, _, err := runtime.LoadApps(ctx)
	if err != nil {
		return BackupRecord{}, err
	}
	app := App{}
	managed := false
	for index := range apps {
		if apps[index].ID == appID {
			app, managed = apps[index], true
			break
		}
	}
	if !managed {
		return BackupRecord{}, ErrBackupRunAppUnknown
	}
	if !validAgentID(app.AgentID) {
		return BackupRecord{}, ErrAgentOffline
	}
	if targetAgentID != "" {
		managedAgents, err := runtime.ManagedBackupAgents(ctx)
		if err != nil {
			return BackupRecord{}, err
		}
		if !managedAgentContains(managedAgents, targetAgentID) {
			return BackupRecord{}, backupNodeFailure(nodeStageTargetUnmanaged)
		}
	}
	plans, err := planBackupVolumes(app.Compose)
	if err != nil {
		return BackupRecord{}, err
	}
	created := time.Now().UTC()
	for _, plan := range plans {
		archivePath, err := runtime.VolumeArchive(ctx, app, plan.Spec)
		if err != nil {
			runtime.cleanBackupStaging(ctx, app)
			return BackupRecord{}, fmt.Errorf("backup run failed at volume archive (%s): %w", plan.Spec, err)
		}
		if want := path.Join(app.ID, pluginsdk.DockerVolumeStagingDir, plan.Staged+".tar"); archivePath != want {
			runtime.cleanBackupStaging(ctx, app)
			return BackupRecord{}, fmt.Errorf("backup run failed at volume archive (%s): %w", plan.Spec, ErrTypedHandlesUnavailable)
		}
	}
	packed, err := runtime.packBackup(ctx, app, plans, created)
	if err != nil {
		runtime.cleanBackupStaging(ctx, app)
		return BackupRecord{}, fmt.Errorf("backup run failed at pack: %w", err)
	}
	record := BackupRecord{
		ID: packed.Name, AppID: app.ID, OriginAgentID: app.AgentID,
		Created: packed.Created, SizeBytes: packed.Size, SHA256: packed.SHA256,
	}
	if useS3 {
		object, err := runtime.uploadBackupArtifact(ctx, app, settings, packed)
		if err != nil {
			runtime.cleanBackupStaging(ctx, app)
			runtime.discardBackupArtifact(ctx, app, packed.Path)
			return BackupRecord{}, fmt.Errorf("backup run failed at upload: %w", err)
		}
		record.Destination = BackupDestinationRef{Type: BackupDestinationS3, Location: object}
	} else if targetAgentID != "" {
		// Node destination with an explicit target: the finished artifact is
		// pushed to the target Agent's plugin-managed backups/ tree; the record
		// location names that target so cross-node restore can find it.
		result, err := runtime.PushPackedBackupArtifact(ctx, settings, app, targetAgentID, packed)
		if err != nil {
			runtime.cleanBackupStaging(ctx, app)
			runtime.discardBackupArtifact(ctx, app, packed.Path)
			return BackupRecord{}, fmt.Errorf("backup run failed at node transfer: %w", err)
		}
		record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: result.TargetAgentID}
	} else {
		// Node destination: the artifact stays in the origin Agent workspace.
		record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: app.AgentID}
	}
	if err := runtime.appendBackupRecord(ctx, record); err != nil {
		return BackupRecord{}, runtime.compensateFailedRecord(ctx, app, settings, record, err)
	}
	return record, nil
}

// backupRunLocks serializes backup runs per app: two concurrent runs of one
// app would interleave their staging trees inside the same workspace.
var backupRunLocks sync.Map // app ID -> *sync.Mutex

// lockBackupRun fails fast when another backup of the same app is already
// running; busy then reports that fast failure and unlock is a no-op.
func (runtime *hostCapabilityRuntime) lockBackupRun(appID string) (unlock func(), busy bool) {
	value, _ := backupRunLocks.LoadOrStore(appID, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	if !mutex.TryLock() {
		return func() {}, true
	}
	return mutex.Unlock, false
}

// ErrBackupRunBusy reports a backup rejected because another backup of the
// same app is already running.
var ErrBackupRunBusy = errors.New("backup run failed: another backup of this app is already running")

// compensateFailedRecord removes the destination object of a run whose record
// could not be stored and reports both the store failure and the cleanup
// outcome, mirroring the s3 path for node artifacts: a discard failure is part
// of the returned error so no silent unrecorded artifact remains.
func (runtime *hostCapabilityRuntime) compensateFailedRecord(ctx context.Context, app App, settings BackupSettings, record BackupRecord, cause error) error {
	if record.Destination.Type == BackupDestinationS3 {
		if err := runtime.deleteBackupObject(ctx, app, settings, record); err != nil {
			return fmt.Errorf("backup run failed: %s: %v (destination object could not be removed: %v)", backupRunStageRecordStore, cause, err)
		}
		return fmt.Errorf("backup run failed: %s: %w", backupRunStageRecordStore, cause)
	}
	if location := strings.TrimSpace(record.Destination.Location); location != "" && location != app.AgentID {
		if err := runtime.discardBackupArtifactChecked(ctx, App{ID: app.ID, AgentID: location, WorkDir: app.WorkDir}, path.Join(backupArtifactDir, record.ID)); err != nil {
			return fmt.Errorf("backup run failed: %s: %v (target workspace artifact could not be removed: %v)", backupRunStageRecordStore, cause, err)
		}
	}
	if err := runtime.discardBackupArtifactChecked(ctx, app, path.Join(backupArtifactDir, record.ID)); err != nil {
		return fmt.Errorf("backup run failed: %s: %v (workspace artifact could not be removed: %v)", backupRunStageRecordStore, cause, err)
	}
	return fmt.Errorf("backup run failed: %s: %w", backupRunStageRecordStore, cause)
}

func (runtime *hostCapabilityRuntime) packBackup(ctx context.Context, app App, plans []backupVolumePlan, created time.Time) (packedBackupArtifact, error) {
	volumes := make([]backupVolumePlan, len(plans))
	copy(volumes, plans)
	payload := map[string]any{
		"action": backupPackActionPack, "agent_id": app.AgentID, "app_id": app.ID,
		"workdir": app.WorkDir, "compose": app.Compose, "created": created.Format(time.RFC3339),
		"volumes": volumes,
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Path     string `json:"path"`
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
		Created  string `json:"created"`
	}
	if err := runtime.pluginCall(ctx, app.AgentID, pluginCallBackupPackName, payload, &result); err != nil {
		return packedBackupArtifact{}, err
	}
	if !result.Accepted || !boundedText(result.Name, 160) || !boundedText(result.Path, 512) ||
		result.Size <= 0 || !sha256Hex(result.SHA256) || !boundedText(result.Created, 64) {
		return packedBackupArtifact{}, ErrTypedHandlesUnavailable
	}
	return packedBackupArtifact{
		Name: result.Name, Path: result.Path, Size: result.Size,
		SHA256: result.SHA256, Created: result.Created,
	}, nil
}

func (runtime *hostCapabilityRuntime) uploadBackupArtifact(ctx context.Context, app App, settings BackupSettings, packed packedBackupArtifact) (string, error) {
	s3 := settings.S3
	payload := map[string]any{
		"action": backupS3ActionUpload, "agent_id": app.AgentID, "app_id": app.ID,
		"workdir": app.WorkDir, "endpoint": s3.Endpoint, "bucket": s3.Bucket,
		"prefix": s3.Prefix, "credentials_secret": s3.CredentialsSecret,
		"object": packed.Name, "path": packed.Path,
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Object   string `json:"object"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if err := runtime.pluginCall(ctx, app.AgentID, pluginCallBackupS3Name, payload, &result); err != nil {
		return "", err
	}
	if !result.Accepted || !boundedText(result.Object, 512) {
		return "", ErrTypedHandlesUnavailable
	}
	if result.Size != packed.Size || result.SHA256 != packed.SHA256 {
		return "", backupRunFailure(backupRunStageObjectMismatch)
	}
	return result.Object, nil
}

func (runtime *hostCapabilityRuntime) deleteBackupObject(ctx context.Context, app App, settings BackupSettings, record BackupRecord) error {
	object := backupObjectName(record.Destination.Location, settings.S3.Prefix)
	if object == "" {
		return backupRunFailure(backupRunStageObjectReference)
	}
	payload := map[string]any{
		"action": backupS3ActionDelete, "agent_id": app.AgentID, "app_id": app.ID,
		"workdir": app.WorkDir, "endpoint": settings.S3.Endpoint, "bucket": settings.S3.Bucket,
		"prefix": settings.S3.Prefix, "credentials_secret": settings.S3.CredentialsSecret,
		"object": object,
	}
	var result struct {
		Accepted bool `json:"accepted"`
	}
	if err := runtime.pluginCall(ctx, app.AgentID, pluginCallBackupS3Name, payload, &result); err != nil {
		return err
	}
	if !result.Accepted {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

// backupObjectName strips the configured prefix from a stored object key so
// the delete call can rejoin it.
func backupObjectName(location, prefix string) string {
	location = strings.TrimSpace(location)
	prefix = strings.TrimSpace(prefix)
	if prefix != "" && strings.HasPrefix(location, prefix+"/") {
		return strings.TrimPrefix(location, prefix+"/")
	}
	return location
}

func (runtime *hostCapabilityRuntime) appendBackupRecord(ctx context.Context, record BackupRecord) error {
	return runtime.backups.Append(ctx, record)
}

// cleanBackupStaging asks the Agent face to remove the staging tree of a
// failed run. Best-effort: cleanup failures never mask the run failure.
func (runtime *hostCapabilityRuntime) cleanBackupStaging(ctx context.Context, app App) {
	if runtime == nil || runtime.client == nil || !validAgentID(app.AgentID) {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backupRunCleanupTimeout)
	defer cancel()
	_ = runtime.pluginCall(cleanupCtx, app.AgentID, pluginCallBackupPackName, map[string]any{
		"action": backupPackActionClean, "agent_id": app.AgentID, "app_id": app.ID, "workdir": app.WorkDir,
	}, nil)
}

// discardBackupArtifact asks the Agent face to remove one partial artifact of
// a failed run. Best-effort.
func (runtime *hostCapabilityRuntime) discardBackupArtifact(ctx context.Context, app App, artifactPath string) {
	_ = runtime.discardBackupArtifactChecked(ctx, app, artifactPath)
}

// discardBackupArtifactChecked is discardBackupArtifact with the dispatch
// outcome, so record-store compensation can surface a failed cleanup.
func (runtime *hostCapabilityRuntime) discardBackupArtifactChecked(ctx context.Context, app App, artifactPath string) error {
	if runtime == nil || runtime.client == nil || !validAgentID(app.AgentID) || strings.TrimSpace(artifactPath) == "" {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), backupRunCleanupTimeout)
	defer cancel()
	return runtime.pluginCall(cleanupCtx, app.AgentID, pluginCallBackupPackName, map[string]any{
		"action": backupPackActionDiscard, "agent_id": app.AgentID, "app_id": app.ID,
		"workdir": app.WorkDir, "path": artifactPath,
	}, nil)
}

// ListBackups returns every stored backup record, newest first.
func (runtime *hostCapabilityRuntime) ListBackups(ctx context.Context) ([]BackupRecord, error) {
	if runtime == nil || runtime.client == nil || runtime.backups == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	return runtime.backups.List(ctx)
}
