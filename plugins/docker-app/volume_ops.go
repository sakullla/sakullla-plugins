package dockerapp

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// Agent execution-face volume archive/restore. Two bind classes are operable:
// named volumes run through the host docker command proxy as the controlled
// volume-archive/volume-restore operations (the SDK arg builders are the only
// request shape), and workspace-relative binds never leave the app workspace,
// so they are archived in place into the same staging directory. Host binds
// are rejected before any request is built and never reach the proxy.

const (
	volumeActionArchive = "archive"
	volumeActionRestore = "restore"
)

const (
	volumeStageHostBind       = "host bind is not operable"
	volumeStageVolumeInvalid  = "volume name is invalid"
	volumeStageBindInvalid    = "relative bind is not operable"
	volumeStageVolumeMissing  = "volume was not found"
	volumeStageArchiveMissing = "archive is missing"
	volumeStageBindMissing    = "bind directory is missing"
	volumeStageRejected       = "proxy rejected the operation"
	volumeStageFailed         = "execution failed"
	volumeStageUnavailable    = "workspace is not available"
)

var (
	errVolumeBindMissing    = errors.New(volumeStageBindMissing)
	errVolumeArchiveMissing = errors.New(volumeStageArchiveMissing)
)

type volumeCallRequest struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	AppID   string `json:"app_id"`
	WorkDir string `json:"workdir"`
	Volume  string `json:"volume"`
}

// callVolume is the Agent execution-face entry for volume archive/restore.
func (controller *Controller) callVolume(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request volumeCallRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, errors.New("volume payload is invalid")
	}
	if !validID(request.AppID) {
		return nil, errors.New("volume app id is invalid")
	}
	action := strings.TrimSpace(request.Action)
	switch action {
	case volumeActionArchive, volumeActionRestore:
		return controller.runVolumeOp(ctx, action, request)
	default:
		return nil, fmt.Errorf("volume action %q is unknown", action)
	}
}

func (controller *Controller) runVolumeOp(ctx context.Context, action string, request volumeCallRequest) ([]byte, error) {
	spec := strings.TrimSpace(request.Volume)
	host, named, _ := classifyVolume(spec)
	if host != "" {
		// Host binds never enter the operation face: no proxy request is built.
		return nil, volumeCallFailure(action, volumeStageHostBind)
	}
	root := controller.callWorkDirRoot(request.WorkDir)
	if named != "" {
		return controller.runNamedVolumeOp(ctx, action, request, root, named)
	}
	return controller.runRelativeBindOp(action, request, root, volumeSource(spec))
}

// runNamedVolumeOp executes one host-mediated volume operation through the
// docker command proxy. The sandboxed proxy CLI derives the calling app
// identity from the working directory, so the app workspace must exist before
// the request runs; the host stages archives under the SDK staging convention.
func (controller *Controller) runNamedVolumeOp(ctx context.Context, action string, request volumeCallRequest, root, name string) ([]byte, error) {
	if !validBackupVolumeName(name) {
		return nil, volumeCallFailure(action, volumeStageVolumeInvalid)
	}
	workdir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, volumeCallFailure(action, volumeStageUnavailable)
	}
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		return nil, volumeCallFailure(action, volumeStageUnavailable)
	}
	staged := volumeStagedArchivePath(root, request.AppID, name)
	if action == volumeActionRestore {
		if info, statErr := os.Lstat(staged); statErr != nil || !info.Mode().IsRegular() {
			return nil, volumeCallFailure(action, volumeStageArchiveMissing)
		}
	}
	args := pluginsdk.DockerVolumeArchiveArgs(name)
	if action == volumeActionRestore {
		args = pluginsdk.DockerVolumeRestoreArgs(name)
	}
	output, err := controller.runCommand(ctx, workdir, "docker", args...)
	if err != nil {
		return nil, volumeProxyFailure(action, output, err, name)
	}
	if action == volumeActionArchive {
		if info, statErr := os.Lstat(staged); statErr != nil || !info.Mode().IsRegular() {
			return nil, volumeCallFailure(action, volumeStageArchiveMissing)
		}
	}
	return marshalVolumeOpResult(request.AppID, name), nil
}

// runRelativeBindOp archives or restores one workspace-relative bind inside
// the app workspace. The staged tar follows the same staging convention as
// host-mediated named volume archives.
func (controller *Controller) runRelativeBindOp(action string, request volumeCallRequest, root, source string) ([]byte, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, volumeCallFailure(action, volumeStageVolumeInvalid)
	}
	if classifyBindSource(source) != bindRelative {
		return nil, volumeCallFailure(action, volumeStageBindInvalid)
	}
	workdir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, volumeCallFailure(action, volumeStageUnavailable)
	}
	bindDir, err := resolveRelativePath(workdir, source)
	if err != nil {
		return nil, volumeCallFailure(action, volumeStageBindInvalid)
	}
	stagedName, ok := stagedVolumeMemberName(source)
	if !ok {
		return nil, volumeCallFailure(action, volumeStageBindInvalid)
	}
	staged := volumeStagedArchivePath(root, request.AppID, stagedName)
	if action == volumeActionArchive {
		if err := archiveDirToVolumeTar(bindDir, staged); err != nil {
			return nil, volumeRelativeFailure(action, err)
		}
	} else if err := restoreDirFromVolumeTar(staged, bindDir); err != nil {
		return nil, volumeRelativeFailure(action, err)
	}
	return marshalVolumeOpResult(request.AppID, stagedName), nil
}

func marshalVolumeOpResult(appID, stagedName string) []byte {
	// Both fields are validated plugin-controlled values; marshaling cannot
	// fail for this shape.
	encoded, _ := json.Marshal(map[string]any{
		"accepted":     true,
		"archive_path": volumeArchiveDisplayPath(appID, stagedName),
	})
	return encoded
}

// volumeStagedArchivePath is the workspace-local path of one staged volume
// archive, following the SDK staging convention.
func volumeStagedArchivePath(root, appID, stagedName string) string {
	return filepath.Join(root, appID, filepath.FromSlash(pluginsdk.DockerVolumeStagingDir), stagedName+".tar")
}

// volumeArchiveDisplayPath is the staged archive path relative to the
// workspace root, matching the proxy wire ArchivePath convention.
func volumeArchiveDisplayPath(appID, stagedName string) string {
	return path.Join(appID, pluginsdk.DockerVolumeStagingDir, stagedName+".tar")
}

// stagedVolumeMemberName flattens a workspace-relative bind source into a
// staging member name; sources that would not form a valid archive name are
// rejected.
func stagedVolumeMemberName(source string) (string, bool) {
	normalized := strings.ReplaceAll(strings.TrimSpace(source), "\\", "/")
	normalized = strings.TrimPrefix(normalized, "./")
	if normalized == "" || strings.HasPrefix(normalized, "/") {
		return "", false
	}
	flattened := strings.ReplaceAll(normalized, "/", "_")
	if !validBackupVolumeName(flattened) {
		return "", false
	}
	return flattened, true
}

// volumeProxyFailure maps a refused or failed proxy run to its operation
// stage. Proxy output may echo host-side paths, so only the stage is public.
func volumeProxyFailure(action string, output []byte, err error, name string) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(normalizeCommandOutput(output)) + " " + strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "was not found"):
		return volumeCallFailure(action, volumeStageVolumeMissing+" ("+name+")")
	case strings.Contains(lower, "is missing"):
		return volumeCallFailure(action, volumeStageArchiveMissing)
	case strings.Contains(lower, "not allowed"), strings.Contains(lower, "is invalid"),
		strings.Contains(lower, "credential"), strings.Contains(lower, "rejected"),
		strings.Contains(lower, "unavailable"), strings.Contains(lower, "request"):
		return volumeCallFailure(action, volumeStageRejected)
	default:
		return volumeCallFailure(action, volumeStageFailed)
	}
}

func volumeRelativeFailure(action string, err error) error {
	switch {
	case errors.Is(err, errVolumeBindMissing):
		return volumeCallFailure(action, volumeStageBindMissing)
	case errors.Is(err, errVolumeArchiveMissing):
		return volumeCallFailure(action, volumeStageArchiveMissing)
	default:
		return volumeCallFailure(action, volumeStageFailed)
	}
}

func volumeCallFailure(action, stage string) error {
	return fmt.Errorf("volume %s failed: %s", action, stage)
}

// archiveDirToVolumeTar writes one uncompressed tar of dir into target,
// staging it atomically so a failed run leaves no partial archive behind.
func archiveDirToVolumeTar(dir, target string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errVolumeBindMissing
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errVolumeBindMissing
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".volume-archive-*")
	if err != nil {
		return err
	}
	tempName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempName)
		}
	}()
	tarWriter := tar.NewWriter(temporary)
	if err := writeVolumeTar(tarWriter, dir); err != nil {
		_ = tarWriter.Close()
		_ = temporary.Close()
		return err
	}
	if err := tarWriter.Close(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, target); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeVolumeTar(tarWriter *tar.Writer, root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("volume bind contains a symlink")
		}
		slash := filepath.ToSlash(rel)
		if entry.IsDir() {
			return tarWriter.WriteHeader(&tar.Header{
				Name: slash + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: info.ModTime(),
			})
		}
		if !info.Mode().IsRegular() {
			return errors.New("volume bind contains an irregular file")
		}
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: slash, Typeflag: tar.TypeReg, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime(),
		}); err != nil {
			return err
		}
		file, err := os.Open(current)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

// restoreDirFromVolumeTar extracts a staged volume tar back into dir,
// rejecting entries that would escape the bind directory.
func restoreDirFromVolumeTar(staged, dir string) error {
	file, err := os.Open(staged)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errVolumeArchiveMissing
		}
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errVolumeArchiveMissing
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tarReader := tar.NewReader(file)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("volume archive is invalid: %w", err)
		}
		rel, ok := safeBackupEntryName(strings.TrimSuffix(header.Name, "/"))
		if !ok {
			return fmt.Errorf("volume archive entry %q escapes the bind directory", header.Name)
		}
		if rel == "" || rel == "." {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			if err := writeTarFile(tarReader, target, mode); err != nil {
				return err
			}
		default:
			return fmt.Errorf("volume archive entry %q has an unsupported type", header.Name)
		}
	}
}
