package dockerapp_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

// The restore/delete pipelines drive the Agent execution face through the
// plugin.call wire names exercised here: backup-s3 download (S3 retrieval),
// volume restore, compose apply/start, backup-pack discard (node artifact
// deletion), and backup-s3 delete. Heavy artifact bytes never cross the wire;
// these tests follow the package's controller.Call stub/fake style.

const restoreWireCompose = `services:
  app:
    image: example/app:1
    volumes:
      - appdata:/var/lib/app
      - ./data:/data
`

func restoreWireVolumeTar(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "db.bin", Mode: 0o644, Size: int64(len("volume-db"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("volume-db")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// buildRestoreWireArtifact packs one real artifact with the T2 library and
// returns its file name and bytes.
func buildRestoreWireArtifact(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	source := t.TempDir()
	workdir := filepath.Join(source, "media")
	if err := os.MkdirAll(filepath.Join(workdir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "notes.txt"), []byte("workspace-note"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "data", "db.txt"), []byte("bind-db"), 0o644); err != nil {
		t.Fatal(err)
	}
	volumeTar := restoreWireVolumeTar(t)
	destDir := filepath.Join(workdir, "backups")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := dockerapp.CreateBackupArtifact(destDir, dockerapp.BackupSource{
		AppID: "media", Compose: restoreWireCompose, Workdir: workdir,
		Volumes:   []dockerapp.BackupVolumeSource{{Name: "vol-appdata", Tar: bytes.NewReader(volumeTar)}},
		CreatedAt: time.Date(2026, 10, 22, 8, 9, 10, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(info.Path), content, volumeTar
}

func restoreWirePluginCall(t *testing.T, controller *dockerapp.Controller, name string, payload map[string]any) ([]byte, error) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", name, raw)
}

func TestRestorePipelineDispatchesWireFaceAndRebuildsWorkspace(t *testing.T) {
	root := t.TempDir()
	name, artifact, volumeTar := buildRestoreWireArtifact(t)
	var commands []string
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(_ context.Context, dir, command string, args ...string) ([]byte, error) {
			if command != "docker" {
				t.Fatalf("command = %s", command)
			}
			joined := strings.Join(args, " ")
			commands = append(commands, joined)
			switch {
			case joined == "volume restore appdata":
				staged := filepath.Join(root, "media", filepath.FromSlash(pluginsdk.DockerVolumeStagingDir), "appdata.tar")
				stagedContent, readErr := os.ReadFile(staged)
				if readErr != nil || !bytes.Equal(stagedContent, volumeTar) {
					t.Fatalf("staged volume archive mismatch: err = %v", readErr)
				}
				if dir != filepath.Join(root, "media") {
					t.Fatalf("volume restore dir = %s", dir)
				}
				return []byte("ok"), nil
			case joined == "compose up -d":
				executed, readErr := os.ReadFile(filepath.Join(dir, dockerapp.ComposeFileName))
				if readErr != nil || string(executed) != restoreWireCompose {
					t.Fatalf("executed compose = %q err = %v", executed, readErr)
				}
				return []byte("ok"), nil
			default:
				// The compose apply path also probes the engine; a plain ok
				// keeps those auxiliary probes harmless.
				return []byte("ok"), nil
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The S3 retrieval wire fails closed without a configured destination.
	_, err = restoreWirePluginCall(t, controller, "backup-s3", map[string]any{
		"action": "download", "agent_id": "agent-1", "app_id": "media",
		"object": name, "path": "backups/" + name, "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err == nil || err.Error() != "backup-s3 download failed: destination is not configured" {
		t.Fatalf("download gate err = %v", err)
	}

	// A successful download lands the artifact in the target workspace.
	if err := os.MkdirAll(filepath.Join(root, "media", "backups"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "media", "backups", name), artifact, 0o600); err != nil {
		t.Fatal(err)
	}

	// Verification reads the manifest and the compose document back.
	reader, err := dockerapp.OpenBackupArtifact(filepath.Join(root, "media", "backups", name))
	if err != nil {
		t.Fatal(err)
	}
	if reader.Manifest().AppID != "media" {
		t.Fatalf("manifest app = %q", reader.Manifest().AppID)
	}
	compose, err := reader.ReadCompose()
	if err != nil || compose != restoreWireCompose {
		t.Fatalf("artifact compose = %q err = %v", compose, err)
	}

	// Workspace rebuild plus workspace-member extraction (relative binds are
	// workspace members).
	if _, err := dockerapp.PrepareAppWorkspace(root, "media", compose); err != nil {
		t.Fatal(err)
	}
	if err := reader.ExtractWorkspace(filepath.Join(root, "media")); err != nil {
		t.Fatal(err)
	}

	// The named volume member is staged for the proxy restore operation and
	// restored through the volume wire name.
	staged := filepath.Join(root, "media", filepath.FromSlash(pluginsdk.DockerVolumeStagingDir), "appdata.tar")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, volumeTar, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := restoreWirePluginCall(t, controller, "volume", map[string]any{
		"action": "restore", "agent_id": "agent-1", "app_id": "media", "volume": "appdata:/var/lib/app",
	})
	if err != nil {
		t.Fatal(err)
	}
	var volumeResult struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &volumeResult); err != nil || !volumeResult.Accepted {
		t.Fatalf("volume restore result = %s err = %v", raw, err)
	}

	// Adoption and start run through the compose wire face.
	if _, err := restoreWirePluginCall(t, controller, "compose", map[string]any{
		"action": "apply", "agent_id": "agent-1", "app_id": "media", "compose": compose,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreWirePluginCall(t, controller, "compose", map[string]any{
		"action": "start", "agent_id": "agent-1", "app_id": "media",
	}); err != nil {
		t.Fatal(err)
	}

	// The restored app runs with the backed-up data.
	if notes, readErr := os.ReadFile(filepath.Join(root, "media", "notes.txt")); readErr != nil || string(notes) != "workspace-note" {
		t.Fatalf("restored notes = %q err = %v", notes, readErr)
	}
	if bind, readErr := os.ReadFile(filepath.Join(root, "media", "data", "db.txt")); readErr != nil || string(bind) != "bind-db" {
		t.Fatalf("restored bind data = %q err = %v", bind, readErr)
	}
	joined := strings.Join(commands, " | ")
	if !strings.Contains(joined, "volume restore appdata") {
		t.Fatalf("wire commands = %q", joined)
	}
	if occurrences := strings.Count(joined, "compose up -d"); occurrences != 2 {
		t.Fatalf("compose up dispatched %d times: %q", occurrences, joined)
	}
	// The volume restore must precede the started application.
	if strings.Index(joined, "volume restore appdata") > strings.LastIndex(joined, "compose up -d") {
		t.Fatalf("volume restore ran after start: %q", joined)
	}
}

func TestBackupDeleteDispatchesDiscardWireAndS3DeleteGate(t *testing.T) {
	root := t.TempDir()
	name, artifact, _ := buildRestoreWireArtifact(t)
	artifactDir := filepath.Join(root, "media", "backups")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, name), artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			t.Fatal("backup deletion must not run docker commands")
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Node-destination deletion removes the workspace artifact through the
	// backup-pack discard wire.
	if _, err := restoreWirePluginCall(t, controller, "backup-pack", map[string]any{
		"action": "discard", "agent_id": "agent-1", "app_id": "media", "path": "backups/" + name,
	}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(artifactDir, name)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("artifact still present: %v", statErr)
	}

	// The S3 deletion wire fails closed without a configured destination.
	_, err = restoreWirePluginCall(t, controller, "backup-s3", map[string]any{
		"action": "delete", "agent_id": "agent-1", "app_id": "media", "object": name,
	})
	if err == nil || err.Error() != "backup-s3 delete failed: destination is not configured" {
		t.Fatalf("delete gate err = %v", err)
	}
}
