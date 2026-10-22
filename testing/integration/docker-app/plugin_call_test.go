package dockerapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestExecutionFaceCallComposeApplyWritesWorkspace(t *testing.T) {
	root := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27\n    environment:\n      APP_MODE: production\n    volumes:\n      - ./data:/data\n"
	environment := "DATABASE_PASSWORD=fixture-value\n"
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
			if name != "docker" || len(args) != 3 || args[0] != "compose" || args[1] != "up" || args[2] != "-d" {
				t.Fatalf("command=%s %v", name, args)
			}
			if value, readErr := os.ReadFile(filepath.Join(dir, dockerapp.ComposeFileName)); readErr != nil || string(value) != compose {
				t.Fatalf("executed compose=%q err=%v", value, readErr)
			}
			if value, readErr := os.ReadFile(filepath.Join(dir, ".env")); readErr != nil || string(value) != environment {
				t.Fatalf("executed env=%q err=%v", value, readErr)
			}
			return []byte("ok"), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media",
		"compose": compose, "env": environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", "compose", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "media", dockerapp.ComposeFileName)); err != nil {
		t.Fatalf("execution-face compose file: %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "media", ".env")); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("execution-face env mode=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Join(root, "media", "data")); err != nil || !info.IsDir() {
		t.Fatalf("execution-face relative bind: %#v err=%v", info, err)
	}
}

func TestMissingExecutionFaceOrOfflineAgentDeployFails(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: "services:\n  web:\n    image: nginx:1.27\n"}
	if _, err := dockerapp.DeployComposeAppForAgent(context.Background(), nil, spec, dockerapp.AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"}, nil, auditor); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("missing execution face err=%v", err)
	}
	if _, err := dockerapp.DeployComposeAppForAgent(context.Background(), nil, spec, dockerapp.AgentEngineReport{AgentID: "agent-1", Online: false, Installed: true, Version: "27.1.1"}, dockerapp.AppApplyExecutorFunc(func(context.Context, dockerapp.App) error {
		t.Fatal("offline agent still applied")
		return nil
	}), auditor); !errors.Is(err, dockerapp.ErrAgentOffline) {
		t.Fatalf("offline deploy err=%v", err)
	}
}

func TestExecutionFaceEngineReportMissingDockerIsNotInstalled(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return nil, exec.ErrNotFound
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", "engine.report", payload)
	if err != nil {
		t.Fatal(err)
	}
	report, err := dockerapp.DecodeAgentEngineReport(raw)
	if err != nil || !report.Online || report.Installed || report.Version != "" {
		t.Fatalf("missing docker report=%#v err=%v", report, err)
	}
}

func TestExecutionFaceEngineReportTransientProbeIsUnavailable(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", "engine.report", payload)
	if !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("transient probe err=%v raw=%s", err, raw)
	}
}

func TestExecutionFaceCallVolumeArchiveNamedVolumeRunsProxyOperation(t *testing.T) {
	root := t.TempDir()
	var proxyArgv []string
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
			proxyArgv = args
			if name != "docker" || dir != filepath.Join(root, "media") {
				t.Fatalf("command=%s dir=%s args=%v", name, dir, args)
			}
			if len(args) != 3 || args[0] != "volume" || args[1] != "archive" || args[2] != "appdata" {
				t.Fatalf("proxy argv=%v want volume archive appdata", args)
			}
			staged := filepath.Join(root, "media", filepath.FromSlash(pluginsdk.DockerVolumeStagingDir), "appdata.tar")
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, []byte("tar-fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			return []byte("ok"), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"action": "archive", "agent_id": "agent-1", "app_id": "media", "volume": "appdata:/var/lib/app",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", "volume", payload)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted    bool   `json:"accepted"`
		ArchivePath string `json:"archive_path"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.ArchivePath != path.Join("media", pluginsdk.DockerVolumeStagingDir, "appdata.tar") {
		t.Fatalf("archive result=%s", raw)
	}
	if strings.Join(proxyArgv, " ") != "volume archive appdata" {
		t.Fatalf("proxy argv=%v", proxyArgv)
	}
}

func TestExecutionFaceCallVolumeHostBindNeverReachesProxy(t *testing.T) {
	root := t.TempDir()
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			t.Fatal("host bind reached the command surface")
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"archive", "restore"} {
		payload, err := json.Marshal(map[string]any{
			"action": action, "agent_id": "agent-1", "app_id": "media", "volume": "/srv/appdata:/data",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Call(context.Background(), "generation-1", "volume", payload); err == nil ||
			!strings.Contains(err.Error(), "host bind is not operable") {
			t.Fatalf("action %s host bind err=%v", action, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "media")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host bind call touched the app workspace: %v", err)
	}
}

func TestExecutionFaceCallVolumeRelativeBindArchiveAndRestore(t *testing.T) {
	root := t.TempDir()
	bindDir := filepath.Join(root, "media", "data")
	if err := os.MkdirAll(filepath.Join(bindDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindDir, "sub", "db.txt"), []byte("fixture-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			t.Fatal("relative bind archive must not run docker commands")
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	archivePayload, err := json.Marshal(map[string]any{
		"action": "archive", "agent_id": "agent-1", "app_id": "media", "volume": "./data:/data",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", "volume", archivePayload)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted    bool   `json:"accepted"`
		ArchivePath string `json:"archive_path"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.ArchivePath != path.Join("media", pluginsdk.DockerVolumeStagingDir, "data.tar") {
		t.Fatalf("archive result=%s", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "media", filepath.FromSlash(pluginsdk.DockerVolumeStagingDir), "data.tar")); err != nil {
		t.Fatalf("staged archive: %v", err)
	}

	if err := os.RemoveAll(bindDir); err != nil {
		t.Fatal(err)
	}
	restorePayload, err := json.Marshal(map[string]any{
		"action": "restore", "agent_id": "agent-1", "app_id": "media", "volume": "./data:/data",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", "volume", restorePayload); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(filepath.Join(bindDir, "sub", "db.txt")); err != nil || string(value) != "fixture-data" {
		t.Fatalf("restored file=%q err=%v", value, err)
	}
}
