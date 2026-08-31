package dockerapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestExecutionFaceCallComposeApplyWritesWorkspace(t *testing.T) {
	root := t.TempDir()
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte("ok"), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media",
		"compose": "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./data:/data\n",
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
