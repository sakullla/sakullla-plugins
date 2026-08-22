package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerCallComposeApplyWritesWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var dirs []string
	var argv [][]string
	runner := CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		dirs = append(dirs, dir)
		argv = append(argv, append([]string{name}, args...))
		return []byte("ok"), nil
	})
	controller := newCallController(t, root, runner, nil)
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./data:/data\n"
	payload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media", "compose": compose,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload)
	if err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(root, "media")
	if _, err := os.Stat(filepath.Join(workdir, ComposeFileName)); err != nil {
		t.Fatalf("compose file: %v", err)
	}
	if info, err := os.Stat(filepath.Join(workdir, "data")); err != nil || !info.IsDir() {
		t.Fatalf("relative bind data dir: %#v err=%v", info, err)
	}
	if len(argv) != 1 || argv[0][0] != "docker" || strings.Join(argv[0][1:], " ") != "compose up -d" {
		t.Fatalf("compose argv=%#v", argv)
	}
	if len(dirs) != 1 || dirs[0] != workdir {
		t.Fatalf("compose dir=%#v want %q", dirs, workdir)
	}
	var decoded map[string]any
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["accepted"] != true || decoded["workdir"] != workdir {
		t.Fatalf("apply result=%#v", decoded)
	}
}

func TestControllerCallUnknownNameFailsClosed(t *testing.T) {
	t.Parallel()
	var called bool
	runner := CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	controller := newCallController(t, t.TempDir(), runner, nil)
	if _, err := controller.Call(context.Background(), "generation-1", "agent.compose", []byte(`{"action":"apply"}`)); err == nil || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unknown name err=%v", err)
	}
	if called {
		t.Fatal("unknown name invoked docker CLI")
	}
}

func TestControllerCallEngineReportMissingDocker(t *testing.T) {
	t.Parallel()
	runner := CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, errors.New("executable file not found")
	})
	controller := newCallController(t, t.TempDir(), runner, nil)
	payload, err := json.Marshal(map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", pluginCallEngineName, payload)
	if err != nil {
		t.Fatal(err)
	}
	report, err := DecodeAgentEngineReport(raw)
	if err != nil || report.AgentID != "agent-1" || !report.Online || report.Installed || report.Version != "" {
		t.Fatalf("missing docker report=%#v err=%v", report, err)
	}
}

func TestControllerCallImageUsesInjectedObserver(t *testing.T) {
	t.Parallel()
	observer := ImageUpdateObserverFunc(func(_ context.Context, app App) (UpdateObservation, error) {
		if app.Image != "nginx:latest" {
			t.Fatalf("observe image=%q", app.Image)
		}
		return UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"}, nil
	})
	controller := newCallController(t, t.TempDir(), CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("image observe must not fall back to docker CLI")
		return nil, nil
	}), observer)
	payload, err := json.Marshal(map[string]any{"action": "observe", "app_id": "media", "image": "nginx:latest"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Call(context.Background(), "generation-1", pluginCallImageName, payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["current_digest"] != "sha256:current" || decoded["latest_digest"] != "sha256:latest" {
		t.Fatalf("image result=%#v", decoded)
	}
}

func TestControllerCallUnknownComposeActionDoesNotWriteWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	controller := newCallController(t, root, CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("unknown compose action invoked docker CLI")
		return nil, nil
	}), nil)
	payload, err := json.Marshal(map[string]any{"action": "explode", "app_id": "media", "compose": "services:\n  web:\n    image: nginx:1.27\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload); err == nil {
		t.Fatal("unknown compose action succeeded")
	}
	if _, err := os.Stat(filepath.Join(root, "media", ComposeFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown action wrote workspace: %v", err)
	}
}

func TestControllerCallComposeInspectReportsLiveInstance(t *testing.T) {
	t.Parallel()
	const appID = "media"
	root := t.TempDir()
	workdir := filepath.Join(root, appID)
	t.Run("successful compose ps populates RuntimeState", func(t *testing.T) {
		var argv [][]string
		runner := CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
			if dir != workdir {
				t.Fatalf("compose dir=%q want %q", dir, workdir)
			}
			argv = append(argv, append([]string{name}, args...))
			return []byte("NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS"), nil
		})
		controller := newCallController(t, root, runner, nil)
		payload, err := json.Marshal(map[string]any{"action": "inspect", "app_id": appID})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(argv) != 1 || argv[0][0] != "docker" || strings.Join(argv[0][1:], " ") != "compose ps" {
			t.Fatalf("compose argv=%#v", argv)
		}
		var state RuntimeState
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		if state.CandidateInstance != appID {
			t.Fatalf("CandidateInstance=%q want %q", state.CandidateInstance, appID)
		}
		if !state.Instances[appID] {
			t.Fatalf("Instances=%#v want %q present", state.Instances, appID)
		}
	})
	t.Run("failed compose ps does not look like gone instances", func(t *testing.T) {
		composeErr := errors.New("compose ps failed")
		runner := CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return nil, composeErr
		})
		controller := newCallController(t, root, runner, nil)
		payload, err := json.Marshal(map[string]any{"action": "inspect", "app_id": appID})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload)
		if err == nil {
			t.Fatal("inspect succeeded when compose ps failed")
		}
		if !errors.Is(err, composeErr) {
			t.Fatalf("inspect err=%v want %v", err, composeErr)
		}
		if len(raw) == 0 {
			return
		}
		var state RuntimeState
		if json.Unmarshal(raw, &state) != nil {
			return
		}
		if state.CandidateInstance == "" && len(state.Instances) == 0 {
			t.Fatalf("failed inspect returned empty RuntimeState payload=%s", raw)
		}
	})
}

func newCallController(t *testing.T, root string, runner CommandRunner, images ImageUpdateObserver) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: runner,
		CallImages:    images,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
