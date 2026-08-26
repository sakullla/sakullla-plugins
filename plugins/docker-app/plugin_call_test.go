package dockerapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultExecutionWorkDirRootIsDurableOutsideTempDir(t *testing.T) {
	t.Setenv("NRE_DOCKER_APP_WORKDIR", "")
	root := defaultExecutionWorkDirRoot()
	if root == "" {
		t.Fatal("durable workdir root is empty")
	}
	temp := filepath.Clean(os.TempDir())
	cleaned := filepath.Clean(root)
	if cleaned == filepath.Join(temp, "nre-docker-app") || strings.HasPrefix(cleaned, temp+string(os.PathSeparator)) {
		t.Fatalf("workdir %q still uses TempDir %q", root, temp)
	}
}

func TestDefaultExecutionWorkDirRootUsesTempForSandboxHome(t *testing.T) {
	temporary := t.TempDir()
	want := filepath.Join(temporary, "nre-docker-app")
	got, ok := sandboxExecutionWorkDirRoot("linux", "/nonexistent", temporary)
	if !ok || got != want {
		t.Fatalf("sandbox workdir root = %q, want writable temp staging root %q", got, want)
	}
	if _, ok := sandboxExecutionWorkDirRoot("windows", "/nonexistent", temporary); ok {
		t.Fatal("Windows unexpectedly treated the Linux sandbox HOME sentinel as active")
	}
}

func TestControllerCallComposeApplySanitizesDockerError(t *testing.T) {
	t.Parallel()
	runner := CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte("failed to pull: password=fixture-value\nunix:///var/run/docker.sock"), errors.New("exit status 1")
	})
	controller := newCallController(t, t.TempDir(), runner, nil)
	payload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media", "compose": "services:\n  web:\n    image: nginx:1.27\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload)
	if err == nil {
		t.Fatal("expected compose apply failure")
	}
	message := err.Error()
	if !strings.Contains(message, "compose apply failed") {
		t.Fatalf("missing compose stage: %q", message)
	}
	if strings.Contains(message, "fixture-value") || strings.Contains(message, "docker.sock") {
		t.Fatalf("compose failure leaked secret or socket: %q", message)
	}
}

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
	environment := "DATABASE_PASSWORD=fixture-value\n"
	payload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media", "compose": compose, "env": environment,
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
	envPath := filepath.Join(workdir, ".env")
	if value, err := os.ReadFile(envPath); err != nil || string(value) != environment {
		t.Fatalf("compose env=%q err=%v", value, err)
	}
	if info, err := os.Stat(envPath); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("compose env mode=%v err=%v", info, err)
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
	if strings.Contains(string(result), "fixture-value") {
		t.Fatal("compose environment leaked into call response")
	}
}

func TestControllerCallComposeActionRehydratesGenerationWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./data:/data\n"
	runner := CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		if name != "docker" || strings.Join(args, " ") != "compose restart" {
			t.Fatalf("command=%s %q", name, args)
		}
		payload, err := os.ReadFile(filepath.Join(dir, ComposeFileName))
		if err != nil {
			t.Fatalf("rehydrated compose err=%v", err)
		}
		if string(payload) != compose {
			t.Fatalf("rehydrated compose rewritten relative ./ binds: %s", payload)
		}
		dataDir := filepath.Join(root, "media", "data")
		if !appliedComposeResolvesBind(t, dir, string(payload), "/data", dataDir) {
			t.Fatalf("rehydrated compose did not resolve ./data to %q: %s", dataDir, payload)
		}
		if _, err := os.Stat(filepath.Join(dir, ".env")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("blank update must not materialize an environment file: %v", err)
		}
		return []byte("ok"), nil
	})
	controller := newCallController(t, root, runner, nil)
	payload, err := json.Marshal(map[string]any{"action": "restart", "app_id": "media", "compose": compose})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-2", pluginCallComposeName, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "media", "data")); err != nil {
		t.Fatalf("relative data directory was not restored: %v", err)
	}
}

func TestControllerCallComposeRemoveCleansWorkspaceAfterDown(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27\n"
	var commands []string
	runner := CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		if dir != filepath.Join(root, "media") || name != "docker" {
			t.Fatalf("command dir=%q name=%q", dir, name)
		}
		command := strings.Join(args, " ")
		commands = append(commands, command)
		return []byte("ok"), nil
	})
	controller := newCallController(t, root, runner, nil)
	payload, err := json.Marshal(map[string]any{"action": "remove", "app_id": "media", "compose": compose})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload); err != nil {
		t.Fatal(err)
	}
	want := []string{"compose down", "workspace remove"}
	if strings.Join(commands, "|") != strings.Join(want, "|") {
		t.Fatalf("remove commands=%q want=%q", commands, want)
	}
}

func TestControllerCallComposeRemoveDoesNotCleanWorkspaceAfterDownFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var commands []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if command == "compose down" {
			return nil, errors.New("down failed")
		}
		return nil, nil
	})
	controller := newCallController(t, root, runner, nil)
	payload, err := json.Marshal(map[string]any{
		"action": "remove", "app_id": "media", "compose": "services:\n  web:\n    image: nginx:1.27\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload); err == nil {
		t.Fatal("remove succeeded after compose down failure")
	}
	if len(commands) != 1 || commands[0] != "compose down" {
		t.Fatalf("commands after down failure=%q", commands)
	}
}

func TestControllerCallComposeRemoveReportsWorkspaceCleanupFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var commands []string
	runner := CommandRunnerFunc(func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if command == "workspace remove" {
			return []byte("cleanup password=fixture-value"), errors.New("cleanup failed")
		}
		return nil, nil
	})
	controller := newCallController(t, root, runner, nil)
	payload, err := json.Marshal(map[string]any{
		"action": "remove", "app_id": "media", "compose": "services:\n  web:\n    image: nginx:1.27\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload)
	if err == nil || !strings.Contains(err.Error(), "compose remove-workspace failed") || strings.Contains(err.Error(), "fixture-value") {
		t.Fatalf("workspace cleanup error=%v", err)
	}
	if len(commands) != 2 || commands[0] != "compose down" || commands[1] != "workspace remove" {
		t.Fatalf("workspace cleanup commands=%q", commands)
	}
}

func TestControllerCallFiles(t *testing.T) {
	t.Parallel()

	t.Run("list-mkdir-read-write-delete", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, unusedDockerRunner(t), nil)
		if _, err := callFiles(t, controller, map[string]any{"action": "mkdir", "app_id": "media", "path": "data"}); err != nil {
			t.Fatal(err)
		}
		raw, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "data/note.txt", "content": []byte("from-panel"),
		})
		if err != nil {
			t.Fatal(err)
		}
		assertAccepted(t, raw)
		onDisk, err := os.ReadFile(filepath.Join(root, "media", "data", "note.txt"))
		if err != nil || string(onDisk) != "from-panel" {
			t.Fatalf("disk=%q err=%v", onDisk, err)
		}
		listed, err := callFiles(t, controller, map[string]any{"action": "list", "app_id": "media", "path": "data"})
		if err != nil {
			t.Fatal(err)
		}
		assertFileEntries(t, listed, []fileListEntry{{Name: "note.txt", Dir: false}})
		read, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": "./data/note.txt"})
		if err != nil {
			t.Fatal(err)
		}
		assertFileContent(t, read, "from-panel")
		raw, err = callFiles(t, controller, map[string]any{"action": "delete", "app_id": "media", "path": "data/note.txt"})
		if err != nil {
			t.Fatal(err)
		}
		assertAccepted(t, raw)
		if _, err := os.Stat(filepath.Join(root, "media", "data", "note.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deleted file still present: %v", err)
		}
		listed, err = callFiles(t, controller, map[string]any{"action": "list", "app_id": "media", "path": "."})
		if err != nil {
			t.Fatal(err)
		}
		assertFileEntries(t, listed, []fileListEntry{{Name: "data", Dir: true}})
	})

	t.Run("rejects-absolute-parent-and-other-app", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, unusedDockerRunner(t), nil)
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "keep.txt", "content": []byte("media"),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "other", "path": "secret.txt", "content": []byte("other"),
		}); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside.txt")
		if err := os.WriteFile(outside, []byte("keep-outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		otherSecret := filepath.Join(root, "other", "secret.txt")
		for _, path := range []string{"/mnt/data/komga", outside, filepath.ToSlash(outside), "..", "../other/secret.txt"} {
			if _, err := callFiles(t, controller, map[string]any{
				"action": "write", "app_id": "media", "path": path, "content": []byte("escaped"),
			}); err == nil {
				t.Fatalf("write path %q succeeded", path)
			}
			if _, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": path}); err == nil {
				t.Fatalf("read path %q succeeded", path)
			}
			if _, err := callFiles(t, controller, map[string]any{"action": "delete", "app_id": "media", "path": path}); err == nil {
				t.Fatalf("delete path %q succeeded", path)
			}
			if _, err := callFiles(t, controller, map[string]any{"action": "list", "app_id": "media", "path": path}); err == nil {
				t.Fatalf("list path %q succeeded", path)
			}
			if _, err := callFiles(t, controller, map[string]any{"action": "mkdir", "app_id": "media", "path": path}); err == nil {
				t.Fatalf("mkdir path %q succeeded", path)
			}
		}
		if _, err := callFiles(t, controller, map[string]any{"action": "write", "app_id": "media", "path": "", "content": []byte("x")}); err == nil {
			t.Fatal("empty path succeeded")
		}
		if got, err := os.ReadFile(outside); err != nil || string(got) != "keep-outside" {
			t.Fatalf("outside file changed: %q err=%v", got, err)
		}
		if got, err := os.ReadFile(otherSecret); err != nil || string(got) != "other" {
			t.Fatalf("other app file changed: %q err=%v", got, err)
		}
		if got, err := os.ReadFile(filepath.Join(root, "media", "keep.txt")); err != nil || string(got) != "media" {
			t.Fatalf("current app file=%q err=%v", got, err)
		}
	})

	t.Run("rejects-symlink-directory-escape", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, unusedDockerRunner(t), nil)
		workdir := filepath.Join(root, "media")
		if err := os.MkdirAll(workdir, 0o755); err != nil {
			t.Fatal(err)
		}
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "secret.txt")
		if err := os.WriteFile(outsideFile, []byte("keep-outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(workdir, "link")); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		escaped := "link/secret.txt"
		if _, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": escaped}); err == nil {
			t.Fatal("read through symlink directory succeeded")
		}
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": escaped, "content": []byte("escaped"),
		}); err == nil {
			t.Fatal("write through symlink directory succeeded")
		}
		if _, err := callFiles(t, controller, map[string]any{"action": "list", "app_id": "media", "path": "link"}); err == nil {
			t.Fatal("list through symlink directory succeeded")
		}
		if _, err := callFiles(t, controller, map[string]any{"action": "mkdir", "app_id": "media", "path": "link/pwned"}); err == nil {
			t.Fatal("mkdir through symlink directory succeeded")
		}
		if _, err := callFiles(t, controller, map[string]any{"action": "delete", "app_id": "media", "path": escaped}); err == nil {
			t.Fatal("delete through symlink directory succeeded")
		}
		if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "keep-outside" {
			t.Fatalf("outside file changed: %q err=%v", got, err)
		}
		if _, err := os.Stat(filepath.Join(outsideDir, "pwned")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("mkdir through symlink created outside path: %v", err)
		}
	})

	t.Run("rejects-oversize-without-truncation", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, unusedDockerRunner(t), nil)
		huge := strings.Repeat("x", MaxConfigBytes+1)
		target := filepath.Join(root, "media", "huge.txt")
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "huge.txt", "content": []byte(huge),
		}); err == nil {
			t.Fatal("oversize write succeeded")
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("oversize write left a target file: %v", err)
		}
		if leftovers := leftoverTempFiles(t, filepath.Join(root, "media")); len(leftovers) != 0 {
			t.Fatalf("oversize write left temp files: %v", leftovers)
		}
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "huge.txt", "content": []byte("ok"),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "huge.txt", "content": []byte(huge),
		}); err == nil {
			t.Fatal("oversize replace succeeded")
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "ok" {
			t.Fatalf("existing file truncated: %q err=%v", got, err)
		}
		if err := os.WriteFile(target, []byte(huge), 0o644); err != nil {
			t.Fatal(err)
		}
		raw, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": "huge.txt"})
		if err == nil {
			t.Fatal("oversize read succeeded")
		}
		if strings.Contains(string(raw), "xxxxx") {
			t.Fatalf("oversize read returned truncated content: %q", raw)
		}
	})

	t.Run("absolute-volume-compose-apply-unchanged", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		var argv [][]string
		runner := CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
			if dir != filepath.Join(root, "media") {
				t.Fatalf("compose dir=%q", dir)
			}
			argv = append(argv, append([]string{name}, args...))
			return []byte("ok"), nil
		})
		controller := newCallController(t, root, runner, nil)
		compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - /mnt/data/komga:/data\n"
		payload, err := json.Marshal(map[string]any{"action": "apply", "app_id": "media", "compose": compose})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload); err != nil {
			t.Fatal(err)
		}
		if len(argv) != 1 || strings.Join(argv[0], " ") != "docker compose up -d" {
			t.Fatalf("compose argv=%#v", argv)
		}
		onDisk, err := os.ReadFile(filepath.Join(root, "media", ComposeFileName))
		if err != nil || string(onDisk) != compose {
			t.Fatalf("compose YAML rewritten: %q err=%v", onDisk, err)
		}
		if _, err := callFiles(t, controller, map[string]any{"action": "list", "app_id": "media", "path": "/mnt/data/komga"}); err == nil {
			t.Fatal("files listed absolute host mount")
		}
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "/mnt/data/komga/config.yaml", "content": []byte("escaped"),
		}); err == nil {
			t.Fatal("files wrote absolute host mount")
		}
	})

	t.Run("relative-bind-apply-uses-files-workdir", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte("ok"), nil
		}), nil)
		want := []byte("listen: 80\n")
		if _, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "config.yaml", "content": want,
		}); err != nil {
			t.Fatal(err)
		}
		compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yaml:/app/config.yaml\n      - /mnt/data/komga:/data\n"
		payload, err := json.Marshal(map[string]any{"action": "apply", "app_id": "media", "compose": compose})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, payload); err != nil {
			t.Fatal(err)
		}
		workdir := filepath.Join(root, "media")
		configPath := filepath.Join(workdir, "config.yaml")
		onDisk, err := os.ReadFile(filepath.Join(workdir, ComposeFileName))
		if err != nil {
			t.Fatal(err)
		}
		if string(onDisk) != compose {
			t.Fatalf("apply rewrote compose YAML: %q", onDisk)
		}
		if !appliedComposeResolvesBind(t, workdir, string(onDisk), "/app/config.yaml", configPath) {
			t.Fatalf("apply did not resolve ./config.yaml to %q: %s", configPath, onDisk)
		}
		got, err := os.ReadFile(configPath)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("AppWorkDir file=%q err=%v", got, err)
		}
		read, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": "config.yaml"})
		if err != nil {
			t.Fatal(err)
		}
		assertFileContent(t, read, string(want))
	})

	t.Run("write-read-nul-base64", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		controller := newCallController(t, root, unusedDockerRunner(t), nil)
		want := []byte{'a', 0, 'b', 0xff}
		raw, err := callFiles(t, controller, map[string]any{
			"action": "write", "app_id": "media", "path": "blob.bin", "content": want,
		})
		if err != nil {
			t.Fatal(err)
		}
		assertAccepted(t, raw)
		onDisk, err := os.ReadFile(filepath.Join(root, "media", "blob.bin"))
		if err != nil || !bytes.Equal(onDisk, want) {
			t.Fatalf("disk=%q err=%v", onDisk, err)
		}
		read, err := callFiles(t, controller, map[string]any{"action": "read", "app_id": "media", "path": "blob.bin"})
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Content []byte `json:"content"`
		}
		if err := json.Unmarshal(read, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.Content, want) {
			t.Fatalf("content=%q want %q", decoded.Content, want)
		}
		if !strings.Contains(string(read), base64.StdEncoding.EncodeToString(want)) {
			t.Fatalf("read did not use base64 content: %s", read)
		}
	})

	t.Run("unknown-call-name-fails-closed", func(t *testing.T) {
		t.Parallel()
		var called bool
		controller := newCallController(t, t.TempDir(), CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		}), nil)
		if _, err := controller.Call(context.Background(), "generation-1", "agent.compose", []byte(`{"action":"apply"}`)); err == nil || !errors.Is(err, ErrTypedHandlesUnavailable) {
			t.Fatalf("unknown name err=%v", err)
		}
		if _, err := controller.Call(context.Background(), "generation-1", "file", []byte(`{"action":"list","app_id":"media"}`)); err == nil || !errors.Is(err, ErrTypedHandlesUnavailable) {
			t.Fatalf("unknown files alias err=%v", err)
		}
		if called {
			t.Fatal("unknown name invoked docker CLI")
		}
	})
}

func TestControllerCallFilesHonorsWorkDir(t *testing.T) {
	t.Parallel()
	defaultRoot := t.TempDir()
	overrideRoot := t.TempDir()
	var composeDir string
	controller := newCallController(t, defaultRoot, CommandRunnerFunc(func(_ context.Context, dir, _ string, _ ...string) ([]byte, error) {
		composeDir = dir
		return []byte("ok"), nil
	}), nil)
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yml:/app/config.yml\n      - /mnt/data/komga:/data\n"
	applyPayload, err := json.Marshal(map[string]any{
		"action": "apply", "app_id": "media", "compose": compose, "workdir": overrideRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, applyPayload); err != nil {
		t.Fatal(err)
	}
	workdir, err := AppWorkDir(overrideRoot, "media")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(composeDir) != filepath.Clean(workdir) {
		t.Fatalf("compose project dir = %q want AppWorkDir %q", composeDir, workdir)
	}
	if _, err := os.Stat(filepath.Join(defaultRoot, "media", ComposeFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compose apply used default workdir root: %v", err)
	}

	if _, err := callFiles(t, controller, map[string]any{
		"action": "write", "app_id": "media", "path": "other.txt", "content": []byte("default"),
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(defaultRoot, "media", "other.txt")); err != nil || string(got) != "default" {
		t.Fatalf("files without workdir should use execution root: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(workdir, "other.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("files without workdir wrote into payload workdir")
	}

	want := []byte("listen: 80\n")
	if _, err := callFiles(t, controller, map[string]any{
		"action": "write", "app_id": "media", "path": "config.yml", "content": want, "workdir": overrideRoot,
	}); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workdir, "config.yml")
	got, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("payload workdir file=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(defaultRoot, "media", "config.yml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("files workdir override leaked into default workdir")
	}

	onDisk, err := os.ReadFile(filepath.Join(workdir, ComposeFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != compose {
		t.Fatalf("apply rewrote compose YAML: %q", onDisk)
	}
	if !strings.Contains(string(onDisk), "/mnt/data/komga") {
		t.Fatal("absolute host volume was stripped from compose YAML")
	}
	if !appliedComposeResolvesBind(t, workdir, string(onDisk), "/app/config.yml", configPath) {
		t.Fatalf("apply did not resolve ./config.yml to %q: %s", configPath, onDisk)
	}
	if _, err := callFiles(t, controller, map[string]any{
		"action": "list", "app_id": "media", "path": "/mnt/data/komga", "workdir": overrideRoot,
	}); err == nil {
		t.Fatal("files listed absolute host mount")
	}
	if _, err := os.Stat(filepath.Join(workdir, "mnt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("absolute host mount was materialized inside the app workdir")
	}

	read, err := callFiles(t, controller, map[string]any{
		"action": "read", "app_id": "media", "path": "config.yml", "workdir": overrideRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, read, string(want))
}

func unusedDockerRunner(t *testing.T) CommandRunner {
	t.Helper()
	return CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("files must not invoke docker CLI")
		return nil, nil
	})
}

func callFiles(t *testing.T, controller *Controller, payload map[string]any) ([]byte, error) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", pluginCallFilesName, raw)
}

func assertAccepted(t *testing.T, raw []byte) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["accepted"] != true {
		t.Fatalf("result=%#v", decoded)
	}
}

func assertFileContent(t *testing.T, raw []byte, want string) {
	t.Helper()
	var decoded struct {
		Content []byte `json:"content"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Content) != want {
		t.Fatalf("content=%q want %q", decoded.Content, want)
	}
}

func appliedComposeResolvesBind(t *testing.T, workdir, document, containerPath, wantHost string) bool {
	t.Helper()
	binds, err := ResolveComposeBinds(workdir, document)
	if err != nil {
		t.Fatalf("resolve applied compose: %v", err)
	}
	want := filepath.Clean(wantHost)
	for _, bind := range binds {
		if bind.ContainerPath != containerPath {
			continue
		}
		if !bind.Relative || filepath.Clean(bind.Source) == want {
			return false
		}
		return filepath.Clean(bind.HostPath) == want
	}
	return false
}

func assertFileEntries(t *testing.T, raw []byte, want []fileListEntry) {
	t.Helper()
	var decoded struct {
		Entries []fileListEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) != len(want) {
		t.Fatalf("entries=%#v want %#v", decoded.Entries, want)
	}
	for i := range want {
		if decoded.Entries[i] != want[i] {
			t.Fatalf("entries=%#v want %#v", decoded.Entries, want)
		}
	}
}

func leftoverTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	items, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	var leftovers []string
	for _, item := range items {
		name := item.Name()
		if strings.HasPrefix(name, ".nre-files-") || strings.HasPrefix(name, ".file-") {
			leftovers = append(leftovers, name)
		}
	}
	return leftovers
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

func TestControllerCallEngineReportRejectsDaemonErrorText(t *testing.T) {
	t.Parallel()
	runner := CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte("Cannot connect to the Docker daemon at unix:///var/run/docker.sock"), nil
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
	if err != nil || report.Installed || report.Version != "" {
		t.Fatalf("daemon error text still marked installed: %#v err=%v", report, err)
	}
}

func TestControllerCallEngineReportInstalledWithoutComposePlugin(t *testing.T) {
	t.Parallel()
	var argv [][]string
	runner := CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		argv = append(argv, append([]string{name}, args...))
		joined := strings.Join(append([]string{name}, args...), " ")
		if strings.Contains(joined, "compose version") {
			t.Fatal("engine report must not require docker compose version")
		}
		return []byte("29.7.2\n"), nil
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
	if err != nil || !report.Online || !report.Installed || report.Version != "29.7.2" {
		t.Fatalf("ready engine report=%#v err=%v", report, err)
	}
	if len(argv) != 1 || strings.Join(argv[0], " ") != "docker version --format {{.Server.Version}}" {
		t.Fatalf("engine probe argv=%#v", argv)
	}
}

func TestParseDockerServerVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{name: "clean", output: "29.7.2\n", want: "29.7.2"},
		{name: "with-warning", output: "27.1.1\nWARNING: daemon is deprecated\n", want: "27.1.1"},
		{name: "v-prefix", output: "v27.1.1\n", want: "27.1.1"},
		{name: "build-meta", output: "20.10.24+azure\n", want: "20.10.24+azure"},
		{name: "daemon-error", output: "Cannot connect to the Docker daemon", wantErr: true},
		{name: "no-value", output: "<no value>", wantErr: true},
		{name: "empty", output: "  \n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDockerServerVersion([]byte(tc.output))
			if tc.wantErr {
				if err == nil || got != "" {
					t.Fatalf("got=%q err=%v", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got=%q err=%v want=%q", got, err, tc.want)
			}
		})
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

func TestControllerCallImageObserveComparesRepoDigestWithRegistryManifest(t *testing.T) {
	t.Parallel()
	index := "sha256:" + strings.Repeat("a", 64)
	platform := "sha256:" + strings.Repeat("b", 64)
	moved := "sha256:" + strings.Repeat("c", 64)
	current := "nginx@" + index
	verbosePlatforms := `[{"Descriptor":{"digest":"` + platform + `","platform":{"architecture":"amd64","os":"linux"}}},{"Descriptor":{"digest":"sha256:` + strings.Repeat("d", 64) + `"}}]`

	observe := func(t *testing.T, registryDigest string) (map[string]any, [][]string) {
		t.Helper()
		var argv [][]string
		runner := CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
			argv = append(argv, append([]string{name}, args...))
			switch dockerObserveCommand(name, args) {
			case "image-inspect":
				if !strings.Contains(strings.Join(args, " "), "RepoDigests") {
					t.Fatalf("image inspect must prefer RepoDigests, args=%q", args)
				}
				return []byte(current + "\n"), nil
			case "manifest-inspect":
				return []byte(verbosePlatforms), nil
			case "imagetools":
				return []byte(`{"Manifest":{"Digest":"` + registryDigest + `"}}`), nil
			default:
				t.Fatalf("unexpected command %s %q", name, args)
				return nil, errors.New("unexpected command")
			}
		})
		return callImageObserve(t, runner, "nginx:latest"), argv
	}

	t.Run("multi-arch index matches RepoDigest", func(t *testing.T) {
		t.Parallel()
		decoded, argv := observe(t, index)
		if decoded["current_digest"] != current {
			t.Fatalf("current_digest=%q want %q", decoded["current_digest"], current)
		}
		if decoded["latest_digest"] != current {
			t.Fatalf("latest_digest=%q want same-form current %q, not platform %q", decoded["latest_digest"], current, platform)
		}
		assertNoImageMutation(t, argv)
	})

	t.Run("moved registry digest differs from RepoDigest", func(t *testing.T) {
		t.Parallel()
		decoded, argv := observe(t, moved)
		wantLatest := sameFormDigest(current, moved)
		if decoded["current_digest"] != current {
			t.Fatalf("current_digest=%q want %q", decoded["current_digest"], current)
		}
		if decoded["latest_digest"] != wantLatest {
			t.Fatalf("latest_digest=%q want %q", decoded["latest_digest"], wantLatest)
		}
		if decoded["current_digest"] == decoded["latest_digest"] {
			t.Fatal("moved registry tag still equalized current and latest")
		}
		if decoded["latest_digest"] == sameFormDigest(current, platform) {
			t.Fatal("latest_digest used verbose platform Descriptor.digest")
		}
		assertNoImageMutation(t, argv)
	})
}

func TestControllerCallImageObserveEqualizesWhenRegistryLookupFails(t *testing.T) {
	t.Parallel()
	current := "nginx@sha256:" + strings.Repeat("c", 64)
	var argv [][]string
	runner := CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		argv = append(argv, append([]string{name}, args...))
		switch dockerObserveCommand(name, args) {
		case "image-inspect":
			return []byte(current), nil
		case "manifest-inspect", "imagetools":
			return nil, errors.New("dial unix:///var/run/docker.sock: registry offline")
		default:
			t.Fatalf("unexpected command %s %q", name, args)
			return nil, errors.New("unexpected command")
		}
	})
	decoded := callImageObserve(t, runner, "nginx:latest")
	if decoded["current_digest"] != current || decoded["latest_digest"] != current {
		t.Fatalf("registry failure should equalize digests, got %#v", decoded)
	}
	assertNoImageMutation(t, argv)
	for _, value := range decoded {
		text, _ := value.(string)
		if containsLocalDockerMarker(strings.ToLower(text)) {
			t.Fatalf("observe leaked docker socket marker: %#v", decoded)
		}
	}
}

func TestControllerCallImageObserveFallsBackToImageIDWithoutRepoDigest(t *testing.T) {
	t.Parallel()
	imageID := "sha256:" + strings.Repeat("d", 64)
	latest := "sha256:" + strings.Repeat("e", 64)
	runner := CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		switch dockerObserveCommand(name, args) {
		case "image-inspect":
			return []byte(`{"Id":"` + imageID + `","RepoDigests":[]}`), nil
		case "manifest-inspect", "imagetools":
			return []byte(latest), nil
		default:
			t.Fatalf("unexpected command %s %q", name, args)
			return nil, errors.New("unexpected command")
		}
	})
	decoded := callImageObserve(t, runner, "nginx:latest")
	if decoded["current_digest"] != imageID {
		t.Fatalf("current_digest=%q want image id fallback %q", decoded["current_digest"], imageID)
	}
	if decoded["latest_digest"] != latest || decoded["latest_digest"] == decoded["current_digest"] {
		t.Fatalf("latest_digest=%q want %q", decoded["latest_digest"], latest)
	}
}

func TestControllerCallImageObserveFailsWhenLocalDigestMissing(t *testing.T) {
	t.Parallel()
	runner := CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		if dockerObserveCommand(name, args) == "image-inspect" {
			return nil, errors.New("Error: No such image: nginx:latest")
		}
		t.Fatalf("registry lookup must not run when local inspect fails: %s %q", name, args)
		return nil, errors.New("unexpected command")
	})
	controller := newCallController(t, t.TempDir(), runner, nil)
	payload, err := json.Marshal(map[string]any{"action": "observe", "app_id": "media", "image": "nginx:latest"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallImageName, payload); err == nil {
		t.Fatal("missing local digest succeeded")
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
		if !strings.Contains(err.Error(), "compose inspect failed") || !strings.Contains(err.Error(), composeErr.Error()) {
			t.Fatalf("inspect err=%v want staged compose inspect failure", err)
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

func callImageObserve(t *testing.T, runner CommandRunner, image string) map[string]any {
	t.Helper()
	controller := newCallController(t, t.TempDir(), runner, nil)
	payload, err := json.Marshal(map[string]any{"action": "observe", "app_id": "media", "image": image})
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
	return decoded
}

func dockerObserveCommand(name string, args []string) string {
	if name != "docker" {
		return strings.Join(append([]string{name}, args...), " ")
	}
	joined := strings.Join(args, " ")
	switch {
	case len(args) >= 2 && args[0] == "image" && args[1] == "inspect":
		return "image-inspect"
	case strings.Contains(joined, "manifest inspect") || (len(args) > 0 && args[0] == "manifest"):
		return "manifest-inspect"
	case strings.Contains(joined, "imagetools"):
		return "imagetools"
	default:
		return joined
	}
}

func assertNoImageMutation(t *testing.T, argv [][]string) {
	t.Helper()
	for _, args := range argv {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " pull") || strings.HasSuffix(joined, " pull") || strings.Contains(joined, "compose up") {
			t.Fatalf("observe mutated local image: %q", joined)
		}
	}
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
