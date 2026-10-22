package dockerapp

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func callVolumeAction(t *testing.T, controller *Controller, action, appID, volume string) ([]byte, error) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"action": action, "agent_id": "agent-1", "app_id": appID, "volume": volume,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", pluginCallVolumeName, payload)
}

// namedVolumeProxyRunner stubs the docker proxy CLI: it records the executed
// argv, asserts the working directory is the app workspace, and materializes
// the staged archive for archive runs.
func namedVolumeProxyRunner(t *testing.T, root string, failWith func(argv []string) ([]byte, error)) (CommandRunner, *[][]string) {
	t.Helper()
	var argv [][]string
	return CommandRunnerFunc(func(_ context.Context, dir, name string, args ...string) ([]byte, error) {
		joined := append([]string{name}, args...)
		argv = append(argv, joined)
		if name != "docker" || len(args) != 3 || args[0] != "volume" {
			t.Fatalf("proxy command = %q %v", name, args)
		}
		if want := filepath.Join(root, "media"); dir != want {
			t.Fatalf("proxy working dir = %q want %q", dir, want)
		}
		if failWith != nil {
			return failWith(args)
		}
		if args[1] == "archive" {
			staged := volumeStagedArchivePath(root, "media", args[2])
			if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, []byte("tar-fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return []byte("ok"), nil
	}), &argv
}

func TestControllerCallVolumeArchiveNamedVolumeThroughProxy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	runner, argv := namedVolumeProxyRunner(t, root, nil)
	controller := newCallController(t, root, runner, nil)
	raw, err := callVolumeAction(t, controller, "archive", "media", "appdata:/var/lib/app")
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
	if !result.Accepted {
		t.Fatalf("result=%s", raw)
	}
	want := "media/" + pluginsdk.DockerVolumeStagingDir + "/appdata.tar"
	if result.ArchivePath != want {
		t.Fatalf("archive path = %q want %q", result.ArchivePath, want)
	}
	if len(*argv) != 1 || strings.Join((*argv)[0][1:], " ") != "volume archive appdata" {
		t.Fatalf("proxy argv = %#v", *argv)
	}
	if _, err := os.Stat(volumeStagedArchivePath(root, "media", "appdata")); err != nil {
		t.Fatalf("staged archive not verified: %v", err)
	}
}

func TestControllerCallVolumeRestoreNamedVolumeThroughProxy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	staged := volumeStagedArchivePath(root, "media", "appdata")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("tar-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, argv := namedVolumeProxyRunner(t, root, nil)
	controller := newCallController(t, root, runner, nil)
	if _, err := callVolumeAction(t, controller, "restore", "media", "appdata"); err != nil {
		t.Fatal(err)
	}
	if len(*argv) != 1 || strings.Join((*argv)[0][1:], " ") != "volume restore appdata" {
		t.Fatalf("proxy argv = %#v", *argv)
	}
}

func TestControllerCallVolumeArchiveRelativeBind(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bindDir := filepath.Join(root, "media", "data")
	nested := filepath.Join(bindDir, "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindDir, "db.txt"), []byte("fixture-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "inner.txt"), []byte("nested-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	controller := newCallController(t, root, unusedDockerRunner(t), nil)
	raw, err := callVolumeAction(t, controller, "archive", "media", "./data:/data")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		ArchivePath string `json:"archive_path"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	want := "media/" + pluginsdk.DockerVolumeStagingDir + "/data.tar"
	if result.ArchivePath != want {
		t.Fatalf("archive path = %q want %q", result.ArchivePath, want)
	}
	staged := volumeStagedArchivePath(root, "media", "data")
	entries := readVolumeTarMembers(t, staged)
	if string(entries["db.txt"]) != "fixture-data" || string(entries["sub/inner.txt"]) != "nested-data" {
		t.Fatalf("archive members = %#v", entries)
	}

	// Round-trip: restoring after deleting the bind recreates its content.
	if err := os.RemoveAll(bindDir); err != nil {
		t.Fatal(err)
	}
	if _, err := callVolumeAction(t, controller, "restore", "media", "./data:/data"); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(filepath.Join(bindDir, "sub", "inner.txt")); err != nil || string(value) != "nested-data" {
		t.Fatalf("restored nested file = %q err=%v", value, err)
	}
}

func TestControllerCallVolumeRejectsHostBindWithoutRequest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	controller := newCallController(t, root, CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("host bind reached the command surface")
		return nil, errors.New("unreachable")
	}), nil)
	for _, spec := range []string{"/var/lib/app:/data", "/var/lib/app", "~/appdata:/data", "../escape:/data", `C:\host:/data`} {
		for _, action := range []string{"archive", "restore"} {
			_, err := callVolumeAction(t, controller, action, "media", spec)
			if err == nil || !strings.Contains(err.Error(), "volume "+action+" failed: host bind is not operable") {
				t.Fatalf("spec %q action %q err = %v", spec, action, err)
			}
		}
	}
}

func TestControllerCallVolumeStagedFailures(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	missingVolume := func([]string) ([]byte, error) {
		return []byte(`Docker volume "appdata" was not found`), errors.New("exit status 1")
	}
	rejected := func([]string) ([]byte, error) {
		return []byte("Docker command is not allowed"), errors.New("exit status 1")
	}
	failed := func([]string) ([]byte, error) {
		return []byte("tar: unexpected eof"), errors.New("exit status 1")
	}
	tests := []struct {
		name    string
		action  string
		volume  string
		runner  func([]string) ([]byte, error)
		arrange func(t *testing.T, root string)
		want    string
	}{
		{
			name:   "missing named volume",
			action: "archive", volume: "appdata", runner: missingVolume,
			want: "volume archive failed: volume was not found (appdata)",
		},
		{
			name:   "proxy rejection",
			action: "archive", volume: "appdata", runner: rejected,
			want: "volume archive failed: proxy rejected the operation",
		},
		{
			name:   "execution failure",
			action: "archive", volume: "appdata", runner: failed,
			want: "volume archive failed: execution failed",
		},
		{
			name:   "restore without staged archive",
			action: "restore", volume: "appdata",
			runner: func([]string) ([]byte, error) {
				t.Fatal("restore without staged archive reached the proxy")
				return nil, errors.New("unreachable")
			},
			want: "volume restore failed: archive is missing",
		},
		{
			name:   "relative bind directory missing",
			action: "archive", volume: "./data:/data", runner: nil,
			want: "volume archive failed: bind directory is missing",
		},
		{
			name:   "relative restore without staged archive",
			action: "restore", volume: "./data:/data",
			arrange: func(t *testing.T, root string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(root, "media", "data"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "volume restore failed: archive is missing",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.arrange != nil {
				test.arrange(t, root)
			}
			runner, _ := namedVolumeProxyRunner(t, root, test.runner)
			controller := newCallController(t, root, runner, nil)
			_, err := callVolumeAction(t, controller, test.action, "media", test.volume)
			if err == nil || err.Error() != test.want {
				t.Fatalf("err = %v want %q", err, test.want)
			}
		})
	}
}

func TestControllerCallVolumeRequestValidation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	controller := newCallController(t, root, unusedDockerRunner(t), nil)
	payload, err := json.Marshal(map[string]any{"action": "archive", "agent_id": "agent-1", "volume": "appdata"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallVolumeName, payload); err == nil || err.Error() != "volume app id is invalid" {
		t.Fatalf("app id err = %v", err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallVolumeName, []byte("{not-json")); err == nil || err.Error() != "volume payload is invalid" {
		t.Fatalf("payload err = %v", err)
	}
	if _, err := callVolumeAction(t, controller, "prune", "media", "appdata"); err == nil || err.Error() != `volume action "prune" is unknown` {
		t.Fatalf("action err = %v", err)
	}
	if _, err := callVolumeAction(t, controller, "archive", "media", "   "); err == nil || err.Error() != "volume archive failed: volume name is invalid" {
		t.Fatalf("empty volume err = %v", err)
	}
}

func TestStagedVolumeMemberName(t *testing.T) {
	t.Parallel()
	valid := map[string]string{"./data": "data", "configs/app": "configs_app", "data": "data"}
	for source, want := range valid {
		got, ok := stagedVolumeMemberName(source)
		if !ok || got != want {
			t.Fatalf("stagedVolumeMemberName(%q) = %q, %v want %q", source, got, ok, want)
		}
	}
	for _, source := range []string{"./", "/etc", "my data", "with:colon", ".backup"} {
		if _, ok := stagedVolumeMemberName(source); ok {
			t.Fatalf("stagedVolumeMemberName(%q) unexpectedly valid", source)
		}
	}
}

func TestHostCapabilityRuntimeVolumeOpsDispatch(t *testing.T) {
	t.Parallel()
	var calls []pluginsdk.HostRuntimeCall
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		calls = append(calls, call)
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallVolumeName {
			t.Fatalf("plugin.call name = %q", request.Name)
		}
		payload := decodePluginCallInner(t, request)
		if payload["volume"] == "./broken" {
			return errors.New("volume archive failed: proxy rejected the operation")
		}
		return copyHostResult(map[string]any{
			"accepted": true, "archive_path": "media/" + pluginsdk.DockerVolumeStagingDir + "/data.tar",
		}, target)
	})
	runtime := newHostCapabilityRuntime(client)
	app := App{ID: "media", AgentID: "agent-1", WorkDir: "/apps/media"}

	archivePath, err := runtime.VolumeArchive(context.Background(), app, "./data:/data")
	if err != nil || archivePath != "media/"+pluginsdk.DockerVolumeStagingDir+"/data.tar" {
		t.Fatalf("archive = %q err = %v", archivePath, err)
	}
	if err := runtime.VolumeRestore(context.Background(), app, "appdata"); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.VolumeArchive(context.Background(), app, "./broken"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("broken err = %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("host calls = %d", len(calls))
	}
	archive := decodePluginCallInner(t, decodePluginCallRequest(t, calls[0]))
	if archive["action"] != "archive" || archive["agent_id"] != "agent-1" || archive["app_id"] != "media" ||
		archive["workdir"] != "/apps/media" || archive["volume"] != "./data:/data" {
		t.Fatalf("archive payload = %#v", archive)
	}
	restore := decodePluginCallInner(t, decodePluginCallRequest(t, calls[1]))
	if restore["action"] != "restore" || restore["volume"] != "appdata" {
		t.Fatalf("restore payload = %#v", restore)
	}
}

func TestHostCapabilityRuntimeVolumeOpsGuards(t *testing.T) {
	t.Parallel()
	runtime := newHostCapabilityRuntime(nil)
	app := App{ID: "media", AgentID: "agent-1"}
	if _, err := runtime.VolumeArchive(context.Background(), app, "appdata"); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unavailable err = %v", err)
	}
	online := newHostCapabilityRuntime(hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
		t.Fatal("offline agent still dispatched")
		return nil
	}))
	if _, err := online.VolumeArchive(context.Background(), App{ID: "media", AgentID: ""}, "appdata"); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("offline err = %v", err)
	}
	if err := online.VolumeRestore(context.Background(), app, "  "); err == nil || err.Error() != "volume reference is required" {
		t.Fatalf("empty volume err = %v", err)
	}
}

func readVolumeTarMembers(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	members := map[string][]byte{}
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return members
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		members[strings.TrimPrefix(header.Name, "./")] = content
	}
}
