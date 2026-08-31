package dockerapp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPinComposeImagesPinsServiceDigest(t *testing.T) {
	t.Parallel()
	document := "services:\n  web:\n    image: nginx:latest\n"
	got := pinComposeImages(document, "sha256:0123456789abcdef0123456789abcdef")
	refs := composeImageRefs(got)
	if len(refs) != 1 || refs[0] != "nginx:latest@sha256:0123456789abcdef0123456789abcdef" {
		t.Fatalf("pinned refs=%v document=%q", refs, got)
	}
	replaced := pinComposeImages(got, "sha256:fedcba9876543210fedcba9876543210")
	replacedRefs := composeImageRefs(replaced)
	if len(replacedRefs) != 1 || replacedRefs[0] != "nginx:latest@sha256:fedcba9876543210fedcba9876543210" {
		t.Fatalf("re-pin refs=%v document=%q", replacedRefs, replaced)
	}
	fullReference := pinComposeImages(document, "nginx@sha256:abcdef0123456789abcdef0123456789")
	fullReferenceRefs := composeImageRefs(fullReference)
	if len(fullReferenceRefs) != 1 || fullReferenceRefs[0] != "nginx:latest@sha256:abcdef0123456789abcdef0123456789" {
		t.Fatalf("full-reference digest refs=%v document=%q", fullReferenceRefs, fullReference)
	}
}

func TestPrepareAppWorkspaceCreatesFileBindsNotDirectories(t *testing.T) {
	root := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yaml:/CLIProxyAPI/config.yaml\n      - ./data/auth-dir:/root/.cli-proxy-api\n"
	workspace, err := PrepareAppWorkspace(root, "cli-proxy-api", compose)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workspace.Dir, "config.yaml")
	info, err := os.Lstat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatal("relative ./config.yaml bind created a directory")
	}
	dataDir := filepath.Join(workspace.Dir, "data", "auth-dir")
	dirInfo, err := os.Stat(dataDir)
	if err != nil || !dirInfo.IsDir() {
		t.Fatalf("relative data bind = %#v err=%v", dirInfo, err)
	}
}

func TestPrepareAppWorkspaceReplacesEmptyFileBindDirectory(t *testing.T) {
	root := t.TempDir()
	workdir := filepath.Join(root, "cli-proxy-api")
	configPath := filepath.Join(workdir, "config.yaml")
	if err := os.MkdirAll(configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yaml:/CLIProxyAPI/config.yaml\n"
	if _, err := PrepareAppWorkspace(root, "cli-proxy-api", compose); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatal("empty config.yaml directory was not replaced with a file")
	}
}

func TestParseComposeUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  any
		uid  int
		gid  int
		ok   bool
	}{
		{name: "quoted uid gid", raw: "1000:1000", uid: 1000, gid: 1000, ok: true},
		{name: "uid only string", raw: "1000", uid: 1000, gid: -1, ok: true},
		{name: "int uid", raw: 1000, uid: 1000, gid: -1, ok: true},
		{name: "int64 uid", raw: int64(1000), uid: 1000, gid: -1, ok: true},
		{name: "uint64 uid", raw: uint64(1000), uid: 1000, gid: -1, ok: true},
		{name: "root", raw: "0:0", uid: 0, gid: 0, ok: true},
		{name: "named user", raw: "ubuntu"},
		{name: "empty", raw: ""},
		{name: "nil", raw: nil},
		{name: "extra field", raw: "1000:1000:1000"},
		{name: "blank group", raw: "1000:"},
		{name: "negative", raw: "-1"},
		{name: "name group", raw: "1000:ubuntu"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			uid, gid, ok := parseComposeUser(test.raw)
			if ok != test.ok || uid != test.uid || gid != test.gid {
				t.Fatalf("parseComposeUser(%v) = %d,%d,%v want %d,%d,%v", test.raw, uid, gid, ok, test.uid, test.gid, test.ok)
			}
		})
	}
}

type recordedChown struct {
	path string
	uid  int
	gid  int
}

func stubLchown(t *testing.T) *[]recordedChown {
	t.Helper()
	original := lchownPath
	got := &[]recordedChown{}
	lchownPath = func(name string, uid, gid int) error {
		*got = append(*got, recordedChown{path: name, uid: uid, gid: gid})
		return nil
	}
	t.Cleanup(func() { lchownPath = original })
	return got
}

func TestPrepareAppWorkspaceChownsRelativeBindFromComposeUser(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: \"1000:1000\"\n    volumes:\n      - ./config:/config\n      - /mnt/data/komga:/data\n"
	workspace, err := PrepareAppWorkspace(root, "komga", compose)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workspace.Dir, "config")
	info, err := os.Stat(configPath)
	if err != nil || !info.IsDir() {
		t.Fatalf("config dir = %#v err=%v", info, err)
	}
	if len(*got) != 1 || (*got)[0].path != configPath || (*got)[0].uid != 1000 || (*got)[0].gid != 1000 {
		t.Fatalf("chown = %#v want %q 1000:1000", *got, configPath)
	}
	assertWorldWritableDir(t, configPath)
}

func TestPrepareAppWorkspaceChownsLongFormRelativeBind(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: \"1000:1000\"\n    volumes:\n      - type: bind\n        source: ./config\n        target: /config\n"
	workspace, err := PrepareAppWorkspace(root, "komga", compose)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workspace.Dir, "config")
	if len(*got) != 1 || (*got)[0].path != configPath || (*got)[0].uid != 1000 || (*got)[0].gid != 1000 {
		t.Fatalf("long-form chown = %#v want %q 1000:1000", *got, configPath)
	}
}

func TestPrepareAppWorkspaceRechownsExistingRelativeTree(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	logs := filepath.Join(root, "komga", "config", "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: \"1000:1000\"\n    volumes:\n      - ./config:/config\n"
	if _, err := PrepareAppWorkspace(root, "komga", compose); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(root, "komga", "config"):         false,
		filepath.Join(root, "komga", "config", "logs"): false,
	}
	for _, call := range *got {
		if _, ok := want[call.path]; !ok || call.uid != 1000 || call.gid != 1000 {
			t.Fatalf("unexpected chown %#v from %#v", call, *got)
		}
		want[call.path] = true
	}
	for path, seen := range want {
		if !seen {
			t.Fatalf("missing chown %q in %#v", path, *got)
		}
	}
}

func TestPrepareAppWorkspaceSkipsNamedComposeUser(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: ubuntu\n    volumes:\n      - ./config:/config\n"
	if _, err := PrepareAppWorkspace(root, "komga", compose); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 {
		t.Fatalf("named user triggered chown %#v", *got)
	}
}

func TestPrepareAppWorkspaceSkipsChownWithoutUser(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./data:/data\n"
	if _, err := PrepareAppWorkspace(root, "media", compose); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 {
		t.Fatalf("missing user triggered chown %#v", *got)
	}
}

func TestPrepareAppWorkspaceChownsOnlyMatchingServiceBinds(t *testing.T) {
	got := stubLchown(t)
	root := t.TempDir()
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: \"1000:1000\"\n    volumes:\n      - ./config:/config\n  sidecar:\n    image: busybox:1.36\n    volumes:\n      - ./sidecar:/data\n"
	workspace, err := PrepareAppWorkspace(root, "komga", compose)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(workspace.Dir, "config")
	sidecarPath := filepath.Join(workspace.Dir, "sidecar")
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0].path != configPath {
		t.Fatalf("chown = %#v want only %q", *got, configPath)
	}
}

func TestPrepareAppWorkspaceChownErrorStillMakesRelativeBindWritable(t *testing.T) {
	original := lchownPath
	lchownPath = func(string, int, int) error {
		return errors.New("invalid user")
	}
	t.Cleanup(func() { lchownPath = original })
	root := t.TempDir()
	compose := "services:\n  komga:\n    image: gotson/komga\n    user: \"1000:1000\"\n    volumes:\n      - ./config:/config\n"
	workspace, err := PrepareAppWorkspace(root, "komga", compose)
	if err != nil {
		t.Fatal(err)
	}
	assertWorldWritableDir(t, filepath.Join(workspace.Dir, "config"))
}

func assertWorldWritableDir(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir %q = %#v err=%v", path, info, err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("dir %q mode = %o want 0777", path, info.Mode().Perm())
	}
}
