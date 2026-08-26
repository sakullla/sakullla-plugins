package dockerapp

import (
	"os"
	"path/filepath"
	"testing"
)

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
