package buildkit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuildRustWorkspaceAllowsGoPluginDirectories(t *testing.T) {
	t.Parallel()
	cargo := findCargo(t)
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate workspace test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	manifest, err := os.ReadFile(filepath.Join(repositoryRoot, "Cargo.toml"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "Cargo.toml"), manifest)
	writeTestFile(t, filepath.Join(root, "crates", "fixture", "Cargo.toml"), []byte("[package]\nname='fixture-sdk-crate'\nversion='0.0.0'\nedition.workspace=true\nlicense.workspace=true\nrust-version.workspace=true\n"))
	writeTestFile(t, filepath.Join(root, "crates", "fixture", "src", "lib.rs"), []byte("pub const READY: bool = true;\n"))
	writeTestFile(t, filepath.Join(root, "plugins", "_workspace", "Cargo.toml"), []byte("[package]\nname='workspace-anchor'\nversion='0.0.0'\nedition.workspace=true\nlicense.workspace=true\nrust-version.workspace=true\n"))
	writeTestFile(t, filepath.Join(root, "plugins", "_workspace", "src", "lib.rs"), []byte("pub const READY: bool = true;\n"))
	writeTestFile(t, filepath.Join(root, "plugins", "waf", "Cargo.toml"), []byte("[package]\nname='fixture-waf'\nversion='0.0.0'\nedition.workspace=true\nlicense.workspace=true\nrust-version.workspace=true\n"))
	writeTestFile(t, filepath.Join(root, "plugins", "waf", "src", "lib.rs"), []byte("pub const READY: bool = true;\n"))
	for _, pluginID := range []string{"reverse-l4", "webdav"} {
		if err := os.MkdirAll(filepath.Join(root, "plugins", pluginID), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(cargo, "metadata", "--no-deps", "--format-version", "1")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mixed Rust/Go plugin workspace is invalid: %v\n%s", err, output)
	}
}

func findCargo(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("cargo"); err == nil {
		return path
	}
	home, err := os.UserHomeDir()
	if err == nil {
		candidate := filepath.Join(home, ".cargo", "bin", "cargo")
		if runtime.GOOS == "windows" {
			candidate += ".exe"
		}
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	t.Skip("cargo is unavailable")
	return ""
}

func writeTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}
