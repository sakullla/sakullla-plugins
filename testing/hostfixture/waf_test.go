package hostfixture

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
)

func TestWAFStreamingBodyWindowObserveDenyBudgetGeneration(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join(testSourceDirectory(t), "..", ".."))
	cargo := testCargo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, args := range [][]string{
		{"test", "-p", "sakullla-waf", "--locked"},
		{"build", "-p", "sakullla-waf", "--target", "wasm32v1-none", "--release", "--locked"},
	} {
		command := exec.CommandContext(ctx, cargo, args...)
		command.Dir = repositoryRoot
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cargo %v failed: %v\n%s", args, err, output)
		}
	}
	artifactPath := filepath.Join(repositoryRoot, "target", "wasm32v1-none", "release", "sakullla_waf.wasm")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		t.Fatalf("normalize empty rust-lld function table: %v", err)
	}
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		t.Fatalf("WAF artifact violates canonical nre:policy/v1 ABI: %v", err)
	}
	if bytes.Contains(artifact, []byte("wasi_snapshot_preview1")) {
		t.Fatal("WAF artifact unexpectedly imports WASI")
	}
}

func testSourceDirectory(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate WAF host fixture source")
	}
	return filepath.Dir(source)
}

func testCargo(t *testing.T) string {
	t.Helper()
	if cargo, err := exec.LookPath("cargo"); err == nil {
		return cargo
	}
	home, err := os.UserHomeDir()
	if err == nil {
		cargo := filepath.Join(home, ".cargo", "bin", "cargo")
		if runtime.GOOS == "windows" {
			cargo += ".exe"
		}
		if _, err := os.Stat(cargo); err == nil {
			return cargo
		}
	}
	t.Fatal("cargo is required for WAF host fixture")
	return ""
}
