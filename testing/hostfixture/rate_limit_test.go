package hostfixture

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
)

func TestRateLimitGCRAConcurrentMonotonicNewConnectionGenerationQuotaBoundary(t *testing.T) {
	artifact := buildRateLimitArtifact(t)
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		t.Fatalf("rate-limit artifact violates canonical nre:policy/v1 ABI: %v", err)
	}
	if bytes.Contains(artifact, []byte("wasi_snapshot_preview1")) {
		t.Fatal("rate-limit artifact unexpectedly imports WASI")
	}
	status, _ := runWAFArtifact(t, artifact, []byte(`{"enabled":true}`), "/", nil, true)
	if status != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("missing monotonic-clock/atomic-state capability init status = %d", status)
	}
}

func buildRateLimitArtifact(t *testing.T) []byte {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join(testSourceDirectory(t), "..", ".."))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, testCargo(t), "build", "-p", "sakullla-rate-limit", "--target", "wasm32v1-none", "--release", "--locked")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cargo build rate-limit failed: %v\n%s", err, output)
	}
	artifact, err := os.ReadFile(filepath.Join(repositoryRoot, "target", "wasm32v1-none", "release", "sakullla_rate_limit.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		t.Fatalf("normalize empty rust-lld function table: %v", err)
	}
	return artifact
}
