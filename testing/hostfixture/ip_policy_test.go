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

func TestIPPolicyCIDRGeoIPTrustedSourceForgedOverlayGeneration(t *testing.T) {
	artifact := buildIPPolicyArtifact(t)
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		t.Fatalf("IP policy artifact violates canonical nre:policy/v1 ABI: %v", err)
	}
	if bytes.Contains(artifact, []byte("wasi_snapshot_preview1")) {
		t.Fatal("IP policy artifact unexpectedly imports WASI")
	}
	status, _ := runWAFArtifact(t, artifact, []byte(`{"default":"allow"}`), "/", nil, true)
	if status != pluginsdk.PolicyStatusIncompatibleABI {
		t.Fatalf("missing trusted-source capability init status = %d", status)
	}
}

func buildIPPolicyArtifact(t *testing.T) []byte {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join(testSourceDirectory(t), "..", ".."))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, testCargo(t), "build", "-p", "sakullla-ip-policy", "--target", "wasm32v1-none", "--release", "--locked")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cargo build ip-policy failed: %v\n%s", err, output)
	}
	artifact, err := os.ReadFile(filepath.Join(repositoryRoot, "target", "wasm32v1-none", "release", "sakullla_ip_policy.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		t.Fatalf("normalize empty rust-lld function table: %v", err)
	}
	return artifact
}
