package hostfixture

import (
	"bytes"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
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
