package hostfixture

import (
	"bytes"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
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
