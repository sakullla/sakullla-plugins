package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sakullla/sakullla-plugins/internal/ci/performance"
	"github.com/sakullla/sakullla-plugins/internal/sdklock"
)

func TestPluginGateRequiresHostCapabilitiesBeforeBuild(t *testing.T) {
	lock := sdklock.Lock{
		SchemaVersion: 1,
		Repository: sdklock.Repository{
			URL:    "https://example.invalid/sdk.git",
			Commit: strings.Repeat("a", 40),
		},
		SDK: sdklock.SDK{
			ModulePath:      "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go",
			ModuleDirectory: "plugin-sdk/go",
			ContractTreeOID: strings.Repeat("b", 40),
		},
		Artifacts: sdklock.Artifacts{
			DescriptorSetSHA256:  strings.Repeat("c", 64),
			PolicyProtoSHA256:    strings.Repeat("d", 64),
			RPCProtoSHA256:       strings.Repeat("e", 64),
			CanonicalGuestSHA256: strings.Repeat("f", 64),
			ValidatorTreeOID:     strings.Repeat("1", 40),
		},
		RequiredCapabilities: []sdklock.Capability{{
			ID:            "policy.trusted-source",
			MissingReason: "fixture capability is unavailable",
		}},
	}
	lock.CapabilityContractSHA256 = sdklock.CapabilityDigest(lock.RequiredCapabilities)
	encoded, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(t.TempDir(), "sdk.lock.json")
	if err := os.WriteFile(lockPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	verified := false
	buildSentinel := errors.New("required host capabilities are unavailable")
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "waf", "--sdk-lock", lockPath}, func(_ context.Context, got sdklock.Lock, requireHostCapabilities bool, _ string) (sdklock.Verification, error) {
		verified = true
		if !requireHostCapabilities {
			t.Fatal("plugin command disabled the required Host capability gate")
		}
		if got.Repository.Commit != lock.Repository.Commit {
			t.Fatal("plugin command did not load the reachable fixture lock")
		}
		return sdklock.Verification{}, buildSentinel
	})
	if !verified || !errors.Is(err, buildSentinel) || !strings.Contains(err.Error(), "SDK release gate") {
		t.Fatalf("plugin command did not fail at the SDK capability gate before build: %v", err)
	}
}

func TestPluginReverseL4PostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "reverse-l4", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, requireHostCapabilities bool, _ string) (sdklock.Verification, error) {
		verified = true
		if !requireHostCapabilities {
			t.Fatal("RPC plugin bypassed SDK capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("SDK verifier was not invoked")
	}
	name := "reverse-l4"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "reverse-l4", name)); err != nil || info.IsDir() {
		t.Fatalf("deterministic RPC artifact output missing: %v", err)
	}
}

func TestPluginArtifactSourceLayoutIsStrictAndRuntimeSpecific(t *testing.T) {
	rpc, err := pluginArtifactSpecFor("reverse-l4")
	if err != nil || rpc.kind != artifactRPCService || !strings.Contains(rpc.sourcePath, "reverse-l4/cmd/reverse-l4") {
		t.Fatalf("reverse-l4 artifact spec = %#v err=%v", rpc, err)
	}
	wasm, err := pluginArtifactSpecFor("waf")
	if err != nil || wasm.kind != artifactWASMPolicy || wasm.packageName != "sakullla-waf" {
		t.Fatalf("WAF artifact spec = %#v err=%v", wasm, err)
	}
	if _, err := pluginArtifactSpecFor("unmapped-plugin"); err == nil {
		t.Fatal("unknown plugin source layout was accepted")
	}
}

func TestPerformanceReleaseRejectsSelfAttestedOrMissingEvidence(t *testing.T) {
	err := checkPerformance(context.Background(), []string{"--profile", "release"})
	if !errors.Is(err, performance.ErrReleaseCapabilities) {
		t.Fatalf("release profile did not fail at the trusted Agent capability gate: %v", err)
	}
	if err := checkPerformance(context.Background(), []string{"--profile", "release", "--evidence", "self-attested.json"}); err == nil {
		t.Fatal("performance command accepted caller-supplied release evidence")
	}
}
