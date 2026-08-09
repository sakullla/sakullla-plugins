package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
