package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sakullla/sakullla-plugins/internal/ci/performance"
	"github.com/sakullla/sakullla-plugins/internal/pluginmanifest"
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
			ModulePath:      "github.com/sakullla/nginx-reverse-emby/plugin-sdk",
			ModuleDirectory: "plugin-sdk",
			PackagePath:     "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go",
			ContractTreeOID: strings.Repeat("b", 40),
		},
		Artifacts: sdklock.Artifacts{
			DescriptorSetSHA256:  strings.Repeat("c", 64),
			PluginSchemaSHA256:   strings.Repeat("2", 64),
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

func TestPromoteSDKUpdateRollsBackOnLateFailure(t *testing.T) {
	repository := t.TempDir()
	staging := t.TempDir()
	for _, relative := range []string{"go.mod", "go.sum"} {
		if err := os.WriteFile(filepath.Join(repository, relative), []byte("old "+relative), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "go.mod"), []byte("new go.mod"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := promoteSDKUpdate(repository, staging, []string{"go.mod", "go.sum"}); err == nil {
		t.Fatal("promotion unexpectedly accepted an incomplete staged transaction")
	}
	for _, relative := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(repository, relative))
		if err != nil || string(data) != "old "+relative {
			t.Fatalf("%s was not rolled back: %q, %v", relative, data, err)
		}
	}
}

func TestRemoveModuleSumsDropsOnlySelectedModule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.sum")
	const module = "example.invalid/sdk"
	input := module + " v1.0.0 h1:old\nother.invalid/module v1.0.0 h1:keep\n" + module + " v1.0.0/go.mod h1:oldmod\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeModuleSums(path, module); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "other.invalid/module v1.0.0 h1:keep\n" {
		t.Fatalf("filtered go.sum = %q, %v", data, err)
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
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		id           string
		kind         pluginArtifactKind
		sourceNeedle string
		packageName  string
	}{
		{id: "reverse-l4", kind: artifactRPCService, sourceNeedle: "reverse-l4/cmd/reverse-l4"},
		{id: "docker-app", kind: artifactRPCService, sourceNeedle: "docker-app/cmd/docker-app"},
		{id: "accelerator-sources", kind: artifactRPCService, sourceNeedle: "accelerator-sources/cmd/accelerator-sources"},
		{id: "doh", kind: artifactRPCService, sourceNeedle: "doh/cmd/doh"},
		{id: "cloudflare-dns", kind: artifactRPCService, sourceNeedle: "cloudflare-dns/cmd/cloudflare-dns"},
		{id: "shadowsocks-server", kind: artifactRPCService, sourceNeedle: "shadowsocks-server/cmd/shadowsocks-server"},
		{id: "waf", kind: artifactWASMPolicy, packageName: "sakullla-waf"},
		{id: "ip-policy", kind: artifactWASMPolicy, packageName: "sakullla-ip-policy"},
		{id: "rate-limit", kind: artifactWASMPolicy, packageName: "sakullla-rate-limit"},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			spec, err := pluginArtifactSpecFor(repositoryRoot, test.id)
			if err != nil || spec.kind != test.kind || (test.sourceNeedle != "" && !strings.Contains(spec.sourcePath, test.sourceNeedle)) || spec.packageName != test.packageName {
				t.Fatalf("artifact spec = %#v err=%v", spec, err)
			}
		})
	}
	if _, err := pluginArtifactSpecFor(repositoryRoot, "unmapped-plugin"); err == nil {
		t.Fatal("unknown plugin source layout was accepted")
	}
}

func TestPluginReverseL4ManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, id, kind, abi, entry, needle string
	}{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "reverse-l4", needle: "manifest id"},
		{name: "kind", id: "reverse-l4", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "reverse-l4", needle: "runtime kind"},
		{name: "abi", id: "reverse-l4", kind: "rpc-service", abi: "nre:rpc/v2", entry: "reverse-l4", needle: "ABI"},
		{name: "entry", id: "reverse-l4", kind: "rpc-service", abi: "nre:rpc/v1", entry: "other", needle: "entry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "reverse-l4", test.id, test.kind, test.abi, test.entry)
			_, err := pluginArtifactSpecFor(root, "reverse-l4")
			if err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("manifest drift error = %v", err)
			}
		})
	}
}

func TestCargoTargetDirectoryFollowsCargoEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CARGO_TARGET_DIR", "")
	if got, want := cargoTargetDirectory(root), filepath.Join(root, "target"); got != want {
		t.Fatalf("default Cargo target = %q, want %q", got, want)
	}
	absolute := filepath.Join(t.TempDir(), "cargo-output")
	t.Setenv("CARGO_TARGET_DIR", absolute)
	if got := cargoTargetDirectory(root); got != absolute {
		t.Fatalf("absolute Cargo target = %q, want %q", got, absolute)
	}
	t.Setenv("CARGO_TARGET_DIR", "cache/cargo")
	if got, want := cargoTargetDirectory(root), filepath.Join(root, "cache", "cargo"); got != want {
		t.Fatalf("relative Cargo target = %q, want %q", got, want)
	}
}

func TestReleaseStagingCreatesMissingOutputParent(t *testing.T) {
	output := filepath.Join(t.TempDir(), "missing", "nested", "candidate")
	staging, err := makeReleaseStaging(output)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(staging)
	if filepath.Dir(staging) != filepath.Dir(output) {
		t.Fatalf("release staging = %q, want parent %q", staging, filepath.Dir(output))
	}
}

func TestReleaseManifestUsesGeneratedArtifactMetadataWithoutRewritingSource(t *testing.T) {
	root := t.TempDir()
	writeRPCManifest(t, root, "reverse-l4", "reverse-l4", "rpc-service", "nre:rpc/v1", "reverse-l4")
	source := filepath.Join(root, "plugins", "reverse-l4", "plugin.yaml")
	if err := os.WriteFile(filepath.Join(filepath.Dir(source), "config.schema.json"), []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	artifactDirectory := filepath.Join(root, "target", "nre-ci", "reverse-l4")
	if err := os.MkdirAll(artifactDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDirectory, "reverse-l4")
	if err := os.WriteFile(artifact, []byte("workflow artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	metadata, err := releaseManifest(source, "reverse-l4", pluginArtifactSpec{kind: artifactRPCService}, artifact, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := metadata.manifest, filepath.Join(artifactDirectory, "plugin.yaml"); got != want {
		t.Fatalf("generated manifest path = %q, want %q", got, want)
	}
	if current, err := os.ReadFile(source); err != nil || !bytes.Equal(current, original) {
		t.Fatalf("source manifest changed: %v", err)
	}
	generated, err := pluginmanifest.Load(metadata.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := pluginmanifest.ValidateSource(generated, filepath.Dir(source), "reverse-l4", artifact); err != nil {
		t.Fatalf("generated manifest does not bind workflow artifact: %v", err)
	}
}

func writeRPCManifest(t *testing.T, root, pluginID, id, kind, abi, entry string) {
	t.Helper()
	directory := filepath.Join(root, "plugins", pluginID)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"schema_version": 1, "id": id, "version": "0.1.0", "name": "Reverse L4", "description": "fixture",
		"compatibility": map[string]any{"host": "*", "agent": "*"}, "runtime": map[string]any{"kind": kind, "abi": abi, "host_scope": "agent", "entry": entry},
		"artifacts":        []map[string]any{{"path": "artifacts/linux-amd64/" + pluginID, "sha256": strings.Repeat("a", 64), "size": 1, "mode": "executable", "goos": "linux", "goarch": "amd64"}},
		"extension_points": []string{"l4.accept"}, "permissions": []map[string]string{{"name": "l4.inspect"}}, "config_schema": "config.schema.json",
		"resource_budget": map[string]any{"timeout_ms": 1000, "memory_bytes": 65536, "concurrency": 1, "input_bytes": 1, "output_bytes": 1, "cpu_millis": 1, "restarts": 0},
		"failure_policy":  map[string]any{"on_error": "fail-closed", "on_budget": "fail-closed", "restart": "on-failure", "core_fallback": "preserve"},
		"signature":       map[string]any{"algorithm": "ed25519", "key_id": "sakullla-official-root-2026", "file": "signature.json"},
		"cleanup":         map[string]any{"instances": "delete", "config": "delete", "owned_data": "delete", "grants": "delete", "shared_refs": "retain", "audit_events": "retain"},
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "plugin.yaml"), wire, 0o600); err != nil {
		t.Fatal(err)
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
