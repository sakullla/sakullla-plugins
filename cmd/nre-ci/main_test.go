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
			ModulePath:      "github.com/sakullla/nginx-reverse-emby/plugin-sdk",
			ModuleDirectory: "plugin-sdk",
			PackagePath:     "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go",
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

func TestPluginDockerAppPostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "docker-app", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, required bool, _ string) (sdklock.Verification, error) {
		if !required {
			t.Fatal("Docker RPC plugin bypassed capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "docker-app"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "docker-app", name)); err != nil || info.IsDir() {
		t.Fatalf("Docker RPC artifact missing: %v", err)
	}
}

func TestPluginAcceleratorSourcesPostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "accelerator-sources", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, required bool, _ string) (sdklock.Verification, error) {
		if !required {
			t.Fatal("accelerator RPC plugin bypassed capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "accelerator-sources"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "accelerator-sources", name)); err != nil || info.IsDir() {
		t.Fatalf("accelerator RPC artifact missing: %v", err)
	}
}

func TestPluginDoHPostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "doh", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, required bool, _ string) (sdklock.Verification, error) {
		if !required {
			t.Fatal("DoH RPC plugin bypassed capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "doh"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "doh", name)); err != nil || info.IsDir() {
		t.Fatalf("DoH RPC artifact missing: %v", err)
	}
}

func TestPluginCloudflareDNSPostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "cloudflare-dns", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, required bool, _ string) (sdklock.Verification, error) {
		if !required {
			t.Fatal("Cloudflare DNS RPC plugin bypassed capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "cloudflare-dns"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "cloudflare-dns", name)); err != nil || info.IsDir() {
		t.Fatalf("Cloudflare DNS RPC artifact missing: %v", err)
	}
}

func TestPluginShadowsocksPostGateBuildsAndValidatesRPCArtifact(t *testing.T) {
	lockPath, err := filepath.Abs(filepath.Join("..", "..", "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkPluginWithVerifier(context.Background(), []string{"--id", "shadowsocks-server", "--sdk-lock", lockPath}, func(_ context.Context, _ sdklock.Lock, required bool, _ string) (sdklock.Verification, error) {
		if !required {
			t.Fatal("Shadowsocks RPC plugin bypassed capability gate")
		}
		return sdklock.Verification{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "shadowsocks-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if info, err := os.Stat(filepath.Join("..", "..", "target", "nre-ci", "shadowsocks-server", name)); err != nil || info.IsDir() {
		t.Fatalf("Shadowsocks RPC artifact missing: %v", err)
	}
}

func TestPluginArtifactSourceLayoutIsStrictAndRuntimeSpecific(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := pluginArtifactSpecFor(repositoryRoot, "reverse-l4")
	if err != nil || rpc.kind != artifactRPCService || !strings.Contains(rpc.sourcePath, "reverse-l4/cmd/reverse-l4") {
		t.Fatalf("reverse-l4 artifact spec = %#v err=%v", rpc, err)
	}
	docker, err := pluginArtifactSpecFor(repositoryRoot, "docker-app")
	if err != nil || docker.kind != artifactRPCService || !strings.Contains(docker.sourcePath, "docker-app/cmd/docker-app") {
		t.Fatalf("docker-app artifact spec = %#v err=%v", docker, err)
	}
	accelerator, err := pluginArtifactSpecFor(repositoryRoot, "accelerator-sources")
	if err != nil || accelerator.kind != artifactRPCService || !strings.Contains(accelerator.sourcePath, "accelerator-sources/cmd/accelerator-sources") {
		t.Fatalf("accelerator-sources artifact spec = %#v err=%v", accelerator, err)
	}
	dohArtifact, err := pluginArtifactSpecFor(repositoryRoot, "doh")
	if err != nil || dohArtifact.kind != artifactRPCService || !strings.Contains(dohArtifact.sourcePath, "doh/cmd/doh") {
		t.Fatalf("DoH artifact spec = %#v err=%v", dohArtifact, err)
	}
	cloudflareArtifact, err := pluginArtifactSpecFor(repositoryRoot, "cloudflare-dns")
	if err != nil || cloudflareArtifact.kind != artifactRPCService || !strings.Contains(cloudflareArtifact.sourcePath, "cloudflare-dns/cmd/cloudflare-dns") {
		t.Fatalf("Cloudflare DNS artifact spec = %#v err=%v", cloudflareArtifact, err)
	}
	shadowsocksArtifact, err := pluginArtifactSpecFor(repositoryRoot, "shadowsocks-server")
	if err != nil || shadowsocksArtifact.kind != artifactRPCService || !strings.Contains(shadowsocksArtifact.sourcePath, "shadowsocks-server/cmd/shadowsocks-server") {
		t.Fatalf("Shadowsocks artifact spec = %#v err=%v", shadowsocksArtifact, err)
	}
	wasm, err := pluginArtifactSpecFor(repositoryRoot, "waf")
	if err != nil || wasm.kind != artifactWASMPolicy || wasm.packageName != "sakullla-waf" {
		t.Fatalf("WAF artifact spec = %#v err=%v", wasm, err)
	}
	if _, err := pluginArtifactSpecFor(repositoryRoot, "unmapped-plugin"); err == nil {
		t.Fatal("unknown plugin source layout was accepted")
	}
}

func TestPluginReverseL4ManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, id, kind, abi, entry, needle string
	}{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/reverse-l4", needle: "manifest id"},
		{name: "kind", id: "reverse-l4", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/reverse-l4", needle: "runtime kind"},
		{name: "abi", id: "reverse-l4", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/reverse-l4", needle: "ABI"},
		{name: "entry", id: "reverse-l4", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other", needle: "entry"},
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

func TestPluginDockerAppManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, id, kind, abi, entry string }{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/docker-app"},
		{name: "kind", id: "docker-app", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/docker-app"},
		{name: "abi", id: "docker-app", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/docker-app"},
		{name: "entry", id: "docker-app", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "docker-app", test.id, test.kind, test.abi, test.entry)
			if _, err := pluginArtifactSpecFor(root, "docker-app"); err == nil {
				t.Fatal("docker-app manifest drift was accepted")
			}
		})
	}
}

func TestPluginAcceleratorSourcesManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, id, kind, abi, entry string }{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/accelerator-sources"},
		{name: "kind", id: "accelerator-sources", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/accelerator-sources"},
		{name: "abi", id: "accelerator-sources", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/accelerator-sources"},
		{name: "entry", id: "accelerator-sources", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "accelerator-sources", test.id, test.kind, test.abi, test.entry)
			if _, err := pluginArtifactSpecFor(root, "accelerator-sources"); err == nil {
				t.Fatal("accelerator-sources manifest drift was accepted")
			}
		})
	}
}

func TestPluginDoHManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, id, kind, abi, entry string }{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/doh"},
		{name: "kind", id: "doh", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/doh"},
		{name: "abi", id: "doh", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/doh"},
		{name: "entry", id: "doh", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "doh", test.id, test.kind, test.abi, test.entry)
			if _, err := pluginArtifactSpecFor(root, "doh"); err == nil {
				t.Fatal("DoH manifest drift was accepted")
			}
		})
	}
}

func TestPluginCloudflareDNSManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, id, kind, abi, entry string }{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/cloudflare-dns"},
		{name: "kind", id: "cloudflare-dns", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/cloudflare-dns"},
		{name: "abi", id: "cloudflare-dns", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/cloudflare-dns"},
		{name: "entry", id: "cloudflare-dns", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "cloudflare-dns", test.id, test.kind, test.abi, test.entry)
			if _, err := pluginArtifactSpecFor(root, "cloudflare-dns"); err == nil {
				t.Fatal("Cloudflare DNS manifest drift was accepted")
			}
		})
	}
}

func TestPluginShadowsocksManifestDriftFailsClosed(t *testing.T) {
	for _, test := range []struct{ name, id, kind, abi, entry string }{
		{name: "id", id: "other", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/shadowsocks-server"},
		{name: "kind", id: "shadowsocks-server", kind: "wasm-policy", abi: "nre:rpc/v1", entry: "artifacts/shadowsocks-server"},
		{name: "abi", id: "shadowsocks-server", kind: "rpc-service", abi: "nre:rpc/v2", entry: "artifacts/shadowsocks-server"},
		{name: "entry", id: "shadowsocks-server", kind: "rpc-service", abi: "nre:rpc/v1", entry: "artifacts/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRPCManifest(t, root, "shadowsocks-server", test.id, test.kind, test.abi, test.entry)
			if _, err := pluginArtifactSpecFor(root, "shadowsocks-server"); err == nil {
				t.Fatal("Shadowsocks manifest drift was accepted")
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

func writeRPCManifest(t *testing.T, root, pluginID, id, kind, abi, entry string) {
	t.Helper()
	directory := filepath.Join(root, "plugins", pluginID)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"schema_version": 1, "id": id, "version": "0.1.0", "name": "Reverse L4", "description": "fixture",
		"compatibility": map[string]any{}, "runtime": map[string]any{"kind": kind, "abi": abi, "host_scope": "agent", "entry": entry},
		"permissions": []string{}, "config_schema": "config.schema.json", "failure_policy": map[string]any{},
		"cleanup": map[string]any{}, "metadata": map[string]any{},
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
