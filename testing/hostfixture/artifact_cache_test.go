package hostfixture

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
)

type policyArtifactSpec struct {
	packageName string
	target      string
	fileName    string
}

type policyArtifactCache struct {
	once     sync.Once
	artifact []byte
	err      error
}

var (
	wafArtifactCache       policyArtifactCache
	ipPolicyArtifactCache  policyArtifactCache
	rateLimitArtifactCache policyArtifactCache
)

func buildWAFArtifact(t *testing.T) []byte {
	t.Helper()
	return cachedPolicyArtifact(t, &wafArtifactCache, policyArtifactSpec{
		packageName: "sakullla-waf",
		target:      "wasm32-unknown-unknown",
		fileName:    "sakullla_waf.wasm",
	})
}

func buildIPPolicyArtifact(t *testing.T) []byte {
	t.Helper()
	return cachedPolicyArtifact(t, &ipPolicyArtifactCache, policyArtifactSpec{
		packageName: "sakullla-ip-policy",
		target:      "wasm32v1-none",
		fileName:    "sakullla_ip_policy.wasm",
	})
}

func buildRateLimitArtifact(t *testing.T) []byte {
	t.Helper()
	return cachedPolicyArtifact(t, &rateLimitArtifactCache, policyArtifactSpec{
		packageName: "sakullla-rate-limit",
		target:      "wasm32v1-none",
		fileName:    "sakullla_rate_limit.wasm",
	})
}

func cachedPolicyArtifact(t *testing.T, cache *policyArtifactCache, spec policyArtifactSpec) []byte {
	t.Helper()
	cache.once.Do(func() {
		cache.artifact, cache.err = buildPolicyArtifact(spec)
	})
	if cache.err != nil {
		t.Fatalf("build %s policy artifact: %v", spec.packageName, cache.err)
	}
	return bytes.Clone(cache.artifact)
}

func buildPolicyArtifact(spec policyArtifactSpec) ([]byte, error) {
	repositoryRoot, err := hostfixtureRepositoryRoot()
	if err != nil {
		return nil, err
	}
	cargo, err := findTestCargo()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, cargo, "build", "-p", spec.packageName, "--target", spec.target, "--release", "--locked")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cargo build: %w\n%s", err, output)
	}
	artifactPath := filepath.Join(repositoryRoot, "target", spec.target, "release", spec.fileName)
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		return nil, fmt.Errorf("normalize empty rust-lld function table: %w", err)
	}
	return artifact, nil
}

func hostfixtureRepositoryRoot() (string, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate hostfixture source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..")), nil
}

func findTestCargo() (string, error) {
	if cargo, err := exec.LookPath("cargo"); err == nil {
		return cargo, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate cargo: %w", err)
	}
	cargo := filepath.Join(home, ".cargo", "bin", "cargo")
	if runtime.GOOS == "windows" {
		cargo += ".exe"
	}
	if _, err := os.Stat(cargo); err != nil {
		return "", fmt.Errorf("cargo is required for policy artifact tests: %w", err)
	}
	return cargo, nil
}
