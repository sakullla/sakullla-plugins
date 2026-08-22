package sdklock

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerificationCacheHitAndInputInvalidation(t *testing.T) {
	repository, workspace, lock := newVerificationCacheFixture(t)
	_ = repository
	var executions atomic.Int32
	toolchainVersion := "toolchain-v1"
	options := verificationCacheOptions{
		cacheRoot: filepath.Join(workspace, "target", "c"),
		toolchain: func(context.Context) (string, string, string, error) {
			return "go-" + toolchainVersion, "rust-" + toolchainVersion, "cargo-" + toolchainVersion, nil
		},
		canonicalVerify: func(_ context.Context, current Lock, required bool, _, _ string) (Verification, error) {
			executions.Add(1)
			return fixtureVerification(current, required)
		},
	}
	verify := func(current Lock) {
		t.Helper()
		if _, err := verifyCached(context.Background(), current, false, workspace, options); err != nil {
			t.Fatal(err)
		}
	}
	verify(lock)
	verify(lock)
	if got := executions.Load(); got != 1 {
		t.Fatalf("canonical executions after cache hit = %d, want 1", got)
	}

	writeCacheTestFile(t, workspace, "source.txt", "source-v1")
	verify(lock)
	writeCacheTestFile(t, workspace, "crates/nre-policy-guest/src/abi_generated.rs", "projection-v2")
	verify(lock)
	goMod, err := os.ReadFile(filepath.Join(workspace, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	writeCacheTestFile(t, workspace, "go.mod", string(goMod)+"\n// cache identity change\n")
	verify(lock)
	toolchainVersion = "toolchain-v2"
	verify(lock)

	changedLock := lock
	changedLock.RequiredCapabilities[0].Symbols = append([]string{}, lock.RequiredCapabilities[0].Symbols...)
	changedLock.RequiredCapabilities[0].Symbols = append(changedLock.RequiredCapabilities[0].Symbols, "AdditionalEvidence")
	changedLock.CapabilityContractSHA256 = CapabilityDigest(changedLock.RequiredCapabilities)
	verify(changedLock)
	if got := executions.Load(); got != 6 {
		t.Fatalf("canonical executions after invalidations = %d, want 6", got)
	}
}

func TestVerificationCacheRepairsCheckoutAndResultDamage(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	var executions atomic.Int32
	options := fixtureVerificationCacheOptions(workspace, &executions)
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	result := singleCacheMatch(t, filepath.Join(options.cacheRoot, "results", "*.json"))
	checkout := singleCacheMatch(t, filepath.Join(options.cacheRoot, "checkouts", "*", "repository"))

	if err := os.WriteFile(filepath.Join(checkout, "dirty.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	if got := executions.Load(); got != 2 {
		t.Fatalf("dirty checkout reused cached success; canonical executions = %d", got)
	}

	checkout = singleCacheMatch(t, filepath.Join(options.cacheRoot, "checkouts", "*", "repository"))
	runGitTest(t, checkout, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "wrong-origin"))
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	if got := executions.Load(); got != 3 {
		t.Fatalf("wrong checkout identity reused cached success; canonical executions = %d", got)
	}

	if err := os.WriteFile(result, []byte("{truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	if got := executions.Load(); got != 4 {
		t.Fatalf("truncated result reused cached success; canonical executions = %d", got)
	}

	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var envelope verificationResultEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Verification.Commit = "tampered"
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(result, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	if got := executions.Load(); got != 5 {
		t.Fatalf("tampered result reused cached success; canonical executions = %d", got)
	}

	checkout = singleCacheMatch(t, filepath.Join(options.cacheRoot, "checkouts", "*", "repository"))
	if err := os.RemoveAll(filepath.Dir(checkout)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	if got := executions.Load(); got != 6 {
		t.Fatalf("missing checkout reused cached success; canonical executions = %d", got)
	}
}

func TestVerificationCacheDoesNotPublishFailure(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	options := verificationCacheOptions{
		cacheRoot: filepath.Join(workspace, "target", "c"),
		toolchain: fixtureToolchainIdentity,
		canonicalVerify: func(context.Context, Lock, bool, string, string) (Verification, error) {
			return Verification{}, errors.New("fixture verification failed")
		},
	}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err == nil {
		t.Fatal("failed canonical verification was accepted")
	}
	results, err := filepath.Glob(filepath.Join(options.cacheRoot, "results", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("failed verification published results: %v", results)
	}
}

func TestVerificationCacheSerializesConcurrentMiss(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	var executions atomic.Int32
	options := fixtureVerificationCacheOptions(workspace, &executions)
	options.canonicalVerify = func(_ context.Context, current Lock, required bool, _, _ string) (Verification, error) {
		executions.Add(1)
		time.Sleep(50 * time.Millisecond)
		return fixtureVerification(current, required)
	}
	const callers = 8
	var wait sync.WaitGroup
	errorsByCaller := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := verifyCached(context.Background(), lock, false, workspace, options)
			errorsByCaller <- err
		}()
	}
	wait.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := executions.Load(); got != 1 {
		t.Fatalf("concurrent canonical executions = %d, want 1", got)
	}
}

func TestVerificationCacheRejectsSymlinkRoot(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	outside := t.TempDir()
	cacheRoot := filepath.Join(workspace, "target", "c")
	if err := os.MkdirAll(filepath.Dir(cacheRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, cacheRoot); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	options := verificationCacheOptions{cacheRoot: cacheRoot, toolchain: fixtureToolchainIdentity}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err == nil {
		t.Fatal("symbolic-link cache root was accepted")
	}
}

func TestVerificationCacheRejectsSymlinkSubdirectory(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	outside := t.TempDir()
	cacheRoot := filepath.Join(workspace, "target", "c")
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cacheRoot, "results")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	options := verificationCacheOptions{cacheRoot: cacheRoot, toolchain: fixtureToolchainIdentity}
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err == nil {
		t.Fatal("symbolic-link cache result directory was accepted")
	}
}

func newVerificationCacheFixture(t *testing.T) (string, string, Lock) {
	t.Helper()
	repository := newSDKFixtureRepository(t)
	workspace := t.TempDir()
	writeProjectionFixture(t, workspace, "locked-projection")
	lock := fixtureLock(t, repository)
	writeModuleIdentityFixture(t, workspace, lock)
	return repository, workspace, lock
}

func fixtureVerificationCacheOptions(workspace string, executions *atomic.Int32) verificationCacheOptions {
	return verificationCacheOptions{
		cacheRoot: filepath.Join(workspace, "target", "c"),
		toolchain: fixtureToolchainIdentity,
		canonicalVerify: func(_ context.Context, lock Lock, required bool, _, _ string) (Verification, error) {
			executions.Add(1)
			return fixtureVerification(lock, required)
		},
	}
}

func fixtureToolchainIdentity(context.Context) (string, string, string, error) {
	return "fixture-go", "fixture-rust", "fixture-cargo", nil
}

func fixtureVerification(lock Lock, required bool) (Verification, error) {
	return finalizeVerification(lock, required, lock.Artifacts.DescriptorSetSHA256, lock.Artifacts.CanonicalGuestSHA256)
}

func writeCacheTestFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func singleCacheMatch(t *testing.T, pattern string) string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("cache matches for %q = %v, want one", pattern, matches)
	}
	return matches[0]
}

func TestVerificationCacheCheckoutRemainsClean(t *testing.T) {
	_, workspace, lock := newVerificationCacheFixture(t)
	var executions atomic.Int32
	options := fixtureVerificationCacheOptions(workspace, &executions)
	if _, err := verifyCached(context.Background(), lock, false, workspace, options); err != nil {
		t.Fatal(err)
	}
	checkout := singleCacheMatch(t, filepath.Join(options.cacheRoot, "checkouts", "*", "repository"))
	command := exec.Command("git", "-C", checkout, "status", "--porcelain=v1", "--untracked-files=all")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("cached checkout is dirty: %q", output)
	}
}
