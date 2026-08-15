package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sdkLockHelperEnvironment = "SAKULLLA_SDK_LOCK_HELPER"

func TestSDKUpdateLockSerializesDifferentGenerationsAcrossProcessesWithDifferentTempDirectories(t *testing.T) {
	repository := t.TempDir()
	writeSDKGitDirectory(t, repository)
	stagingA := t.TempDir()
	stagingB := t.TempDir()
	writeSDKTransactionGeneration(t, repository, "old")
	writeSDKTransactionGeneration(t, stagingA, "generation-a")
	writeSDKTransactionGeneration(t, stagingB, "generation-b")
	coordination := t.TempDir()

	first := startSDKLockHelper(t, "hold-promote", repository, stagingA, coordination, "first")
	waitForSDKLockMarker(t, filepath.Join(coordination, "first.acquired"))
	second := startSDKLockHelper(t, "promote", repository, stagingB, coordination, "second")
	waitForSDKLockMarker(t, filepath.Join(coordination, "second.started"))
	waitForSDKLockMarker(t, filepath.Join(coordination, "second.temp"))
	firstTemp := readSDKLockMarker(t, filepath.Join(coordination, "first.temp"))
	secondTemp := readSDKLockMarker(t, filepath.Join(coordination, "second.temp"))
	if filepath.Clean(firstTemp) == filepath.Clean(secondTemp) {
		t.Fatalf("helpers did not observe distinct temporary directories: %q", firstTemp)
	}
	assertMarkerAbsentFor(t, filepath.Join(coordination, "second.acquired"), 250*time.Millisecond)
	if err := os.WriteFile(filepath.Join(coordination, "first.release"), []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitSDKLockHelper(t, first, false)
	waitSDKLockHelper(t, second, false)
	assertSDKTransactionGeneration(t, repository, "generation-b")
	assertNoSDKTransactionArtifacts(t, repository)
}

func TestSDKUpdateLockProcessDeathReleasesAndNextHolderRecovers(t *testing.T) {
	repository := t.TempDir()
	writeSDKGitDirectory(t, repository)
	crashStaging := t.TempDir()
	nextStaging := t.TempDir()
	writeSDKTransactionGeneration(t, repository, "old")
	writeSDKTransactionGeneration(t, crashStaging, "crash-generation")
	writeSDKTransactionGeneration(t, nextStaging, "next-generation")
	coordination := t.TempDir()

	crasher := startSDKLockHelper(t, "crash-after-manifest", repository, crashStaging, coordination, "crasher")
	waitSDKLockHelper(t, crasher, true)
	if _, err := os.Stat(filepath.Join(repository, sdkTransactionManifestName)); err != nil {
		t.Fatalf("crashed owner did not preserve durable journal: %v", err)
	}
	next := startSDKLockHelper(t, "recover-promote", repository, nextStaging, coordination, "next")
	waitSDKLockHelper(t, next, false)
	if _, err := os.Stat(filepath.Join(coordination, "next.recovered")); err != nil {
		t.Fatalf("next holder did not observe recovered generation: %v", err)
	}
	assertSDKTransactionGeneration(t, repository, "next-generation")
	assertNoSDKTransactionArtifacts(t, repository)
}

func TestSDKUpdateLockPathUsesCanonicalStableRepositoryIdentity(t *testing.T) {
	repository := t.TempDir()
	gitDirectory := writeSDKGitDirectory(t, repository)
	first, err := sdkUpdateLockPath(repository)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sdkUpdateLockPath(filepath.Join(repository, "."))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first != filepath.Join(gitDirectory, sdkUpdateLockName) {
		t.Fatalf("lock paths differ: %q != %q", first, second)
	}
}

func TestSDKUpdateLockPathUsesWorktreeGitDirectoryIdentity(t *testing.T) {
	gitDirectory := t.TempDir()
	firstRepository := t.TempDir()
	secondRepository := t.TempDir()
	writeSDKGitFile(t, firstRepository, gitDirectory)
	writeSDKGitFile(t, secondRepository, gitDirectory)

	first, err := sdkUpdateLockPath(firstRepository)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sdkUpdateLockPath(secondRepository)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first != filepath.Join(gitDirectory, sdkUpdateLockName) {
		t.Fatalf("worktree aliases resolve to different locks: %q != %q", first, second)
	}
}

func TestSDKUpdateLockPathFailsClosedForMissingOrMalformedGitMetadata(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"missing": func(t *testing.T, repository string) {},
		"empty": func(t *testing.T, repository string) {
			if err := os.WriteFile(filepath.Join(repository, ".git"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"wrong key": func(t *testing.T, repository string) {
			if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("directory: elsewhere\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"multiple lines": func(t *testing.T, repository string) {
			if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: elsewhere\nextra\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing target": func(t *testing.T, repository string) {
			if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: missing\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"target is file": func(t *testing.T, repository string) {
			target := filepath.Join(repository, "git-file")
			if err := os.WriteFile(target, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: git-file\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			repository := t.TempDir()
			setup(t, repository)
			if _, err := sdkUpdateLockPath(repository); err == nil {
				t.Fatal("invalid Git metadata was accepted")
			}
		})
	}
}

func TestSDKUpdateLockWaitHonorsContextCancellation(t *testing.T) {
	repository := t.TempDir()
	writeSDKGitDirectory(t, repository)
	owner, err := acquireSDKUpdateLock(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Errorf("close owner lock: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	waiter, err := acquireSDKUpdateLock(ctx, repository)
	if waiter != nil {
		_ = waiter.Close()
		t.Fatal("waiter acquired an already-held repository lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want context deadline exceeded", err)
	}
}

func TestSDKUpdateLockCloseJoinsOperationUnlockAndFileCloseErrors(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "lock-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	operationErr := errors.New("operation failed")
	unlockErr := errors.New("unlock failed")
	closeErr := errors.New("close failed")
	lock := &sdkUpdateLock{
		file:   file,
		unlock: func(*os.File) error { return unlockErr },
		close:  func(*os.File) error { return closeErr },
	}
	result := operationErr
	joinSDKUpdateLockClose(&result, lock)
	for _, want := range []error{operationErr, unlockErr, closeErr} {
		if !errors.Is(result, want) {
			t.Errorf("joined error %v does not include %v", result, want)
		}
	}
}

func TestSDKUpdateLockProcessHelper(t *testing.T) {
	mode := os.Getenv(sdkLockHelperEnvironment)
	if mode == "" {
		return
	}
	repository := os.Getenv("SAKULLLA_SDK_LOCK_REPOSITORY")
	staging := os.Getenv("SAKULLLA_SDK_LOCK_STAGING")
	coordination := os.Getenv("SAKULLLA_SDK_LOCK_COORDINATION")
	identity := os.Getenv("SAKULLLA_SDK_LOCK_IDENTITY")
	if err := os.WriteFile(filepath.Join(coordination, identity+".temp"), []byte(os.TempDir()), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSDKLockMarker(t, filepath.Join(coordination, identity+".started"))

	lock, err := acquireSDKUpdateLock(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	writeSDKLockMarker(t, filepath.Join(coordination, identity+".acquired"))
	if mode == "hold-promote" {
		waitForSDKLockMarker(t, filepath.Join(coordination, identity+".release"))
	}
	if mode == "recover-promote" {
		if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
			t.Fatal(err)
		}
		assertSDKTransactionGeneration(t, repository, "crash-generation")
		writeSDKLockMarker(t, filepath.Join(coordination, identity+".recovered"))
	}
	if mode == "crash-after-manifest" {
		fault := &faultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}, failForwardAfter: 1, forwardErr: errSDKTransactionCrash}
		if err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault); !errors.Is(err, errSDKTransactionCrash) {
			t.Fatalf("crash helper transaction = %v", err)
		}
		writeSDKLockMarker(t, filepath.Join(coordination, identity+".crashed"))
		os.Exit(86)
	}
	if err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, osSDKTransactionFS{}); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func startSDKLockHelper(t *testing.T, mode, repository, staging, coordination, identity string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	processTemp := filepath.Join(coordination, identity+"-temp")
	if err := os.MkdirAll(processTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSDKUpdateLockProcessHelper$", "-test.count=1")
	command.Env = sdkLockHelperEnvironmentWithOverrides(os.Environ(), map[string]string{
		sdkLockHelperEnvironment:         mode,
		"SAKULLLA_SDK_LOCK_REPOSITORY":   repository,
		"SAKULLLA_SDK_LOCK_STAGING":      staging,
		"SAKULLLA_SDK_LOCK_COORDINATION": coordination,
		"SAKULLLA_SDK_LOCK_IDENTITY":     identity,
		"TEMP":                           processTemp,
		"TMP":                            processTemp,
		"TMPDIR":                         processTemp,
	})
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return command
}

func sdkLockHelperEnvironmentWithOverrides(environment []string, overrides map[string]string) []string {
	result := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[strings.ToUpper(key)]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func writeSDKGitDirectory(t *testing.T, repository string) string {
	t.Helper()
	gitDirectory := filepath.Join(repository, ".git")
	if err := os.Mkdir(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	return gitDirectory
}

func writeSDKGitFile(t *testing.T, repository, gitDirectory string) {
	t.Helper()
	relative, err := filepath.Rel(repository, gitDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, ".git"), []byte("gitdir: "+relative+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitSDKLockHelper(t *testing.T, command *exec.Cmd, wantFailure bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if wantFailure && err == nil {
			t.Fatal("SDK lock helper unexpectedly succeeded")
		}
		if !wantFailure && err != nil {
			t.Fatalf("SDK lock helper failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("SDK lock helper timed out")
	}
}

func waitForSDKLockMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for marker %s", path)
}

func assertMarkerAbsentFor(t *testing.T, path string, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("second process acquired repository lock before release: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeSDKLockMarker(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readSDKLockMarker(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
