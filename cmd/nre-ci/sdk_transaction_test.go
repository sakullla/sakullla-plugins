package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKTransactionRollsBackAfterEveryBackupAndPromoteRename(t *testing.T) {
	for failAfter := 1; failAfter <= len(sdkUpdateTargets)*2; failAfter++ {
		t.Run(fmt.Sprintf("rename-%d", failAfter), func(t *testing.T) {
			repository, staging := newSDKTransactionFixture(t)
			fault := &faultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}, failForwardAfter: failAfter, forwardErr: errors.New("injected rename failure")}
			err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
			if err == nil || !strings.Contains(err.Error(), "injected rename failure") {
				t.Fatalf("transaction error = %v", err)
			}
			if fault.forwardRenames < failAfter {
				t.Fatalf("fault fired before requested rename: got %d, want %d", fault.forwardRenames, failAfter)
			}
			assertSDKTransactionGeneration(t, repository, "old")
			assertNoSDKTransactionArtifacts(t, repository)
		})
	}
}

func TestSDKTransactionRestartCompletesNewGenerationAfterEveryRename(t *testing.T) {
	for crashAfter := 1; crashAfter <= len(sdkUpdateTargets)*2; crashAfter++ {
		t.Run(fmt.Sprintf("rename-%d", crashAfter), func(t *testing.T) {
			repository, staging := newSDKTransactionFixture(t)
			fault := &faultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}, failForwardAfter: crashAfter, forwardErr: errSDKTransactionCrash}
			err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
			if !errors.Is(err, errSDKTransactionCrash) {
				t.Fatalf("transaction error = %v, want simulated crash", err)
			}
			if _, err := os.Stat(filepath.Join(repository, sdkTransactionManifestName)); err != nil {
				t.Fatalf("durable manifest missing after simulated crash: %v", err)
			}
			if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
				t.Fatal(err)
			}
			assertSDKTransactionGeneration(t, repository, "new")
			assertNoSDKTransactionArtifacts(t, repository)
		})
	}
}

func TestSDKTransactionRestartFallsBackToCompleteOldGeneration(t *testing.T) {
	repository, staging := newSDKTransactionFixture(t)
	fault := &faultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}, failForwardAfter: 2, forwardErr: errSDKTransactionCrash}
	if err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault); !errors.Is(err, errSDKTransactionCrash) {
		t.Fatalf("transaction error = %v, want simulated crash", err)
	}
	lastNew := sdkTransactionPath(repository, sdkUpdateTargets[len(sdkUpdateTargets)-1]) + sdkTransactionNewSuffix
	if err := os.Remove(lastNew); err != nil {
		t.Fatal(err)
	}
	if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
		t.Fatal(err)
	}
	assertSDKTransactionGeneration(t, repository, "old")
	assertNoSDKTransactionArtifacts(t, repository)
}

func TestSDKTransactionPropagatesRollbackFailureAndRemainsRestartRecoverable(t *testing.T) {
	repository, staging := newSDKTransactionFixture(t)
	fault := &faultSDKTransactionFS{
		sdkTransactionFS:    osSDKTransactionFS{},
		failForwardAfter:    3,
		forwardErr:          errors.New("forward failure"),
		failRollbackRestore: true,
	}
	err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
	if err == nil || !strings.Contains(err.Error(), "forward failure") || !strings.Contains(err.Error(), "rollback failure") {
		t.Fatalf("combined transaction error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(repository, sdkTransactionManifestName)); err != nil {
		t.Fatalf("manifest was removed after failed rollback: %v", err)
	}
	if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
		t.Fatal(err)
	}
	assertSDKTransactionGeneration(t, repository, "old")
	assertNoSDKTransactionArtifacts(t, repository)
}

func TestSDKTransactionUsesDeterministicDurableArtifactsAndSyncsDirectories(t *testing.T) {
	repository, staging := newSDKTransactionFixture(t)
	tracking := &faultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}}
	if err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, tracking); err != nil {
		t.Fatal(err)
	}
	if tracking.durableWrites != len(sdkUpdateTargets)+1 {
		t.Fatalf("durable writes = %d, want %d staged files plus manifest", tracking.durableWrites, len(sdkUpdateTargets)+1)
	}
	if tracking.directorySyncs < len(sdkUpdateTargets)*4+2 {
		t.Fatalf("directory syncs = %d, want durable rename and cleanup syncs", tracking.directorySyncs)
	}
	assertSDKTransactionGeneration(t, repository, "new")
	assertNoSDKTransactionArtifacts(t, repository)
}

type faultSDKTransactionFS struct {
	sdkTransactionFS
	failForwardAfter    int
	forwardErr          error
	failRollbackRestore bool
	forwardRenames      int
	durableWrites       int
	directorySyncs      int
}

func (fileSystem *faultSDKTransactionFS) WriteDurable(path string, data []byte, mode fs.FileMode) error {
	fileSystem.durableWrites++
	return fileSystem.sdkTransactionFS.WriteDurable(path, data, mode)
}

func (fileSystem *faultSDKTransactionFS) SyncDir(path string) error {
	fileSystem.directorySyncs++
	return fileSystem.sdkTransactionFS.SyncDir(path)
}

func (fileSystem *faultSDKTransactionFS) Rename(oldPath, newPath string) error {
	if fileSystem.failRollbackRestore && strings.HasSuffix(oldPath, sdkTransactionOldSuffix) {
		fileSystem.failRollbackRestore = false
		return errors.New("rollback failure")
	}
	isForward := strings.HasSuffix(newPath, sdkTransactionOldSuffix) || strings.HasSuffix(oldPath, sdkTransactionNewSuffix)
	if !isForward {
		return fileSystem.sdkTransactionFS.Rename(oldPath, newPath)
	}
	fileSystem.forwardRenames++
	if err := fileSystem.sdkTransactionFS.Rename(oldPath, newPath); err != nil {
		return err
	}
	if fileSystem.forwardRenames == fileSystem.failForwardAfter {
		return fileSystem.forwardErr
	}
	return nil
}

func newSDKTransactionFixture(t *testing.T) (string, string) {
	t.Helper()
	repository := t.TempDir()
	staging := t.TempDir()
	for _, relative := range sdkUpdateTargets {
		for root, generation := range map[string]string{repository: "old", staging: "new"} {
			path := sdkTransactionPath(root, relative)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(generation+":"+relative), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return repository, staging
}

func assertSDKTransactionGeneration(t *testing.T, repository, generation string) {
	t.Helper()
	for _, relative := range sdkUpdateTargets {
		data, err := os.ReadFile(sdkTransactionPath(repository, relative))
		if err != nil || string(data) != generation+":"+relative {
			t.Fatalf("%s = %q, %v; want %s generation", relative, data, err, generation)
		}
	}
}

func assertNoSDKTransactionArtifacts(t *testing.T, repository string) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(repository, sdkTransactionManifestName),
		filepath.Join(repository, sdkTransactionManifestTemp),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction artifact remains: %s (%v)", path, err)
		}
	}
	for _, relative := range sdkUpdateTargets {
		target := sdkTransactionPath(repository, relative)
		for _, suffix := range []string{sdkTransactionNewSuffix, sdkTransactionOldSuffix} {
			if _, err := os.Stat(target + suffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("transaction artifact remains: %s (%v)", target+suffix, err)
			}
		}
	}
}
