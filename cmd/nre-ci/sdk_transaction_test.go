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

func TestSDKTransactionEveryDurabilityOperationRecoversBeforeAndAfterEffect(t *testing.T) {
	repository, staging := newSDKTransactionFixture(t)
	trace := &indexedFaultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}}
	if err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, trace); err != nil {
		t.Fatal(err)
	}
	if len(trace.operations) == 0 {
		t.Fatal("successful transaction produced no filesystem operation trace")
	}
	for operationIndex, operation := range trace.operations {
		for _, mode := range []string{"before-error", "after-crash"} {
			t.Run(fmt.Sprintf("%03d-%s-%s", operationIndex+1, operation, mode), func(t *testing.T) {
				repository, staging := newSDKTransactionFixture(t)
				fault := &indexedFaultSDKTransactionFS{
					sdkTransactionFS: osSDKTransactionFS{},
					failAt:           operationIndex + 1,
					failMode:         mode,
				}
				err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
				if err == nil {
					t.Fatalf("operation %d %s unexpectedly succeeded", operationIndex+1, mode)
				}
				if mode == "after-crash" && !errors.Is(err, errSDKTransactionCrash) {
					t.Fatalf("operation %d error = %v, want simulated crash", operationIndex+1, err)
				}
				if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
					t.Fatalf("restart recovery after operation %d: %v", operationIndex+1, err)
				}
				assertSDKTransactionIsComplete(t, repository)
				assertNoSDKTransactionArtifacts(t, repository)
			})
		}
	}
}

func TestSDKTransactionRollbackRestoreFaultsPreserveRecoveryAuthority(t *testing.T) {
	for _, mode := range []string{"before-error", "after-crash"} {
		t.Run(mode, func(t *testing.T) {
			repository, staging := newSDKTransactionFixture(t)
			fault := &rollbackRestoreFaultFS{sdkTransactionFS: osSDKTransactionFS{}, mode: mode}
			err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
			if err == nil || !strings.Contains(err.Error(), "rollback restore fault") {
				t.Fatalf("transaction error = %v", err)
			}
			if mode == "after-crash" && !errors.Is(err, errSDKTransactionCrash) {
				t.Fatalf("transaction error = %v, want simulated crash", err)
			}
			if _, err := os.Stat(filepath.Join(repository, sdkTransactionManifestName)); err != nil {
				t.Fatalf("journal was lost after rollback failure: %v", err)
			}
			if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
				t.Fatal(err)
			}
			assertSDKTransactionIsComplete(t, repository)
			assertNoSDKTransactionArtifacts(t, repository)
		})
	}
}

func TestSDKTransactionUnrecoverableLiveRollbackRetainsJournal(t *testing.T) {
	repository, staging := newSDKTransactionFixture(t)
	traceRepository, traceStaging := newSDKTransactionFixture(t)
	trace := &indexedFaultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}}
	if err := promoteSDKUpdateWithFS(traceRepository, traceStaging, sdkUpdateTargets, trace); err != nil {
		t.Fatal(err)
	}
	failAt := 0
	for index, operation := range trace.operations {
		if strings.HasPrefix(operation, "remove-go.sum"+sdkTransactionOldSuffix) {
			failAt = index + 1
			break
		}
	}
	if failAt == 0 {
		t.Fatal("successful trace has no second-generation backup cleanup")
	}
	fault := &indexedFaultSDKTransactionFS{sdkTransactionFS: osSDKTransactionFS{}, failAt: failAt, failMode: "before-error"}
	err := promoteSDKUpdateWithFS(repository, staging, sdkUpdateTargets, fault)
	if err == nil || !strings.Contains(err.Error(), "durable journal retained") {
		t.Fatalf("transaction error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(repository, sdkTransactionManifestName)); err != nil {
		t.Fatalf("unrecoverable rollback removed journal: %v", err)
	}
	if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
		t.Fatal(err)
	}
	assertSDKTransactionGeneration(t, repository, "new")
	assertNoSDKTransactionArtifacts(t, repository)
}

func TestSDKTransactionRecoveryFailsClosedForCorruptManifestAndOrphanBackup(t *testing.T) {
	t.Run("corrupt manifest", func(t *testing.T) {
		repository, _ := newSDKTransactionFixture(t)
		manifest := filepath.Join(repository, sdkTransactionManifestName)
		if err := os.WriteFile(manifest, []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err == nil {
			t.Fatal("corrupt manifest was accepted")
		}
		if _, err := os.Stat(manifest); err != nil {
			t.Fatalf("corrupt recovery authority was removed: %v", err)
		}
	})
	t.Run("orphan old", func(t *testing.T) {
		repository, _ := newSDKTransactionFixture(t)
		orphan := sdkTransactionPath(repository, sdkUpdateTargets[0]) + sdkTransactionOldSuffix
		if err := os.WriteFile(orphan, []byte("old authority"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err == nil {
			t.Fatal("orphan old generation was accepted")
		}
		if _, err := os.Stat(orphan); err != nil {
			t.Fatalf("orphan old authority was removed: %v", err)
		}
	})
}

func TestSDKTransactionRecoverySafelyCleansOrphanNewAndManifestTemp(t *testing.T) {
	repository, _ := newSDKTransactionFixture(t)
	for _, relative := range sdkUpdateTargets {
		path := sdkTransactionPath(repository, relative) + sdkTransactionNewSuffix
		if err := os.WriteFile(path, []byte("unpublished new generation"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, sdkTransactionManifestTemp), []byte("unpublished manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverSDKUpdateWithFS(repository, osSDKTransactionFS{}); err != nil {
		t.Fatal(err)
	}
	assertSDKTransactionGeneration(t, repository, "old")
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

type indexedFaultSDKTransactionFS struct {
	sdkTransactionFS
	operations []string
	failAt     int
	failMode   string
}

func (fileSystem *indexedFaultSDKTransactionFS) run(operation string, effect func() error) error {
	fileSystem.operations = append(fileSystem.operations, operation)
	index := len(fileSystem.operations)
	if index == fileSystem.failAt && fileSystem.failMode == "before-error" {
		return errors.New("injected before-effect filesystem error")
	}
	if err := effect(); err != nil {
		return err
	}
	if index == fileSystem.failAt && fileSystem.failMode == "after-crash" {
		return errSDKTransactionCrash
	}
	return nil
}

func (fileSystem *indexedFaultSDKTransactionFS) WriteDurable(path string, data []byte, mode fs.FileMode) error {
	return fileSystem.run("write-"+filepath.Base(path), func() error {
		return fileSystem.sdkTransactionFS.WriteDurable(path, data, mode)
	})
}

func (fileSystem *indexedFaultSDKTransactionFS) Rename(oldPath, newPath string) error {
	return fileSystem.run("rename-"+filepath.Base(oldPath)+"-to-"+filepath.Base(newPath), func() error {
		return fileSystem.sdkTransactionFS.Rename(oldPath, newPath)
	})
}

func (fileSystem *indexedFaultSDKTransactionFS) Remove(path string) error {
	return fileSystem.run("remove-"+filepath.Base(path), func() error {
		return fileSystem.sdkTransactionFS.Remove(path)
	})
}

func (fileSystem *indexedFaultSDKTransactionFS) SyncDir(path string) error {
	return fileSystem.run("sync-"+filepath.Base(path), func() error {
		return fileSystem.sdkTransactionFS.SyncDir(path)
	})
}

type rollbackRestoreFaultFS struct {
	sdkTransactionFS
	mode               string
	forwardRenames     int
	rollbackFaultFired bool
}

func (fileSystem *rollbackRestoreFaultFS) Rename(oldPath, newPath string) error {
	isForward := strings.HasSuffix(newPath, sdkTransactionOldSuffix) || strings.HasSuffix(oldPath, sdkTransactionNewSuffix)
	if isForward {
		fileSystem.forwardRenames++
		if err := fileSystem.sdkTransactionFS.Rename(oldPath, newPath); err != nil {
			return err
		}
		if fileSystem.forwardRenames == 3 {
			return errors.New("force rollback")
		}
		return nil
	}
	if !fileSystem.rollbackFaultFired && strings.HasSuffix(oldPath, sdkTransactionOldSuffix) {
		fileSystem.rollbackFaultFired = true
		if fileSystem.mode == "before-error" {
			return errors.New("rollback restore fault")
		}
		if err := fileSystem.sdkTransactionFS.Rename(oldPath, newPath); err != nil {
			return err
		}
		return fmt.Errorf("rollback restore fault: %w", errSDKTransactionCrash)
	}
	return fileSystem.sdkTransactionFS.Rename(oldPath, newPath)
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
	writeSDKTransactionGeneration(t, repository, "old")
	writeSDKTransactionGeneration(t, staging, "new")
	return repository, staging
}

func writeSDKTransactionGeneration(t *testing.T, root, generation string) {
	t.Helper()
	for _, relative := range sdkUpdateTargets {
		path := sdkTransactionPath(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(generation+":"+relative), 0o644); err != nil {
			t.Fatal(err)
		}
	}
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

func assertSDKTransactionIsComplete(t *testing.T, repository string) {
	t.Helper()
	generation := ""
	for _, relative := range sdkUpdateTargets {
		data, err := os.ReadFile(sdkTransactionPath(repository, relative))
		if err != nil {
			t.Fatal(err)
		}
		current, _, ok := strings.Cut(string(data), ":")
		if !ok || (current != "old" && current != "new") {
			t.Fatalf("%s has unknown generation %q", relative, data)
		}
		if generation == "" {
			generation = current
		} else if generation != current {
			t.Fatalf("mixed SDK transaction generation: %s is %s, want %s", relative, current, generation)
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
