package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	sdkTransactionManifestName = ".nre-sdk-update-transaction.json"
	sdkTransactionManifestTemp = ".nre-sdk-update-transaction.json.tmp"
	sdkTransactionNewSuffix    = ".nre-sdk-update.new"
	sdkTransactionOldSuffix    = ".nre-sdk-update.old"
)

var sdkUpdateTargets = []string{
	"go.mod",
	"go.sum",
	"crates/nre-policy-guest/src/abi_generated.rs",
	"sdk.lock.json",
}

// errSDKTransactionCrash is test-only fault vocabulary. Production filesystem
// operations never return it; tests use it to model termination after a rename
// without allowing the live process to roll the transaction back.
var errSDKTransactionCrash = errors.New("simulated SDK transaction process crash")

type sdkTransactionManifest struct {
	SchemaVersion int                   `json:"schema_version"`
	Files         []sdkTransactionEntry `json:"files"`
}

type sdkTransactionEntry struct {
	Path      string `json:"path"`
	OldSHA256 string `json:"old_sha256"`
	NewSHA256 string `json:"new_sha256"`
}

type sdkTransactionFS interface {
	ReadFile(string) ([]byte, error)
	Stat(string) (fs.FileInfo, error)
	WriteDurable(string, []byte, fs.FileMode) error
	Rename(string, string) error
	Remove(string) error
	SyncDir(string) error
}

type osSDKTransactionFS struct{}

func (osSDKTransactionFS) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (osSDKTransactionFS) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }
func (osSDKTransactionFS) Rename(oldPath, newPath string) error  { return os.Rename(oldPath, newPath) }
func (osSDKTransactionFS) Remove(path string) error              { return os.Remove(path) }
func (osSDKTransactionFS) SyncDir(path string) error             { return syncSDKTransactionDirectory(path) }

func (osSDKTransactionFS) WriteDurable(path string, data []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func promoteSDKUpdate(repositoryRoot, stagingRoot string, relatives []string) error {
	return promoteSDKUpdateWithFS(repositoryRoot, stagingRoot, relatives, osSDKTransactionFS{})
}

func promoteSDKUpdateWithFS(repositoryRoot, stagingRoot string, relatives []string, fileSystem sdkTransactionFS) error {
	if err := validateSDKTransactionTargets(relatives); err != nil {
		return err
	}
	if err := recoverSDKUpdateWithFS(repositoryRoot, fileSystem); err != nil {
		return fmt.Errorf("recover previous SDK update transaction: %w", err)
	}

	manifest := sdkTransactionManifest{SchemaVersion: 1, Files: make([]sdkTransactionEntry, 0, len(relatives))}
	abortBeforeManifest := func(operationErr error) error {
		return errors.Join(operationErr, cleanupSDKPreManifest(repositoryRoot, manifest.Files, fileSystem))
	}
	for _, relative := range relatives {
		target := sdkTransactionPath(repositoryRoot, relative)
		oldData, err := fileSystem.ReadFile(target)
		if err != nil {
			return abortBeforeManifest(fmt.Errorf("read SDK update target %s: %w", relative, err))
		}
		info, err := fileSystem.Stat(target)
		if err != nil {
			return abortBeforeManifest(fmt.Errorf("inspect SDK update target %s: %w", relative, err))
		}
		newData, err := fileSystem.ReadFile(sdkTransactionPath(stagingRoot, relative))
		if err != nil {
			return abortBeforeManifest(fmt.Errorf("read staged SDK update %s: %w", relative, err))
		}
		entry := sdkTransactionEntry{
			Path:      relative,
			OldSHA256: sdkTransactionDigest(oldData),
			NewSHA256: sdkTransactionDigest(newData),
		}
		manifest.Files = append(manifest.Files, entry)
		newPath := target + sdkTransactionNewSuffix
		if err := fileSystem.WriteDurable(newPath, newData, info.Mode()); err != nil {
			return abortBeforeManifest(fmt.Errorf("write durable staged SDK update %s: %w", relative, err))
		}
		if err := fileSystem.SyncDir(filepath.Dir(newPath)); err != nil {
			return abortBeforeManifest(fmt.Errorf("sync staged SDK update directory %s: %w", relative, err))
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	manifestTemp := filepath.Join(repositoryRoot, sdkTransactionManifestTemp)
	manifestPath := filepath.Join(repositoryRoot, sdkTransactionManifestName)
	if err := fileSystem.WriteDurable(manifestTemp, encoded, 0o600); err != nil {
		return abortBeforeManifest(fmt.Errorf("write durable SDK transaction manifest: %w", err))
	}
	if err := fileSystem.Rename(manifestTemp, manifestPath); err != nil {
		return abortBeforeManifest(fmt.Errorf("publish SDK transaction manifest: %w", err))
	}
	if err := fileSystem.SyncDir(repositoryRoot); err != nil {
		return failSDKTransaction(repositoryRoot, manifest, fileSystem, fmt.Errorf("sync SDK transaction manifest directory: %w", err))
	}

	if err := rollSDKTransactionForward(repositoryRoot, manifest, fileSystem); err != nil {
		if errors.Is(err, errSDKTransactionCrash) {
			return err
		}
		return failSDKTransaction(repositoryRoot, manifest, fileSystem, err)
	}
	return nil
}

func recoverSDKUpdateWithFS(repositoryRoot string, fileSystem sdkTransactionFS) error {
	manifestPath := filepath.Join(repositoryRoot, sdkTransactionManifestName)
	encoded, err := fileSystem.ReadFile(manifestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return cleanupSDKOrphans(repositoryRoot, fileSystem)
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest sdkTransactionManifest
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode SDK transaction manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("SDK transaction manifest contains trailing data")
	}
	if err := validateSDKTransactionManifest(manifest); err != nil {
		return err
	}
	var forwardErr error
	if sdkTransactionCanRollForward(repositoryRoot, manifest, fileSystem) {
		if err := rollSDKTransactionForward(repositoryRoot, manifest, fileSystem); err == nil {
			return nil
		} else {
			forwardErr = fmt.Errorf("complete SDK transaction new generation: %w", err)
		}
	}
	if sdkTransactionCanRollback(repositoryRoot, manifest, fileSystem) {
		if err := rollbackSDKTransaction(repositoryRoot, manifest, fileSystem); err != nil {
			return errors.Join(forwardErr, fmt.Errorf("restore SDK transaction old generation: %w", err))
		}
		return nil
	}
	return errors.Join(forwardErr, fmt.Errorf("SDK transaction cannot recover a complete old or new generation"))
}

func rollSDKTransactionForward(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS) error {
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		newPath := target + sdkTransactionNewSuffix
		oldPath := target + sdkTransactionOldSuffix
		targetDigest, targetExists, err := sdkTransactionFileDigest(fileSystem, target)
		if err != nil {
			return err
		}
		if targetExists && targetDigest == entry.NewSHA256 {
			continue
		}
		if targetExists {
			if targetDigest != entry.OldSHA256 {
				return fmt.Errorf("SDK transaction target %s has unknown content", entry.Path)
			}
			if _, oldExists, err := sdkTransactionFileDigest(fileSystem, oldPath); err != nil {
				return err
			} else if oldExists {
				return fmt.Errorf("SDK transaction target and backup both contain old generation for %s", entry.Path)
			}
			if err := sdkTransactionRename(fileSystem, target, oldPath); err != nil {
				return fmt.Errorf("backup SDK transaction target %s: %w", entry.Path, err)
			}
		}
		newDigest, newExists, err := sdkTransactionFileDigest(fileSystem, newPath)
		if err != nil {
			return err
		}
		if !newExists || newDigest != entry.NewSHA256 {
			return fmt.Errorf("SDK transaction staged generation is unavailable for %s", entry.Path)
		}
		if err := sdkTransactionRename(fileSystem, newPath, target); err != nil {
			return fmt.Errorf("promote SDK transaction target %s: %w", entry.Path, err)
		}
	}
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		if digest, exists, err := sdkTransactionFileDigest(fileSystem, target); err != nil || !exists || digest != entry.NewSHA256 {
			return fmt.Errorf("SDK transaction new generation verification failed for %s: %v", entry.Path, err)
		}
	}
	return cleanupSDKTransaction(repositoryRoot, manifest, fileSystem)
}

func rollbackSDKTransaction(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS) error {
	var failures []error
	for index := len(manifest.Files) - 1; index >= 0; index-- {
		entry := manifest.Files[index]
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		oldPath := target + sdkTransactionOldSuffix
		targetDigest, targetExists, err := sdkTransactionFileDigest(fileSystem, target)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if targetExists && targetDigest == entry.OldSHA256 {
			continue
		}
		oldDigest, oldExists, err := sdkTransactionFileDigest(fileSystem, oldPath)
		if err != nil || !oldExists || oldDigest != entry.OldSHA256 {
			failures = append(failures, fmt.Errorf("SDK transaction old generation is unavailable for %s: %v", entry.Path, err))
			continue
		}
		if targetExists {
			if err := sdkTransactionRemove(fileSystem, target); err != nil {
				failures = append(failures, fmt.Errorf("remove failed SDK target %s: %w", entry.Path, err))
				continue
			}
		}
		if err := sdkTransactionRename(fileSystem, oldPath, target); err != nil {
			failures = append(failures, fmt.Errorf("restore SDK target %s: %w", entry.Path, err))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		if digest, exists, err := sdkTransactionFileDigest(fileSystem, target); err != nil || !exists || digest != entry.OldSHA256 {
			return fmt.Errorf("SDK transaction old generation verification failed for %s: %v", entry.Path, err)
		}
	}
	return cleanupSDKTransaction(repositoryRoot, manifest, fileSystem)
}

func failSDKTransaction(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS, operationErr error) error {
	rollbackErr := rollbackSDKTransaction(repositoryRoot, manifest, fileSystem)
	if rollbackErr != nil {
		return errors.Join(operationErr, fmt.Errorf("rollback SDK transaction: %w", rollbackErr))
	}
	return operationErr
}

func cleanupSDKTransaction(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS) error {
	var failures []error
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		for _, path := range []string{target + sdkTransactionNewSuffix, target + sdkTransactionOldSuffix} {
			if err := sdkTransactionRemove(fileSystem, path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	if err := sdkTransactionRemove(fileSystem, filepath.Join(repositoryRoot, sdkTransactionManifestName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func cleanupSDKPreManifest(repositoryRoot string, entries []sdkTransactionEntry, fileSystem sdkTransactionFS) error {
	var failures []error
	for _, entry := range entries {
		path := sdkTransactionPath(repositoryRoot, entry.Path) + sdkTransactionNewSuffix
		if err := sdkTransactionRemove(fileSystem, path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	for _, path := range []string{filepath.Join(repositoryRoot, sdkTransactionManifestTemp)} {
		if err := sdkTransactionRemove(fileSystem, path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func cleanupSDKOrphans(repositoryRoot string, fileSystem sdkTransactionFS) error {
	for _, relative := range sdkUpdateTargets {
		target := sdkTransactionPath(repositoryRoot, relative)
		if _, exists, err := sdkTransactionFileDigest(fileSystem, target+sdkTransactionOldSuffix); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("orphan SDK transaction backup exists without durable manifest: %s", relative)
		}
		if err := sdkTransactionRemove(fileSystem, target+sdkTransactionNewSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := sdkTransactionRemove(fileSystem, filepath.Join(repositoryRoot, sdkTransactionManifestTemp)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func sdkTransactionCanRollForward(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS) bool {
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		targetDigest, targetExists, err := sdkTransactionFileDigest(fileSystem, target)
		if err != nil {
			return false
		}
		newDigest, newExists, err := sdkTransactionFileDigest(fileSystem, target+sdkTransactionNewSuffix)
		if err != nil || !((targetExists && targetDigest == entry.NewSHA256) || (newExists && newDigest == entry.NewSHA256)) {
			return false
		}
	}
	return true
}

func sdkTransactionCanRollback(repositoryRoot string, manifest sdkTransactionManifest, fileSystem sdkTransactionFS) bool {
	for _, entry := range manifest.Files {
		target := sdkTransactionPath(repositoryRoot, entry.Path)
		targetDigest, targetExists, err := sdkTransactionFileDigest(fileSystem, target)
		if err != nil {
			return false
		}
		oldDigest, oldExists, err := sdkTransactionFileDigest(fileSystem, target+sdkTransactionOldSuffix)
		if err != nil || !((targetExists && targetDigest == entry.OldSHA256) || (oldExists && oldDigest == entry.OldSHA256)) {
			return false
		}
	}
	return true
}

func validateSDKTransactionTargets(relatives []string) error {
	if len(relatives) != len(sdkUpdateTargets) {
		return fmt.Errorf("SDK transaction requires exactly four canonical targets")
	}
	for index := range sdkUpdateTargets {
		if relatives[index] != sdkUpdateTargets[index] {
			return fmt.Errorf("SDK transaction target %d = %q, want %q", index, relatives[index], sdkUpdateTargets[index])
		}
	}
	return nil
}

func validateSDKTransactionManifest(manifest sdkTransactionManifest) error {
	if manifest.SchemaVersion != 1 || len(manifest.Files) != len(sdkUpdateTargets) {
		return fmt.Errorf("invalid SDK transaction manifest shape")
	}
	for index, entry := range manifest.Files {
		if entry.Path != sdkUpdateTargets[index] || len(entry.OldSHA256) != 64 || len(entry.NewSHA256) != 64 {
			return fmt.Errorf("invalid SDK transaction manifest entry %d", index)
		}
		if _, err := hex.DecodeString(entry.OldSHA256); err != nil {
			return fmt.Errorf("invalid SDK transaction old digest %d", index)
		}
		if _, err := hex.DecodeString(entry.NewSHA256); err != nil {
			return fmt.Errorf("invalid SDK transaction new digest %d", index)
		}
	}
	return nil
}

func sdkTransactionRename(fileSystem sdkTransactionFS, oldPath, newPath string) error {
	if err := fileSystem.Rename(oldPath, newPath); err != nil {
		return err
	}
	if err := fileSystem.SyncDir(filepath.Dir(oldPath)); err != nil {
		return err
	}
	if filepath.Dir(oldPath) != filepath.Dir(newPath) {
		return fileSystem.SyncDir(filepath.Dir(newPath))
	}
	return nil
}

func sdkTransactionRemove(fileSystem sdkTransactionFS, path string) error {
	if err := fileSystem.Remove(path); err != nil {
		return err
	}
	return fileSystem.SyncDir(filepath.Dir(path))
}

func sdkTransactionFileDigest(fileSystem sdkTransactionFS, path string) (string, bool, error) {
	data, err := fileSystem.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return sdkTransactionDigest(data), true, nil
}

func sdkTransactionDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sdkTransactionPath(root, relative string) string {
	return filepath.Join(root, filepath.FromSlash(relative))
}
