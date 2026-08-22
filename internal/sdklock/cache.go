package sdklock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	verificationCacheSchema   = 1
	canonicalVerifierVersion  = 1
	maximumCacheEnvelopeBytes = 1 << 20
)

type verificationCacheInput struct {
	Schema                  int    `json:"schema"`
	VerifierVersion         int    `json:"verifier_version"`
	RepositoryInputSHA256   string `json:"repository_input_sha256"`
	LockSHA256              string `json:"lock_sha256"`
	GOOS                    string `json:"goos"`
	GOARCH                  string `json:"goarch"`
	GoToolchain             string `json:"go_toolchain"`
	RustToolchain           string `json:"rust_toolchain"`
	CargoToolchain          string `json:"cargo_toolchain"`
	RequireHostCapabilities bool   `json:"require_host_capabilities"`
}

type verificationResultEnvelope struct {
	Schema        int                    `json:"schema"`
	Key           string                 `json:"key"`
	Input         verificationCacheInput `json:"input"`
	CheckoutKey   string                 `json:"checkout_key"`
	CheckoutTree  string                 `json:"checkout_tree"`
	Verification  Verification           `json:"verification"`
	PayloadSHA256 string                 `json:"payload_sha256"`
}

type verificationCacheOptions struct {
	cacheRoot       string
	toolchain       func(context.Context) (string, string, string, error)
	canonicalVerify func(context.Context, Lock, bool, string, string) (Verification, error)
}

func verifyCached(ctx context.Context, lock Lock, requireHostCapabilities bool, repositoryRoot string, options verificationCacheOptions) (Verification, error) {
	if err := lock.Validate(); err != nil {
		return Verification{}, err
	}
	repositoryRoot, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return Verification{}, fmt.Errorf("resolve repository root: %w", err)
	}
	repositoryRoot, err = filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return Verification{}, fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	if err := VerifyModuleIdentity(repositoryRoot, lock); err != nil {
		return Verification{}, err
	}
	cacheRoot := options.cacheRoot
	if cacheRoot == "" {
		cacheRoot = filepath.Join(repositoryRoot, "target", "nre-ci", "cache", "sdk")
	}
	cacheRoot, err = prepareVerificationCacheRoot(repositoryRoot, cacheRoot)
	if err != nil {
		return Verification{}, err
	}
	for _, child := range []string{"locks", "checkouts", "results"} {
		if err := prepareCacheDirectory(filepath.Join(cacheRoot, child)); err != nil {
			return Verification{}, err
		}
	}
	toolchain := options.toolchain
	if toolchain == nil {
		toolchain = toolchainIdentity
	}
	canonicalVerify := options.canonicalVerify
	if canonicalVerify == nil {
		canonicalVerify = verifyCanonical
	}
	input, key, err := buildVerificationCacheInput(ctx, lock, requireHostCapabilities, repositoryRoot, toolchain)
	if err != nil {
		return Verification{}, err
	}
	resultLock, err := acquireVerificationCacheLock(ctx, filepath.Join(cacheRoot, "locks", "result-"+key+".lock"))
	if err != nil {
		return Verification{}, err
	}
	defer resultLock.Close()

	checkoutKey, err := checkoutCacheKey(lock)
	if err != nil {
		return Verification{}, err
	}
	checkoutLock, err := acquireVerificationCacheLock(ctx, filepath.Join(cacheRoot, "locks", "checkout-"+cachePathComponent(checkoutKey)+".lock"))
	if err != nil {
		return Verification{}, err
	}
	checkout, checkoutReused, checkoutTree, err := ensureCachedCheckout(ctx, cacheRoot, checkoutKey, lock)
	closeErr := checkoutLock.Close()
	if err != nil {
		return Verification{}, err
	}
	if closeErr != nil {
		return Verification{}, closeErr
	}
	resultPath := filepath.Join(cacheRoot, "results", key+".json")
	if checkoutReused {
		if cached, ok := loadCachedVerification(resultPath, key, checkoutKey, checkoutTree, input, lock, requireHostCapabilities); ok {
			currentInput, currentKey, err := buildVerificationCacheInput(ctx, lock, requireHostCapabilities, repositoryRoot, toolchain)
			if err != nil {
				return Verification{}, err
			}
			if currentKey != key || currentInput != input {
				return Verification{}, fmt.Errorf("SDK verification inputs changed while reading the cache")
			}
			return cached, nil
		}
	}
	if err := os.RemoveAll(resultPath); err != nil {
		return Verification{}, fmt.Errorf("remove invalid SDK verification cache result: %w", err)
	}

	verification, err := canonicalVerify(ctx, lock, requireHostCapabilities, repositoryRoot, checkout)
	if err != nil {
		return Verification{}, err
	}
	if err := validateCachedVerification(verification, lock, requireHostCapabilities); err != nil {
		return Verification{}, fmt.Errorf("canonical SDK verification returned an invalid result: %w", err)
	}
	verifiedTree, err := validateCachedCheckout(ctx, checkout, lock)
	if err != nil {
		return Verification{}, fmt.Errorf("SDK checkout cache changed during canonical verification: %w", err)
	}
	if verifiedTree != checkoutTree {
		return Verification{}, fmt.Errorf("SDK checkout cache tree changed during canonical verification")
	}
	currentInput, currentKey, err := buildVerificationCacheInput(ctx, lock, requireHostCapabilities, repositoryRoot, toolchain)
	if err != nil {
		return Verification{}, err
	}
	if currentKey != key || currentInput != input {
		return Verification{}, fmt.Errorf("SDK verification inputs changed during canonical verification")
	}
	envelope := verificationResultEnvelope{
		Schema: verificationCacheSchema, Key: key, Input: input,
		CheckoutKey: checkoutKey, CheckoutTree: checkoutTree, Verification: verification,
	}
	envelope.PayloadSHA256, err = cacheEnvelopeDigest(envelope)
	if err != nil {
		return Verification{}, err
	}
	if err := writeCacheEnvelopeAtomically(resultPath, envelope); err != nil {
		return Verification{}, err
	}
	return verification, nil
}

func buildVerificationCacheInput(ctx context.Context, lock Lock, requireHostCapabilities bool, repositoryRoot string, toolchain func(context.Context) (string, string, string, error)) (verificationCacheInput, string, error) {
	repositoryDigest, err := repositoryInputDigest(ctx, repositoryRoot)
	if err != nil {
		return verificationCacheInput{}, "", fmt.Errorf("fingerprint SDK verification repository inputs: %w", err)
	}
	encodedLock, err := json.Marshal(lock)
	if err != nil {
		return verificationCacheInput{}, "", err
	}
	lockDigest := sha256.Sum256(encodedLock)
	goIdentity, rustIdentity, cargoIdentity, err := toolchain(ctx)
	if err != nil {
		return verificationCacheInput{}, "", err
	}
	input := verificationCacheInput{
		Schema: verificationCacheSchema, VerifierVersion: canonicalVerifierVersion,
		RepositoryInputSHA256: repositoryDigest, LockSHA256: hex.EncodeToString(lockDigest[:]),
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoToolchain: goIdentity,
		RustToolchain: rustIdentity, CargoToolchain: cargoIdentity,
		RequireHostCapabilities: requireHostCapabilities,
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return verificationCacheInput{}, "", err
	}
	digest := sha256.Sum256(encoded)
	return input, hex.EncodeToString(digest[:]), nil
}

func toolchainIdentity(ctx context.Context) (string, string, string, error) {
	identities := make([]string, 3)
	commands := []struct {
		name string
		args []string
	}{
		{name: "go", args: []string{"version"}},
		{name: "rustc", args: []string{"-Vv"}},
		{name: "cargo", args: []string{"-V"}},
	}
	for index, invocation := range commands {
		path, err := exec.LookPath(invocation.name)
		if err != nil {
			return "", "", "", fmt.Errorf("resolve %s toolchain identity: %w", invocation.name, err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return "", "", "", fmt.Errorf("resolve %s toolchain path: %w", invocation.name, err)
		}
		command := exec.CommandContext(ctx, path, invocation.args...)
		command.Env = commandEnvironment(invocation.name)
		output, err := command.CombinedOutput()
		if err != nil {
			return "", "", "", fmt.Errorf("read %s toolchain identity: %w: %s", invocation.name, err, strings.TrimSpace(string(output)))
		}
		identities[index] = filepath.Clean(path) + "\n" + strings.TrimSpace(string(output))
	}
	return identities[0], identities[1], identities[2], nil
}

func checkoutCacheKey(lock Lock) (string, error) {
	identity := struct {
		Repository       Repository `json:"repository"`
		ContractTreeOID  string     `json:"contract_tree_oid"`
		ValidatorTreeOID string     `json:"validator_tree_oid"`
	}{
		Repository: lock.Repository, ContractTreeOID: lock.SDK.ContractTreeOID,
		ValidatorTreeOID: lock.Artifacts.ValidatorTreeOID,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ensureCachedCheckout(ctx context.Context, cacheRoot, key string, lock Lock) (string, bool, string, error) {
	checkoutsRoot := filepath.Join(cacheRoot, "checkouts")
	if err := os.MkdirAll(checkoutsRoot, 0o755); err != nil {
		return "", false, "", err
	}
	pathKey := cachePathComponent(key)
	entry := filepath.Join(checkoutsRoot, pathKey)
	checkout := filepath.Join(entry, "repository")
	entryInfo, entryErr := os.Lstat(entry)
	if entryErr == nil && entryInfo.Mode()&os.ModeSymlink == 0 && entryInfo.IsDir() {
		if tree, err := validateCachedCheckout(ctx, checkout, lock); err == nil {
			return checkout, true, tree, nil
		}
	} else if entryErr != nil && !errors.Is(entryErr, os.ErrNotExist) {
		return "", false, "", entryErr
	}
	if err := os.RemoveAll(entry); err != nil {
		return "", false, "", fmt.Errorf("remove invalid SDK checkout cache: %w", err)
	}
	temporary, err := os.MkdirTemp(checkoutsRoot, ".c-"+pathKey[:8]+"-")
	if err != nil {
		return "", false, "", err
	}
	defer os.RemoveAll(temporary)
	temporaryCheckout, err := checkoutLockedRepository(ctx, temporary, lock.Repository)
	if err != nil {
		return "", false, "", err
	}
	tree, err := validateCachedCheckout(ctx, temporaryCheckout, lock)
	if err != nil {
		return "", false, "", fmt.Errorf("validate new SDK checkout cache: %w", err)
	}
	if err := os.Rename(temporary, entry); err != nil {
		return "", false, "", fmt.Errorf("publish SDK checkout cache: %w", err)
	}
	return checkout, false, tree, nil
}

func cachePathComponent(key string) string {
	const length = 20
	if len(key) <= length {
		return key
	}
	return key[:length]
}

func validateCachedCheckout(ctx context.Context, checkout string, lock Lock) (string, error) {
	for _, path := range []string{checkout, filepath.Join(checkout, ".git")} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("SDK checkout cache path %q is not a real directory", path)
		}
	}
	remote, err := run(ctx, checkout, "git", "remote", "get-url", "origin")
	if err != nil || normalizeGitOutput(remote) != lock.Repository.URL {
		return "", fmt.Errorf("SDK checkout cache remote identity mismatch")
	}
	head, err := run(ctx, checkout, "git", "rev-parse", "HEAD")
	if err != nil || normalizeGitOutput(head) != lock.Repository.Commit {
		return "", fmt.Errorf("SDK checkout cache commit identity mismatch")
	}
	status, err := run(ctx, checkout, "git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || len(bytes.TrimSpace(status)) != 0 {
		return "", fmt.Errorf("SDK checkout cache is dirty")
	}
	if _, err := run(ctx, checkout, "git", "cat-file", "-e", lock.Repository.Commit+"^{commit}"); err != nil {
		return "", fmt.Errorf("SDK checkout cache commit object is unreadable: %w", err)
	}
	tree, err := run(ctx, checkout, "git", "rev-parse", lock.Repository.Commit+"^{tree}")
	if err != nil || !fullOID.MatchString(normalizeGitOutput(tree)) {
		return "", fmt.Errorf("SDK checkout cache tree identity is unreadable")
	}
	contractTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:"+lock.SDK.ModuleDirectory)
	if err != nil || normalizeGitOutput(contractTree) != lock.SDK.ContractTreeOID {
		return "", fmt.Errorf("SDK checkout cache contract tree identity mismatch")
	}
	validatorTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:panel/backend-go/internal/controlplane/plugins")
	if err != nil || normalizeGitOutput(validatorTree) != lock.Artifacts.ValidatorTreeOID {
		return "", fmt.Errorf("SDK checkout cache validator tree identity mismatch")
	}
	return normalizeGitOutput(tree), nil
}

func loadCachedVerification(path, key, checkoutKey, checkoutTree string, input verificationCacheInput, lock Lock, requireHostCapabilities bool) (Verification, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumCacheEnvelopeBytes {
		return Verification{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Verification{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope verificationResultEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return Verification{}, false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Verification{}, false
	}
	if envelope.Schema != verificationCacheSchema || envelope.Key != key || envelope.Input != input || envelope.CheckoutKey != checkoutKey || envelope.CheckoutTree != checkoutTree {
		return Verification{}, false
	}
	digest, err := cacheEnvelopeDigest(envelope)
	if err != nil || digest != envelope.PayloadSHA256 {
		return Verification{}, false
	}
	if err := validateCachedVerification(envelope.Verification, lock, requireHostCapabilities); err != nil {
		return Verification{}, false
	}
	return envelope.Verification, true
}

func validateCachedVerification(verification Verification, lock Lock, requireHostCapabilities bool) error {
	if verification.Commit != lock.Repository.Commit ||
		verification.DescriptorSetSHA256 != lock.Artifacts.DescriptorSetSHA256 ||
		verification.PluginManifestSchemaSHA256 != lock.Artifacts.PluginSchemaSHA256 ||
		verification.CanonicalGuestSHA256 != lock.Artifacts.CanonicalGuestSHA256 {
		return fmt.Errorf("verification identity does not match the SDK lock")
	}
	wantMissing := lock.MissingCapabilities()
	if len(verification.MissingCapabilities) != len(wantMissing) {
		return fmt.Errorf("verification missing-capability result does not match the SDK lock")
	}
	for index := range wantMissing {
		if verification.MissingCapabilities[index] != wantMissing[index] {
			return fmt.Errorf("verification missing-capability result does not match the SDK lock")
		}
	}
	if requireHostCapabilities && len(wantMissing) != 0 {
		return fmt.Errorf("required host capabilities are unavailable")
	}
	return nil
}

func cacheEnvelopeDigest(envelope verificationResultEnvelope) (string, error) {
	envelope.PayloadSHA256 = ""
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func writeCacheEnvelopeAtomically(path string, envelope verificationResultEnvelope) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".result-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish SDK verification cache result: %w", err)
	}
	return nil
}

func prepareVerificationCacheRoot(repositoryRoot, requested string) (string, error) {
	requested, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(repositoryRoot, requested)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("SDK verification cache must stay below the repository root")
	}
	current := repositoryRoot
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("SDK verification cache path %q is not a real directory", current)
		}
	}
	return requested, nil
}

func prepareCacheDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("SDK verification cache path %q is not a real directory", path)
	}
	return nil
}

func repositoryInputDigest(ctx context.Context, root string) (string, error) {
	paths, err := repositoryInputPaths(ctx, root)
	if err != nil {
		return "", err
	}
	records := make([]string, 0, len(paths))
	for _, relative := range paths {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			records = append(records, relative+"\x00missing")
			continue
		}
		if err != nil {
			return "", err
		}
		var data []byte
		kind := "file"
		switch {
		case info.Mode().IsRegular():
			data, err = os.ReadFile(path)
		case info.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
			var target string
			target, err = os.Readlink(path)
			data = []byte(target)
		default:
			return "", fmt.Errorf("repository input %q is not a regular file or symbolic link", relative)
		}
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		records = append(records, relative+"\x00"+kind+"\x00"+info.Mode().String()+"\x00"+hex.EncodeToString(digest[:]))
	}
	sort.Strings(records)
	digest := sha256.Sum256([]byte(strings.Join(records, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func repositoryInputPaths(ctx context.Context, root string) ([]string, error) {
	gitDirectory := filepath.Join(root, ".git")
	if _, err := os.Lstat(gitDirectory); err == nil {
		command := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
		output, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("enumerate Git repository inputs: %w", err)
		}
		seen := make(map[string]bool)
		var paths []string
		for _, item := range bytes.Split(output, []byte{0}) {
			if len(item) == 0 {
				continue
			}
			relative := filepath.ToSlash(filepath.Clean(string(item)))
			if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, "../") || seen[relative] {
				return nil, fmt.Errorf("Git returned invalid repository input path %q", relative)
			}
			seen[relative] = true
			paths = append(paths, relative)
		}
		sort.Strings(paths)
		return paths, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".cache", "target", "dist", "coverage", "runtime-data", ".idea", ".vscode":
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}
