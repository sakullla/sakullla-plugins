package sdklock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Refresh resolves the configured immutable selector and recalculates every
// derived SDK lock identity from Git object bytes and generated contracts.
func Refresh(ctx context.Context, lock Lock) (Lock, error) {
	if lock.SchemaVersion != 1 || lock.Repository.URL == "" || lock.SDK.ModuleDirectory != "plugin-sdk" || lock.SDK.ModulePath == "" || lock.SDK.PackagePath == "" {
		return Lock{}, fmt.Errorf("SDK lock selector and canonical module identity are required")
	}
	if lock.Repository.Branch != "" && lock.Repository.Tag != "" {
		return Lock{}, fmt.Errorf("SDK lock repository branch and tag are mutually exclusive")
	}
	if lock.Repository.Branch != "" && !validGitRefName(lock.Repository.Branch) {
		return Lock{}, fmt.Errorf("SDK lock repository branch is invalid")
	}
	if lock.Repository.Tag != "" && !validGitRefName(lock.Repository.Tag) {
		return Lock{}, fmt.Errorf("SDK lock repository tag is invalid")
	}

	temporaryRoot, err := os.MkdirTemp("", "sakullla-sdk-refresh-")
	if err != nil {
		return Lock{}, err
	}
	defer os.RemoveAll(temporaryRoot)
	checkout := filepath.Join(temporaryRoot, "repository")
	if err := os.Mkdir(checkout, 0o755); err != nil {
		return Lock{}, err
	}
	fetchTarget := lock.Repository.Commit
	if lock.Repository.Branch != "" {
		fetchTarget = "refs/heads/" + lock.Repository.Branch
	} else if lock.Repository.Tag != "" {
		fetchTarget = "refs/tags/" + lock.Repository.Tag
	}
	if fetchTarget == "" {
		return Lock{}, fmt.Errorf("SDK lock repository selector is required")
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "core.autocrlf", "false"},
		{"config", "core.eol", "lf"},
		{"remote", "add", "origin", lock.Repository.URL},
		{"fetch", "--quiet", "--depth=1", "origin", fetchTarget},
	} {
		if _, err := run(ctx, checkout, "git", args...); err != nil {
			return Lock{}, fmt.Errorf("refresh SDK selector %s: %w", fetchTarget, err)
		}
	}
	resolvedBytes, err := run(ctx, checkout, "git", "rev-parse", "FETCH_HEAD^{commit}")
	if err != nil {
		return Lock{}, fmt.Errorf("resolve SDK selector %s: %w", fetchTarget, err)
	}
	resolved := normalizeGitOutput(resolvedBytes)
	if _, err := run(ctx, checkout, "git", "checkout", "--quiet", "--detach", resolved); err != nil {
		return Lock{}, fmt.Errorf("checkout refreshed SDK commit: %w", err)
	}
	lock.Repository.Commit = resolved

	contractTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:"+lock.SDK.ModuleDirectory)
	if err != nil {
		return Lock{}, err
	}
	lock.SDK.ContractTreeOID = normalizeGitOutput(contractTree)
	validatorTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:panel/backend-go/internal/controlplane/plugins")
	if err != nil {
		return Lock{}, err
	}
	lock.Artifacts.ValidatorTreeOID = normalizeGitOutput(validatorTree)

	for path, target := range map[string]*string{
		"plugin-sdk/policy/v1/policy.proto":                   &lock.Artifacts.PolicyProtoSHA256,
		"plugin-sdk/rpc/v1/plugin.proto":                      &lock.Artifacts.RPCProtoSHA256,
		"plugin-sdk/go/schema/plugin-manifest-v1.schema.json": &lock.Artifacts.PluginSchemaSHA256,
	} {
		digest, err := gitBlobSHA256(ctx, checkout, path)
		if err != nil {
			return Lock{}, err
		}
		*target = digest
	}

	sdkRoot := filepath.Join(checkout, filepath.FromSlash(lock.SDK.ModuleDirectory))
	descriptorDigest, err := descriptorSetDigest(ctx, temporaryRoot, sdkRoot, lock.SDK.ModulePath, lock.SDK.PackagePath)
	if err != nil {
		return Lock{}, fmt.Errorf("generate canonical descriptor set: %w", err)
	}
	lock.Artifacts.DescriptorSetSHA256 = descriptorDigest
	packageDirectory, err := packageDirectory(lock.SDK.ModulePath, lock.SDK.PackagePath)
	if err != nil {
		return Lock{}, err
	}
	guestHex, err := run(ctx, sdkRoot, "go", "run", "./"+filepath.ToSlash(filepath.Join(packageDirectory, "compatfixture", "cmd", "generate")))
	if err != nil {
		return Lock{}, fmt.Errorf("generate canonical compatibility guest: %w", err)
	}
	guestBytes, err := hex.DecodeString(strings.TrimSpace(string(guestHex)))
	if err != nil {
		return Lock{}, fmt.Errorf("decode canonical compatibility guest: %w", err)
	}
	guestSum := sha256.Sum256(guestBytes)
	lock.Artifacts.CanonicalGuestSHA256 = hex.EncodeToString(guestSum[:])
	lock.CapabilityContractSHA256 = CapabilityDigest(lock.RequiredCapabilities)
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// Write atomically replaces one canonical lock after all derived values have
// been calculated and validated.
func Write(path string, lock Lock) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sdk-lock-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
