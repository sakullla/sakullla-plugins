package sdklock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Verification struct {
	Commit               string   `json:"commit"`
	DescriptorSetSHA256  string   `json:"descriptor_set_sha256"`
	CanonicalGuestSHA256 string   `json:"canonical_guest_sha256"`
	MissingCapabilities  []string `json:"missing_capabilities"`
}

func Verify(ctx context.Context, lock Lock, requireHostCapabilities bool) (Verification, error) {
	root, err := os.MkdirTemp("", "sakullla-sdk-checkout-")
	if err != nil {
		return Verification{}, err
	}
	defer os.RemoveAll(root)
	checkout := filepath.Join(root, "repository")
	if err := os.Mkdir(checkout, 0o755); err != nil {
		return Verification{}, err
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", lock.Repository.URL},
		{"fetch", "--quiet", "--depth=1", "origin", lock.Repository.Commit},
		{"checkout", "--quiet", "--detach", "FETCH_HEAD"},
	} {
		if _, err := run(ctx, checkout, "git", args...); err != nil {
			return Verification{}, fmt.Errorf("establish clean SDK checkout at %s: %w", lock.Repository.Commit, err)
		}
	}
	head, err := run(ctx, checkout, "git", "rev-parse", "HEAD")
	if err != nil || normalizeGitOutput(head) != lock.Repository.Commit {
		return Verification{}, fmt.Errorf("clean checkout commit mismatch")
	}
	contractTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:"+lock.SDK.ModuleDirectory)
	if err != nil || normalizeGitOutput(contractTree) != lock.SDK.ContractTreeOID {
		return Verification{}, fmt.Errorf("canonical SDK tree digest mismatch")
	}
	validatorTree, err := run(ctx, checkout, "git", "rev-parse", "HEAD:panel/backend-go/internal/controlplane/plugins")
	if err != nil || normalizeGitOutput(validatorTree) != lock.Artifacts.ValidatorTreeOID {
		return Verification{}, fmt.Errorf("validator tree digest mismatch")
	}
	for path, expected := range map[string]string{
		"plugin-sdk/policy/v1/policy.proto": lock.Artifacts.PolicyProtoSHA256,
		"plugin-sdk/rpc/v1/plugin.proto":    lock.Artifacts.RPCProtoSHA256,
	} {
		actual, err := gitBlobSHA256(ctx, checkout, path)
		if err != nil || actual != expected {
			return Verification{}, fmt.Errorf("descriptor source %s digest mismatch: got %s, want %s", path, actual, expected)
		}
	}
	sdkRoot := filepath.Join(checkout, filepath.FromSlash(lock.SDK.ModuleDirectory))
	moduleFile, err := os.ReadFile(filepath.Join(sdkRoot, "go.mod"))
	if err != nil || goModulePath(moduleFile) != lock.SDK.ModulePath {
		return Verification{}, fmt.Errorf("canonical SDK module path mismatch")
	}
	if output, err := run(ctx, sdkRoot, "go", "test", "./..."); err != nil {
		return Verification{}, fmt.Errorf("canonical SDK tests failed: %w: %s", err, output)
	}
	descriptorDigest, err := descriptorSetDigest(ctx, root, sdkRoot, lock.SDK.ModulePath)
	if err != nil || descriptorDigest != lock.Artifacts.DescriptorSetSHA256 {
		return Verification{}, fmt.Errorf("canonical descriptor set digest mismatch: %v", err)
	}
	guestHex, err := run(ctx, sdkRoot, "go", "run", "./compatfixture/cmd/generate")
	if err != nil {
		return Verification{}, fmt.Errorf("canonical compatibility guest generation failed: %w", err)
	}
	guestBytes, err := hex.DecodeString(strings.TrimSpace(string(guestHex)))
	if err != nil {
		return Verification{}, fmt.Errorf("decode canonical compatibility guest: %w", err)
	}
	guestSum := sha256.Sum256(guestBytes)
	guestDigest := hex.EncodeToString(guestSum[:])
	if guestDigest != lock.Artifacts.CanonicalGuestSHA256 {
		return Verification{}, fmt.Errorf("canonical compatibility guest digest mismatch")
	}
	for _, capability := range lock.RequiredCapabilities {
		if !capability.Available {
			continue
		}
		data, err := os.ReadFile(filepath.Join(checkout, filepath.FromSlash(capability.EvidencePath)))
		if err != nil {
			return Verification{}, fmt.Errorf("read capability %s evidence: %w", capability.ID, err)
		}
		for _, symbol := range capability.Symbols {
			if !strings.Contains(string(data), symbol) {
				return Verification{}, fmt.Errorf("capability %s evidence symbol %q is missing", capability.ID, symbol)
			}
		}
	}
	missing := lock.MissingCapabilities()
	result := Verification{Commit: lock.Repository.Commit, DescriptorSetSHA256: descriptorDigest, CanonicalGuestSHA256: guestDigest, MissingCapabilities: missing}
	if requireHostCapabilities && len(missing) != 0 {
		return result, fmt.Errorf("required host capabilities are unavailable: %s", strings.Join(missing, "; "))
	}
	return result, nil
}

func descriptorSetDigest(ctx context.Context, temporaryRoot, sdkRoot, modulePath string) (string, error) {
	probe := filepath.Join(temporaryRoot, "descriptor-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		return "", err
	}
	module := fmt.Sprintf("module sdkprobe\n\ngo 1.26.5\n\nrequire %s v0.0.0\nreplace %s => %s\n", modulePath, modulePath, filepath.ToSlash(sdkRoot))
	program := fmt.Sprintf("package main\nimport (\"crypto/sha256\"; \"fmt\"; \"%s/protoschema\")\nfunc main(){ b,e:=protoschema.DescriptorSetBytes(); if e!=nil { panic(e) }; fmt.Printf(\"%%x\\n\", sha256.Sum256(b)) }\n", modulePath)
	if err := os.WriteFile(filepath.Join(probe, "go.mod"), []byte(module), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(probe, "main.go"), []byte(program), 0o644); err != nil {
		return "", err
	}
	output, err := run(ctx, probe, "go", "run", ".")
	if err != nil {
		return "", err
	}
	return normalizeGitOutput(output), nil
}

func gitBlobSHA256(ctx context.Context, checkout, path string) (string, error) {
	data, err := run(ctx, checkout, "git", "cat-file", "blob", "HEAD:"+path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func goModulePath(goMod []byte) string {
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`)
		}
	}
	return ""
}

func run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
