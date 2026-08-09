package sdklock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

func Verify(ctx context.Context, lock Lock, requireHostCapabilities bool, repositoryRoot string) (Verification, error) {
	root, err := os.MkdirTemp("", "sakullla-sdk-checkout-")
	if err != nil {
		return Verification{}, err
	}
	defer os.RemoveAll(root)
	checkout := filepath.Join(root, "repository")
	if err := os.Mkdir(checkout, 0o755); err != nil {
		return Verification{}, err
	}
	fetchTarget := lock.Repository.Commit
	selector := "commit"
	if lock.Repository.Branch != "" {
		fetchTarget = "refs/heads/" + lock.Repository.Branch
		selector = "branch " + lock.Repository.Branch
	} else if lock.Repository.Tag != "" {
		fetchTarget = "refs/tags/" + lock.Repository.Tag
		selector = "tag " + lock.Repository.Tag
	}
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "core.autocrlf", "false"},
		{"config", "core.eol", "lf"},
		{"remote", "add", "origin", lock.Repository.URL},
		{"fetch", "--quiet", "--depth=1", "origin", fetchTarget},
	} {
		if _, err := run(ctx, checkout, "git", args...); err != nil {
			return Verification{}, fmt.Errorf("establish clean SDK checkout at %s: %w", lock.Repository.Commit, err)
		}
	}
	resolved, err := run(ctx, checkout, "git", "rev-parse", "FETCH_HEAD^{commit}")
	if err != nil || normalizeGitOutput(resolved) != lock.Repository.Commit {
		return Verification{}, fmt.Errorf("repository %s does not resolve to locked commit %s", selector, lock.Repository.Commit)
	}
	if _, err := run(ctx, checkout, "git", "checkout", "--quiet", "--detach", lock.Repository.Commit); err != nil {
		return Verification{}, fmt.Errorf("establish clean SDK checkout at %s: %w", lock.Repository.Commit, err)
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
	descriptorDigest, err := descriptorSetDigest(ctx, root, sdkRoot, lock.SDK.ModulePath, lock.SDK.PackagePath)
	if err != nil || descriptorDigest != lock.Artifacts.DescriptorSetSHA256 {
		return Verification{}, fmt.Errorf("canonical descriptor set digest mismatch: %v", err)
	}
	packageDirectory, err := packageDirectory(lock.SDK.ModulePath, lock.SDK.PackagePath)
	if err != nil {
		return Verification{}, err
	}
	guestGenerator := "./" + filepath.ToSlash(filepath.Join(packageDirectory, "compatfixture", "cmd", "generate"))
	guestHex, err := run(ctx, sdkRoot, "go", "run", guestGenerator)
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
	if err := verifyRustProjection(ctx, root, repositoryRoot, sdkRoot, lock.SDK.ModulePath); err != nil {
		return Verification{}, err
	}
	for _, capability := range lock.RequiredCapabilities {
		if !capability.Available {
			continue
		}
		if err := verifyCapability(ctx, root, checkout, sdkRoot, lock.SDK.ModulePath, lock.SDK.PackagePath, capability); err != nil {
			return Verification{}, err
		}
	}
	missing := lock.MissingCapabilities()
	result := Verification{Commit: lock.Repository.Commit, DescriptorSetSHA256: descriptorDigest, CanonicalGuestSHA256: guestDigest, MissingCapabilities: missing}
	if requireHostCapabilities && len(missing) != 0 {
		return result, fmt.Errorf("required host capabilities are unavailable: %s", strings.Join(missing, "; "))
	}
	return result, nil
}

func verifyRustProjection(ctx context.Context, temporaryRoot, repositoryRoot, sdkRoot, modulePath string) error {
	if repositoryRoot == "" {
		return fmt.Errorf("repository root is required for lock-resolved Rust projection verification")
	}
	expectedPath := filepath.Join(repositoryRoot, "crates", "nre-policy-guest", "src", "abi_generated.rs")
	expected, err := os.ReadFile(expectedPath)
	if err != nil {
		return fmt.Errorf("read repository Rust SDK projection: %w", err)
	}
	projectionRoot := filepath.Join(temporaryRoot, "projection-workspace")
	if err := os.Mkdir(projectionRoot, 0o755); err != nil {
		return err
	}
	module := fmt.Sprintf("module github.com/sakullla/sakullla-plugins\n\ngo 1.26.5\n\nrequire %s v0.0.0\nreplace %s => %s\n", modulePath, modulePath, filepath.ToSlash(sdkRoot))
	if err := os.WriteFile(filepath.Join(projectionRoot, "go.mod"), []byte(module), 0o644); err != nil {
		return err
	}
	sourceDirectory := filepath.Join(repositoryRoot, "internal", "ci", "sdk", "cmd", "generate-policy-rust")
	targetDirectory := filepath.Join(projectionRoot, "cmd", "generate-policy-rust")
	if err := copyGoSources(sourceDirectory, targetDirectory); err != nil {
		return fmt.Errorf("copy repository Rust SDK generator: %w", err)
	}
	actualPath := filepath.Join(temporaryRoot, "abi_generated.rs")
	if output, err := run(ctx, projectionRoot, "go", "run", "-mod=mod", "./cmd/generate-policy-rust", "--output", actualPath); err != nil {
		return fmt.Errorf("generate Rust SDK projection from lock-resolved checkout: %w: %s", err, output)
	}
	actual, err := os.ReadFile(actualPath)
	if err != nil {
		return fmt.Errorf("read lock-resolved Rust SDK projection: %w", err)
	}
	if !bytes.Equal(expected, actual) {
		return fmt.Errorf("repository Rust SDK projection differs from lock-resolved canonical SDK")
	}
	return nil
}

func copyGoSources(source, target string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	copied := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("generator source %s is not a regular file", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), data, 0o644); err != nil {
			return err
		}
		copied++
	}
	if copied == 0 {
		return fmt.Errorf("generator has no Go sources")
	}
	return nil
}

func verifyCapability(ctx context.Context, temporaryRoot, checkout, sdkRoot, modulePath, packagePath string, capability Capability) error {
	data, err := gitRegularBlob(ctx, checkout, capability.EvidencePath)
	if err != nil {
		return fmt.Errorf("read capability %s evidence: %w", capability.ID, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), capability.EvidencePath, data, 0)
	if err != nil {
		return fmt.Errorf("parse capability %s evidence as Go source: %w", capability.ID, err)
	}
	declared := make(map[string]bool)
	for _, declaration := range file.Decls {
		switch value := declaration.(type) {
		case *ast.FuncDecl:
			declared[value.Name.Name] = true
		case *ast.GenDecl:
			for _, specification := range value.Specs {
				switch item := specification.(type) {
				case *ast.TypeSpec:
					declared[item.Name.Name] = true
				case *ast.ValueSpec:
					for _, name := range item.Names {
						declared[name.Name] = true
					}
				}
			}
		}
	}
	for _, symbol := range capability.Symbols {
		if !declared[symbol] {
			return fmt.Errorf("capability %s evidence declaration %q is missing", capability.ID, symbol)
		}
	}
	probe, ok := capabilityProbe(capability.ID, packagePath)
	if !ok {
		return fmt.Errorf("available capability %s has no typed public-contract probe", capability.ID)
	}
	probeRoot := filepath.Join(temporaryRoot, "capability-"+strings.ReplaceAll(capability.ID, ".", "-"))
	if err := os.Mkdir(probeRoot, 0o755); err != nil {
		return err
	}
	module := fmt.Sprintf("module capabilityprobe\n\ngo 1.26.5\n\nrequire %s v0.0.0\nreplace %s => %s\n", modulePath, modulePath, filepath.ToSlash(sdkRoot))
	if err := os.WriteFile(filepath.Join(probeRoot, "go.mod"), []byte(module), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(probeRoot, "main.go"), []byte(probe), 0o644); err != nil {
		return err
	}
	if output, err := run(ctx, probeRoot, "go", "run", "-mod=mod", "."); err != nil {
		return fmt.Errorf("capability %s typed public-contract probe failed: %w: %s", capability.ID, err, output)
	}
	return nil
}

func capabilityProbe(id, packagePath string) (string, bool) {
	quotedImport := fmt.Sprintf("sdk %q", packagePath)
	switch id {
	case "policy.body-window":
		return fmt.Sprintf("package main\nimport (\"context\"; %s)\ntype required interface { ReadBodyWindow(context.Context, uint32, uint32) ([]byte, error) }\nvar _ required = (sdk.PolicyHost)(nil)\nconst _ string = sdk.PolicyHostReadBodyWindow\nfunc main() {}\n", quotedImport), true
	case "policy.event-metric":
		return fmt.Sprintf("package main\nimport (\"context\"; %s)\ntype required interface { EmitEvent(context.Context, sdk.PolicySecurityEvent) error; AddMetric(context.Context, string, int64) error }\nvar _ required = (sdk.PolicyHost)(nil)\nconst (_ string = sdk.PolicyHostEmitEvent; _ string = sdk.PolicyHostAddMetric)\nfunc main() {}\n", quotedImport), true
	case "rpc.lifecycle":
		return fmt.Sprintf("package main\nimport %s\nconst _ string = sdk.RPCABIV1\nvar _ = sdk.RPCHandshakeRequest{ABI: \"\", PluginID: \"\", PluginVersion: \"\", PackageDigest: \"\", ArtifactDigest: \"\", GrantedScopes: []string{}, Generation: \"\"}\nvar _ = sdk.RPCHandshakeResponse{ABI: \"\", Capabilities: []string{}}\nvar _ = sdk.LifecycleRequest{Generation: \"\", Config: []byte{}}\nvar _ = sdk.LifecycleResponse{Success: &sdk.LifecycleSuccess{Ready: true}}\nvar _ = sdk.LifecycleResponse.Validate\nfunc main() {}\n", quotedImport), true
	default:
		return "", false
	}
}

func descriptorSetDigest(ctx context.Context, temporaryRoot, sdkRoot, modulePath, packagePath string) (string, error) {
	probe := filepath.Join(temporaryRoot, "descriptor-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		return "", err
	}
	module := fmt.Sprintf("module sdkprobe\n\ngo 1.26.5\n\nrequire %s v0.0.0\nreplace %s => %s\n", modulePath, modulePath, filepath.ToSlash(sdkRoot))
	program := fmt.Sprintf("package main\nimport (\"crypto/sha256\"; \"fmt\"; \"%s/protoschema\")\nfunc main(){ b,e:=protoschema.DescriptorSetBytes(); if e!=nil { panic(e) }; fmt.Printf(\"%%x\\n\", sha256.Sum256(b)) }\n", packagePath)
	if err := os.WriteFile(filepath.Join(probe, "go.mod"), []byte(module), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(probe, "main.go"), []byte(program), 0o644); err != nil {
		return "", err
	}
	output, err := run(ctx, probe, "go", "run", "-mod=mod", ".")
	if err != nil {
		return "", err
	}
	return normalizeGitOutput(output), nil
}

func gitBlobSHA256(ctx context.Context, checkout, path string) (string, error) {
	data, err := gitRegularBlob(ctx, checkout, path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func gitRegularBlob(ctx context.Context, checkout, path string) ([]byte, error) {
	listing, err := run(ctx, checkout, "git", "ls-tree", "HEAD", "--", path)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(listing))
	if len(fields) < 3 || (fields[0] != "100644" && fields[0] != "100755") || fields[1] != "blob" {
		return nil, fmt.Errorf("%s is not a regular file in the locked commit", path)
	}
	return run(ctx, checkout, "git", "cat-file", "blob", "HEAD:"+path)
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

func packageDirectory(modulePath, packagePath string) (string, error) {
	if packagePath == modulePath {
		return ".", nil
	}
	prefix := modulePath + "/"
	if !strings.HasPrefix(packagePath, prefix) {
		return "", fmt.Errorf("SDK package path must be inside the locked module")
	}
	directory := strings.TrimPrefix(packagePath, prefix)
	if !canonicalRepositoryPath(directory) {
		return "", fmt.Errorf("SDK package path has an invalid module-relative directory")
	}
	return directory, nil
}

func run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = commandEnvironment(name)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func commandEnvironment(name string) []string {
	environment := os.Environ()
	if strings.ToLower(filepath.Base(name)) != "go" && strings.ToLower(filepath.Base(name)) != "go.exe" {
		return environment
	}
	blocked := map[string]bool{"GOENV": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "GOWORK": true}
	controlled := make([]string, 0, len(environment)+4)
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[strings.ToUpper(key)] {
			controlled = append(controlled, entry)
		}
	}
	return append(controlled, "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off")
}
