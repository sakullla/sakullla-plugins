package sdklock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKVerificationUsesCleanCheckoutAndCapabilityGate(t *testing.T) {
	t.Parallel()
	repository := t.TempDir()
	workspace := t.TempDir()
	writeSDKFixture(t, repository)
	writeProjectionFixture(t, workspace, "locked-projection")
	runGitTest(t, repository, "init", "--quiet")
	runGitTest(t, repository, "config", "user.email", "sdk-fixture@example.invalid")
	runGitTest(t, repository, "config", "user.name", "SDK Fixture")
	runGitTest(t, repository, "add", ".")
	runGitTest(t, repository, "commit", "--quiet", "-m", "fixture")
	lock := fixtureLock(t, repository)
	commit := lock.Repository.Commit
	if err := lock.Validate(); err != nil {
		t.Fatal(err)
	}
	verification, err := Verify(context.Background(), lock, false, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Commit != commit || len(verification.MissingCapabilities) != 1 {
		t.Fatalf("unexpected verification: %#v", verification)
	}
	projectionPath := filepath.Join(workspace, "crates", "nre-policy-guest", "src", "abi_generated.rs")
	if err := os.WriteFile(projectionPath, []byte("sibling-projection"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), lock, false, workspace); err == nil || !strings.Contains(err.Error(), "differs from lock-resolved") {
		t.Fatalf("sibling-derived Rust projection did not fail closed: %v", err)
	}
	if err := os.WriteFile(projectionPath, []byte("locked-projection"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), lock, true, workspace); err == nil {
		t.Fatal("required missing Host capability did not fail closed")
	}
}

func TestSDKCapabilityEvidenceFailsClosed(t *testing.T) {
	t.Parallel()
	for name, contracts := range map[string]string{
		"comment only":    "package pluginsdk\nimport \"context\"\n// PolicyHostReadBodyWindow is not a declaration.\nconst Projection = \"locked-projection\"\ntype PolicyHost interface { ReadBodyWindow(context.Context, uint32, uint32) ([]byte, error) }\n",
		"wrong signature": "package pluginsdk\nimport \"context\"\nconst PolicyHostReadBodyWindow = \"fixture\"\nconst Projection = \"locked-projection\"\ntype PolicyHost interface { ReadBodyWindow(context.Context, string) ([]byte, error) }\n",
	} {
		t.Run(name, func(t *testing.T) {
			repository := t.TempDir()
			workspace := t.TempDir()
			writeSDKFixture(t, repository)
			writeProjectionFixture(t, workspace, "locked-projection")
			if err := os.WriteFile(filepath.Join(repository, "plugin-sdk", "go", "contracts.go"), []byte(contracts), 0o644); err != nil {
				t.Fatal(err)
			}
			runGitTest(t, repository, "init", "--quiet")
			runGitTest(t, repository, "config", "user.email", "sdk-fixture@example.invalid")
			runGitTest(t, repository, "config", "user.name", "SDK Fixture")
			runGitTest(t, repository, "add", ".")
			runGitTest(t, repository, "commit", "--quiet", "-m", "fixture")
			if _, err := Verify(context.Background(), fixtureLock(t, repository), false, workspace); err == nil {
				t.Fatal("invalid capability evidence did not fail closed")
			}
		})
	}
}

func TestSDKLockRejectsCapabilityEvidencePathEscapes(t *testing.T) {
	t.Parallel()
	for _, evidence := range []string{"../contracts.go", "/contracts.go", `C:/contracts.go`, `plugin-sdk/go/../contracts.go`, `plugin-sdk\go\contracts.go`, "other/contracts.go"} {
		lock := Lock{
			SchemaVersion:        1,
			Repository:           Repository{URL: "https://example.invalid/repository.git", Commit: strings.Repeat("a", 40)},
			SDK:                  SDK{ModulePath: "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go", ModuleDirectory: "plugin-sdk/go", ContractTreeOID: strings.Repeat("b", 40)},
			Artifacts:            Artifacts{DescriptorSetSHA256: strings.Repeat("c", 64), PolicyProtoSHA256: strings.Repeat("d", 64), RPCProtoSHA256: strings.Repeat("e", 64), CanonicalGuestSHA256: strings.Repeat("f", 64), ValidatorTreeOID: strings.Repeat("1", 40)},
			RequiredCapabilities: []Capability{{ID: "policy.body-window", Available: true, EvidencePath: evidence, Symbols: []string{"PolicyHostReadBodyWindow"}}},
		}
		lock.CapabilityContractSHA256 = CapabilityDigest(lock.RequiredCapabilities)
		if err := lock.Validate(); err == nil {
			t.Fatalf("evidence path %q did not fail closed", evidence)
		}
	}
}

func TestSDKCapabilityEvidenceRejectsSymlinkBlob(t *testing.T) {
	t.Parallel()
	repository := t.TempDir()
	runGitTest(t, repository, "init", "--quiet")
	runGitTest(t, repository, "config", "user.email", "sdk-fixture@example.invalid")
	runGitTest(t, repository, "config", "user.name", "SDK Fixture")
	target := filepath.Join(repository, "target.txt")
	if err := os.WriteFile(target, []byte("outside.go"), 0o644); err != nil {
		t.Fatal(err)
	}
	blob := strings.TrimSpace(runGitTest(t, repository, "hash-object", "-w", "target.txt"))
	runGitTest(t, repository, "update-index", "--add", "--cacheinfo", "120000", blob, "plugin-sdk/go/contracts.go")
	runGitTest(t, repository, "commit", "--quiet", "-m", "symlink fixture")
	if _, err := gitRegularBlob(context.Background(), repository, "plugin-sdk/go/contracts.go"); err == nil {
		t.Fatal("symlink capability evidence did not fail closed")
	}
}

func TestSDKGoModulePathAcceptsCheckoutLineEndings(t *testing.T) {
	t.Parallel()
	const want = "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	for _, goMod := range []string{
		"module " + want + "\n\ngo 1.26.5\n",
		"module \"" + want + "\"\r\n\r\ngo 1.26.5\r\n",
	} {
		if got := goModulePath([]byte(goMod)); got != want {
			t.Fatalf("goModulePath() = %q, want %q", got, want)
		}
	}
}

func writeSDKFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"plugin-sdk/go/go.mod":                                        "module github.com/sakullla/nginx-reverse-emby/plugin-sdk/go\n\ngo 1.26.5\n",
		"plugin-sdk/go/contracts.go":                                  "package pluginsdk\nimport \"context\"\nconst PolicyHostReadBodyWindow = \"fixture\"\nconst Projection = \"locked-projection\"\ntype PolicyHost interface { ReadBodyWindow(context.Context, uint32, uint32) ([]byte, error) }\n",
		"plugin-sdk/go/protoschema/schema.go":                         "package protoschema\nfunc DescriptorSetBytes() ([]byte,error) { return []byte(\"fixture-descriptor\"),nil }\n",
		"plugin-sdk/go/compatfixture/cmd/generate/main.go":            "package main\nimport \"fmt\"\nfunc main(){ fmt.Print(\"666978747572652d6775657374\\n\") }\n",
		"plugin-sdk/policy/v1/policy.proto":                           "syntax = \"proto3\"; package fixture.policy;\n",
		"plugin-sdk/rpc/v1/plugin.proto":                              "syntax = \"proto3\"; package fixture.rpc;\n",
		"panel/backend-go/internal/controlplane/plugins/validator.go": "package plugins\n",
	}
	for rel, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeProjectionFixture(t *testing.T, root, expected string) {
	t.Helper()
	files := map[string]string{
		"crates/nre-policy-guest/src/abi_generated.rs": expected,
		"internal/ci/sdk/cmd/generate-policy-rust/main.go": `package main
import (
    "flag"
    "os"
    sdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)
func main() {
    output := flag.String("output", "", "")
    flag.Parse()
    if err := os.WriteFile(*output, []byte(sdk.Projection), 0o644); err != nil { panic(err) }
}
`,
	}
	for rel, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func fixtureLock(t *testing.T, repository string) Lock {
	t.Helper()
	descriptor := sha256.Sum256([]byte("fixture-descriptor"))
	guest := sha256.Sum256([]byte("fixture-guest"))
	lock := Lock{
		SchemaVersion: 1,
		Repository:    Repository{URL: repository, Commit: strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD"))},
		SDK: SDK{
			ModulePath:      "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go",
			ModuleDirectory: "plugin-sdk/go",
			ContractTreeOID: strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD:plugin-sdk/go")),
		},
		Artifacts: Artifacts{
			DescriptorSetSHA256:  hex.EncodeToString(descriptor[:]),
			PolicyProtoSHA256:    mustGitBlobSHA(t, repository, "plugin-sdk/policy/v1/policy.proto"),
			RPCProtoSHA256:       mustGitBlobSHA(t, repository, "plugin-sdk/rpc/v1/plugin.proto"),
			CanonicalGuestSHA256: hex.EncodeToString(guest[:]),
			ValidatorTreeOID:     strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD:panel/backend-go/internal/controlplane/plugins")),
		},
		RequiredCapabilities: []Capability{
			{ID: "policy.body-window", Available: true, EvidencePath: "plugin-sdk/go/contracts.go", Symbols: []string{"PolicyHostReadBodyWindow"}},
			{ID: "policy.atomic-state", MissingReason: "fixture intentionally lacks atomic state"},
		},
	}
	lock.CapabilityContractSHA256 = CapabilityDigest(lock.RequiredCapabilities)
	if err := lock.Validate(); err != nil {
		t.Fatal(err)
	}
	return lock
}

func runGitTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	output, err := exec.Command("git", commandArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
	return string(output)
}

func mustGitBlobSHA(t *testing.T, root, path string) string {
	t.Helper()
	digest, err := gitBlobSHA256(context.Background(), root, path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
