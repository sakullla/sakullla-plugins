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
	writeSDKFixture(t, repository)
	runGitTest(t, repository, "init", "--quiet")
	runGitTest(t, repository, "config", "user.email", "sdk-fixture@example.invalid")
	runGitTest(t, repository, "config", "user.name", "SDK Fixture")
	runGitTest(t, repository, "add", ".")
	runGitTest(t, repository, "commit", "--quiet", "-m", "fixture")
	commit := strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD"))
	contractTree := strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD:plugin-sdk/go"))
	validatorTree := strings.TrimSpace(runGitTest(t, repository, "rev-parse", "HEAD:panel/backend-go/internal/controlplane/plugins"))
	descriptor := sha256.Sum256([]byte("fixture-descriptor"))
	guest := sha256.Sum256([]byte("fixture-guest"))
	lock := Lock{
		SchemaVersion: 1,
		Repository:    Repository{URL: repository, Commit: commit},
		SDK:           SDK{ModulePath: "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go", ModuleDirectory: "plugin-sdk/go", ContractTreeOID: contractTree},
		Artifacts: Artifacts{
			DescriptorSetSHA256:  hex.EncodeToString(descriptor[:]),
			PolicyProtoSHA256:    mustGitBlobSHA(t, repository, "plugin-sdk/policy/v1/policy.proto"),
			RPCProtoSHA256:       mustGitBlobSHA(t, repository, "plugin-sdk/rpc/v1/plugin.proto"),
			CanonicalGuestSHA256: hex.EncodeToString(guest[:]), ValidatorTreeOID: validatorTree,
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
	verification, err := Verify(context.Background(), lock, false)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Commit != commit || len(verification.MissingCapabilities) != 1 {
		t.Fatalf("unexpected verification: %#v", verification)
	}
	if _, err := Verify(context.Background(), lock, true); err == nil {
		t.Fatal("required missing Host capability did not fail closed")
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
		"plugin-sdk/go/contracts.go":                                  "package pluginsdk\nconst PolicyHostReadBodyWindow = \"fixture\"\n",
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
