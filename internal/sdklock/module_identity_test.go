package sdklock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyModuleIdentityRequiresExactModuleAndChecksums(t *testing.T) {
	lock := moduleIdentityLock()
	root := t.TempDir()
	writeIdentityFiles(t, root,
		"module fixture\n\ngo 1.27.0\n\nrequire (\n\t"+lock.SDK.ModulePath+" v0.6.0\n)\n",
		lock.SDK.ModulePath+" v0.6.0 h1:module\n"+lock.SDK.ModulePath+" v0.6.0/go.mod h1:mod\n")
	if err := VerifyModuleIdentity(root, lock); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyModuleIdentityAcceptsQuotedCanonicalRequire(t *testing.T) {
	lock := moduleIdentityLock()
	root := t.TempDir()
	writeIdentityFiles(t, root,
		"module fixture\n\ngo 1.27.0\n\nrequire \""+lock.SDK.ModulePath+"\" v0.6.0\n",
		lock.SDK.ModulePath+" v0.6.0 h1:module\n"+lock.SDK.ModulePath+" v0.6.0/go.mod h1:mod\n")
	if err := VerifyModuleIdentity(root, lock); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyModuleIdentityRejectsDuplicateCanonicalRequire(t *testing.T) {
	lock := moduleIdentityLock()
	root := t.TempDir()
	writeIdentityFiles(t, root,
		"module fixture\n\ngo 1.27.0\n\nrequire (\n\t"+lock.SDK.ModulePath+" v0.6.0\n\t\""+lock.SDK.ModulePath+"\" v0.6.0\n)\n",
		lock.SDK.ModulePath+" v0.6.0 h1:module\n"+lock.SDK.ModulePath+" v0.6.0/go.mod h1:mod\n")
	if err := VerifyModuleIdentity(root, lock); err == nil {
		t.Fatal("duplicate canonical SDK require was accepted")
	}
}

func TestVerifyModuleIdentityFailsClosed(t *testing.T) {
	lock := moduleIdentityLock()
	module := lock.SDK.ModulePath
	tests := map[string]struct{ goMod, goSum, want string }{
		"wrong require":     {"module fixture\nrequire " + module + " v0.5.0\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n", "want exactly"},
		"replace":           {"module fixture\nrequire " + module + " v0.6.0\nreplace " + module + " => ../sdk\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n", "must not replace"},
		"quoted replace":    {"module fixture\nrequire " + module + " v0.6.0\nreplace \"" + module + "\" => ../sdk\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n", "must not replace"},
		"versioned replace": {"module fixture\nrequire " + module + " v0.6.0\nreplace " + module + " v0.6.0 => ../sdk\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n", "must not replace"},
		"block replace":     {"module fixture\nrequire " + module + " v0.6.0\nreplace (\n\t\"" + module + "\" v0.6.0 => ../sdk\n)\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n", "must not replace"},
		"stale sum":         {"module fixture\nrequire " + module + " v0.6.0\n", module + " v0.6.0 h1:x\n" + module + " v0.6.0/go.mod h1:y\n" + module + " v0.5.0/go.mod h1:z\n", "stale SDK identities"},
		"missing zip sum":   {"module fixture\nrequire " + module + " v0.6.0\n", module + " v0.6.0/go.mod h1:y\n", "module and go.mod checksums"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeIdentityFiles(t, root, test.goMod, test.goSum)
			err := VerifyModuleIdentity(root, lock)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("VerifyModuleIdentity() = %v, want %q", err, test.want)
			}
		})
	}
}

func moduleIdentityLock() Lock {
	return Lock{
		Repository: Repository{Tag: "plugin-sdk/v0.6.0"},
		SDK:        SDK{ModulePath: "github.com/sakullla/nginx-reverse-emby/plugin-sdk"},
	}
}

func writeIdentityFiles(t *testing.T, root, goMod, goSum string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte(goSum), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRequireHTTPBackendProviderAddsCanonicalTypedEvidence(t *testing.T) {
	lock := RequireHTTPBackendProvider(Lock{RequiredCapabilities: []Capability{{ID: "rpc.lifecycle", MissingReason: "fixture"}}})
	if len(lock.RequiredCapabilities) != 2 || lock.RequiredCapabilities[1].ID != "rpc.lifecycle" {
		t.Fatalf("unexpected capability catalog: %#v", lock.RequiredCapabilities)
	}
	provider := lock.RequiredCapabilities[0]
	if provider.ID != "rpc.http-backend-provider" || !provider.Available || provider.EvidencePath != "plugin-sdk/go/http_backend_provider.go" {
		t.Fatalf("unexpected provider evidence: %#v", provider)
	}
	if lock.CapabilityContractSHA256 != CapabilityDigest(lock.RequiredCapabilities) {
		t.Fatal("capability digest was not refreshed")
	}
}
