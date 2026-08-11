package pluginmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nunknown: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestValidateSourceAndPackageTreeUseOneV1Contract(t *testing.T) {
	root := t.TempDir()
	artifactData := []byte("ELF fixture")
	artifactFile := writeTestFile(t, root, "build/example-plugin", artifactData, 0o755)
	digest := sha256.Sum256(artifactData)
	manifest := validRPCManifest(hex.EncodeToString(digest[:]), int64(len(artifactData)))
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	if err := ValidateSource(manifest, root, manifest.ID, artifactFile); err != nil {
		t.Fatal(err)
	}

	packageRoot := t.TempDir()
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"plugin.yaml", []byte("fixture"), 0o644},
		{"config.schema.json", []byte(`{"type":"object"}`), 0o644},
		{"artifacts/linux-amd64/example-plugin", artifactData, 0o755},
		{"NOTICE", []byte("notice"), 0o644},
		{"sbom.spdx.json", []byte(`{}`), 0o644},
		{"package.files.json", []byte(`{}`), 0o644},
		{"signature.json", []byte(`{}`), 0o644},
	} {
		writeTestFile(t, packageRoot, file.name, file.data, file.mode)
	}
	if err := ValidatePackageTree(packageRoot, manifest); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, packageRoot, "package.sig", []byte("legacy"), 0o644)
	if err := ValidatePackageTree(packageRoot, manifest); err == nil || !strings.Contains(err.Error(), "unknown file") {
		t.Fatalf("legacy package.sig error = %v", err)
	}
}

func TestValidateRejectsBusinessPermissionAndIncompleteDynamicActionGrant(t *testing.T) {
	manifest := validRPCManifest(strings.Repeat("a", 64), 1)
	manifest.Permissions = []Permission{{Name: "scheduler"}}
	if err := Validate(manifest, manifest.ID); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("business permission error = %v", err)
	}

	root := t.TempDir()
	artifact := writeTestFile(t, root, "build/example-plugin", []byte("x"), 0o755)
	digest := sha256.Sum256([]byte("x"))
	manifest = validRPCManifest(hex.EncodeToString(digest[:]), 1)
	manifest.UISchema = "ui.schema.json"
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	writeTestFile(t, root, "ui.schema.json", []byte(`{"actions":[{"type":"dynamic","capability":"dns.manage"}]}`), 0o644)
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err == nil || !strings.Contains(err.Error(), "ui.dynamic-actions") {
		t.Fatalf("dynamic action permission error = %v", err)
	}
	manifest.Permissions = append(manifest.Permissions, Permission{Name: "ui.dynamic-actions"})
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err == nil || !strings.Contains(err.Error(), "dns.manage") {
		t.Fatalf("dynamic action capability error = %v", err)
	}
	manifest.Permissions = append(manifest.Permissions, Permission{Name: "dns.manage"})
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err != nil {
		t.Fatal(err)
	}
}

func validRPCManifest(digest string, size int64) Manifest {
	return Manifest{
		SchemaVersion: 1, ID: "example-plugin", Version: "1.0.0", Name: "Example Plugin", Description: "Example description",
		Compatibility:   Compatibility{Host: "*", Agent: "*"},
		Runtime:         Runtime{Kind: RuntimeRPCService, ABI: RPCABIV1, HostScope: "agent", Entry: "example-plugin"},
		Artifacts:       []Artifact{{Path: "artifacts/linux-amd64/example-plugin", SHA256: digest, Size: size, Mode: "executable", GOOS: "linux", GOARCH: "amd64"}},
		ExtensionPoints: []string{"dns.provider"}, Permissions: []Permission{{Name: "secret.use"}}, ConfigSchema: "config.schema.json",
		ResourceBudget: ResourceBudget{TimeoutMS: 30000, MemoryBytes: 268435456, Concurrency: 8, InputBytes: 1048576, OutputBytes: 1048576, CPUMillis: 1000, Restarts: 3},
		FailurePolicy:  FailurePolicy{OnError: "fail-closed", OnBudget: "fail-closed", Restart: "on-failure", CoreFallback: "preserve"},
		Signature:      Signature{Algorithm: "ed25519", KeyID: OfficialKeyID, File: "signature.json"},
		Cleanup:        Cleanup{Instances: "delete", Config: "delete", OwnedData: "delete", Grants: "delete", SharedRefs: "retain", AuditEvents: "retain"},
	}
}

func writeTestFile(t *testing.T, root, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
	return filename
}
