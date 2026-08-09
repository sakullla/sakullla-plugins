package buildkit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

type deterministicSigner struct{}

func (deterministicSigner) Sign(_ context.Context, digest []byte) (Signature, error) {
	return Signature{Algorithm: "test-only-sha256", Identity: "test://fixture", Value: append([]byte("fixture:"), digest...)}, nil
}

type inspectingValidator struct {
	t *testing.T
}

func (validator inspectingValidator) Validate(_ context.Context, packageDir string) error {
	validator.t.Helper()
	for _, name := range []string{"plugin.yaml", "NOTICE", "sbom.spdx.json", "package.files.json", "signature.json", "artifact/plugin.wasm"} {
		if _, err := os.Stat(filepath.Join(packageDir, filepath.FromSlash(name))); err != nil {
			validator.t.Errorf("validator did not receive %s: %v", name, err)
		}
	}
	return nil
}

func TestPackageReproducible(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := writeFixture(t, root, "source/plugin.yaml", "schema_version: 1\nid: fixture\n")
	artifact := writeFixture(t, root, "source/plugin.wasm", "deterministic wasm bytes")
	license := writeFixture(t, root, "source/LICENSE", "fixture license\r\n")
	request := PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, NoticePaths: []string{license},
		Signer: deterministicSigner{}, Validator: inspectingValidator{t: t},
	}
	request.OutputDir = filepath.Join(root, "package-one")
	first, err := BuildPackage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.OutputDir = filepath.Join(root, "package-two")
	second, err := BuildPackage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.PayloadDigest != second.PayloadDigest || first.PackageDigest != second.PackageDigest {
		t.Fatalf("package digests differ: %#v != %#v", first, second)
	}
	firstSignature, err := os.ReadFile(filepath.Join(first.OutputDir, "signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	secondSignature, err := os.ReadFile(filepath.Join(second.OutputDir, "signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstSignature, secondSignature) {
		t.Fatal("signature documents are not deterministic")
	}
}

func TestSignerAndValidatorRequired(t *testing.T) {
	t.Parallel()
	_, err := BuildPackage(context.Background(), PackageRequest{})
	if err == nil {
		t.Fatal("BuildPackage accepted a request without signer and validator")
	}
}

func TestPackageRefusesExistingOutput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := writeFixture(t, root, "plugin.yaml", "schema_version: 1\n")
	artifact := writeFixture(t, root, "plugin.wasm", "wasm")
	license := writeFixture(t, root, "LICENSE", "license")
	output := filepath.Join(root, "existing")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := BuildPackage(context.Background(), PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, NoticePaths: []string{license}, OutputDir: output,
		Signer: deterministicSigner{}, Validator: inspectingValidator{t: t},
	})
	if err == nil {
		t.Fatal("BuildPackage overwrote an existing output")
	}
}

func writeFixture(t *testing.T, root, name, contents string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
