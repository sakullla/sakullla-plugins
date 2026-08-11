package buildkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type deterministicSigner struct{}

func (deterministicSigner) Sign(_ context.Context, digest []byte) (Signature, error) {
	return Signature{Algorithm: "test-only-sha256", Identity: "test://fixture", Value: append([]byte("fixture:"), digest...)}, nil
}

type ed25519Signer struct {
	identity string
	key      ed25519.PrivateKey
}

func (signer ed25519Signer) Sign(_ context.Context, digest []byte) (Signature, error) {
	return Signature{Algorithm: "ed25519", Identity: signer.identity, Value: ed25519.Sign(signer.key, digest)}, nil
}

type inspectingValidator struct {
	t *testing.T
}

type validatorFunc func(context.Context, string) error

func (function validatorFunc) Validate(ctx context.Context, packageDir string) error {
	return function(ctx, packageDir)
}

func (validator inspectingValidator) Validate(_ context.Context, packageDir string) error {
	validator.t.Helper()
	for _, name := range []string{"plugin.yaml", "NOTICE", "sbom.spdx.json", "package.files.json", "signature.json", "artifact/plugin.wasm"} {
		if _, err := os.Stat(filepath.Join(packageDir, filepath.FromSlash(name))); err != nil {
			validator.t.Errorf("validator did not receive %s: %v", name, err)
		}
	}
	sbom, err := os.ReadFile(filepath.Join(packageDir, "sbom.spdx.json"))
	if err != nil {
		return err
	}
	if err := ValidateSPDX23JSON(sbom); err != nil {
		validator.t.Errorf("generated SBOM failed the SPDX 2.3 validator: %v", err)
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

func TestPackageEnvelopeVerifiesEd25519AndRejectsTamper(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := writeFixture(t, root, "source/plugin.yaml", "schema_version: 1\nid: fixture\n")
	artifact := writeFixture(t, root, "source/plugin.wasm", "deterministic wasm bytes")
	license := writeFixture(t, root, "source/LICENSE", "fixture license\n")
	seed := bytes.Repeat([]byte{0x2a}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	identity := "sakullla-official-root-2026"
	output := filepath.Join(root, "package")
	result, err := BuildPackage(context.Background(), PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, NoticePaths: []string{license}, OutputDir: output,
		Signer: ed25519Signer{identity: identity, key: privateKey},
		Validator: validatorFunc(func(_ context.Context, packageDir string) error {
			return VerifyPackageEnvelope(packageDir, identity, publicKey)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DigestTree(output)
	if err != nil {
		t.Fatal(err)
	}
	if digest != result.PackageDigest {
		t.Fatalf("DigestTree = %s, BuildPackage = %s", digest, result.PackageDigest)
	}
	if err := VerifyPackageEnvelope(output, identity, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "artifact", "plugin.wasm"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackageEnvelope(output, identity, publicKey); err == nil {
		t.Fatal("tampered package passed envelope verification")
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

func TestPackageUsesManifestArtifactPathAndIncludesSchemas(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := writeFixture(t, root, "plugin.yaml", "schema_version: 1\n")
	artifact := writeFixture(t, root, "plugin.exe", "binary")
	schema := writeFixture(t, root, "config.schema.json", `{}`)
	license := writeFixture(t, root, "LICENSE", "license")
	output := filepath.Join(root, "package")
	validator := validatorFunc(func(_ context.Context, packageDir string) error {
		for _, name := range []string{"artifacts/plugin", "config.schema.json"} {
			if _, err := os.Stat(filepath.Join(packageDir, filepath.FromSlash(name))); err != nil {
				t.Fatalf("package lacks %s: %v", name, err)
			}
		}
		return nil
	})
	_, err := BuildPackage(context.Background(), PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, ArtifactDestination: "artifacts/plugin",
		ExtraFiles: map[string]string{"config.schema.json": schema}, NoticePaths: []string{license},
		OutputDir: output, Signer: deterministicSigner{}, Validator: validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPackage(context.Background(), PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, ArtifactDestination: "../escape",
		NoticePaths: []string{license}, OutputDir: filepath.Join(root, "escape"),
		Signer: deterministicSigner{}, Validator: validator,
	}); err == nil {
		t.Fatal("package accepted an artifact path escape")
	}
}

func TestPackageAppliesDeclaredArtifactMode(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := writeFixture(t, root, "plugin.yaml", "schema_version: 1\n")
	artifact := writeFixture(t, root, "plugin", "binary")
	license := writeFixture(t, root, "LICENSE", "license")
	output := filepath.Join(root, "package")
	result, err := BuildPackage(context.Background(), PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, ArtifactDestination: "artifacts/linux-amd64/plugin", ArtifactMode: "executable",
		NoticePaths: []string{license}, OutputDir: output, Signer: deterministicSigner{}, Validator: validatorFunc(func(context.Context, string) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DigestTree(output)
	if err != nil {
		t.Fatal(err)
	}
	if digest != result.PackageDigest {
		t.Fatalf("executable DigestTree = %s, BuildPackage = %s", digest, result.PackageDigest)
	}
	data, err := os.ReadFile(filepath.Join(output, "package.files.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fileManifest packageFileManifest
	if err := json.Unmarshal(data, &fileManifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range fileManifest.Files {
		if record.Path == "artifacts/linux-amd64/plugin" {
			found = true
			if record.Mode != "0755" {
				t.Fatalf("artifact mode = %s, want 0755", record.Mode)
			}
		}
	}
	if !found {
		t.Fatal("package.files.json lacks executable artifact")
	}
}

func TestPackageSPDXValidatorRejectsNonSchemaShape(t *testing.T) {
	t.Parallel()
	invalid := []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "name": "missing-required-fields",
  "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: fixture"]},
  "documentNamespace": "https://spdx.org/spdxdocs/fixture",
  "documentDescribes": ["SPDXRef-File-001"],
  "files": [{"SPDXID": "SPDXRef-File-001", "fileName": "./artifact", "sha256": "deadbeef"}]
}`)
	if err := ValidateSPDX23JSON(invalid); err == nil {
		t.Fatal("non-schema SPDX document was accepted")
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
