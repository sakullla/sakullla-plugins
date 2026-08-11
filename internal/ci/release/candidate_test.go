package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
)

func TestPackageMarketProvenanceIsDeterministicAndTamperEvident(t *testing.T) {
	root := t.TempDir()
	legal := writeLegal(t, root)
	firstPackage := writePackage(t, root, "zeta")
	secondPackage := writePackage(t, root, "alpha")
	first := filepath.Join(root, "candidate-one")
	second := filepath.Join(root, "candidate-two")
	input := fixtureInput(first, legal, []Package{firstPackage, secondPackage})
	result, err := Assemble(input)
	if err != nil {
		t.Fatal(err)
	}
	input.OutputDir = second
	if _, err := Assemble(input); err != nil {
		t.Fatal(err)
	}
	one, _ := buildkit.DigestTree(first)
	two, _ := buildkit.DigestTree(second)
	if one != two || result.MarketSHA256 == "" {
		t.Fatalf("candidate digests differ: %s != %s", one, two)
	}
	market, err := os.ReadFile(filepath.Join(first, "market.yaml"))
	if err != nil || strings.Index(string(market), `id: "alpha"`) > strings.Index(string(market), `id: "zeta"`) {
		t.Fatalf("market projection is not sorted: %v\n%s", err, market)
	}
	if err := os.WriteFile(filepath.Join(first, "packages", "alpha", "0.1.0", "artifacts", "linux-amd64", "alpha"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(first); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered package was accepted: %v", err)
	}
}

func TestOfficialLockEvidenceBindsSDKCommitABIAndMarket(t *testing.T) {
	root := t.TempDir()
	legal := writeLegal(t, root)
	candidate := filepath.Join(root, "candidate")
	result, err := Assemble(fixtureInput(candidate, legal, []Package{writePackage(t, root, "plugin")}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Provenance.RepositoryCommit != strings.Repeat("a", 40) ||
		result.Provenance.SDKRepositoryCommit != strings.Repeat("b", 40) ||
		result.Provenance.SDKDescriptorSHA256 != strings.Repeat("c", 64) ||
		result.Provenance.MarketSHA256 != result.MarketSHA256 || len(result.Provenance.SDKABIs) != 2 {
		t.Fatalf("incomplete official-lock evidence: %#v", result.Provenance)
	}
}

func TestProvenanceSignatureCoversExactPersistedBytesAsRawDigest(t *testing.T) {
	root := t.TempDir()
	legal := writeLegal(t, root)
	candidate := filepath.Join(root, "candidate")
	if _, err := Assemble(fixtureInput(candidate, legal, []Package{writePackage(t, root, "plugin")})); err != nil {
		t.Fatal(err)
	}
	provenanceBytes, err := os.ReadFile(filepath.Join(candidate, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes, err := os.ReadFile(filepath.Join(candidate, "provenance.signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document provenanceSignature
	if err := json.Unmarshal(signatureBytes, &document); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(provenanceBytes)
	if document.SchemaVersion != 1 || document.Algorithm != "ed25519" || document.Identity != "sakullla-official-root-2026" ||
		document.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("invalid provenance signature document: %#v", document)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), digest[:], signature) {
		t.Fatal("signature does not cover the raw 32-byte provenance digest")
	}
	if err := os.WriteFile(filepath.Join(candidate, "provenance.json"), append(provenanceBytes, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(candidate); err == nil || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("exact-byte provenance tampering was accepted: %v", err)
	}
}

func TestNoticeAndSBOMAreRequired(t *testing.T) {
	root := t.TempDir()
	legal := writeLegal(t, root)
	if err := os.WriteFile(legal.sbom, []byte("not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Assemble(fixtureInput(filepath.Join(root, "candidate"), legal, []Package{writePackage(t, root, "plugin")}))
	if err == nil || !strings.Contains(err.Error(), "SBOM") {
		t.Fatalf("invalid SBOM was accepted: %v", err)
	}
}

func TestNoticeSBOMAndThirdPartyInventoryMatchRepositoryLocks(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateLegalInventory(root); err != nil {
		t.Fatal(err)
	}
}

func TestOfficialCandidateFailurePreservesExistingOutput(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "candidate")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "previous")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	legal := writeLegal(t, root)
	_, err := Assemble(fixtureInput(output, legal, []Package{writePackage(t, root, "plugin")}))
	if err == nil {
		t.Fatal("existing candidate was replaced")
	}
	if data, readErr := os.ReadFile(sentinel); readErr != nil || string(data) != "keep" {
		t.Fatalf("existing candidate changed: %v %q", readErr, data)
	}
}

func TestOfficialMarketPromotionRejectsTamperedCandidate(t *testing.T) {
	root := t.TempDir()
	legal := writeLegal(t, root)
	candidate := filepath.Join(root, "candidate")
	if _, err := Assemble(fixtureInput(candidate, legal, []Package{writePackage(t, root, "plugin")})); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "market.yaml"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	market := filepath.Join(root, "market.yaml")
	if err := PromoteMarket(candidate, market); err == nil {
		t.Fatal("tampered candidate was promoted")
	}
	if _, err := os.Stat(market); !os.IsNotExist(err) {
		t.Fatalf("market was written after failed verification: %v", err)
	}
}

type legalPaths struct{ notice, thirdParty, sbom string }

func writeLegal(t *testing.T, root string) legalPaths {
	t.Helper()
	paths := legalPaths{filepath.Join(root, "NOTICE"), filepath.Join(root, "THIRD.json"), filepath.Join(root, "SBOM.json")}
	for path, data := range map[string]string{
		paths.notice:     "license notices\n",
		paths.thirdParty: `{"schema_version":1,"code_dependencies":[],"data_dependencies":[]}`,
		paths.sbom:       `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","packages":[{"name":"fixture","versionInfo":"v1","licenseDeclared":"MIT"}]}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func writePackage(t *testing.T, root, id string) Package {
	t.Helper()
	source := filepath.Join(root, "source-"+id)
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	artifactData := []byte(id)
	artifact := filepath.Join(source, id)
	if err := os.WriteFile(artifact, artifactData, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifactData)
	manifest := filepath.Join(source, "plugin.yaml")
	manifestData := fmt.Sprintf(`schema_version: 1
id: %s
version: 0.1.0
name: Fixture
description: Fixture package
compatibility: {host: "*", agent: "*"}
runtime: {kind: rpc-service, abi: "nre:rpc/v1", host_scope: agent, entry: %s}
artifacts:
  - {path: artifacts/linux-amd64/%s, sha256: %s, size: %d, mode: executable, goos: linux, goarch: amd64}
extension_points: [dns.provider]
permissions: [{name: secret.use}]
config_schema: config.schema.json
resource_budget: {timeout_ms: 1000, memory_bytes: 65536, concurrency: 1, input_bytes: 1, output_bytes: 1, cpu_millis: 1, restarts: 0}
failure_policy: {on_error: fail-closed, on_budget: fail-closed, restart: on-failure, core_fallback: preserve}
signature: {algorithm: ed25519, key_id: sakullla-official-root-2026, file: signature.json}
cleanup: {instances: delete, config: delete, owned_data: delete, grants: delete, shared_refs: retain, audit_events: retain}
`, id, id, id, hex.EncodeToString(digest[:]), len(artifactData))
	if err := os.WriteFile(manifest, []byte(manifestData), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(source, "config.schema.json")
	if err := os.WriteFile(config, []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	license := filepath.Join(source, "LICENSE")
	if err := os.WriteFile(license, []byte("fixture license"), 0o644); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "package-"+id)
	seed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	signer := candidateFixtureSigner{key: ed25519.NewKeyFromSeed(seed)}
	result, err := buildkit.BuildPackage(context.Background(), buildkit.PackageRequest{
		ManifestPath: manifest, ArtifactPath: artifact, ArtifactDestination: "artifacts/linux-amd64/" + id, ArtifactMode: "executable",
		ExtraFiles: map[string]string{"config.schema.json": config}, NoticePaths: []string{license}, OutputDir: directory,
		Signer: signer, Validator: candidateFixtureValidator{publicKey: signer.key.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Package{ID: id, Version: "0.1.0", Runtime: "rpc-service", ABI: "nre:rpc/v1", Directory: directory, PackageSHA256: result.PackageDigest, SignerIdentity: "sakullla-official-root-2026"}
}

type candidateFixtureSigner struct{ key ed25519.PrivateKey }

func (signer candidateFixtureSigner) Sign(_ context.Context, digest []byte) (buildkit.Signature, error) {
	return buildkit.Signature{Algorithm: "ed25519", Identity: "sakullla-official-root-2026", Value: ed25519.Sign(signer.key, digest)}, nil
}

type candidateFixtureValidator struct{ publicKey ed25519.PublicKey }

func (validator candidateFixtureValidator) Validate(_ context.Context, packageDir string) error {
	return buildkit.VerifyPackageEnvelope(packageDir, "sakullla-official-root-2026", validator.publicKey)
}

func fixtureInput(output string, legal legalPaths, packages []Package) Input {
	return Input{
		OutputDir: output, RepositoryCommit: strings.Repeat("a", 40), SDKRepositoryCommit: strings.Repeat("b", 40),
		SDKDescriptorSHA256: strings.Repeat("c", 64), SDKABIs: []string{"nre:rpc/v1", "nre:policy/v1"}, SignerIdentity: "sakullla-official-root-2026",
		Signer:     candidateFixtureSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))},
		NoticePath: legal.notice, ThirdPartyLicensesPath: legal.thirdParty, SBOMPath: legal.sbom, Packages: packages,
	}
}
