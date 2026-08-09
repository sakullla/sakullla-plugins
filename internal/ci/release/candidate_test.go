package release

import (
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
	if err := os.WriteFile(filepath.Join(first, "packages", "alpha", "0.1.0", "artifact.bin"), []byte("tampered"), 0o644); err != nil {
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
	directory := filepath.Join(root, "source-"+id)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "artifact.bin"), []byte(id), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, "artifact.bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := buildkit.DigestTree(directory)
	if err != nil {
		t.Fatal(err)
	}
	return Package{ID: id, Version: "0.1.0", Runtime: "rpc-service", ABI: "nre:rpc/v1", Directory: directory, PackageSHA256: digest, SignerIdentity: "official"}
}

func fixtureInput(output string, legal legalPaths, packages []Package) Input {
	return Input{
		OutputDir: output, RepositoryCommit: strings.Repeat("a", 40), SDKRepositoryCommit: strings.Repeat("b", 40),
		SDKDescriptorSHA256: strings.Repeat("c", 64), SDKABIs: []string{"nre:rpc/v1", "nre:policy/v1"}, SignerIdentity: "official",
		NoticePath: legal.notice, ThirdPartyLicensesPath: legal.thirdParty, SBOMPath: legal.sbom, Packages: packages,
	}
}
