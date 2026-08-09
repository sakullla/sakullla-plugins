package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sakullla/sakullla-plugins/internal/buildkit"
	"github.com/sakullla/sakullla-plugins/internal/ci/common"
)

var fullOID = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Package struct {
	ID             string
	Version        string
	Runtime        string
	ABI            string
	Directory      string
	PackageSHA256  string
	SignerIdentity string
}

type Input struct {
	OutputDir              string
	RepositoryCommit       string
	SDKRepositoryCommit    string
	SDKDescriptorSHA256    string
	SDKABIs                []string
	SignerIdentity         string
	NoticePath             string
	ThirdPartyLicensesPath string
	SBOMPath               string
	Packages               []Package
}

type packageEvidence struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	Path          string `json:"path"`
	PackageSHA256 string `json:"package_sha256"`
}

type Provenance struct {
	SchemaVersion       int               `json:"schema_version"`
	RepositoryCommit    string            `json:"repository_commit"`
	MarketSHA256        string            `json:"market_sha256"`
	SDKRepositoryCommit string            `json:"sdk_repository_commit"`
	SDKDescriptorSHA256 string            `json:"sdk_descriptor_sha256"`
	SDKABIs             []string          `json:"sdk_abis"`
	SignerIdentity      string            `json:"signer_identity"`
	Packages            []packageEvidence `json:"packages"`
}

type Result struct {
	OutputDir    string
	MarketSHA256 string
	Provenance   Provenance
}

type legalDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type thirdPartyDocument struct {
	SchemaVersion    int               `json:"schema_version"`
	CodeDependencies []legalDependency `json:"code_dependencies"`
	DataDependencies []legalDependency `json:"data_dependencies"`
}

type repositorySBOM struct {
	SPDXVersion string `json:"spdxVersion"`
	DataLicense string `json:"dataLicense"`
	Packages    []struct {
		Name            string `json:"name"`
		VersionInfo     string `json:"versionInfo"`
		LicenseDeclared string `json:"licenseDeclared"`
	} `json:"packages"`
}

func Assemble(input Input) (Result, error) {
	if input.OutputDir == "" || !fullOID.MatchString(input.RepositoryCommit) ||
		!fullOID.MatchString(input.SDKRepositoryCommit) || !isSHA256(input.SDKDescriptorSHA256) {
		return Result{}, fmt.Errorf("release candidate requires output, full repository OIDs, and SDK descriptor digest")
	}
	if input.SignerIdentity == "" || len(input.SDKABIs) == 0 || len(input.Packages) == 0 {
		return Result{}, fmt.Errorf("release candidate requires signer, SDK ABIs, and packages")
	}
	if _, err := os.Lstat(input.OutputDir); !os.IsNotExist(err) {
		if err == nil {
			return Result{}, fmt.Errorf("release candidate output %q already exists", input.OutputDir)
		}
		return Result{}, err
	}
	if err := validateLegalInputs(input); err != nil {
		return Result{}, err
	}

	packages := append([]Package{}, input.Packages...)
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].ID == packages[j].ID {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
	market := buildkit.Market{SchemaVersion: 1, Commit: input.RepositoryCommit, SDKABI: strings.Join(input.SDKABIs, ",")}
	seen := make(map[string]bool)
	var evidence []packageEvidence
	for _, pkg := range packages {
		key := pkg.ID + "\x00" + pkg.Version
		if seen[key] || pkg.SignerIdentity != input.SignerIdentity || !isSHA256(pkg.PackageSHA256) {
			return Result{}, fmt.Errorf("package %s@%s has duplicate, signer, or digest mismatch", pkg.ID, pkg.Version)
		}
		seen[key] = true
		actual, err := buildkit.DigestTree(pkg.Directory)
		if err != nil || actual != pkg.PackageSHA256 {
			return Result{}, fmt.Errorf("package %s@%s tree digest mismatch", pkg.ID, pkg.Version)
		}
		rel := filepath.ToSlash(filepath.Join("packages", pkg.ID, pkg.Version))
		market.Packages = append(market.Packages, buildkit.MarketPackage{
			ID: pkg.ID, Version: pkg.Version, Runtime: pkg.Runtime, ABI: pkg.ABI,
			PackageSHA256: pkg.PackageSHA256, PackageURL: rel, SignerIdentity: pkg.SignerIdentity,
		})
		evidence = append(evidence, packageEvidence{ID: pkg.ID, Version: pkg.Version, Path: rel, PackageSHA256: pkg.PackageSHA256})
	}
	marketBytes, err := buildkit.RenderMarket(market)
	if err != nil {
		return Result{}, err
	}
	marketDigest := digest(marketBytes)
	abis := append([]string{}, input.SDKABIs...)
	sort.Strings(abis)
	provenance := Provenance{
		SchemaVersion: 1, RepositoryCommit: input.RepositoryCommit, MarketSHA256: marketDigest,
		SDKRepositoryCommit: input.SDKRepositoryCommit, SDKDescriptorSHA256: input.SDKDescriptorSHA256,
		SDKABIs: abis, SignerIdentity: input.SignerIdentity, Packages: evidence,
	}

	parent := filepath.Dir(input.OutputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".official-candidate-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(temporary)
	for _, item := range []struct{ source, destination string }{
		{input.NoticePath, "NOTICE"}, {input.ThirdPartyLicensesPath, "THIRD_PARTY_LICENSES.json"}, {input.SBOMPath, "SBOM.spdx.json"},
	} {
		if err := copyRegularFile(item.source, filepath.Join(temporary, item.destination)); err != nil {
			return Result{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(temporary, "market.yaml"), marketBytes, 0o644); err != nil {
		return Result{}, err
	}
	provenanceBytes, err := canonicalJSON(provenance)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, "provenance.json"), provenanceBytes, 0o644); err != nil {
		return Result{}, err
	}
	for _, pkg := range packages {
		destination := filepath.Join(temporary, "packages", pkg.ID, pkg.Version)
		if err := copyTree(pkg.Directory, destination); err != nil {
			return Result{}, err
		}
	}
	if err := Verify(temporary); err != nil {
		return Result{}, err
	}
	if err := os.Rename(temporary, input.OutputDir); err != nil {
		return Result{}, err
	}
	return Result{OutputDir: input.OutputDir, MarketSHA256: marketDigest, Provenance: provenance}, nil
}

func Verify(candidate string) error {
	data, err := os.ReadFile(filepath.Join(candidate, "provenance.json"))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var provenance Provenance
	if err := decoder.Decode(&provenance); err != nil {
		return fmt.Errorf("decode release provenance: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("release provenance contains trailing JSON")
	}
	market, err := os.ReadFile(filepath.Join(candidate, "market.yaml"))
	if err != nil || digest(market) != provenance.MarketSHA256 {
		return fmt.Errorf("release market digest mismatch")
	}
	if provenance.SchemaVersion != 1 || !fullOID.MatchString(provenance.RepositoryCommit) ||
		!fullOID.MatchString(provenance.SDKRepositoryCommit) || !isSHA256(provenance.SDKDescriptorSHA256) ||
		provenance.SignerIdentity == "" || len(provenance.SDKABIs) == 0 || len(provenance.Packages) == 0 {
		return fmt.Errorf("release provenance is incomplete")
	}
	for _, pkg := range provenance.Packages {
		clean := filepath.Clean(filepath.FromSlash(pkg.Path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !isSHA256(pkg.PackageSHA256) {
			return fmt.Errorf("release package evidence path or digest is invalid")
		}
		actual, err := buildkit.DigestTree(filepath.Join(candidate, clean))
		if err != nil || actual != pkg.PackageSHA256 {
			return fmt.Errorf("release package %s@%s digest mismatch", pkg.ID, pkg.Version)
		}
	}
	return validateLegalInputs(Input{
		NoticePath:             filepath.Join(candidate, "NOTICE"),
		ThirdPartyLicensesPath: filepath.Join(candidate, "THIRD_PARTY_LICENSES.json"),
		SBOMPath:               filepath.Join(candidate, "SBOM.spdx.json"),
	})
}

func PromoteMarket(candidate, destination string) error {
	if err := Verify(candidate); err != nil {
		return err
	}
	market, err := os.ReadFile(filepath.Join(candidate, "market.yaml"))
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(destination); err == nil {
		if bytes.Equal(existing, market) {
			return nil
		}
		return fmt.Errorf("market destination already contains a different projection")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".market-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(market); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func ValidateLegalInventory(root string) error {
	if err := validateLegalInputs(Input{
		NoticePath: filepath.Join(root, "NOTICE"), ThirdPartyLicensesPath: filepath.Join(root, "THIRD_PARTY_LICENSES.json"),
		SBOMPath: filepath.Join(root, "SBOM.spdx.json"),
	}); err != nil {
		return err
	}
	policy, err := common.DefaultLicensePolicy()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_LICENSES.json"))
	if err != nil {
		return err
	}
	var document thirdPartyDocument
	if err := json.Unmarshal(data, &document); err != nil || document.SchemaVersion != 1 {
		return fmt.Errorf("third-party license inventory must use schema_version 1")
	}
	versions, err := goModuleVersions(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, dependency := range document.CodeDependencies {
		if seen[dependency.Name] || policy.Modules[dependency.Name] != dependency.License || versions[dependency.Name] != dependency.Version {
			return fmt.Errorf("third-party dependency %q is duplicate or differs from reviewed module/version/license", dependency.Name)
		}
		seen[dependency.Name] = true
	}
	for name := range policy.Modules {
		if !seen[name] {
			return fmt.Errorf("reviewed dependency %q is missing from third-party inventory", name)
		}
	}
	if len(policy.Crates) != 0 {
		return fmt.Errorf("Rust dependency inventory is not represented by the current legal document schema")
	}
	return nil
}

func validateLegalInputs(input Input) error {
	notice, err := os.ReadFile(input.NoticePath)
	if err != nil || len(bytes.TrimSpace(notice)) == 0 {
		return fmt.Errorf("NOTICE is required and must be non-empty")
	}
	thirdParty, err := os.ReadFile(input.ThirdPartyLicensesPath)
	if err != nil {
		return fmt.Errorf("third-party licenses must be valid JSON")
	}
	var inventory thirdPartyDocument
	if json.Unmarshal(thirdParty, &inventory) != nil || inventory.SchemaVersion != 1 {
		return fmt.Errorf("third-party licenses must be valid schema_version 1 JSON")
	}
	sbomData, err := os.ReadFile(input.SBOMPath)
	if err != nil {
		return fmt.Errorf("SBOM must be valid SPDX JSON")
	}
	var sbom repositorySBOM
	if json.Unmarshal(sbomData, &sbom) != nil || sbom.SPDXVersion != "SPDX-2.3" || sbom.DataLicense != "CC0-1.0" || len(sbom.Packages) == 0 {
		return fmt.Errorf("SBOM must be valid SPDX-2.3 JSON with packages")
	}
	packages := make(map[string]repositorySBOMPackage, len(sbom.Packages))
	for _, pkg := range sbom.Packages {
		packages[pkg.Name] = repositorySBOMPackage{Version: pkg.VersionInfo, License: pkg.LicenseDeclared}
	}
	for _, dependency := range inventory.CodeDependencies {
		pkg, ok := packages[dependency.Name]
		if !ok || pkg.Version != dependency.Version || pkg.License != dependency.License {
			return fmt.Errorf("SBOM does not cover dependency %s@%s with its declared license", dependency.Name, dependency.Version)
		}
	}
	return nil
}

type repositorySBOMPackage struct{ Version, License string }

func goModuleVersions(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	versions := make(map[string]string)
	scanner := bufio.NewScanner(file)
	inBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "//", 2)[0])
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			versions[fields[0]] = fields[1]
		}
	}
	return versions, scanner.Err()
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("candidate package contains non-regular entry %q", path)
		}
		return copyPackageFile(path, target, info.Mode())
	})
}

func copyPackageFile(source, destination string, mode fs.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	permissions := fs.FileMode(0o644)
	if mode&0o111 != 0 {
		permissions = 0o755
	}
	return os.WriteFile(destination, data, permissions)
}

func copyRegularFile(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("release input %q is not a regular file", source)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o644)
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func isSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
