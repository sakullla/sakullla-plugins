package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/sakullla/sakullla-plugins/internal/pluginmanifest"
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
	Signer                 buildkit.Signer
	SignerPublicKey        ed25519.PublicKey
	NoticePath             string
	ThirdPartyLicensesPath string
	SBOMPath               string
	GuidePath              string
	Packages               []Package
}

type provenanceSignature struct {
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	Identity      string `json:"identity"`
	PayloadSHA256 string `json:"payload_sha256"`
	Signature     string `json:"signature"`
}

type packageEvidence struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	PackageSHA256 string `json:"package_sha256"`
	PackageURL    string `json:"package_url"`
	BlobSHA256    string `json:"blob_sha256"`
	BlobSize      int64  `json:"blob_size"`
	BlobFormat    string `json:"blob_format"`
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
	return AssembleContext(context.Background(), input)
}

func AssembleContext(ctx context.Context, input Input) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("release candidate context is required")
	}
	if input.OutputDir == "" || !fullOID.MatchString(input.RepositoryCommit) ||
		!fullOID.MatchString(input.SDKRepositoryCommit) || !isSHA256(input.SDKDescriptorSHA256) {
		return Result{}, fmt.Errorf("release candidate requires output, full repository OIDs, and SDK descriptor digest")
	}
	if input.SignerIdentity == "" || input.Signer == nil || len(input.SignerPublicKey) != ed25519.PublicKeySize || len(input.SDKABIs) == 0 || len(input.Packages) == 0 {
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
	parent := filepath.Dir(input.OutputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".official-candidate-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(temporary)
	market := buildkit.Market{SchemaVersion: 2, Commit: input.RepositoryCommit, SDKABI: strings.Join(input.SDKABIs, ",")}
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
		manifest, err := pluginmanifest.Load(filepath.Join(pkg.Directory, "plugin.yaml"))
		if err != nil {
			return Result{}, err
		}
		if manifest.ID != pkg.ID || manifest.Version != pkg.Version || manifest.Runtime.Kind != pkg.Runtime || manifest.Runtime.ABI != pkg.ABI || manifest.Signature.KeyID != pkg.SignerIdentity {
			return Result{}, fmt.Errorf("package %s@%s differs from its signed plugin contract", pkg.ID, pkg.Version)
		}
		artifacts := make([]buildkit.MarketArtifact, 0, len(manifest.Artifacts))
		for _, artifact := range manifest.Artifacts {
			artifacts = append(artifacts, buildkit.MarketArtifact{SHA256: artifact.SHA256, Size: artifact.Size, GOOS: artifact.GOOS, GOARCH: artifact.GOARCH})
		}
		blob, err := buildkit.BuildPackageBlob(pkg.Directory, filepath.Join(temporary, "blobs", "."+pkg.ID+"-"+pkg.Version+".nrepkg"))
		if err != nil {
			return Result{}, fmt.Errorf("package %s@%s transport blob: %w", pkg.ID, pkg.Version, err)
		}
		blobName := PackageBlobName(pkg.ID, pkg.Version, blob.SHA256)
		blobPath := filepath.Join(temporary, "blobs", blobName)
		if err := os.Rename(blob.Path, blobPath); err != nil {
			return Result{}, err
		}
		blob.Path = blobPath
		packageURL := PackageBlobURL(input.RepositoryCommit, blobName)
		market.Packages = append(market.Packages, buildkit.MarketPackage{
			ID: pkg.ID, Version: pkg.Version, Description: manifest.Description, Capabilities: append([]string(nil), manifest.ExtensionPoints...),
			Compatibility: buildkit.MarketCompatibility{Host: manifest.Compatibility.Host, Agent: manifest.Compatibility.Agent},
			Runtime:       pkg.Runtime, ABI: pkg.ABI, HostScope: manifest.Runtime.HostScope, PolicyKind: manifest.Runtime.PolicyKind, Artifacts: artifacts,
			PackageSHA256: pkg.PackageSHA256, PackageURL: packageURL, BlobSHA256: blob.SHA256, BlobSize: blob.Size, BlobFormat: buildkit.PackageBlobFormatV1, SignerIdentity: pkg.SignerIdentity,
		})
		evidence = append(evidence, packageEvidence{ID: pkg.ID, Version: pkg.Version, PackageSHA256: pkg.PackageSHA256, PackageURL: packageURL, BlobSHA256: blob.SHA256, BlobSize: blob.Size, BlobFormat: buildkit.PackageBlobFormatV1})
	}
	marketBytes, err := buildkit.RenderMarket(market)
	if err != nil {
		return Result{}, err
	}
	marketDigest := digest(marketBytes)
	abis := append([]string{}, input.SDKABIs...)
	sort.Strings(abis)
	provenance := Provenance{
		SchemaVersion: 2, RepositoryCommit: input.RepositoryCommit, MarketSHA256: marketDigest,
		SDKRepositoryCommit: input.SDKRepositoryCommit, SDKDescriptorSHA256: input.SDKDescriptorSHA256,
		SDKABIs: abis, SignerIdentity: input.SignerIdentity, Packages: evidence,
	}

	for _, item := range []struct{ source, destination string }{
		{input.NoticePath, "NOTICE"}, {input.ThirdPartyLicensesPath, "THIRD_PARTY_LICENSES.json"}, {input.SBOMPath, "SBOM.spdx.json"},
	} {
		if err := copyRegularFile(item.source, filepath.Join(temporary, item.destination)); err != nil {
			return Result{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(temporary, ".gitattributes"), []byte("* -text\n"), 0o644); err != nil {
		return Result{}, err
	}
	if input.GuidePath != "" {
		if err := copyRegularFile(input.GuidePath, filepath.Join(temporary, "AGENTS.md")); err != nil {
			return Result{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(temporary, "market.yaml"), marketBytes, 0o644); err != nil {
		return Result{}, err
	}
	for _, pkg := range packages {
		destination := filepath.Join(temporary, "packages", pkg.ID, pkg.Version)
		if err := copyTree(pkg.Directory, destination); err != nil {
			return Result{}, err
		}
	}
	provenanceBytes, err := canonicalJSON(provenance)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, "provenance.json"), provenanceBytes, 0o644); err != nil {
		return Result{}, err
	}
	provenanceDigest := sha256.Sum256(provenanceBytes)
	signature, err := input.Signer.Sign(ctx, provenanceDigest[:])
	if err != nil {
		return Result{}, fmt.Errorf("sign release provenance: %w", err)
	}
	if signature.Algorithm != "ed25519" || signature.Identity != input.SignerIdentity || len(signature.Value) != ed25519.SignatureSize {
		return Result{}, fmt.Errorf("provenance signer returned an invalid Ed25519 signature")
	}
	if !ed25519.Verify(input.SignerPublicKey, provenanceDigest[:], signature.Value) {
		return Result{}, fmt.Errorf("provenance signer returned a signature that does not verify with the official public key")
	}
	signatureDocument := provenanceSignature{
		SchemaVersion: 1, Algorithm: signature.Algorithm, Identity: signature.Identity,
		PayloadSHA256: hex.EncodeToString(provenanceDigest[:]), Signature: base64.StdEncoding.EncodeToString(signature.Value),
	}
	signatureBytes, err := canonicalJSON(signatureDocument)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, "provenance.signature.json"), signatureBytes, 0o644); err != nil {
		return Result{}, err
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
	marketDocument, err := buildkit.ParseMarket(market)
	if err != nil {
		return err
	}
	if provenance.SchemaVersion != 2 || !fullOID.MatchString(provenance.RepositoryCommit) ||
		!fullOID.MatchString(provenance.SDKRepositoryCommit) || !isSHA256(provenance.SDKDescriptorSHA256) ||
		provenance.SignerIdentity == "" || len(provenance.SDKABIs) == 0 || len(provenance.Packages) == 0 {
		return fmt.Errorf("release provenance is incomplete")
	}
	if err := verifyProvenanceSignature(candidate, data, provenance.SignerIdentity); err != nil {
		return err
	}
	marketABIs := strings.Split(marketDocument.SDKABI, ",")
	sort.Strings(marketABIs)
	if marketDocument.Commit != provenance.RepositoryCommit || strings.Join(marketABIs, ",") != strings.Join(provenance.SDKABIs, ",") || len(marketDocument.Packages) != len(provenance.Packages) {
		return fmt.Errorf("release market identity, SDK ABI, or package count differs from provenance")
	}
	marketPackages := make(map[string]buildkit.MarketPackage, len(marketDocument.Packages))
	for _, pkg := range marketDocument.Packages {
		marketPackages[pkg.ID+"\x00"+pkg.Version] = pkg
	}
	for _, pkg := range provenance.Packages {
		if !isSHA256(pkg.PackageSHA256) || !isSHA256(pkg.BlobSHA256) || pkg.BlobSize <= 0 || pkg.BlobFormat != buildkit.PackageBlobFormatV1 {
			return fmt.Errorf("release package evidence transport or digest is invalid")
		}
		clean := filepath.Join("packages", pkg.ID, pkg.Version)
		actual, err := buildkit.DigestTree(filepath.Join(candidate, clean))
		if err != nil || actual != pkg.PackageSHA256 {
			return fmt.Errorf("release package %s@%s digest mismatch", pkg.ID, pkg.Version)
		}
		entry, ok := marketPackages[pkg.ID+"\x00"+pkg.Version]
		if !ok || entry.PackageSHA256 != pkg.PackageSHA256 || entry.PackageURL != pkg.PackageURL || entry.BlobSHA256 != pkg.BlobSHA256 || entry.BlobSize != pkg.BlobSize || entry.BlobFormat != pkg.BlobFormat || entry.SignerIdentity != provenance.SignerIdentity {
			return fmt.Errorf("release market entry %s@%s differs from package evidence", pkg.ID, pkg.Version)
		}
		blobPath := filepath.Join(candidate, "blobs", PackageBlobName(pkg.ID, pkg.Version, pkg.BlobSHA256))
		blobData, err := os.ReadFile(blobPath)
		if err != nil || int64(len(blobData)) != pkg.BlobSize || digest(blobData) != pkg.BlobSHA256 {
			return fmt.Errorf("release package %s@%s transport blob mismatch", pkg.ID, pkg.Version)
		}
		packageRoot := filepath.Join(candidate, clean)
		manifest, err := pluginmanifest.Load(filepath.Join(packageRoot, "plugin.yaml"))
		if err != nil {
			return err
		}
		if err := pluginmanifest.ValidatePackageTree(packageRoot, manifest); err != nil {
			return err
		}
		if manifest.ID != entry.ID || manifest.Version != entry.Version || manifest.Runtime.Kind != entry.Runtime || manifest.Runtime.ABI != entry.ABI || manifest.Signature.KeyID != entry.SignerIdentity {
			return fmt.Errorf("release market entry %s@%s differs from signed plugin contract", pkg.ID, pkg.Version)
		}
	}
	return validateLegalInputs(Input{
		NoticePath:             filepath.Join(candidate, "NOTICE"),
		ThirdPartyLicensesPath: filepath.Join(candidate, "THIRD_PARTY_LICENSES.json"),
		SBOMPath:               filepath.Join(candidate, "SBOM.spdx.json"),
	})
}

func PackageBlobName(id, version, blobSHA256 string) string {
	return id + "-" + version + "-" + blobSHA256 + ".nrepkg"
}

func PackageBlobURL(repositoryCommit, blobName string) string {
	return "https://github.com/sakullla/sakullla-plugins/releases/download/official-" + repositoryCommit + "/" + blobName
}

func verifyProvenanceSignature(candidate string, provenanceBytes []byte, identity string) error {
	data, err := os.ReadFile(filepath.Join(candidate, "provenance.signature.json"))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document provenanceSignature
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode provenance signature: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("provenance signature contains trailing JSON")
	}
	digest := sha256.Sum256(provenanceBytes)
	if document.SchemaVersion != 1 || document.Algorithm != "ed25519" || document.Identity != identity ||
		document.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("provenance signature identity, algorithm, or payload digest mismatch")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("provenance signature is not canonical Ed25519 base64")
	}
	return nil
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
