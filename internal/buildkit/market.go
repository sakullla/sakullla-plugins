package buildkit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var marketDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Market struct {
	SchemaVersion int             `json:"schema_version" yaml:"schema_version"`
	Commit        string          `json:"commit" yaml:"commit"`
	SDKABI        string          `json:"sdk_abi" yaml:"sdk_abi"`
	Packages      []MarketPackage `json:"packages" yaml:"packages"`
}

type MarketPackage struct {
	ID             string              `json:"id" yaml:"id"`
	Version        string              `json:"version" yaml:"version"`
	Description    string              `json:"description" yaml:"description"`
	Capabilities   []string            `json:"capabilities" yaml:"capabilities"`
	Compatibility  MarketCompatibility `json:"compatibility" yaml:"compatibility"`
	Runtime        string              `json:"runtime" yaml:"runtime"`
	ABI            string              `json:"abi" yaml:"abi"`
	HostScope      string              `json:"host_scope" yaml:"host_scope"`
	PolicyKind     string              `json:"policy_kind,omitempty" yaml:"policy_kind,omitempty"`
	Artifacts      []MarketArtifact    `json:"artifacts" yaml:"artifacts"`
	PackageSHA256  string              `json:"package_sha256" yaml:"package_sha256"`
	PackageURL     string              `json:"package_url" yaml:"package_url"`
	BlobSHA256     string              `json:"blob_sha256" yaml:"blob_sha256"`
	BlobSize       int64               `json:"blob_size" yaml:"blob_size"`
	BlobFormat     string              `json:"blob_format" yaml:"blob_format"`
	SignerIdentity string              `json:"signer_identity" yaml:"signer_identity"`
}

type MarketCompatibility struct {
	Host  string `json:"host" yaml:"host"`
	Agent string `json:"agent" yaml:"agent"`
}

type MarketArtifact struct {
	SHA256 string `json:"sha256" yaml:"sha256"`
	Size   int64  `json:"size" yaml:"size"`
	GOOS   string `json:"goos,omitempty" yaml:"goos,omitempty"`
	GOARCH string `json:"goarch,omitempty" yaml:"goarch,omitempty"`
}

func ParseMarket(data []byte) (Market, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var market Market
	if err := decoder.Decode(&market); err != nil {
		return Market{}, fmt.Errorf("strictly decode market.yaml: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Market{}, fmt.Errorf("market.yaml must contain exactly one document")
	}
	if err := validateMarket(market); err != nil {
		return Market{}, err
	}
	return market, nil
}

func RenderMarket(market Market) ([]byte, error) {
	if err := validateMarket(market); err != nil {
		return nil, err
	}
	packages := append([]MarketPackage{}, market.Packages...)
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].ID == packages[j].ID {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
	seen := make(map[string]bool)
	var output bytes.Buffer
	fmt.Fprintf(&output, "schema_version: %d\n", market.SchemaVersion)
	fmt.Fprintf(&output, "commit: %s\n", yamlString(market.Commit))
	fmt.Fprintf(&output, "sdk_abi: %s\n", yamlString(market.SDKABI))
	output.WriteString("packages:\n")
	for _, pkg := range packages {
		key := pkg.ID + "\x00" + pkg.Version
		if seen[key] {
			return nil, fmt.Errorf("duplicate market package %s@%s", pkg.ID, pkg.Version)
		}
		seen[key] = true
		if pkg.ID == "" || pkg.Version == "" || pkg.Description == "" || len(pkg.Capabilities) == 0 ||
			pkg.Compatibility.Host == "" || pkg.Compatibility.Agent == "" || pkg.Runtime == "" || pkg.ABI == "" || pkg.HostScope == "" ||
			len(pkg.Artifacts) == 0 || pkg.PackageSHA256 == "" || pkg.PackageURL == "" || pkg.BlobSHA256 == "" || pkg.BlobSize <= 0 || pkg.BlobFormat == "" || pkg.SignerIdentity == "" {
			return nil, fmt.Errorf("market package %q has an empty required field", pkg.ID)
		}
		fmt.Fprintf(&output, "  - id: %s\n", yamlString(pkg.ID))
		fmt.Fprintf(&output, "    version: %s\n", yamlString(pkg.Version))
		fmt.Fprintf(&output, "    description: %s\n", yamlString(pkg.Description))
		output.WriteString("    capabilities:\n")
		for _, capability := range pkg.Capabilities {
			fmt.Fprintf(&output, "      - %s\n", yamlString(capability))
		}
		output.WriteString("    compatibility:\n")
		fmt.Fprintf(&output, "      host: %s\n", yamlString(pkg.Compatibility.Host))
		fmt.Fprintf(&output, "      agent: %s\n", yamlString(pkg.Compatibility.Agent))
		fmt.Fprintf(&output, "    runtime: %s\n", yamlString(pkg.Runtime))
		fmt.Fprintf(&output, "    abi: %s\n", yamlString(pkg.ABI))
		fmt.Fprintf(&output, "    host_scope: %s\n", yamlString(pkg.HostScope))
		if pkg.PolicyKind != "" {
			fmt.Fprintf(&output, "    policy_kind: %s\n", yamlString(pkg.PolicyKind))
		}
		output.WriteString("    artifacts:\n")
		for _, artifact := range pkg.Artifacts {
			fmt.Fprintf(&output, "      - sha256: %s\n", yamlString(artifact.SHA256))
			fmt.Fprintf(&output, "        size: %d\n", artifact.Size)
			if artifact.GOOS != "" {
				fmt.Fprintf(&output, "        goos: %s\n", yamlString(artifact.GOOS))
			}
			if artifact.GOARCH != "" {
				fmt.Fprintf(&output, "        goarch: %s\n", yamlString(artifact.GOARCH))
			}
		}
		fmt.Fprintf(&output, "    package_sha256: %s\n", yamlString(pkg.PackageSHA256))
		fmt.Fprintf(&output, "    package_url: %s\n", yamlString(pkg.PackageURL))
		fmt.Fprintf(&output, "    blob_sha256: %s\n", yamlString(pkg.BlobSHA256))
		fmt.Fprintf(&output, "    blob_size: %d\n", pkg.BlobSize)
		fmt.Fprintf(&output, "    blob_format: %s\n", yamlString(pkg.BlobFormat))
		fmt.Fprintf(&output, "    signer_identity: %s\n", yamlString(pkg.SignerIdentity))
	}
	return output.Bytes(), nil
}

func validateMarket(market Market) error {
	if market.SchemaVersion != 2 || market.Commit == "" || market.SDKABI == "" || len(market.Packages) == 0 {
		return fmt.Errorf("market requires schema_version 2, commit, sdk_abi, and packages")
	}
	seen := make(map[string]struct{}, len(market.Packages))
	for _, pkg := range market.Packages {
		key := pkg.ID + "\x00" + pkg.Version
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate market package %s@%s", pkg.ID, pkg.Version)
		}
		seen[key] = struct{}{}
		if pkg.ID == "" || pkg.Version == "" || pkg.Description == "" || len(pkg.Capabilities) == 0 ||
			pkg.Compatibility.Host == "" || pkg.Compatibility.Agent == "" || pkg.Runtime == "" || pkg.ABI == "" || pkg.HostScope == "" ||
			len(pkg.Artifacts) == 0 || !marketDigestPattern.MatchString(pkg.PackageSHA256) || pkg.PackageURL == "" ||
			!marketDigestPattern.MatchString(pkg.BlobSHA256) || pkg.BlobSize <= 0 || pkg.BlobFormat != "tar+gzip-v1" || pkg.SignerIdentity == "" {
			return fmt.Errorf("market package %q has an empty or invalid required field", pkg.ID)
		}
		expectedURL := "https://github.com/sakullla/sakullla-plugins/releases/download/official-" + market.Commit + "/" + pkg.ID + "-" + pkg.Version + "-" + pkg.BlobSHA256 + ".nrepkg"
		if pkg.PackageURL != expectedURL {
			return fmt.Errorf("market package %q URL is not the canonical immutable release asset", pkg.ID)
		}
		for _, artifact := range pkg.Artifacts {
			if !marketDigestPattern.MatchString(artifact.SHA256) || artifact.Size <= 0 {
				return fmt.Errorf("market package %q has an invalid artifact", pkg.ID)
			}
		}
	}
	return nil
}

func yamlString(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strconv.Quote(value)
}
