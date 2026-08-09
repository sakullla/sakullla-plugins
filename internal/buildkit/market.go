package buildkit

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Market struct {
	SchemaVersion int             `json:"schema_version"`
	Commit        string          `json:"commit"`
	SDKABI        string          `json:"sdk_abi"`
	Packages      []MarketPackage `json:"packages"`
}

type MarketPackage struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	Runtime        string `json:"runtime"`
	ABI            string `json:"abi"`
	PackageSHA256  string `json:"package_sha256"`
	PackageURL     string `json:"package_url"`
	SignerIdentity string `json:"signer_identity"`
}

func RenderMarket(market Market) ([]byte, error) {
	if market.SchemaVersion != 1 || market.Commit == "" || market.SDKABI == "" {
		return nil, fmt.Errorf("market requires schema_version 1, commit, and sdk_abi")
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
		if pkg.ID == "" || pkg.Version == "" || pkg.Runtime == "" || pkg.ABI == "" ||
			pkg.PackageSHA256 == "" || pkg.PackageURL == "" || pkg.SignerIdentity == "" {
			return nil, fmt.Errorf("market package %q has an empty required field", pkg.ID)
		}
		fmt.Fprintf(&output, "  - id: %s\n", yamlString(pkg.ID))
		fmt.Fprintf(&output, "    version: %s\n", yamlString(pkg.Version))
		fmt.Fprintf(&output, "    runtime: %s\n", yamlString(pkg.Runtime))
		fmt.Fprintf(&output, "    abi: %s\n", yamlString(pkg.ABI))
		fmt.Fprintf(&output, "    package_sha256: %s\n", yamlString(pkg.PackageSHA256))
		fmt.Fprintf(&output, "    package_url: %s\n", yamlString(pkg.PackageURL))
		fmt.Fprintf(&output, "    signer_identity: %s\n", yamlString(pkg.SignerIdentity))
	}
	return output.Bytes(), nil
}

func yamlString(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strconv.Quote(value)
}
