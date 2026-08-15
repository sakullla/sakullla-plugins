package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sakullla/sakullla-plugins/internal/ci/common"
)

type legalDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type legalInventory struct {
	SchemaVersion    int               `json:"schema_version"`
	CodeDependencies []legalDependency `json:"code_dependencies"`
	DataDependencies []legalDependency `json:"data_dependencies"`
}

type sourceSBOM struct {
	SPDXID            string               `json:"SPDXID"`
	SPDXVersion       string               `json:"spdxVersion"`
	DataLicense       string               `json:"dataLicense"`
	Name              string               `json:"name"`
	DocumentNamespace string               `json:"documentNamespace"`
	CreationInfo      json.RawMessage      `json:"creationInfo"`
	DocumentDescribes []string             `json:"documentDescribes"`
	Packages          []sourceSBOMPackage  `json:"packages"`
	Relationships     []sourceRelationship `json:"relationships"`
}

type sourceSBOMPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
}

type sourceRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func updateLegalInventory(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	policy, err := common.DefaultLicensePolicy()
	if err != nil {
		return err
	}
	versions, err := requiredModuleVersions(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	names := make([]string, 0, len(policy.Modules))
	for name := range policy.Modules {
		if versions[name] == "" {
			return fmt.Errorf("reviewed dependency %q is absent from go.mod", name)
		}
		names = append(names, name)
	}
	for name := range versions {
		if policy.Modules[name] == "" {
			return fmt.Errorf("dependency %q has no reviewed license declaration", name)
		}
	}
	sort.Strings(names)
	inventory := legalInventory{SchemaVersion: 1, CodeDependencies: make([]legalDependency, 0, len(names)), DataDependencies: []legalDependency{}}
	for _, name := range names {
		inventory.CodeDependencies = append(inventory.CodeDependencies, legalDependency{Name: name, Version: versions[name], License: policy.Modules[name]})
	}
	if err := writeIndentedJSON(filepath.Join(root, "THIRD_PARTY_LICENSES.json"), inventory); err != nil {
		return err
	}
	return updateSourceSBOM(filepath.Join(root, "SBOM.spdx.json"), inventory.CodeDependencies)
}

func requiredModuleVersions(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := map[string]string{}
	inBlock := false
	scanner := bufio.NewScanner(file)
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
		if !inBlock || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 {
			result[fields[0]] = fields[1]
		}
	}
	return result, scanner.Err()
}

func updateSourceSBOM(path string, dependencies []legalDependency) error {
	wire, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document sourceSBOM
	if err := json.Unmarshal(wire, &document); err != nil {
		return err
	}
	if len(document.Packages) == 0 {
		return errors.New("source SBOM root package is missing")
	}
	rootPackage := document.Packages[0]
	existing := make(map[string]sourceSBOMPackage, len(document.Packages))
	for _, item := range document.Packages[1:] {
		existing[item.Name] = item
	}
	document.Packages = []sourceSBOMPackage{rootPackage}
	document.Relationships = nil
	for _, dependency := range dependencies {
		item, ok := existing[dependency.Name]
		if !ok {
			item = sourceSBOMPackage{SPDXID: "SPDXRef-Package-" + spdxName(dependency.Name), Name: dependency.Name, DownloadLocation: moduleDownloadLocation(dependency.Name), FilesAnalyzed: false, CopyrightText: "NOASSERTION"}
		}
		item.VersionInfo = dependency.Version
		item.LicenseConcluded = dependency.License
		item.LicenseDeclared = dependency.License
		document.Packages = append(document.Packages, item)
		document.Relationships = append(document.Relationships, sourceRelationship{SPDXElementID: rootPackage.SPDXID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: item.SPDXID})
	}
	return writeIndentedJSON(path, document)
}

func spdxName(module string) string {
	value := strings.NewReplacer("github.com/", "", "golang.org/x/", "x-", "google.golang.org/", "", "gopkg.in/", "", "/", "-", ".", "-").Replace(module)
	return strings.Trim(value, "-")
}

func moduleDownloadLocation(module string) string {
	if strings.HasPrefix(module, "golang.org/x/") {
		return "https://go.googlesource.com/" + strings.TrimPrefix(module, "golang.org/x/")
	}
	if strings.HasPrefix(module, "github.com/") {
		parts := strings.Split(module, "/")
		if len(parts) >= 3 {
			return "https://" + strings.Join(parts[:3], "/")
		}
	}
	if module == "google.golang.org/grpc" {
		return "https://github.com/grpc/grpc-go"
	}
	return "NOASSERTION"
}

func writeIndentedJSON(path string, value any) error {
	wire, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	wire = append(wire, '\n')
	return os.WriteFile(path, wire, 0o644)
}
