package buildkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PackageRequest struct {
	ManifestPath string
	ArtifactPath string
	NoticePaths  []string
	OutputDir    string
	Signer       Signer
	Validator    Validator
}

type PackageResult struct {
	OutputDir      string
	PayloadDigest  string
	PackageDigest  string
	SignerIdentity string
}

type packageFileManifest struct {
	SchemaVersion int          `json:"schema_version"`
	PayloadSHA256 string       `json:"payload_sha256"`
	Files         []FileRecord `json:"files"`
}

type signatureDocument struct {
	SchemaVersion int    `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	Identity      string `json:"identity"`
	PayloadSHA256 string `json:"payload_sha256"`
	Signature     string `json:"signature"`
}

type spdxDocument struct {
	SPDXID            string           `json:"SPDXID"`
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	DocumentDescribes []string         `json:"documentDescribes"`
	Files             []spdxFile       `json:"files"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxFile struct {
	SPDXID    string         `json:"SPDXID"`
	FileName  string         `json:"fileName"`
	Checksums []spdxChecksum `json:"checksums"`
	FileTypes []string       `json:"fileTypes"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

func BuildPackage(ctx context.Context, request PackageRequest) (PackageResult, error) {
	if request.Signer == nil || request.Validator == nil {
		return PackageResult{}, fmt.Errorf("signer and validator are required")
	}
	if request.OutputDir == "" || request.ManifestPath == "" || request.ArtifactPath == "" {
		return PackageResult{}, fmt.Errorf("manifest, artifact, and output paths are required")
	}
	if len(request.NoticePaths) == 0 {
		return PackageResult{}, fmt.Errorf("at least one NOTICE or license source is required")
	}
	if _, err := os.Lstat(request.OutputDir); !os.IsNotExist(err) {
		if err == nil {
			return PackageResult{}, fmt.Errorf("output path %q already exists", request.OutputDir)
		}
		return PackageResult{}, err
	}
	parent := filepath.Dir(request.OutputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return PackageResult{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".nre-package-")
	if err != nil {
		return PackageResult{}, err
	}
	defer os.RemoveAll(temporary)

	artifactName, err := safeBaseName(request.ArtifactPath)
	if err != nil {
		return PackageResult{}, err
	}
	if err := copyRegularFile(request.ManifestPath, filepath.Join(temporary, "plugin.yaml")); err != nil {
		return PackageResult{}, fmt.Errorf("copy manifest: %w", err)
	}
	if err := copyRegularFile(request.ArtifactPath, filepath.Join(temporary, "artifact", artifactName)); err != nil {
		return PackageResult{}, fmt.Errorf("copy artifact: %w", err)
	}
	if err := writeNotice(filepath.Join(temporary, "NOTICE"), request.NoticePaths); err != nil {
		return PackageResult{}, err
	}
	initial, err := recordsForTree(temporary, nil)
	if err != nil {
		return PackageResult{}, err
	}
	initialDigest := digestRecords(initial)
	spdx := spdxDocument{
		SPDXID: "SPDXRef-DOCUMENT", SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0",
		Name: "sakullla-plugin-package", DocumentNamespace: "https://spdx.org/spdxdocs/sakullla-plugin-" + initialDigest,
		CreationInfo: spdxCreationInfo{Created: "1970-01-01T00:00:00Z", Creators: []string{"Tool: sakullla-nre-package-1"}},
	}
	for index, file := range initial {
		id := fmt.Sprintf("SPDXRef-File-%03d", index+1)
		fileType := "BINARY"
		if file.Path == "NOTICE" || strings.HasSuffix(file.Path, ".yaml") || strings.HasSuffix(file.Path, ".json") {
			fileType = "TEXT"
		}
		spdx.DocumentDescribes = append(spdx.DocumentDescribes, id)
		spdx.Files = append(spdx.Files, spdxFile{
			SPDXID: id, FileName: "./" + file.Path,
			Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: file.SHA256}},
			FileTypes: []string{fileType},
		})
	}
	spdxJSON, err := jsonBytes(spdx)
	if err != nil {
		return PackageResult{}, err
	}
	if err := ValidateSPDX23JSON(spdxJSON); err != nil {
		return PackageResult{}, fmt.Errorf("validate generated SPDX 2.3 document: %w", err)
	}
	if err := writeCanonicalJSON(filepath.Join(temporary, "sbom.spdx.json"), spdx); err != nil {
		return PackageResult{}, err
	}
	payloadFiles, err := recordsForTree(temporary, map[string]bool{"package.files.json": true, "signature.json": true})
	if err != nil {
		return PackageResult{}, err
	}
	payloadDigest := digestRecords(payloadFiles)
	manifest := packageFileManifest{SchemaVersion: 1, PayloadSHA256: payloadDigest, Files: payloadFiles}
	if err := writeCanonicalJSON(filepath.Join(temporary, "package.files.json"), manifest); err != nil {
		return PackageResult{}, err
	}
	digestBytes, err := hex.DecodeString(payloadDigest)
	if err != nil {
		return PackageResult{}, err
	}
	signature, err := request.Signer.Sign(ctx, digestBytes)
	if err != nil {
		return PackageResult{}, err
	}
	if signature.Identity == "" || signature.Algorithm == "" || len(signature.Value) == 0 {
		return PackageResult{}, fmt.Errorf("signer returned an incomplete signature")
	}
	signatureFile := signatureDocument{
		SchemaVersion: 1, Algorithm: signature.Algorithm, Identity: signature.Identity,
		PayloadSHA256: payloadDigest, Signature: base64.StdEncoding.EncodeToString(signature.Value),
	}
	if err := writeCanonicalJSON(filepath.Join(temporary, "signature.json"), signatureFile); err != nil {
		return PackageResult{}, err
	}
	if err := request.Validator.Validate(ctx, temporary); err != nil {
		return PackageResult{}, err
	}
	allFiles, err := recordsForTree(temporary, nil)
	if err != nil {
		return PackageResult{}, err
	}
	packageDigest := digestRecords(allFiles)
	if err := os.Rename(temporary, request.OutputDir); err != nil {
		return PackageResult{}, err
	}
	return PackageResult{
		OutputDir: request.OutputDir, PayloadDigest: payloadDigest,
		PackageDigest: packageDigest, SignerIdentity: signature.Identity,
	}, nil
}

func jsonBytes(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func ValidateSPDX23JSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document spdxDocument
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("SPDX document contains trailing JSON values")
	}
	if document.SPDXID != "SPDXRef-DOCUMENT" || document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" {
		return fmt.Errorf("invalid SPDX document identity, version, or data license")
	}
	if document.Name == "" || !strings.HasPrefix(document.DocumentNamespace, "https://spdx.org/spdxdocs/") {
		return fmt.Errorf("SPDX name and document namespace are required")
	}
	if _, err := time.Parse(time.RFC3339, document.CreationInfo.Created); err != nil || len(document.CreationInfo.Creators) == 0 {
		return fmt.Errorf("SPDX creationInfo requires an RFC3339 timestamp and creator")
	}
	if len(document.Files) == 0 || len(document.DocumentDescribes) != len(document.Files) {
		return fmt.Errorf("SPDX document must describe every file")
	}
	described := make(map[string]bool, len(document.DocumentDescribes))
	for _, id := range document.DocumentDescribes {
		described[id] = true
	}
	seen := make(map[string]bool, len(document.Files))
	for _, file := range document.Files {
		if file.SPDXID == "" || seen[file.SPDXID] || !described[file.SPDXID] || !strings.HasPrefix(file.FileName, "./") {
			return fmt.Errorf("invalid or duplicate SPDX file identity %q", file.SPDXID)
		}
		seen[file.SPDXID] = true
		if len(file.Checksums) != 1 || file.Checksums[0].Algorithm != "SHA256" || len(file.Checksums[0].ChecksumValue) != 64 {
			return fmt.Errorf("SPDX file %s requires one SHA256 checksum", file.SPDXID)
		}
		if file.Checksums[0].ChecksumValue != strings.ToLower(file.Checksums[0].ChecksumValue) {
			return fmt.Errorf("SPDX file %s checksum is not lowercase hex", file.SPDXID)
		}
		if _, err := hex.DecodeString(file.Checksums[0].ChecksumValue); err != nil {
			return fmt.Errorf("SPDX file %s checksum is not lowercase hex: %w", file.SPDXID, err)
		}
		if len(file.FileTypes) != 1 || (file.FileTypes[0] != "BINARY" && file.FileTypes[0] != "TEXT") {
			return fmt.Errorf("SPDX file %s has an unsupported file type", file.SPDXID)
		}
	}
	return nil
}

func writeNotice(destination string, sources []string) error {
	paths := append([]string{}, sources...)
	sort.Strings(paths)
	var sections []string
	for _, path := range paths {
		name, err := safeBaseName(path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("notice source %q is not a regular file", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		text = strings.ReplaceAll(text, "\r", "\n")
		sections = append(sections, fmt.Sprintf("===== %s =====\n%s", name, strings.TrimSpace(text)))
	}
	contents := strings.Join(sections, "\n\n") + "\n"
	return os.WriteFile(destination, []byte(contents), 0o644)
}

func DigestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
