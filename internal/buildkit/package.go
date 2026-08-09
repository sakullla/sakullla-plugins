package buildkit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	SPDXVersion string     `json:"spdxVersion"`
	DataLicense string     `json:"dataLicense"`
	Name        string     `json:"name"`
	Files       []spdxFile `json:"files"`
}

type spdxFile struct {
	FileName string `json:"fileName"`
	SHA256   string `json:"sha256"`
	FileType string `json:"fileType"`
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
	spdx := spdxDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", Name: "sakullla-plugin-package"}
	for _, file := range initial {
		spdx.Files = append(spdx.Files, spdxFile{FileName: "./" + file.Path, SHA256: file.SHA256, FileType: "BINARY"})
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
