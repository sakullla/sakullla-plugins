package pluginmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	RuntimeRPCService = pluginsdk.RuntimeRPCService
	RuntimeWASMPolicy = pluginsdk.RuntimeWASMPolicy
	RPCABIV1          = pluginsdk.RPCABIV1
	PolicyABIV1       = pluginsdk.PolicyABIV1
	OfficialKeyID     = "sakullla-official-root-2026"
)

const pluginManifestSchemaURL = "https://github.com/sakullla/nginx-reverse-emby/plugin-sdk/schema/plugin-manifest-v1.schema.json"

var canonicalSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(pluginsdk.PluginManifestSchemaV1()))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SDK plugin manifest schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(pluginManifestSchemaURL, document); err != nil {
		return nil, fmt.Errorf("register SDK plugin manifest schema: %w", err)
	}
	return compiler.Compile(pluginManifestSchemaURL)
})

// The SDK owns the structural plugin.yaml v1 contract. This package adds the
// stricter official-publisher semantic and package-envelope profile.
type Manifest = pluginsdk.Manifest
type Compatibility = pluginsdk.Compatibility
type Runtime = pluginsdk.Runtime
type Artifact = pluginsdk.Artifact
type Permission = pluginsdk.Permission
type ResourceBudget = pluginsdk.ResourceBudget
type FailurePolicy = pluginsdk.FailurePolicy
type Signature = pluginsdk.Signature
type Migration = pluginsdk.Migration
type Cleanup = pluginsdk.CleanupPolicy

func Load(filename string) (Manifest, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return Manifest{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("strictly decode %s: %w", filename, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("%s must contain exactly one YAML document", filename)
	}
	return manifest, nil
}

func ValidateSource(manifest Manifest, root, expectedID, artifactFile string) error {
	if err := ValidateSourceContract(manifest, root, expectedID); err != nil {
		return err
	}
	declared, err := artifactForBuild(manifest)
	if err != nil {
		return err
	}
	info, err := os.Stat(artifactFile)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("artifact %q is not a regular build output: %w", artifactFile, err)
	}
	digest, err := digestFile(artifactFile)
	if err != nil {
		return err
	}
	if info.Size() != declared.Size || digest != declared.SHA256 {
		return fmt.Errorf("artifact %s metadata mismatch: built size=%d sha256=%s, manifest size=%d sha256=%s", declared.Path, info.Size(), digest, declared.Size, declared.SHA256)
	}
	return nil
}

func ValidateSourceContract(manifest Manifest, root, expectedID string) error {
	if err := Validate(manifest, expectedID); err != nil {
		return err
	}
	for _, reference := range manifestReferences(manifest) {
		if err := requireRegular(root, reference); err != nil {
			return err
		}
	}
	if manifest.UISchema != "" {
		if err := validateDynamicUI(filepath.Join(root, filepath.FromSlash(manifest.UISchema)), manifest.Permissions); err != nil {
			return err
		}
	}
	return nil
}

func ValidatePackageTree(root string, manifest Manifest) error {
	if err := Validate(manifest, manifest.ID); err != nil {
		return err
	}
	allowed := stringSet("plugin.yaml", "NOTICE", "sbom.spdx.json", "package.files.json", "signature.json")
	for _, reference := range manifestReferences(manifest) {
		allowed[reference] = struct{}{}
	}
	for _, artifact := range manifest.Artifacts {
		allowed[artifact.Path] = struct{}{}
	}
	var actual []string
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package contains symbolic link %q", current)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("package contains non-regular file %q", current)
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, ok := allowed[rel]; !ok {
			return fmt.Errorf("package contains undeclared or unknown file %q", rel)
		}
		actual = append(actual, rel)
		return nil
	})
	if err != nil {
		return err
	}
	for required := range allowed {
		if err := requireRegular(root, required); err != nil {
			return err
		}
	}
	for _, artifact := range manifest.Artifacts {
		name := filepath.Join(root, filepath.FromSlash(artifact.Path))
		info, err := os.Stat(name)
		if err != nil {
			return err
		}
		wantMode := fs.FileMode(0o644)
		if artifact.Mode == "executable" {
			wantMode = 0o755
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != wantMode {
			return fmt.Errorf("artifact %q mode is %04o, want %04o", artifact.Path, info.Mode().Perm(), wantMode)
		}
		digest, err := digestFile(name)
		if err != nil {
			return err
		}
		if info.Size() != artifact.Size || digest != artifact.SHA256 {
			return fmt.Errorf("artifact %q content differs from plugin.yaml", artifact.Path)
		}
	}
	if err := validateRecordedModes(root, manifest); err != nil {
		return err
	}
	sort.Strings(actual)
	return nil
}

func validateRecordedModes(root string, manifest Manifest) error {
	data, err := os.ReadFile(filepath.Join(root, "package.files.json"))
	if err != nil {
		return err
	}
	var document struct {
		Files []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode package.files.json modes: %w", err)
	}
	executables := make(map[string]struct{})
	for _, artifact := range manifest.Artifacts {
		if artifact.Mode == "executable" {
			executables[artifact.Path] = struct{}{}
		}
	}
	for _, record := range document.Files {
		want := "0644"
		if _, executable := executables[record.Path]; executable {
			want = "0755"
		}
		if record.Mode != want {
			return fmt.Errorf("package.files.json mode for %q is %s, want %s", record.Path, record.Mode, want)
		}
	}
	return nil
}

func ExtraFiles(manifest Manifest, root string) map[string]string {
	result := make(map[string]string)
	for _, reference := range manifestReferences(manifest) {
		result[reference] = filepath.Join(root, filepath.FromSlash(reference))
	}
	return result
}

func ArtifactDestination(manifest Manifest) (string, string, error) {
	artifact, err := artifactForBuild(manifest)
	if err != nil {
		return "", "", err
	}
	return artifact.Path, artifact.Mode, nil
}

func Validate(manifest Manifest, expectedID string) error {
	if err := validateCanonicalSchema(manifest); err != nil {
		return err
	}
	if manifest.ID != expectedID {
		return fmt.Errorf("manifest id %q does not match expected plugin %q", manifest.ID, expectedID)
	}
	if strings.TrimSpace(manifest.Name) == "" || strings.TrimSpace(manifest.Description) == "" || manifest.Compatibility.Host == "" || manifest.Compatibility.Agent == "" {
		return errors.New("manifest name, description, and host/agent compatibility are required")
	}
	if manifest.ConfigSchema != "config.schema.json" || (manifest.UISchema != "" && manifest.UISchema != "ui.schema.json") {
		return errors.New("config_schema must be config.schema.json and ui_schema, when present, must be ui.schema.json")
	}
	if len(manifest.ExtensionPoints) == 0 || len(manifest.Artifacts) == 0 {
		return errors.New("manifest requires extension_points and artifacts")
	}
	if err := validateRuntimeAndArtifacts(manifest); err != nil {
		return err
	}
	if err := validateReferences(manifest); err != nil {
		return err
	}
	budget := manifest.ResourceBudget
	if budget.TimeoutMS <= 0 || budget.MemoryBytes <= 0 || budget.Concurrency <= 0 || budget.InputBytes <= 0 || budget.OutputBytes <= 0 {
		return errors.New("resource_budget requires positive timeout, memory, concurrency, input, and output limits")
	}
	if manifest.Runtime.Kind == RuntimeWASMPolicy && (budget.CPUMillis != 0 || budget.Restarts != 0) {
		return errors.New("wasm-policy must not declare cpu_millis or restarts")
	}
	if manifest.Runtime.Kind == RuntimeRPCService && (budget.CPUMillis <= 0 || budget.Restarts < 0) {
		return errors.New("rpc-service requires cpu_millis and a non-negative restarts budget")
	}
	failure := manifest.FailurePolicy
	if !oneOf(failure.OnError, "fail-open", "fail-closed", "degraded") || !oneOf(failure.OnBudget, "fail-open", "fail-closed") || failure.CoreFallback != "preserve" {
		return errors.New("failure_policy is outside the v1 allowlist")
	}
	if manifest.Runtime.Kind == RuntimeWASMPolicy && failure.Restart != "never" {
		return errors.New("wasm-policy failure_policy.restart must be never")
	}
	if manifest.Runtime.Kind == RuntimeRPCService && !oneOf(failure.Restart, "never", "on-failure") {
		return errors.New("rpc-service failure_policy.restart must be never or on-failure")
	}
	if manifest.Signature != (Signature{Algorithm: "ed25519", KeyID: OfficialKeyID, File: "signature.json"}) {
		return errors.New("signature must declare ed25519, sakullla-official-root-2026, and signature.json")
	}
	cleanup := manifest.Cleanup
	if !oneOf(cleanup.Instances, "delete", "retain") || cleanup.Config != cleanup.Instances || cleanup.OwnedData != cleanup.Instances || cleanup.Grants != cleanup.Instances || cleanup.SharedRefs != "retain" || cleanup.AuditEvents != "retain" {
		return errors.New("cleanup must consistently delete or retain mutable state and retain shared_refs/audit_events")
	}
	return nil
}

func validateRuntimeAndArtifacts(manifest Manifest) error {
	runtime := manifest.Runtime
	switch runtime.Kind {
	case RuntimeWASMPolicy:
		if runtime.ABI != PolicyABIV1 || runtime.HostScope != "agent" || !oneOf(runtime.PolicyKind, "ip", "rate", "waf") || len(manifest.Artifacts) != 1 {
			return errors.New("wasm-policy requires nre:policy/v1, agent scope, policy_kind, and exactly one artifact")
		}
		artifact := manifest.Artifacts[0]
		if artifact.Path != runtime.Entry || !strings.HasPrefix(artifact.Path, "artifacts/") || path.Ext(artifact.Path) != ".wasm" || artifact.Mode != "wasm" || artifact.GOOS != "" || artifact.GOARCH != "" {
			return errors.New("wasm-policy artifact must be the single platform-neutral .wasm runtime entry")
		}
	case RuntimeRPCService:
		if runtime.ABI != RPCABIV1 || !oneOf(runtime.HostScope, "agent", "control-plane") || runtime.PolicyKind != "" || runtime.Entry == "" || strings.ContainsAny(runtime.Entry, `/\\`) {
			return errors.New("rpc-service requires nre:rpc/v1, an allowed host_scope, and a logical entry name")
		}
		for _, artifact := range manifest.Artifacts {
			extension := ""
			if artifact.GOOS == "windows" {
				extension = ".exe"
			}
			want := "artifacts/" + artifact.GOOS + "-" + artifact.GOARCH + "/" + runtime.Entry + extension
			if artifact.Path != want || artifact.Mode != "executable" || !oneOf(artifact.GOOS, "linux", "windows", "darwin", "freebsd") || !oneOf(artifact.GOARCH, "amd64", "arm64") {
				return fmt.Errorf("RPC artifact %q must match artifacts/<goos>-<goarch>/<entry>[.exe]", artifact.Path)
			}
		}
	default:
		return fmt.Errorf("runtime kind %q is not allowed", runtime.Kind)
	}
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if !safePath(artifact.Path) {
			return fmt.Errorf("artifact %q requires a canonical path", artifact.Path)
		}
		if _, duplicate := seen[artifact.Path]; duplicate {
			return fmt.Errorf("duplicate artifact %q", artifact.Path)
		}
		seen[artifact.Path] = struct{}{}
	}
	return nil
}

func validateReferences(manifest Manifest) error {
	seen := stringSet("config.schema.json")
	if manifest.UISchema != "" {
		seen[manifest.UISchema] = struct{}{}
	}
	for _, asset := range manifest.Assets {
		if !safePath(asset) || !strings.HasPrefix(asset, "assets/") {
			return fmt.Errorf("asset %q must be a canonical path below assets/", asset)
		}
		if _, duplicate := seen[asset]; duplicate {
			return fmt.Errorf("duplicate manifest path %q", asset)
		}
		seen[asset] = struct{}{}
	}
	for _, migration := range manifest.Migrations {
		if migration.From == migration.To || !safePath(migration.File) || !strings.HasPrefix(migration.File, "migrations/") || path.Ext(migration.File) != ".json" {
			return fmt.Errorf("migration %q must declare distinct semantic versions and a migrations/*.json file", migration.File)
		}
		if _, duplicate := seen[migration.File]; duplicate {
			return fmt.Errorf("duplicate manifest path %q", migration.File)
		}
		seen[migration.File] = struct{}{}
	}
	return nil
}

func validateDynamicUI(filename string, permissions []Permission) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document struct {
		Actions []struct {
			Type       string `json:"type"`
			Capability string `json:"capability"`
		} `json:"actions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %s: %w", filename, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s contains trailing JSON", filename)
	}
	declared := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		declared[permission.Name] = struct{}{}
	}
	for _, action := range document.Actions {
		if action.Type != "dynamic" {
			continue
		}
		if _, ok := declared["ui.dynamic-actions"]; !ok {
			return errors.New("dynamic UI action requires ui.dynamic-actions permission")
		}
		if action.Capability == "" || action.Capability == "ui.dynamic-actions" {
			return fmt.Errorf("dynamic UI action capability %q is not an allowed action capability", action.Capability)
		}
		if _, ok := declared[action.Capability]; !ok {
			return fmt.Errorf("dynamic UI action capability %q is absent from permissions", action.Capability)
		}
	}
	return nil
}

func artifactForBuild(manifest Manifest) (Artifact, error) {
	if manifest.Runtime.Kind == RuntimeWASMPolicy && len(manifest.Artifacts) == 1 {
		return manifest.Artifacts[0], nil
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.GOOS == "linux" && artifact.GOARCH == "amd64" {
			return artifact, nil
		}
	}
	return Artifact{}, errors.New("official RPC package requires a linux-amd64 artifact")
}

func manifestReferences(manifest Manifest) []string {
	result := []string{manifest.ConfigSchema}
	if manifest.UISchema != "" {
		result = append(result, manifest.UISchema)
	}
	result = append(result, manifest.Assets...)
	for _, migration := range manifest.Migrations {
		result = append(result, migration.File)
	}
	return result
}

func requireRegular(root, reference string) error {
	if !safePath(reference) {
		return fmt.Errorf("non-canonical package path %q", reference)
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(reference)))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("declared package file %q is missing or not regular: %w", reference, err)
	}
	return nil
}

func safePath(value string) bool {
	return value != "" && fs.ValidPath(value) && path.Clean(value) == value && !strings.Contains(value, `\`)
}

func validateCanonicalSchema(manifest Manifest) error {
	schema, err := canonicalSchema()
	if err != nil {
		return err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode plugin manifest for SDK schema validation: %w", err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode plugin manifest for SDK schema validation: %w", err)
	}
	if err := schema.Validate(document); err != nil {
		return fmt.Errorf("SDK plugin manifest schema: %w", err)
	}
	return nil
}

func digestFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
