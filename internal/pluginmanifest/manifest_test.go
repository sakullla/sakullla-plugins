package pluginmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nunknown: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestValidateSourceAndPackageTreeUseOneV1Contract(t *testing.T) {
	root := t.TempDir()
	artifactData := []byte("ELF fixture")
	artifactFile := writeTestFile(t, root, "build/example-plugin", artifactData, 0o755)
	digest := sha256.Sum256(artifactData)
	manifest := validRPCManifest(hex.EncodeToString(digest[:]), int64(len(artifactData)))
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	if err := ValidateSource(manifest, root, manifest.ID, artifactFile); err != nil {
		t.Fatal(err)
	}

	packageRoot := t.TempDir()
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"plugin.yaml", []byte("fixture"), 0o644},
		{"config.schema.json", []byte(`{"type":"object"}`), 0o644},
		{"artifacts/linux-amd64/example-plugin", artifactData, 0o755},
		{"NOTICE", []byte("notice"), 0o644},
		{"sbom.spdx.json", []byte(`{}`), 0o644},
		{"package.files.json", []byte(`{}`), 0o644},
		{"signature.json", []byte(`{}`), 0o644},
	} {
		writeTestFile(t, packageRoot, file.name, file.data, file.mode)
	}
	if err := ValidatePackageTree(packageRoot, manifest); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, packageRoot, "package.sig", []byte("legacy"), 0o644)
	if err := ValidatePackageTree(packageRoot, manifest); err == nil || !strings.Contains(err.Error(), "unknown file") {
		t.Fatalf("legacy package.sig error = %v", err)
	}
}

func TestRenderBuiltArtifactManifestBindsWorkflowOutputWithoutMutatingSource(t *testing.T) {
	root := t.TempDir()
	artifactData := []byte("workflow-built-artifact")
	artifactFile := writeTestFile(t, root, "build/example-plugin", artifactData, 0o755)
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	manifest := validRPCManifest(strings.Repeat("a", 64), 1)
	bound, wire, err := RenderBuiltArtifactManifest(manifest, root, manifest.ID, artifactFile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifactData)
	if got, want := bound.Artifacts[0].SHA256, hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("bound artifact digest = %s, want %s", got, want)
	}
	if got, want := bound.Artifacts[0].Size, int64(len(artifactData)); got != want {
		t.Fatalf("bound artifact size = %d, want %d", got, want)
	}
	if manifest.Artifacts[0].SHA256 != strings.Repeat("a", 64) || manifest.Artifacts[0].Size != 1 {
		t.Fatal("source manifest was mutated")
	}
	second, secondWire, err := RenderBuiltArtifactManifest(manifest, root, manifest.ID, artifactFile)
	if err != nil || second.Artifacts[0] != bound.Artifacts[0] || !bytes.Equal(secondWire, wire) {
		t.Fatalf("generated manifest is not deterministic: %v", err)
	}
}

func TestValidateRejectsBusinessPermissionAndIncompleteDynamicActionGrant(t *testing.T) {
	manifest := validRPCManifest(strings.Repeat("a", 64), 1)
	manifest.Permissions = []Permission{{Name: "scheduler"}}
	if err := Validate(manifest, manifest.ID); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("business permission error = %v", err)
	}

	root := t.TempDir()
	artifact := writeTestFile(t, root, "build/example-plugin", []byte("x"), 0o755)
	digest := sha256.Sum256([]byte("x"))
	manifest = validRPCManifest(hex.EncodeToString(digest[:]), 1)
	manifest.UISchema = "ui.schema.json"
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	writeTestFile(t, root, "ui.schema.json", []byte(`{"actions":[{"type":"dynamic","capability":"dns.manage"}]}`), 0o644)
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err == nil || !strings.Contains(err.Error(), "ui.dynamic-actions") {
		t.Fatalf("dynamic action permission error = %v", err)
	}
	manifest.Permissions = append(manifest.Permissions, Permission{Name: "ui.dynamic-actions"})
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err == nil || !strings.Contains(err.Error(), "dns.manage") {
		t.Fatalf("dynamic action capability error = %v", err)
	}
	manifest.Permissions = append(manifest.Permissions, Permission{Name: "dns.manage"})
	if err := ValidateSource(manifest, root, manifest.ID, artifact); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsRPCPolicyKindWithoutNestedFace(t *testing.T) {
	manifest := validRPCManifest(strings.Repeat("a", 64), 1)
	manifest.Runtime.PolicyKind = "waf"
	if err := Validate(manifest, manifest.ID); err == nil || !strings.Contains(err.Error(), "nested agent policy face") {
		t.Fatalf("rpc policy_kind without nested face error = %v", err)
	}
}

func TestValidateAdmitsControlPlaneRPCWithNestedAgentWAF(t *testing.T) {
	manifest := validDualFaceWAFManifest(strings.Repeat("a", 64), 1)
	if err := Validate(manifest, manifest.ID); err != nil {
		t.Fatal(err)
	}
	if !pluginsdk.RuntimeProjectsControlPlaneUIAndAgentPolicy(manifest.Runtime) || pluginsdk.RuntimeProjectsAgentRPC(manifest.Runtime) {
		t.Fatalf("dual-face runtime = %+v", manifest.Runtime)
	}
	projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
	if !ok || len(projection.ExtensionPoints) != 1 || projection.ExtensionPoints[0] != pluginsdk.ExtensionHTTPRequest {
		t.Fatalf("PolicyStage must keep http.request and omit ui.route: %#v ok=%v", projection, ok)
	}
	for _, point := range projection.ExtensionPoints {
		if point == pluginsdk.ExtensionUIRoute {
			t.Fatalf("PolicyStage copied ui.route: %#v", projection.ExtensionPoints)
		}
	}
}

func validRPCManifest(digest string, size int64) Manifest {
	return Manifest{
		SchemaVersion: 1, ID: "example-plugin", Version: "1.0.0", Name: "Example Plugin", Description: "Example description",
		Compatibility:   Compatibility{Host: "*", Agent: "*"},
		Runtime:         Runtime{Kind: RuntimeRPCService, ABI: RPCABIV1, HostScope: "agent", Entry: "example-plugin"},
		Artifacts:       []Artifact{{Path: "artifacts/linux-amd64/example-plugin", SHA256: digest, Size: size, Mode: "executable", GOOS: "linux", GOARCH: "amd64"}},
		ExtensionPoints: []string{"dns.provider"}, Permissions: []Permission{{Name: "secret.use"}}, ConfigSchema: "config.schema.json",
		ResourceBudget: ResourceBudget{TimeoutMS: 30000, MemoryBytes: 268435456, Concurrency: 8, InputBytes: 1048576, OutputBytes: 1048576, CPUMillis: 1000, Restarts: 3},
		FailurePolicy:  FailurePolicy{OnError: "fail-closed", OnBudget: "fail-closed", Restart: "on-failure", CoreFallback: "preserve"},
		Signature:      Signature{Algorithm: "ed25519", KeyID: OfficialKeyID, File: "signature.json"},
		Cleanup:        Cleanup{Instances: "delete", Config: "delete", OwnedData: "delete", Grants: "delete", SharedRefs: "retain", AuditEvents: "retain"},
	}
}

func validDualFaceWAFManifest(digest string, size int64) Manifest {
	manifest := validRPCManifest(digest, size)
	manifest.Runtime.HostScope = pluginsdk.HostScopeControlPlane
	manifest.Runtime.PolicyKind = "waf"
	manifest.Runtime.Policy = &pluginsdk.RuntimePolicy{
		Kind: RuntimeWASMPolicy, ABI: PolicyABIV1, HostScope: pluginsdk.HostScopeAgent,
		Entry:          "artifacts/waf.wasm",
		ResourceBudget: ResourceBudget{TimeoutMS: 2, MemoryBytes: 16777216, Concurrency: 64, InputBytes: 131072, OutputBytes: 4096},
		FailurePolicy:  FailurePolicy{OnError: "fail-closed", OnBudget: "fail-closed", Restart: "never", CoreFallback: "preserve"},
	}
	manifest.Artifacts = append(manifest.Artifacts, Artifact{Path: "artifacts/waf.wasm", SHA256: strings.Repeat("b", 64), Size: 1, Mode: "wasm"})
	manifest.ExtensionPoints = []string{pluginsdk.ExtensionUIRoute, pluginsdk.ExtensionHTTPRequest}
	return manifest
}

func writeTestFile(t *testing.T, root, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestOfficialSourcesCarryChineseDisplayCopy(t *testing.T) {
	expected := map[string]struct {
		name       string
		declaredUI bool
	}{
		"accelerator-sources": {name: "资源加速"},
		"ip-policy":           {name: "IP 策略", declaredUI: true},
		"rate-limit":          {name: "速率限制", declaredUI: true},
		"cloudflare-dns":      {name: "Cloudflare DNS"},
		"docker-app":          {name: "Docker 应用"},
		"doh":                 {name: "HTTPS 域名解析"},
		"reverse-l4":          {name: "四层反向穿透"},
		"shadowsocks-server":  {name: "Shadowsocks 服务"},
		"waf":                 {name: "Web 防火墙"},
		"webdav":              {name: "文件共享"},
	}
	pluginsRoot := filepath.Join("..", "..", "plugins")
	for id, want := range expected {
		manifest, err := Load(filepath.Join(pluginsRoot, id, "plugin.yaml"))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if err := Validate(manifest, id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if manifest.Name != want.name {
			t.Fatalf("%s name = %q, want %q", id, manifest.Name, want.name)
		}
		if !containsHan(manifest.Description) {
			t.Fatalf("%s description must be Chinese user-facing copy: %q", id, manifest.Description)
		}
		if want.declaredUI && manifest.UISchema != "ui.schema.json" {
			t.Fatalf("%s must declare ui_schema: ui.schema.json", id)
		}
		if !want.declaredUI && manifest.UISchema != "" {
			t.Fatalf("%s must not declare a config UI", id)
		}
		if id == "accelerator-sources" {
			if len(manifest.HTTPBackendProviders) != 1 || manifest.HTTPBackendProviders[0].ID != "default" || manifest.HTTPBackendProviders[0].DisplayName != "资源加速" {
				t.Fatalf("accelerator-sources provider must stay default/资源加速: %#v", manifest.HTTPBackendProviders)
			}
		}
		if id == "waf" {
			if !pluginsdk.RuntimeProjectsControlPlaneUIAndAgentPolicy(manifest.Runtime) {
				t.Fatalf("waf dual-face runtime = %+v", manifest.Runtime)
			}
			if manifest.UISchema != "" {
				t.Fatal("waf must not declare ui.schema.json as the operator path")
			}
			if manifest.Runtime.PolicyKind != "waf" || manifest.Runtime.Policy == nil || manifest.Runtime.Policy.Kind != RuntimeWASMPolicy || manifest.Runtime.Policy.Entry != "artifacts/waf.wasm" {
				t.Fatalf("waf nested wasm-policy = %+v", manifest.Runtime)
			}
			projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
			if !ok || len(projection.ExtensionPoints) != 1 || projection.ExtensionPoints[0] != pluginsdk.ExtensionHTTPRequest {
				t.Fatalf("PolicyStage must keep http.request and omit ui.route: %#v ok=%v", projection, ok)
			}
		}
		if id == "webdav" {
			if manifest.Runtime.HostScope != "agent" {
				t.Fatalf("webdav host_scope = %q, want agent", manifest.Runtime.HostScope)
			}
			if len(manifest.HTTPBackendProviders) != 1 || manifest.HTTPBackendProviders[0].ID != "default" || manifest.HTTPBackendProviders[0].DisplayName != "文件共享" {
				t.Fatalf("webdav provider must stay default/文件共享: %#v", manifest.HTTPBackendProviders)
			}
			for _, point := range manifest.ExtensionPoints {
				if point == "ui.route" || point == "resource.group" {
					t.Fatalf("webdav must not declare %s", point)
				}
			}
			if manifest.UIRouteID != "" || manifest.ResourceGroupID != "" {
				t.Fatalf("webdav must not declare ui.route or resource.group identity: %#v", manifest)
			}
		}
	}
}

func containsHan(value string) bool {
	for _, character := range value {
		if unicode.Is(unicode.Han, character) {
			return true
		}
	}
	return false
}

func TestPackagingContractBindsDeclaredUIAndMachineIdentity(t *testing.T) {
	root := t.TempDir()
	artifactData := []byte("display-contract-artifact")
	artifactFile := writeTestFile(t, root, "build/example-plugin", artifactData, 0o755)
	artifactDigest := sha256.Sum256(artifactData)
	manifest := validRPCManifest(hex.EncodeToString(artifactDigest[:]), int64(len(artifactData)))
	manifest.Name = "资源加速"
	manifest.Description = "为零配置发布的自有域名提供加速"
	manifest.ExtensionPoints = []string{"http.backend-provider"}
	manifest.HTTPBackendProviders = []pluginsdk.HTTPBackendProviderDescriptor{{ID: "default", DisplayName: "资源加速"}}
	manifest.UISchema = "ui.schema.json"
	writeTestFile(t, root, "config.schema.json", []byte(`{"type":"object"}`), 0o644)
	writeTestFile(t, root, "ui.schema.json", []byte(`{"schema_version":1,"title":"资源加速设置","components":[],"actions":[]}`), 0o644)

	if err := ValidateSource(manifest, root, manifest.ID, artifactFile); err != nil {
		t.Fatalf("Chinese display fields must validate: %v", err)
	}
	if _, ok := ExtraFiles(manifest, root)["ui.schema.json"]; !ok {
		t.Fatal("declared ui.schema.json must be packaged via ExtraFiles")
	}

	if err := os.Remove(filepath.Join(root, "ui.schema.json")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceContract(manifest, root, manifest.ID); err == nil || !strings.Contains(err.Error(), "ui.schema.json") {
		t.Fatalf("missing declared UI file must fail: %v", err)
	}

	if err := Validate(manifest, "renamed-plugin"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("renamed plugin id must fail: %v", err)
	}
	manifest.Runtime.Entry = "renamed-entry"
	if err := Validate(manifest, manifest.ID); err == nil {
		t.Fatal("renamed runtime entry must fail")
	}
}
