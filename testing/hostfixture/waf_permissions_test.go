package hostfixture

import (
	"os"
	"path/filepath"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestWAFArtifactImportsStayWithinManifestPermissions(t *testing.T) {
	root, err := hostfixtureRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "plugins", "waf", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	grants := make([]string, 0, len(manifest.Permissions))
	for _, permission := range manifest.Permissions {
		grants = append(grants, permission.Name)
	}
	if err := pluginsdk.ValidatePolicyV1WASMForHost(buildWAFArtifact(t), pluginsdk.PolicyV1MaxMemoryBytes, grants, grants, policyHostImports()); err != nil {
		t.Fatalf("signed WAF permissions cannot admit its release artifact: %v", err)
	}
}
