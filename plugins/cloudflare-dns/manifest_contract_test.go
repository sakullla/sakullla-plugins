package cloudflaredns

import (
	"path/filepath"
	"reflect"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/pluginmanifest"
)

func TestManifestDeclaresControlPlaneFaceOnly(t *testing.T) {
	t.Parallel()
	manifest, err := pluginmanifest.Load(filepath.Join("plugin.yaml"))
	if err != nil {
		t.Fatalf("load plugin.yaml: %v", err)
	}
	if manifest.ID != PluginID {
		t.Fatalf("manifest id = %q, want %q", manifest.ID, PluginID)
	}
	if !pluginsdk.RuntimeDeclaresHostScope(manifest.Runtime, pluginsdk.HostScopeControlPlane) {
		t.Fatal("cloudflare-dns must declare the local management face")
	}
	if pluginsdk.RuntimeDeclaresHostScope(manifest.Runtime, pluginsdk.HostScopeAgent) {
		t.Fatal("cloudflare-dns must not declare an Agent execution face")
	}
	want := []string{pluginsdk.HostScopeControlPlane}
	if got := pluginsdk.RuntimeDeclaredHostScopes(manifest.Runtime); !reflect.DeepEqual(got, want) {
		t.Fatalf("declared host scopes = %v, want %v", got, want)
	}
}
