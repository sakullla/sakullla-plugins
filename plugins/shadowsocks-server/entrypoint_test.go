package shadowsocksserver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestRunEntrypointNormalStartupUsesCanonicalSDKServers(t *testing.T) {
	t.Setenv("NRE_PLUGIN_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("NRE_PLUGIN_HTTP_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_HTTP_COOKIE_FILE", "")

	err := RunEntrypoint(context.Background(), nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("RunEntrypoint() unexpectedly succeeded without host endpoints")
	}
	if errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("RunEntrypoint() returned the old startup sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("RunEntrypoint() error = %v, want canonical SDK endpoint validation", err)
	}
}

func TestRuntimeServicesSkipUIWithoutHostRuntimeEndpoint(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")
	services := runtimeServices()
	if services.UI || !services.UIOptional {
		t.Fatalf("agent execution face services = %#v", services)
	}
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "unix:/run/nre-plugin/host.sock")
	services = runtimeServices()
	if !services.UI || !services.UIOptional {
		t.Fatalf("control-plane services = %#v", services)
	}
}

func TestRunEntrypointHandshakeProbePrintsABI(t *testing.T) {
	output := &bytes.Buffer{}
	if err := RunEntrypoint(context.Background(), []string{CIHandshakeFlag}, output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), pluginsdk.RPCABIV1) {
		t.Fatalf("handshake probe output = %q", output.String())
	}
}

func TestPluginYAMLDeclaresImplicitRemoteAgentExecution(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if !pluginsdk.RuntimeImplicitRemoteAgentExecution(manifest.Runtime) {
		t.Fatalf("shadowsocks-server runtime = %+v, want implicit remote Agent execution", manifest.Runtime)
	}
}

func TestPluginYAMLPermissionsSatisfyRuntimeHandshake(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
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
	requiredFeatures := pluginsdk.RequiredRPCFeaturesForExtensions(grants, manifest.ExtensionPoints)
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: manifest.ID, PluginVersion: manifest.Version,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1",
		RequiredFeatures: requiredFeatures,
	})
	if err != nil {
		t.Fatalf("plugin.yaml permissions do not satisfy the runtime handshake: %v", err)
	}
	if !slices.Equal(response.Features, requiredFeatures) {
		t.Fatalf("runtime handshake features = %v, want %v", response.Features, requiredFeatures)
	}
}

func TestPluginYAMLDeclaresUIRouteNotHostPage(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: shadowsocks-server") {
		t.Fatalf("plugin.yaml must declare ui.route support: %s", text)
	}
	if !strings.Contains(text, "ui.nav.group: 网络") || !strings.Contains(text, "ui.nav.label: Shadowsocks 账号") {
		t.Fatalf("plugin.yaml must declare host nav metadata: %s", text)
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: shadowsocks-server") {
		t.Fatalf("plugin.yaml must declare resource.group support: %s", text)
	}
	if !strings.Contains(text, "host_scope: control-plane") {
		t.Fatalf("plugin.yaml must declare control-plane host_scope: %s", text)
	}
	if !strings.Contains(text, "host_scopes:") || (!strings.Contains(text, "- agent") && !strings.Contains(text, "[agent]")) {
		t.Fatalf("plugin.yaml must declare host_scopes including agent: %s", text)
	}
	if regexp.MustCompile(`(?m)^[[:space:]]*host_scope:[[:space:]]*agent[[:space:]]*$`).MatchString(text) {
		t.Fatal("shadowsocks-server primary host_scope must not be agent")
	}
	if strings.Contains(text, "tunnel.provider") {
		t.Fatal("shadowsocks-server must not declare tunnel.provider")
	}
	if strings.Contains(text, "http.backend-provider") || strings.Contains(text, "http_backend_providers") {
		t.Fatal("shadowsocks-server must not use install-time HTTP backend publish")
	}
	if !strings.Contains(text, "assets/ui/index.html") || !strings.Contains(text, "assets/ui/app.js") || !strings.Contains(text, "assets/ui/style.css") {
		t.Fatal("plugin.yaml must declare frontend files below assets/")
	}
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("admin panel must not use host config ui_schema")
	}
	for _, want := range []string{
		"resource.group.ref: resource-group/shadowsocks-server",
		"resource.group.label: Shadowsocks 服务",
		"resource.group.description: 在组内按节点管理 Shadowsocks 监听与账号",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin.yaml must declare %q: %s", want, text)
		}
	}
}
