package waf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestManifestPermissionsSatisfyHostHandshake(t *testing.T) {
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var grants []string
	for _, permission := range manifest.Permissions {
		grants = append(grants, permission.Name)
	}
	required := pluginsdk.RequiredRPCFeaturesForExtensions(grants, manifest.ExtensionPoints)
	for name, factory := range map[string]func() (pluginsdk.RPCLifecycle, error){
		"runtime": newRuntimeController,
		"probe": func() (pluginsdk.RPCLifecycle, error) {
			return newProbeController(pluginsdk.RPCHandshakeRequest{PackageDigest: "package", ArtifactDigest: "artifact"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			controller, err := factory()
			if err != nil {
				t.Fatal(err)
			}
			response, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
				ABI: pluginsdk.RPCABIV1, PluginID: manifest.ID, PluginVersion: manifest.Version,
				PackageDigest: "package", ArtifactDigest: "artifact", Generation: "generation-1",
				GrantedScopes: grants, RequiredFeatures: required,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := pluginsdk.ValidateRPCFeatures(required, response.Features); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := pluginsdk.ValidateRPCFeatures(required, wafHandshakeDeclaration().SupportedFeatures); err != nil {
		t.Fatalf("build probe must request the host-required features: %v", err)
	}
}

func TestHandshakeDoesNotAdvertiseUngrantedCapabilities(t *testing.T) {
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1",
	}
	response, err := controller.Handshake(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	granted := make(map[string]bool, len(request.GrantedScopes))
	for _, scope := range request.GrantedScopes {
		granted[scope] = true
	}
	for _, capability := range response.Capabilities {
		if !granted[capability] {
			t.Fatalf("handshake advertised ungranted capability %q", capability)
		}
	}
}

func TestRunEntrypointNormalStartupUsesCanonicalSDKServers(t *testing.T) {
	t.Setenv("NRE_PLUGIN_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("NRE_PLUGIN_HTTP_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_HTTP_COOKIE_FILE", "")

	err := RunEntrypoint(context.Background(), nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("RunEntrypoint() unexpectedly succeeded without host endpoints")
	}
	if !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("RunEntrypoint() error = %v, want canonical SDK endpoint validation", err)
	}
}

func TestProductionConfigLeavesCatalogEmptyWithoutHost(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	config := bindProductionHostCapabilities(ControllerConfig{})
	if config.Catalog != nil || config.Overlays != nil || config.Events != nil || config.Configs != nil {
		t.Fatalf("production execution contracts must stay unset without a host runtime endpoint: %+v", config)
	}
}

func TestRunEntrypointProbeHandshake(t *testing.T) {
	output := &bytes.Buffer{}
	if err := RunEntrypoint(context.Background(), []string{CIHandshakeFlag}, output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), pluginsdk.RPCABIV1) {
		t.Fatalf("probe output = %q", output.String())
	}
}

func TestOfficialSourcesDoNotKeepGenericConfigForm(t *testing.T) {
	if _, err := os.Stat("ui.schema.json"); err == nil {
		t.Fatal("ui.schema.json must not remain the operator path")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
