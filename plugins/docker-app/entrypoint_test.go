package dockerapp

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

func TestDockerHandshakeDoesNotAdvertiseUngrantedCapabilities(t *testing.T) {
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
	if errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("RunEntrypoint() returned the old startup sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("RunEntrypoint() error = %v, want canonical SDK endpoint validation", err)
	}
}

func TestRunEntrypointProductionWiresReportedEngineSource(t *testing.T) {
	t.Setenv("NRE_PLUGIN_HOST_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	config := productionControllerConfig()
	if config.UIEngineSource == nil {
		t.Fatal("production entrypoint still pins a zero UIEngine as the only observation path")
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
		t.Fatalf("docker-app runtime = %+v, want implicit remote Agent execution", manifest.Runtime)
	}
}

func TestRuntimeServicesSkipUIWithoutHostRuntimeEndpoint(t *testing.T) {
	t.Setenv("NRE_PLUGIN_DOCKER_PROXY_ENDPOINT", "")
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

func TestRuntimeServicesSkipUIWhenDockerProxyIsPresent(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "unix:/run/nre-plugin/host.sock")
	t.Setenv("NRE_PLUGIN_DOCKER_PROXY_ENDPOINT", "unix:/run/nre-plugin/docker-proxy.sock")
	t.Setenv(pluginsdk.EnvPluginUIEndpoint, "unix:/run/nre-plugin/ui.sock")
	services := runtimeServices()
	if services.UI || !services.UIOptional {
		t.Fatalf("agent docker-proxy face still serves UI: %#v", services)
	}
}

func TestRunEntrypointDeclarationAcknowledgesDurableActions(t *testing.T) {
	output := &bytes.Buffer{}
	err := RunEntrypoint(context.Background(), []string{CIHandshakeFlag}, output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), pluginsdk.RPCABIV1) {
		t.Fatalf("handshake probe output = %q", output.String())
	}
}
