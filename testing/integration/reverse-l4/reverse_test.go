package reversel4_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	reversel4 "github.com/sakullla/sakullla-plugins/plugins/reverse-l4"
)

// The integration suite pins the rewritten control-plane contract: the plugin
// deploys zero-config without any fail-closed typed-handle admission gate,
// demands exactly the new generic capability grants, and no longer carries the
// dropped agent-skeleton model. Deep orchestration against a faked host
// runtime lives in the plugin package tests.

func TestReverseControllerZeroConfigLifecycleWithoutHostRuntime(t *testing.T) {
	newController := func(t *testing.T) *reversel4.Controller {
		t.Helper()
		controller, err := reversel4.NewController(reversel4.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshakeRequest(reverseL4Grants())); err != nil {
			t.Fatalf("zero-config handshake error = %v", err)
		}
		return controller
	}
	for _, config := range []string{"", "null", "{}"} {
		t.Run("config-"+strings.TrimSpace(config), func(t *testing.T) {
			controller := newController(t)
			if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: []byte(config)}); response.Error != nil {
				t.Fatalf("zero-config prepare %q error = %#v", config, response.Error)
			}
		})
	}
	t.Run("deployable-without-host-runtime", func(t *testing.T) {
		controller := newController(t)
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
			t.Fatalf("prepare error = %#v", response.Error)
		}
		if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
			t.Fatalf("activation without host runtime failed closed: %#v", response.Error)
		}
		service := controller.Service()
		if service == nil {
			t.Fatal("prepared controller exposes no orchestration service")
		}
		if _, err := service.Create(context.Background(), testMapping("tcp-map", reversel4.ProtocolTCP)); !errors.Is(err, reversel4.ErrHostRuntimeUnavailable) {
			t.Fatalf("orchestration without host runtime error = %v", err)
		}
		if listed, err := service.List(context.Background()); err != nil || len(listed) != 0 {
			t.Fatalf("listing without host runtime = %#v err=%v", listed, err)
		}
		if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
			t.Fatalf("stop error = %#v", response.Error)
		}
		if controller.Service() != nil {
			t.Fatal("stop left the orchestration service mounted")
		}
	})
	t.Run("rejects-non-empty-config", func(t *testing.T) {
		controller := newController(t)
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: []byte(`{"server":"frp.example.com:7000"}`)}); response.Error == nil {
			t.Fatal("non-empty configuration was accepted although the plugin is zero-config")
		}
	})
}

func TestReverseEntrypointHandshakeProbeSucceeds(t *testing.T) {
	var output bytes.Buffer
	if err := reversel4.RunEntrypoint(context.Background(), []string{reversel4.CIHandshakeFlag}, &output); err != nil {
		t.Fatalf("entrypoint probe error = %v", err)
	}
	if strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("RPC ABI output = %q", output.String())
	}
	if err := reversel4.RunEntrypoint(context.Background(), []string{"--unexpected-argument"}, &output); err == nil {
		t.Fatal("entrypoint accepted an unexpected argument")
	}
}

func TestReverseHandshakeEnforcesGenericCapabilityGrants(t *testing.T) {
	for _, missing := range reverseL4Grants() {
		t.Run("missing-"+missing, func(t *testing.T) {
			controller, err := reversel4.NewController(reversel4.ControllerConfig{
				PackageDigest: "package", ArtifactDigest: "artifact",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(context.Background(), handshakeRequest(withoutGrant(reverseL4Grants(), missing))); !runtimeCode(err, pluginsdk.ErrorPermissionDenied) {
				t.Fatalf("handshake without %s grant error = %v", missing, err)
			}
		})
	}
	t.Run("declared-grants-sufficient", func(t *testing.T) {
		controller, err := reversel4.NewController(reversel4.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshakeRequest(reverseL4Grants())); err != nil {
			t.Fatalf("handshake with every declared grant error = %v", err)
		}
	})
	t.Run("redundant-extra-grant-accepted", func(t *testing.T) {
		controller, err := reversel4.NewController(reversel4.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshakeRequest(append(reverseL4Grants(), "legacy-extra-grant"))); err != nil {
			t.Fatalf("handshake with redundant extra grant error = %v", err)
		}
	})
}

func TestReverseManifestDeclaresControlPlaneCapabilities(t *testing.T) {
	pluginDir := filepath.Join("..", "..", "..", "plugins", "reverse-l4")
	manifest, err := os.ReadFile(filepath.Join(pluginDir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	if !strings.Contains(text, "host_scope: control-plane") {
		t.Fatalf("plugin.yaml is not a control-plane plugin: %s", text)
	}
	for _, permission := range reverseL4Grants() {
		if !strings.Contains(text, "- name: "+permission) {
			t.Fatalf("plugin.yaml must declare the %s capability: %s", permission, text)
		}
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: reverse-l4") || !strings.Contains(text, "resource.group.ref: resource-group/reverse-l4") {
		t.Fatalf("plugin.yaml must declare the plugin resource group: %s", text)
	}
	for _, dropped := range []string{"l4.accept", "tunnel.provider", "l4.inspect", "l4.respond", "reverse-session", "private_agent_id", "public_agent_id"} {
		if strings.Contains(text, dropped) {
			t.Fatalf("plugin.yaml still references the dropped agent-skeleton model: %q", text)
		}
	}

	schemaBytes, err := os.ReadFile(filepath.Join(pluginDir, "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	if required, ok := schema["required"].([]any); ok && len(required) != 0 {
		t.Fatalf("zero-config schema declares required fields: %v", required)
	}
	properties, _ := schema["properties"].(map[string]any)
	if len(properties) != 0 {
		t.Fatalf("zero-config schema declares configuration properties: %v", properties)
	}

	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(pluginDir, name))
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		for _, dropped := range []string{"private_agent_id", "ErrTypedServiceHandlesUnavailable", "AdmitRuntime"} {
			if strings.Contains(source, dropped) {
				t.Fatalf("%s still contains the dropped agent-skeleton symbol %q", name, dropped)
			}
		}
		if strings.Contains(source, "net.Listen(") || strings.Contains(source, "net.Dial(") {
			t.Fatalf("%s opens its own listener or dialer instead of using host effects", name)
		}
	}

	moduleBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	module := string(moduleBytes)
	if strings.Contains(module, "replace ") || strings.Contains(module, "replace(") {
		t.Fatalf("go.mod must not carry a replace directive: %s", module)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "..", "go.work")); err == nil {
		t.Fatal("go.work must not exist in the plugin repository")
	}
}

// --- fixtures ---------------------------------------------------------------

func testMapping(id string, protocol string) reversel4.Mapping {
	return reversel4.Mapping{
		ID: id, EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: protocol, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
	}
}

func reverseL4Grants() []string {
	return []string{"l4.rule", "channel.reverse", "storage.read", "storage.write"}
}

func withoutGrant(grants []string, missing string) []string {
	kept := make([]string, 0, len(grants))
	for _, grant := range grants {
		if grant != missing {
			kept = append(kept, grant)
		}
	}
	return kept
}

func handshakeRequest(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: "reverse-l4", PluginVersion: "0.2.0",
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: grants, Generation: "generation-1",
	}
}

func runtimeCode(err error, code pluginsdk.ErrorCode) bool {
	var runtimeErr *pluginsdk.RuntimeError
	return errors.As(err, &runtimeErr) && runtimeErr.Code == code
}
