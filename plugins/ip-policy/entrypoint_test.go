package ippolicy

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

func TestManifestDeclaresControlPlaneUIAndAgentIPPolicy(t *testing.T) {
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Runtime.Kind != pluginsdk.RuntimeRPCService || manifest.Runtime.HostScope != pluginsdk.HostScopeControlPlane || manifest.Runtime.PolicyKind != "ip" || manifest.Runtime.Policy == nil {
		t.Fatalf("dual face runtime = %+v", manifest.Runtime)
	}
	if pluginsdk.RuntimeProjectsAgentRPC(manifest.Runtime) || !pluginsdk.RuntimeProjectsControlPlaneUIAndAgentPolicy(manifest.Runtime) {
		t.Fatalf("runtime face projection = %+v", manifest.Runtime)
	}
	projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
	if !ok || projection.HostScope != pluginsdk.HostScopeAgent || projection.Entry != "artifacts/ip-policy.wasm" || projection.ModeHandling != pluginsdk.PolicyModeHandlingRaw {
		t.Fatalf("Agent policy projection = %+v", projection)
	}
	if manifest.UISchema != "" || manifest.UIRouteID != PluginID {
		t.Fatalf("dedicated UI declaration schema=%q route=%q", manifest.UISchema, manifest.UIRouteID)
	}
	if manifest.Cleanup.Instances != "delete" || manifest.Cleanup.Config != "delete" || manifest.Cleanup.OwnedData != "delete" || manifest.Cleanup.Grants != "delete" {
		t.Fatalf("plugin-owned state must be removed on uninstall: %+v", manifest.Cleanup)
	}
	if _, err := os.Stat("ui.schema.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy generic UI schema remains")
	}
}

func TestManifestPermissionsSatisfyHandshakeAndProbe(t *testing.T) {
	raw, _ := os.ReadFile("plugin.yaml")
	var manifest pluginsdk.Manifest
	_ = yaml.Unmarshal(raw, &manifest)
	grants := make([]string, 0, len(manifest.Permissions))
	for _, permission := range manifest.Permissions {
		grants = append(grants, permission.Name)
	}
	required, err := pluginsdk.RequiredRPCFeaturesForExecutionScope(grants, manifest.ExtensionPoints, pluginsdk.HostScopeControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	legacyFeatures := make([]string, 0, len(required)-1)
	for _, feature := range required {
		if feature != pluginsdk.RPCFeaturePolicyEntryOverlaysV1 {
			legacyFeatures = append(legacyFeatures, feature)
		}
	}
	if _, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", Generation: "legacy-generation", GrantedScopes: grants, RequiredFeatures: legacyFeatures}); err == nil {
		t.Fatal("Host without required entry-overlay feature completed handshake")
	}
	response, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", Generation: "generation", GrantedScopes: grants, RequiredFeatures: required})
	if err != nil {
		t.Fatal(err)
	}
	if err := pluginsdk.ValidateRPCFeatures(required, response.Features); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(response.Features, ","), pluginsdk.RPCFeatureExecutionScopeV1) {
		t.Fatal("control-plane process omitted explicit execution-scope support")
	}
	if !strings.Contains(strings.Join(response.Features, ","), pluginsdk.RPCFeaturePolicyEntryOverlaysV1) {
		t.Fatal("control-plane process omitted entry-overlay support")
	}
	output := &bytes.Buffer{}
	if err := RunEntrypoint(context.Background(), []string{CIHandshakeFlag}, output); err != nil || !strings.Contains(output.String(), pluginsdk.RPCABIV1) {
		t.Fatalf("probe = %q, %v", output.String(), err)
	}
}
