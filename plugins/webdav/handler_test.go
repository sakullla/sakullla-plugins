package webdav

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestConfigSchemaDeclaresClosedLoadableObject(t *testing.T) {
	data, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("webdav config schema must be a closed object: %#v", schema)
	}
	properties, _ := schema["properties"].(map[string]any)
	if len(properties) != 2 || properties["password"] == nil || properties["root_path"] == nil {
		t.Fatalf("webdav config schema must only declare password and root_path: %#v", properties)
	}
	required, _ := schema["required"].([]any)
	if len(required) != 1 || required[0] != "password" {
		t.Fatalf("webdav config schema must require password: %#v", schema["required"])
	}
}

func TestPluginManifestIsAgentHTTPBackendWithoutControlPlaneUI(t *testing.T) {
	data, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["id"] != PluginID || document["name"] != "文件共享" || document["version"] != PluginVersion {
		t.Fatalf("plugin identity = %#v", document)
	}
	runtime, _ := document["runtime"].(map[string]any)
	if runtime["host_scope"] != "agent" || runtime["kind"] != "rpc-service" || runtime["abi"] != "nre:rpc/v1" || runtime["entry"] != "webdav" {
		t.Fatalf("runtime = %#v", runtime)
	}
	points, _ := document["extension_points"].([]any)
	if len(points) != 1 || points[0] != "http.backend-provider" {
		t.Fatalf("extension_points = %#v", points)
	}
	providers, _ := document["http_backend_providers"].([]any)
	if len(providers) != 1 {
		t.Fatalf("http_backend_providers = %#v", providers)
	}
	provider, _ := providers[0].(map[string]any)
	if provider["id"] != ProviderID || provider["display_name"] != "文件共享" {
		t.Fatalf("provider = %#v", provider)
	}
	permissions, _ := document["permissions"].([]any)
	if len(permissions) != 2 {
		t.Fatalf("permissions = %#v", permissions)
	}
	storage, _ := permissions[1].(map[string]any)
	if storage["name"] != pluginsdk.PermissionStorageWrite || storage["resource"] != pluginsdk.StorageResourceConfigPath+":/root_path" {
		t.Fatalf("storage permission = %#v", storage)
	}
	if document["ui_route_id"] != nil || document["resource_group_id"] != nil || document["ui_schema"] != nil {
		t.Fatalf("control-plane UI fields must be absent: %#v", document)
	}
	encoded := string(data)
	if strings.Contains(encoded, "ui.route") || strings.Contains(encoded, "resource.group") {
		t.Fatal("plugin.yaml must not declare ui.route or resource.group")
	}
}

func TestServeHTTPIs503UntilActivateAndAfterStop(t *testing.T) {
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	assertHTTPStatus(t, controller, http.StatusServiceUnavailable)
	activateController(t, controller, "generation-one")
	recorder := doShareRequest(t, controller, http.MethodGet, "http://provider.test/", testSharePassword, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%q", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-one"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	assertHTTPStatus(t, controller, http.StatusServiceUnavailable)
}

func TestDefaultShareRootIsOwnedDirectoryNotFilesystemRoot(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "owned-root")
	status := controller.Status()
	want := filepath.Join(cwd, OwnedShareName)
	if status.Root != want {
		t.Fatalf("share root = %q, want %q", status.Root, want)
	}
	if isVolumeRoot(status.Root) {
		t.Fatalf("share root must not be the filesystem root: %q", status.Root)
	}
	marker := filepath.Join(status.Root, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "owned-root"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("stop deleted owned share file: %v", err)
	}
}

func TestLoadConfigRequiresPasswordAndRejectsUnknownFields(t *testing.T) {
	if _, err := loadConfig([]byte(`{}`)); err == nil {
		t.Fatal("missing password was accepted")
	}
	if _, err := loadConfig(nil); err == nil {
		t.Fatal("empty config was accepted")
	}
	got, err := loadConfig([]byte(`{"password":"share-pass"}`))
	if err != nil || got.Password != "share-pass" || got.RootPath != "" {
		t.Fatalf("password only = %+v err=%v", got, err)
	}
	if _, err := loadConfig([]byte(`{"legacy":true}`)); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := loadConfig([]byte(`{"password":""}`)); err == nil {
		t.Fatal("empty password was accepted")
	}
	if _, err := loadConfig([]byte(`{}{}`)); err == nil {
		t.Fatal("two documents were accepted")
	}
}

func assertHTTPStatus(t *testing.T, handler http.Handler, want int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://provider.test/", nil))
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d body=%q", recorder.Code, want, recorder.Body.String())
	}
}

func activateController(t *testing.T, controller *Controller, generation string) {
	t.Helper()
	activateControllerWithConfig(t, controller, generation, testShareConfig(testSharePassword, ""))
}

func activateControllerWithConfig(t *testing.T, controller *Controller, generation string, config []byte) {
	t.Helper()
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound, pluginsdk.PermissionStorageWrite}, Generation: generation,
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: generation, Config: config}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: generation}); result.Error != nil {
		t.Fatal(result.Error)
	}
}
