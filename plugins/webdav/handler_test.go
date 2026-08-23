package webdav

import (
	"bytes"
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

func TestBasicAndBearerAuthentication(t *testing.T) {
	root := t.TempDir()
	handler, err := NewHandler(root, testSharePassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []struct {
		name string
		set  func(*http.Request)
	}{
		{name: "basic", set: func(request *http.Request) { request.SetBasicAuth("alice", testSharePassword) }},
		{name: "bearer", set: func(request *http.Request) { request.Header.Set("Authorization", "bEaReR "+testSharePassword) }},
	} {
		t.Run(auth.name, func(t *testing.T) {
			requests := []*http.Request{
				httptest.NewRequest(http.MethodGet, "http://share.test/", nil),
				httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil),
				httptest.NewRequest(http.MethodPut, "http://share.test/dav/"+auth.name+".txt", strings.NewReader(auth.name)),
			}
			for _, request := range requests {
				auth.set(request)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				if recorder.Code == http.StatusUnauthorized || recorder.Code >= 400 {
					t.Fatalf("%s %s status = %d body=%q", request.Method, request.URL.Path, recorder.Code, recorder.Body.String())
				}
			}
		})
	}
	component, err := basicNamespaceComponent("alice")
	if err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(root, component, "basic.txt")); err != nil || string(body) != "basic" {
		t.Fatalf("basic namespace file = %q err=%v", body, err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "bearer.txt")); err != nil || string(body) != "bearer" {
		t.Fatalf("bearer root file = %q err=%v", body, err)
	}

	wrongBasic := httptest.NewRequest(http.MethodGet, "http://share.test/", nil)
	wrongBasic.SetBasicAuth("mallory", "wrong")
	for _, path := range []string{"/", "/api/list?path=/", "/dav/missing.txt"} {
		for _, header := range []string{"", "Basic !!!", wrongBasic.Header.Get("Authorization"), "Bearer", "Bearer wrong", "Bearer " + testSharePassword + " extra", "Digest token"} {
			request := httptest.NewRequest(http.MethodGet, "http://share.test"+path, nil)
			request.Header.Set("Authorization", header)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("path=%q header=%q status=%d", path, header, recorder.Code)
			}
			if got := recorder.Header().Values("WWW-Authenticate"); len(got) != 2 || got[0] != basicChallenge || got[1] != bearerChallenge {
				t.Fatalf("path=%q header=%q challenges=%q", path, header, got)
			}
		}
	}
	malloryComponent, _ := basicNamespaceComponent("mallory")
	if _, err := os.Stat(filepath.Join(root, malloryComponent)); !os.IsNotExist(err) {
		t.Fatalf("wrong Basic password created a namespace: %v", err)
	}
}

func TestInvalidBasicUsername(t *testing.T) {
	root := t.TempDir()
	handler, err := NewHandler(root, testSharePassword)
	if err != nil {
		t.Fatal(err)
	}
	usernames := []string{"", ".", "..", "/absolute", `folder/name`, `folder\name`, `C:\temp`, "nul\x00name", strings.Repeat("x", MaxBasicUsernameBytes+1), string([]byte{0xff})}
	for _, username := range usernames {
		t.Run(strings.ReplaceAll(username, "\x00", "NUL"), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil)
			request.SetBasicAuth(username, testSharePassword)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("username=%q status=%d body=%q", username, recorder.Code, recorder.Body.String())
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("username=%q changed root: entries=%v err=%v", username, entries, err)
			}
		})
	}
}

func TestBasicUserDirectoryIsolation(t *testing.T) {
	root := t.TempDir()
	handler, err := NewHandler(root, testSharePassword)
	if err != nil {
		t.Fatal(err)
	}
	request := func(username, method, target, body string) *httptest.ResponseRecorder {
		t.Helper()
		var reader *bytes.Reader
		if body != "" {
			reader = bytes.NewReader([]byte(body))
		} else {
			reader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, target, reader)
		req.SetBasicAuth(username, testSharePassword)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	if got := request("alice", "MKCOL", "http://share.test/dav/private", ""); got.Code != http.StatusCreated {
		t.Fatalf("alice MKCOL = %d %q", got.Code, got.Body.String())
	}
	if got := request("alice", http.MethodPut, "http://share.test/dav/private/secret.txt", "alice-secret"); got.Code != http.StatusCreated {
		t.Fatalf("alice PUT = %d %q", got.Code, got.Body.String())
	}
	if got := request("alice", http.MethodGet, "http://share.test/api/list?path=/private", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "secret.txt") {
		t.Fatalf("alice API did not see DAV file = %d %q", got.Code, got.Body.String())
	}
	if got := request("bob", http.MethodGet, "http://share.test/api/list?path=/", ""); got.Code != http.StatusOK || strings.Contains(got.Body.String(), "private") {
		t.Fatalf("bob list = %d %q", got.Code, got.Body.String())
	}
	if got := request("bob", http.MethodGet, "http://share.test/dav/private/secret.txt", ""); got.Code != http.StatusNotFound {
		t.Fatalf("bob read alice = %d %q", got.Code, got.Body.String())
	}
	if got := request("bob", http.MethodPut, "http://share.test/dav/private.txt", "bob-private"); got.Code != http.StatusCreated {
		t.Fatalf("bob PUT = %d %q", got.Code, got.Body.String())
	}
	if got := request("alice", http.MethodPut, "http://share.test/dav/private.txt", "alice-private"); got.Code != http.StatusCreated {
		t.Fatalf("alice PUT = %d %q", got.Code, got.Body.String())
	}
	if got := request("bob", http.MethodPost, "http://share.test/api/rename", `{"from":"/private/secret.txt","to":"/stolen.txt"}`); got.Code < 400 {
		t.Fatalf("bob rename alice = %d %q", got.Code, got.Body.String())
	}
	if got := request("bob", http.MethodPost, "http://share.test/api/delete", `{"path":"/private/secret.txt"}`); got.Code != http.StatusNotFound {
		t.Fatalf("bob delete alice = %d %q", got.Code, got.Body.String())
	}
	move := httptest.NewRequest("MOVE", "http://share.test/dav/private/secret.txt", nil)
	move.SetBasicAuth("bob", testSharePassword)
	move.Header.Set("Destination", "http://share.test/dav/stolen.txt")
	moved := httptest.NewRecorder()
	handler.ServeHTTP(moved, move)
	if moved.Code < 400 {
		t.Fatalf("bob MOVE alice = %d %q", moved.Code, moved.Body.String())
	}
	if got := request("bob", http.MethodDelete, "http://share.test/dav/private/secret.txt", ""); got.Code != http.StatusNotFound {
		t.Fatalf("bob DELETE alice = %d %q", got.Code, got.Body.String())
	}

	aliceComponent, _ := basicNamespaceComponent("alice")
	bobComponent, _ := basicNamespaceComponent("bob")
	for component, want := range map[string]string{aliceComponent: "alice-private", bobComponent: "bob-private"} {
		body, err := os.ReadFile(filepath.Join(root, component, "private.txt"))
		if err != nil || string(body) != want {
			t.Fatalf("namespace %q private file = %q err=%v", component, body, err)
		}
	}
	if body, err := os.ReadFile(filepath.Join(root, aliceComponent, "private", "secret.txt")); err != nil || string(body) != "alice-secret" {
		t.Fatalf("alice secret changed = %q err=%v", body, err)
	}
	if handler.lockSystem(aliceComponent) == handler.lockSystem(bobComponent) {
		t.Fatal("basic namespaces share a DAV lock system")
	}
	components := make(map[string]string)
	for _, username := range []string{"Alice", "alice", "é", "e\u0301"} {
		component, err := basicNamespaceComponent(username)
		if err != nil {
			t.Fatalf("username %q: %v", username, err)
		}
		folded := strings.ToLower(component)
		if previous := components[folded]; previous != "" {
			t.Fatalf("usernames %q and %q collide as %q", previous, username, component)
		}
		components[folded] = username
	}
	webdavComponent, err := basicNamespaceComponent(DavMountUsername)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(DavMountUsername, http.MethodGet, "http://share.test/", ""); got.Code != http.StatusOK {
		t.Fatalf("webdav page = %d", got.Code)
	}
	if info, err := os.Stat(filepath.Join(root, webdavComponent)); err != nil || !info.IsDir() {
		t.Fatalf("webdav namespace missing: info=%v err=%v", info, err)
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
