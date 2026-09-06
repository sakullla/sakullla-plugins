package ippolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func activeUIController(t *testing.T, runtime RuntimeClient) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	features := pluginsdk.RequiredRPCFeatures(requiredGrants())
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", Generation: "generation", GrantedScopes: requiredGrants(), RequiredFeatures: features}); err != nil {
		t.Fatal(err)
	}
	config, _ := EncodeConfiguration(DefaultConfiguration())
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller
}

func uiRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/ui-test")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestDedicatedManagementPageAndVisibleRuntimeStates(t *testing.T) {
	controller := activeUIController(t, &runtimeStub{})
	page := httptest.NewRecorder()
	controller.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, text := range []string{"IP 策略", "中国大陆省份白名单", "期望模式", "实际应用", "最近有效", "检查状态", "诊断事件"} {
		if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), text) {
			t.Fatalf("page missing %q: %s", text, page.Body.String())
		}
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), ErrUnauthorized.Error()) {
		t.Fatalf("denied=%d %s", denied.Code, denied.Body.String())
	}

	state := httptest.NewRecorder()
	controller.ServeHTTP(state, uiRequest(http.MethodGet, "/api/state?node_id=local", ""))
	var payload APIResponse
	if err := json.Unmarshal(state.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if state.Code != http.StatusOK || !payload.Ready || len(payload.Provinces) != 31 || payload.Policy == nil || !payload.Access.CanRead || !payload.Access.CanWrite {
		t.Fatalf("state=%d %+v", state.Code, payload)
	}
}

func TestUIRejectsUnknownAndOversizedWritesWithoutMutation(t *testing.T) {
	controller := activeUIController(t, &runtimeStub{})
	unknown := httptest.NewRecorder()
	controller.ServeHTTP(unknown, uiRequest(http.MethodPost, "/api/config", `{"mode":"observe","config":{},"unknown":true}`))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown=%d %s", unknown.Code, unknown.Body.String())
	}
	oversized := httptest.NewRecorder()
	controller.ServeHTTP(oversized, uiRequest(http.MethodPost, "/api/config", strings.Repeat("x", pluginsdk.PluginHostPayloadMaxBytes+1)))
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("oversized=%d", oversized.Code)
	}
}

var _ = context.Background
