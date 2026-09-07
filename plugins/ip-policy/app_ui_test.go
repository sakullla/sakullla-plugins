package ippolicy

import (
	"context"
	"encoding/json"
	"fmt"
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
	features := controlPlaneFeatures()
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

func TestEntryRuleInteractionUsesHostListedEntries(t *testing.T) {
	for index, kind := range []string{pluginsdk.PolicyEntryHTTP, pluginsdk.PolicyEntryTCP, pluginsdk.PolicyEntryUDP, pluginsdk.PolicyEntryManagedTCP, pluginsdk.PolicyEntryManagedUDP} {
		t.Run(kind, func(t *testing.T) {
			token := fmt.Sprintf("entry-token-%012d", index+1)
			snapshot := entrySnapshot(kind, "entry-7", token)
			runtime := &runtimeStub{entries: []pluginsdk.PolicyEntrySnapshot{snapshot}}
			controller := activeUIController(t, runtime)
			body := fmt.Sprintf(`{"entry":{"node_id":"local","kind":%q,"id":"entry-7","token":%q},"rules":[{"id":"one","action":"deny","selector":{"type":"ip","value":"192.0.2.1"}},{"id":"two","action":"allow","selector":{"type":"cidr","value":"198.51.100.0/24"}}]}`, kind, token)
			stored := httptest.NewRecorder()
			controller.ServeHTTP(stored, uiRequest(http.MethodPost, "/api/entry-rules", body))
			if stored.Code != http.StatusOK {
				t.Fatalf("store status=%d body=%s", stored.Code, stored.Body.String())
			}
			mutation := runtime.policyCalls[len(runtime.policyCalls)-1]
			if mutation.Action != pluginsdk.PolicyControlReplaceEntry || mutation.Entry == nil || mutation.Entry.Token != token || len(mutation.Overlay) == 0 {
				t.Fatalf("entry mutation=%+v", mutation)
			}
			deleted := httptest.NewRecorder()
			controller.ServeHTTP(deleted, uiRequest(http.MethodPost, "/api/entry-rules", fmt.Sprintf(`{"entry":{"node_id":"local","kind":%q,"id":"entry-7","token":%q},"rules":[]}`, kind, token)))
			if deleted.Code != http.StatusOK {
				t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
			}
		})
	}
}

func uiRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/ui-test")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestDedicatedManagementPageAndVisibleRuntimeStates(t *testing.T) {
	entries := []pluginsdk.PolicyEntrySnapshot{
		entrySnapshot(pluginsdk.PolicyEntryHTTP, "http-1", "entry-token-000000000001"),
		entrySnapshot(pluginsdk.PolicyEntryTCP, "tcp-1", "entry-token-000000000002"),
		entrySnapshot(pluginsdk.PolicyEntryUDP, "udp-1", "entry-token-000000000003"),
		entrySnapshot(pluginsdk.PolicyEntryManagedTCP, "managed-tcp-1", "entry-token-000000000004"),
		entrySnapshot(pluginsdk.PolicyEntryManagedUDP, "managed-udp-1", "entry-token-000000000005"),
	}
	controller := activeUIController(t, &runtimeStub{entries: entries})
	page := httptest.NewRecorder()
	controller.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, text := range []string{"IP 策略", "中国大陆省份白名单", "选择入口", "全局规则", "入口专属规则", "全局模式", "应用状态", "配置版本", "诊断事件"} {
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
	if state.Code != http.StatusOK || !payload.Ready || len(payload.Provinces) != 31 || payload.Policy == nil || len(payload.Entries) != 5 || !payload.Access.CanRead || !payload.Access.CanWrite {
		t.Fatalf("state=%d %+v", state.Code, payload)
	}
	selected := httptest.NewRecorder()
	controller.ServeHTTP(selected, uiRequest(http.MethodGet, "/api/state?entry_token=entry-token-000000000001", ""))
	if err := json.Unmarshal(selected.Body.Bytes(), &payload); err != nil || payload.Entry == nil || payload.Entry.Entry == nil || payload.Entry.Entry.Token != entries[0].Entry.Token || payload.EntryOverlay == nil {
		t.Fatalf("selected entry state=%d %+v err=%v", selected.Code, payload, err)
	}
	stale := httptest.NewRecorder()
	controller.ServeHTTP(stale, uiRequest(http.MethodGet, "/api/state?entry_token=entry-token-000000000099", ""))
	payload = APIResponse{}
	if err := json.Unmarshal(stale.Body.Bytes(), &payload); err != nil || len(payload.Issues) == 0 || payload.Entry != nil {
		t.Fatalf("stale selected entry=%d %+v err=%v", stale.Code, payload, err)
	}
}

func TestUIRejectsUnknownAndOversizedWritesWithoutMutation(t *testing.T) {
	controller := activeUIController(t, &runtimeStub{})
	unknown := httptest.NewRecorder()
	controller.ServeHTTP(unknown, uiRequest(http.MethodPost, "/api/config", `{"mode":"observe","config":{},"unknown":true}`))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown=%d %s", unknown.Code, unknown.Body.String())
	}
	entryRules := httptest.NewRecorder()
	controller.ServeHTTP(entryRules, uiRequest(http.MethodPost, "/api/config", `{"mode":"observe","config":{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[],"province_whitelist":[],"rules":[],"entry_rules":[]}}`))
	if entryRules.Code != http.StatusBadRequest {
		t.Fatalf("entry_rules config=%d %s", entryRules.Code, entryRules.Body.String())
	}
	oversized := httptest.NewRecorder()
	controller.ServeHTTP(oversized, uiRequest(http.MethodPost, "/api/config", strings.Repeat("x", pluginsdk.PluginHostPayloadMaxBytes+1)))
	if oversized.Code != http.StatusBadRequest {
		t.Fatalf("oversized=%d", oversized.Code)
	}
}

func TestStateDistinguishesEmptyHostListAndPolicyDenial(t *testing.T) {
	empty := activeUIController(t, &runtimeStub{entries: []pluginsdk.PolicyEntrySnapshot{}})
	emptyResponse := httptest.NewRecorder()
	empty.ServeHTTP(emptyResponse, uiRequest(http.MethodGet, "/api/state", ""))
	var payload APIResponse
	if err := json.Unmarshal(emptyResponse.Body.Bytes(), &payload); err != nil || emptyResponse.Code != http.StatusOK || payload.Entries == nil || len(payload.Entries) != 0 {
		t.Fatalf("empty list status=%d payload=%+v err=%v", emptyResponse.Code, payload, err)
	}

	denied := activeUIController(t, &runtimeStub{policyErr: &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "denied"}})
	deniedResponse := httptest.NewRecorder()
	denied.ServeHTTP(deniedResponse, uiRequest(http.MethodGet, "/api/state", ""))
	if deniedResponse.Code != http.StatusForbidden || !strings.Contains(deniedResponse.Body.String(), ErrUnauthorized.Error()) {
		t.Fatalf("policy denial=%d %s", deniedResponse.Code, deniedResponse.Body.String())
	}
}

var _ = context.Background
