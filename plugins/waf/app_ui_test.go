package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestPluginYAMLDeclaresDedicatedManagementPage(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("waf must not use ui.schema.json as the operator path")
	}
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: waf") {
		t.Fatalf("plugin.yaml must declare ui.route: %s", text)
	}
	if !strings.Contains(text, "ui.nav.group: 安全") || !strings.Contains(text, "ui.nav.label: Web 防火墙") {
		t.Fatalf("plugin.yaml must declare host nav metadata: %s", text)
	}
	if !strings.Contains(text, "host_scope: control-plane") {
		t.Fatal("primary host_scope must be control-plane")
	}
	if !strings.Contains(text, "assets/ui/index.html") || !strings.Contains(text, "assets/ui/app.js") {
		t.Fatal("plugin.yaml must declare frontend files below assets/")
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if !pluginsdk.RuntimeProjectsControlPlaneUIAndAgentPolicy(manifest.Runtime) {
		t.Fatalf("dual-face projection missing: %+v", manifest.Runtime)
	}
	if pluginsdk.RuntimeProjectsAgentRPC(manifest.Runtime) {
		t.Fatalf("waf must not project Agent RPC: %+v", manifest.Runtime)
	}
	projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
	if !ok || projection.PolicyKind != "waf" || projection.Entry != "artifacts/waf.wasm" {
		t.Fatalf("policy projection = %+v ok=%v", projection, ok)
	}
	if len(projection.ExtensionPoints) != 1 || projection.ExtensionPoints[0] != pluginsdk.ExtensionHTTPRequest {
		t.Fatalf("policy-face extensions = %v", projection.ExtensionPoints)
	}
}

func TestManagementPageServesChineseCopy(t *testing.T) {
	t.Parallel()
	controller := newUIController(t, uiControllerOptions{})
	page := httptest.NewRecorder()
	controller.ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, `id="app-workspace"`) || !strings.Contains(body, "Web 防火墙") {
		t.Fatalf("page status=%d body=%s", page.Code, body)
	}
	if strings.Contains(body, "{{") {
		t.Fatalf("page still has templates: %s", body)
	}
	for _, want := range []string{"观察中", "拦截", "还没有 HTTP 入口", "无权管理 Web 防火墙", "防护执行面暂时不可用", "命中与跳过事件"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q", want)
		}
	}
}

func TestManagementPageListsHTTPEntriesAsObserve(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	catalog.entries["agent-1"] = []HTTPEntry{{
		RuleRef: "12", FrontendURL: "http://app.example.com", Backend: "127.0.0.1:8096", Enabled: true, Mode: ModeObserve, Attached: true,
	}}
	controller := newUIController(t, uiControllerOptions{catalog: catalog})
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", listed.Code, listed.Body.String())
	}
	payload := decodeWAFState(t, listed.Body.Bytes())
	if payload.DefaultMode != ModeObserve || len(payload.Entries) != 1 || payload.Entries[0].Mode != ModeObserve || payload.Entries[0].FrontendURL != "http://app.example.com" {
		t.Fatalf("state=%#v", payload)
	}
	if !payload.Access.CanRead || !payload.Access.CanWrite {
		t.Fatalf("access=%#v", payload.Access)
	}
}

func TestManagementPageSwitchesEntryAndGlobalMode(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	catalog.entries["agent-1"] = []HTTPEntry{
		{RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
		{RuleRef: "13", FrontendURL: "http://other.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
	}
	controller := newUIController(t, uiControllerOptions{catalog: catalog, overlays: catalog})
	switched := httptest.NewRecorder()
	controller.ServeHTTP(switched, uiJSONRequest(http.MethodPost, "/api/entries/mode", `{"agent_id":"agent-1","rule_ref":"12","mode":"deny"}`))
	payload := decodeWAFState(t, switched.Body.Bytes())
	if switched.Code != http.StatusOK || len(payload.Entries) != 2 {
		t.Fatalf("status=%d body=%s", switched.Code, switched.Body.String())
	}
	if payload.Entries[0].Mode != ModeDeny || payload.Entries[1].Mode != ModeObserve {
		t.Fatalf("per-entry switch = %#v", payload.Entries)
	}
	global := httptest.NewRecorder()
	controller.ServeHTTP(global, uiJSONRequest(http.MethodPost, "/api/mode", `{"agent_id":"agent-1","mode":"deny"}`))
	all := decodeWAFState(t, global.Body.Bytes())
	if global.Code != http.StatusOK || all.DefaultMode != ModeDeny || all.Entries[0].Mode != ModeDeny || all.Entries[1].Mode != ModeDeny {
		t.Fatalf("global switch = %#v", all)
	}
}

func TestManagementPageAddsExclusionAndCustomRule(t *testing.T) {
	t.Parallel()
	controller := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/custom-rules", `{"agent_id":"agent-1","id":"block-admin","target":"path","needle":"/admin"}`))
	if rule.Code != http.StatusOK || !strings.Contains(rule.Body.String(), `"id":"block-admin"`) {
		t.Fatalf("custom rule status=%d body=%s", rule.Code, rule.Body.String())
	}
	exclusion := httptest.NewRecorder()
	controller.ServeHTTP(exclusion, uiJSONRequest(http.MethodPost, "/api/exclusions", `{"agent_id":"agent-1","rule_id":"block-admin","path_prefix":"/health"}`))
	payload := decodeWAFState(t, exclusion.Body.Bytes())
	if exclusion.Code != http.StatusOK || len(payload.CustomRules) != 1 || len(payload.Exclusions) != 1 {
		t.Fatalf("rules status=%d payload=%#v", exclusion.Code, payload)
	}
	if payload.Exclusions[0].PathPrefix != "/health" {
		t.Fatalf("exclusion=%#v", payload.Exclusions)
	}
	filled := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	for index := 0; index < MaxRules; index++ {
		seeded := httptest.NewRecorder()
		filled.ServeHTTP(seeded, uiJSONRequest(http.MethodPost, "/api/custom-rules", fmt.Sprintf(`{"id":"rule-%02d","target":"path","needle":"ab"}`, index)))
		if seeded.Code != http.StatusOK {
			t.Fatalf("seed %d status=%d body=%s", index, seeded.Code, seeded.Body.String())
		}
	}
	denied := httptest.NewRecorder()
	filled.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/custom-rules", `{"id":"too-many-rules","target":"path","needle":"ab"}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), ErrBoundExceeded.Error()) {
		t.Fatalf("bound status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(filled.currentConfig().CustomRules) != MaxRules {
		t.Fatalf("bound mutated config=%#v", filled.currentConfig())
	}
}

func TestManagementPageShowsMatchAndSkipEvents(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	catalog.events = []SecurityEvent{
		{Site: "app.example.com", RuleID: "path-traversal", Digest: "abc", Disposition: ModeObserve, Reason: "rule_matched"},
		{Site: "app.example.com", RuleID: "body-xss", Digest: "def", Disposition: ModeObserve, Reason: "body_window_skipped"},
	}
	controller := newUIController(t, uiControllerOptions{catalog: catalog, events: catalog})
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	body := listed.Body.String()
	if listed.Code != http.StatusOK || !strings.Contains(body, `"rule_id":"path-traversal"`) || !strings.Contains(body, `"reason":"body_window_skipped"`) {
		t.Fatalf("events status=%d body=%s", listed.Code, body)
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "127.0.0.1") {
		t.Fatalf("event payload leaked request content: %s", body)
	}
}

func TestManagementPageVisibleEmptyDeniedUnavailable(t *testing.T) {
	t.Parallel()
	empty := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	listed := httptest.NewRecorder()
	empty.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	payload := decodeWAFState(t, listed.Body.Bytes())
	if listed.Code != http.StatusOK || payload.Notice != emptyEntriesNotice || len(payload.Entries) != 0 {
		t.Fatalf("empty status=%d payload=%#v", listed.Code, payload)
	}

	denied := httptest.NewRecorder()
	empty.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/state?agent_id=agent-1", nil))
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), deniedMessage) {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}

	unavailable := newUIController(t, uiControllerOptions{})
	failed := httptest.NewRecorder()
	unavailable.ServeHTTP(failed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	if failed.Code != http.StatusServiceUnavailable || !strings.Contains(failed.Body.String(), ErrPolicyUnavailable.Error()) {
		t.Fatalf("unavailable status=%d body=%s", failed.Code, failed.Body.String())
	}

	invalid := newMemoryCatalog()
	invalid.entries["agent-1"] = []HTTPEntry{{
		RuleRef: "12", FrontendURL: "http://app.example.com", OverlayInvalid: true, Notice: invalidOverlayNotice,
	}}
	broken := newUIController(t, uiControllerOptions{catalog: invalid})
	overlay := httptest.NewRecorder()
	broken.ServeHTTP(overlay, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	got := decodeWAFState(t, overlay.Body.Bytes())
	if overlay.Code != http.StatusOK || len(got.Entries) != 1 || !got.Entries[0].OverlayInvalid || got.Entries[0].Notice != invalidOverlayNotice {
		t.Fatalf("invalid overlay=%#v", got.Entries)
	}
}

func TestManagementPageRejectsInvalidCustomRuleWithoutMutating(t *testing.T) {
	t.Parallel()
	controller := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/custom-rules", `{"id":"BAD","target":"path","needle":"ab"}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), ErrInvalidRule.Error()) {
		t.Fatalf("status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(controller.currentConfig().CustomRules) != 0 {
		t.Fatalf("invalid rule mutated config=%#v", controller.currentConfig())
	}
}

type uiControllerOptions struct {
	catalog  HTTPEntryCatalog
	overlays OverlayWriter
	events   EventSource
	config   string
}

func newUIController(t *testing.T, opts uiControllerOptions) *Controller {
	t.Helper()
	config := opts.config
	if config == "" {
		config = `{"mode":"observe"}`
	}
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Catalog: opts.catalog, Overlays: opts.overlays, Events: opts.events,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{
		Generation: "generation-1", Config: []byte(config),
	}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller
}

func uiRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	req.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/ui-test")
	return req
}

func uiJSONRequest(method, path, body string) *http.Request {
	req := uiRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeWAFState(t *testing.T, raw []byte) wafAPIResponse {
	t.Helper()
	var payload wafAPIResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return payload
}

type memoryCatalog struct {
	mu      sync.Mutex
	entries map[string][]HTTPEntry
	events  []SecurityEvent
}

func newMemoryCatalog() *memoryCatalog {
	return &memoryCatalog{entries: map[string][]HTTPEntry{}}
}

func (catalog *memoryCatalog) List(_ context.Context, agentID string) ([]HTTPEntry, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	return cloneEntries(catalog.entries[agentID]), nil
}

func (catalog *memoryCatalog) SetMode(_ context.Context, agentID, ruleRef, mode string) error {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	entries := catalog.entries[agentID]
	for index := range entries {
		if entries[index].RuleRef == ruleRef {
			entries[index].Mode = mode
			catalog.entries[agentID] = entries
			return nil
		}
	}
	return ErrUnknownEntry
}

func (catalog *memoryCatalog) ListEvents(_ context.Context, _ string) ([]SecurityEvent, error) {
	return cloneEvents(catalog.events), nil
}
