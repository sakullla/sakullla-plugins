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

func TestLoadAgentsKeepsLocalAgents(t *testing.T) {
	t.Parallel()
	script, err := os.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if !strings.Contains(text, "const loadAgents") {
		t.Fatal("loadAgents missing")
	}
	if strings.Contains(text, "is_local") || strings.Contains(text, `mode !== "local"`) || strings.Contains(text, "mode != \"local\"") {
		t.Fatal("loadAgents must keep local agents that own HTTP entries")
	}
	if !strings.Contains(text, "agent.id") {
		t.Fatal("loadAgents must still require an agent id")
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

	detached := newMemoryCatalog()
	detached.entries["agent-1"] = []HTTPEntry{{
		RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true,
	}}
	unattached := newUIController(t, uiControllerOptions{catalog: detached})
	listedDetached := httptest.NewRecorder()
	unattached.ServeHTTP(listedDetached, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	detachedPayload := decodeWAFState(t, listedDetached.Body.Bytes())
	if listedDetached.Code != http.StatusOK || len(detachedPayload.Entries) != 1 || detachedPayload.Entries[0].Attached || detachedPayload.Entries[0].Notice != notAttachedNotice {
		t.Fatalf("unattached=%#v", detachedPayload.Entries)
	}
}

func TestManagementPageFailsWhenExecutionContractsMissing(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	catalog.entries["agent-1"] = []HTTPEntry{{
		RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true, Mode: ModeObserve, Attached: true,
	}}
	withoutOverlay := newUIController(t, uiControllerOptions{catalog: catalog})
	switched := httptest.NewRecorder()
	withoutOverlay.ServeHTTP(switched, uiJSONRequest(http.MethodPost, "/api/entries/mode", `{"agent_id":"agent-1","rule_ref":"12","mode":"deny"}`))
	if switched.Code != http.StatusServiceUnavailable || !strings.Contains(switched.Body.String(), ErrUnavailable.Error()) {
		t.Fatalf("missing overlay writer status=%d body=%s", switched.Code, switched.Body.String())
	}

	withoutConfig := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog(), omitConfig: true})
	rule := httptest.NewRecorder()
	withoutConfig.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/custom-rules", `{"agent_id":"agent-1","id":"block-admin","target":"path","needle":"/admin"}`))
	if rule.Code != http.StatusServiceUnavailable || !strings.Contains(rule.Body.String(), ErrUnavailable.Error()) {
		t.Fatalf("missing config store status=%d body=%s", rule.Code, rule.Body.String())
	}
	if len(withoutConfig.currentConfig().CustomRules) != 0 {
		t.Fatalf("failed persist mutated config=%#v", withoutConfig.currentConfig())
	}

	withoutEvents := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog(), omitEvents: true})
	listed := httptest.NewRecorder()
	withoutEvents.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), ErrUnavailable.Error()) {
		t.Fatalf("missing events status=%d body=%s", listed.Code, listed.Body.String())
	}
}

func TestGlobalModeDoesNotPersistBeforeOverlayWrites(t *testing.T) {
	t.Parallel()

	t.Run("missing OverlayWriter", func(t *testing.T) {
		t.Parallel()
		catalog := newMemoryCatalog()
		catalog.entries["agent-1"] = []HTTPEntry{{
			RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true, Mode: ModeObserve, Attached: true,
		}}
		store := newMemoryConfigStore()
		controller := newUIController(t, uiControllerOptions{catalog: catalog, configs: store})
		failed := httptest.NewRecorder()
		controller.ServeHTTP(failed, uiJSONRequest(http.MethodPost, "/api/mode", `{"agent_id":"agent-1","mode":"deny"}`))
		payload := decodeWAFState(t, failed.Body.Bytes())
		if failed.Code != http.StatusServiceUnavailable || payload.Error != ErrUnavailable.Error() {
			t.Fatalf("missing overlay writer status=%d body=%s", failed.Code, failed.Body.String())
		}
		if payload.DefaultMode != ModeObserve || controller.currentConfig().Mode != ModeObserve || store.snapshot().Mode == ModeDeny {
			t.Fatalf("missing overlay writer persisted mode payload=%#v config=%#v store=%#v", payload, controller.currentConfig(), store.snapshot())
		}
		if len(payload.Entries) != 1 || payload.Entries[0].Mode != ModeObserve {
			t.Fatalf("missing overlay writer mutated entry=%#v", payload.Entries)
		}
	})

	t.Run("SetMode error after listing attached entries", func(t *testing.T) {
		t.Parallel()
		catalog := newMemoryCatalog()
		catalog.entries["agent-1"] = []HTTPEntry{
			{RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
			{RuleRef: "13", FrontendURL: "http://other.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
		}
		store := newMemoryConfigStore()
		trace := &writeTrace{inner: catalog, store: store, fail: ErrUnavailable}
		controller := newUIController(t, uiControllerOptions{catalog: catalog, overlays: trace, configs: trace})
		failed := httptest.NewRecorder()
		controller.ServeHTTP(failed, uiJSONRequest(http.MethodPost, "/api/mode", `{"agent_id":"agent-1","mode":"deny"}`))
		payload := decodeWAFState(t, failed.Body.Bytes())
		if failed.Code != http.StatusServiceUnavailable || payload.Error != ErrUnavailable.Error() {
			t.Fatalf("overlay error status=%d body=%s", failed.Code, failed.Body.String())
		}
		if payload.DefaultMode != ModeObserve || controller.currentConfig().Mode != ModeObserve || store.snapshot().Mode == ModeDeny {
			t.Fatalf("overlay error persisted mode payload=%#v config=%#v store=%#v", payload, controller.currentConfig(), store.snapshot())
		}
		steps := trace.snapshot()
		if len(steps) == 0 || steps[0] != "overlay:12" {
			t.Fatalf("overlay error steps=%v", steps)
		}
		for _, step := range steps {
			if step == "config" {
				t.Fatalf("overlay error persisted config steps=%v", steps)
			}
		}
		if len(payload.Entries) != 2 || payload.Entries[0].Mode != ModeObserve || payload.Entries[1].Mode != ModeObserve {
			t.Fatalf("overlay error mutated entries=%#v", payload.Entries)
		}
	})

	t.Run("writes overlays then persists instance mode", func(t *testing.T) {
		t.Parallel()
		catalog := newMemoryCatalog()
		catalog.entries["agent-1"] = []HTTPEntry{
			{RuleRef: "12", FrontendURL: "http://app.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
			{RuleRef: "13", FrontendURL: "http://invalid.example.com", OverlayInvalid: true, Notice: invalidOverlayNotice},
			{RuleRef: "", FrontendURL: "http://empty.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
			{RuleRef: "14", FrontendURL: "http://detached.example.com", Enabled: true},
			{RuleRef: "15", FrontendURL: "http://other.example.com", Enabled: true, Mode: ModeObserve, Attached: true},
		}
		store := newMemoryConfigStore()
		trace := &writeTrace{inner: catalog, store: store}
		controller := newUIController(t, uiControllerOptions{catalog: catalog, overlays: trace, configs: trace})
		switched := httptest.NewRecorder()
		controller.ServeHTTP(switched, uiJSONRequest(http.MethodPost, "/api/mode", `{"agent_id":"agent-1","mode":"deny"}`))
		payload := decodeWAFState(t, switched.Body.Bytes())
		if switched.Code != http.StatusOK || payload.DefaultMode != ModeDeny || controller.currentConfig().Mode != ModeDeny || store.snapshot().Mode != ModeDeny {
			t.Fatalf("success status=%d payload=%#v config=%#v store=%#v", switched.Code, payload, controller.currentConfig(), store.snapshot())
		}
		wantSteps := []string{"overlay:12", "overlay:15", "config"}
		steps := trace.snapshot()
		if len(steps) != len(wantSteps) {
			t.Fatalf("success steps=%v want=%v", steps, wantSteps)
		}
		for index, want := range wantSteps {
			if steps[index] != want {
				t.Fatalf("success steps=%v want=%v", steps, wantSteps)
			}
		}
		if len(payload.Entries) != 5 || payload.Entries[0].Mode != ModeDeny || payload.Entries[4].Mode != ModeDeny {
			t.Fatalf("success attached overlays=%#v", payload.Entries)
		}
		if payload.Entries[1].Mode != "" || payload.Entries[2].Mode != ModeObserve || payload.Entries[3].Mode != "" {
			t.Fatalf("success skipped overlays=%#v", payload.Entries)
		}
	})
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
	catalog    HTTPEntryCatalog
	overlays   OverlayWriter
	events     EventSource
	configs    PolicyConfigStore
	config     string
	omitConfig bool
	omitEvents bool
}

func newUIController(t *testing.T, opts uiControllerOptions) *Controller {
	t.Helper()
	config := opts.config
	if config == "" {
		config = `{"mode":"observe"}`
	}
	events := opts.events
	if events == nil && !opts.omitEvents {
		events = emptyEvents{}
	}
	configs := opts.configs
	if configs == nil && !opts.omitConfig {
		configs = newMemoryConfigStore()
	}
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Catalog: opts.catalog, Overlays: opts.overlays, Events: events, Configs: configs,
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

type emptyEvents struct{}

func (emptyEvents) ListEvents(context.Context, string) ([]SecurityEvent, error) {
	return nil, nil
}

type memoryConfigStore struct {
	mu     sync.Mutex
	config Configuration
}

func newMemoryConfigStore() *memoryConfigStore {
	return &memoryConfigStore{}
}

func (store *memoryConfigStore) StoreConfig(_ context.Context, config Configuration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.config = cloneConfiguration(config)
	return nil
}

func (store *memoryConfigStore) snapshot() Configuration {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneConfiguration(store.config)
}

type writeTrace struct {
	mu    sync.Mutex
	steps []string
	fail  error
	inner OverlayWriter
	store PolicyConfigStore
}

func (trace *writeTrace) SetMode(ctx context.Context, agentID, ruleRef, mode string) error {
	trace.mu.Lock()
	trace.steps = append(trace.steps, "overlay:"+ruleRef)
	fail := trace.fail
	inner := trace.inner
	trace.mu.Unlock()
	if fail != nil {
		return fail
	}
	if inner != nil {
		return inner.SetMode(ctx, agentID, ruleRef, mode)
	}
	return nil
}

func (trace *writeTrace) StoreConfig(ctx context.Context, config Configuration) error {
	trace.mu.Lock()
	trace.steps = append(trace.steps, "config")
	store := trace.store
	trace.mu.Unlock()
	if store != nil {
		return store.StoreConfig(ctx, config)
	}
	return nil
}

func (trace *writeTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	copied := make([]string, len(trace.steps))
	copy(copied, trace.steps)
	return copied
}
