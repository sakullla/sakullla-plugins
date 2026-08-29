package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestPluginYAMLDeclaresUIRouteNotHostPage(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: docker-app") {
		t.Fatalf("plugin.yaml must declare ui.route support: %s", text)
	}
	if !strings.Contains(text, "ui.nav.group: 基础设施") || !strings.Contains(text, "ui.nav.label: Docker 应用") {
		t.Fatalf("plugin.yaml must declare host nav metadata: %s", text)
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: docker-app") {
		t.Fatalf("plugin.yaml must declare resource.group support: %s", text)
	}
	if !strings.Contains(text, "host_scope: control-plane") {
		t.Fatalf("plugin.yaml must declare control-plane host_scope: %s", text)
	}
	if !strings.Contains(text, "host_scopes:") || (!strings.Contains(text, "- agent") && !strings.Contains(text, "[agent]")) {
		t.Fatalf("plugin.yaml must declare host_scopes including agent: %s", text)
	}
	if regexp.MustCompile(`(?m)^[[:space:]]*host_scope:[[:space:]]*agent[[:space:]]*$`).MatchString(text) {
		t.Fatal("docker-app primary host_scope must not be agent")
	}
	if strings.Contains(text, "container.provider") {
		t.Fatal("docker-app must not declare container.provider")
	}
	if strings.Contains(text, "http.backend-provider") || strings.Contains(text, "http_backend_providers") {
		t.Fatal("docker-app must not use install-time HTTP backend publish")
	}
	if !strings.Contains(text, "assets/ui/index.html") || !strings.Contains(text, "assets/ui/app.js") {
		t.Fatal("plugin.yaml must declare frontend files below assets/")
	}
	for _, permission := range []string{"storage.read", "storage.write"} {
		if !strings.Contains(text, "- name: "+permission) {
			t.Fatalf("plugin.yaml must declare %s for durable app state", permission)
		}
	}
	if !strings.Contains(text, "resource: docker-compose:managed") {
		t.Fatal("plugin.yaml must request the scoped managed Docker Compose handle")
	}
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("compose UI must not use host config ui_schema")
	}
}

func TestPluginYAMLDeclaresResourceGroupForHostCatalog(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"resource.group.ref: resource-group/docker-app",
		"resource.group.label: Docker 应用",
		"resource.group.description: 在组内管理 compose 应用与 HTTP 入口",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin.yaml must declare %q: %s", want, text)
		}
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: docker-app") {
		t.Fatal("plugin.yaml must declare resource.group as an SDK extension point")
	}
}

func TestAppUIAuthorizedDeployListsAndRequiresDeleteConfirm(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	compose := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if !strings.Contains(created.Body.String(), `"8080"`) && !strings.Contains(created.Body.String(), "8080") {
		t.Fatalf("create omitted published port: %s", created.Body.String())
	}

	page := httptest.NewRecorder()
	controller.ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="app-workspace"`) || !strings.Contains(page.Body.String(), `id="deploy-toggle"`) || !strings.Contains(page.Body.String(), `id="engine-guide"`) || strings.Contains(page.Body.String(), "{{") {
		t.Fatalf("page status=%d body=%s", page.Code, page.Body.String())
	}

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"id":"media"`) || !strings.Contains(listed.Body.String(), `"status":"运行中"`) {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":""}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), ErrDeleteUnconfirmed.Error()) {
		t.Fatalf("unconfirmed delete status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(controller.Apps()) != 1 {
		t.Fatalf("unconfirmed delete changed apps: %#v", controller.Apps())
	}

	emptyDomain := httptest.NewRecorder()
	controller.ServeHTTP(emptyDomain, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"","port":8080}`))
	if emptyDomain.Code != http.StatusBadRequest || !strings.Contains(emptyDomain.Body.String(), ErrEmptyIngressDomain.Error()) {
		t.Fatalf("empty domain status=%d body=%s", emptyDomain.Code, emptyDomain.Body.String())
	}
	if len(controller.Apps()) != 1 {
		t.Fatalf("empty domain mutated apps=%#v", controller.Apps())
	}

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || strings.Contains(deleted.Body.String(), `"id":"media"`) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("delete left apps: %#v", controller.Apps())
	}
}

func TestAppUIRejectsMissingRequiredComposeEnvironmentBeforeDeploy(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	compose := "services:\n  web:\n    image: nginx:1.27\n    environment:\n      DATABASE_PASSWORD: ${DATABASE_PASSWORD:?set DATABASE_PASSWORD in .env}\n"
	response := httptest.NewRecorder()
	controller.ServeHTTP(response, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "DATABASE_PASSWORD") || !strings.Contains(response.Body.String(), "set DATABASE_PASSWORD in .env") {
		t.Fatalf("missing-variable response is not actionable: %s", response.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("rejected deployment mutated apps: %#v", controller.Apps())
	}
}

type uiMemoryAppState struct {
	apps         []App
	runtime      map[string]bool
	deployments  deploymentSnapshot
	found        bool
	deployFound  bool
	stores       int
	deployStores int
	deployErr    error
}

func (state *uiMemoryAppState) LoadApps(context.Context) ([]App, bool, error) {
	return cloneApps(state.apps), state.found, nil
}

func (state *uiMemoryAppState) StoreApps(_ context.Context, apps []App) error {
	state.apps = cloneApps(apps)
	state.found = true
	state.stores++
	return nil
}

func (state *uiMemoryAppState) LoadRuntime(context.Context) (map[string]bool, bool, error) {
	return cloneAppRuntime(state.runtime), state.found, nil
}

func (state *uiMemoryAppState) StoreRuntime(_ context.Context, values map[string]bool) error {
	state.runtime = cloneAppRuntime(values)
	state.found = true
	return nil
}

func (state *uiMemoryAppState) LoadDeployments(context.Context) (deploymentSnapshot, bool, error) {
	if state.deployErr != nil {
		return deploymentSnapshot{}, false, state.deployErr
	}
	return cloneDeploymentSnapshot(state.deployments), state.deployFound, nil
}

func (state *uiMemoryAppState) StoreDeployments(_ context.Context, snapshot deploymentSnapshot) error {
	if state.deployErr != nil {
		return state.deployErr
	}
	state.deployments = cloneDeploymentSnapshot(snapshot)
	state.deployFound = true
	state.deployStores++
	return nil
}

func TestAppUIRestoresPersistedAppsAfterControllerRestart(t *testing.T) {
	state := &uiMemoryAppState{}
	first := newUIControllerWithOptions(t, uiControllerOptions{appState: state})
	created := httptest.NewRecorder()
	first.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"hubproxy","agent_id":"agent-1","compose":"services:\n  hubproxy:\n    image: registry.example.test/hubproxy:latest\n    ports:\n      - \"5000:5000\"\n","env":"DATABASE_PASSWORD=fixture-value\n"}`))
	if created.Code != http.StatusOK || state.stores != 1 || len(state.apps) != 1 {
		t.Fatalf("create status=%d stores=%d apps=%#v body=%s", created.Code, state.stores, state.apps, created.Body.String())
	}
	if state.apps[0].Env != "" || strings.Contains(created.Body.String(), "fixture-value") {
		t.Fatalf("compose environment leaked into persisted/UI state: app=%#v body=%s", state.apps[0], created.Body.String())
	}
	stopped := httptest.NewRecorder()
	first.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/hubproxy/stop", `{}`))
	if stopped.Code != http.StatusOK || state.runtime["hubproxy"] {
		t.Fatalf("stop status=%d runtime=%#v body=%s", stopped.Code, state.runtime, stopped.Body.String())
	}

	restarted := newUIControllerWithOptions(t, uiControllerOptions{appState: state})
	listed := httptest.NewRecorder()
	restarted.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	apps := decodeAppList(t, listed.Body.Bytes())
	if listed.Code != http.StatusOK || len(apps) != 1 || apps[0].ID != "hubproxy" || apps[0].Status != OpsStatusStopped || restarted.Apps()[0].AgentID != "agent-1" {
		t.Fatalf("restored status=%d apps=%#v body=%s", listed.Code, apps, listed.Body.String())
	}
	if restarted.Apps()[0].Generation != "generation-1" {
		t.Fatalf("restored generation=%q", restarted.Apps()[0].Generation)
	}
}

func TestAppUICreatesHTTPRuleFromPublishedPortAndDomain(t *testing.T) {
	t.Parallel()
	assertDetailWorkspacePage(t)
	handle := &recordingHTTPRuleCreate{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if created.Code != http.StatusOK || len(controller.Apps()) != 1 {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK {
		t.Fatalf("http-rule status=%d body=%s", rule.Code, rule.Body.String())
	}
	if len(handle.specs) != 1 || handle.specs[0].AppID != "media" || handle.specs[0].AgentID != "agent-1" || handle.specs[0].Domain != "https://app.example.com" || handle.specs[0].Port != 8080 {
		t.Fatalf("host create spec=%#v", handle.specs)
	}
	if !strings.Contains(rule.Body.String(), `"domain":"https://app.example.com"`) || !strings.Contains(rule.Body.String(), `"backend":"http://127.0.0.1:8080"`) {
		t.Fatalf("http-rule response omitted host rule: %s", rule.Body.String())
	}
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"domain":"https://app.example.com"`) || !strings.Contains(listed.Body.String(), `"port":8080`) || !strings.Contains(listed.Body.String(), `"enabled":true`) {
		t.Fatalf("list did not project host rule summary: %s", listed.Body.String())
	}
	detail := httptest.NewRecorder()
	controller.ServeHTTP(detail, uiRequest(http.MethodGet, "/api/apps/media", ""))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"domain":"https://app.example.com"`) || !strings.Contains(detail.Body.String(), `"ref":`) {
		t.Fatalf("detail omitted openable host rule: status=%d body=%s", detail.Code, detail.Body.String())
	}
	handle.rules = nil
	stale := httptest.NewRecorder()
	controller.ServeHTTP(stale, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if stale.Code != http.StatusOK || strings.Contains(stale.Body.String(), "https://app.example.com") {
		t.Fatalf("app page kept process-local host rules after list emptied: %s", stale.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].ID != "media" || controller.Apps()[0].Image != "nginx:1.27" {
		t.Fatalf("http-rule mutated apps=%#v", controller.Apps())
	}
	if controller.Apps()[0].RuleRef != "" {
		t.Fatalf("http-rule bound App.RuleRef=%q", controller.Apps()[0].RuleRef)
	}
}

func TestAppUIDeletesHTTPRuleFromHostList(t *testing.T) {
	t.Parallel()
	assertDetailWorkspacePage(t)
	handle := &recordingHTTPRuleCreate{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("http-rule status=%d rules=%#v body=%s", rule.Code, handle.rules, rule.Body.String())
	}
	ref := handle.rules[0].Ref

	emptyRef := httptest.NewRecorder()
	controller.ServeHTTP(emptyRef, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule-delete", `{"rule_ref":""}`))
	if emptyRef.Code != http.StatusBadRequest || !strings.Contains(emptyRef.Body.String(), ErrEmptyHTTPRuleRef.Error()) {
		t.Fatalf("empty ref status=%d body=%s", emptyRef.Code, emptyRef.Body.String())
	}
	if len(handle.deletes) != 0 || len(handle.rules) != 1 {
		t.Fatalf("empty ref mutated host rules: deletes=%#v rules=%#v", handle.deletes, handle.rules)
	}

	unknown := httptest.NewRecorder()
	controller.ServeHTTP(unknown, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule-delete", `{"rule_ref":"rule-other"}`))
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), ErrUnknownHTTPRule.Error()) {
		t.Fatalf("unknown ref status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	if len(handle.deletes) != 0 || len(handle.rules) != 1 {
		t.Fatalf("unknown ref mutated host rules: deletes=%#v rules=%#v", handle.deletes, handle.rules)
	}

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule-delete", `{"rule_ref":`+jsonString(ref)+`}`))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if len(handle.deletes) != 1 || handle.deletes[0] != (recordedHTTPRuleDelete{AgentID: "agent-1", RuleRef: ref, OperationID: "operation/ui-test"}) || len(handle.rules) != 0 {
		t.Fatalf("host delete deletes=%#v rules=%#v", handle.deletes, handle.rules)
	}
	if strings.Contains(deleted.Body.String(), "https://app.example.com") {
		t.Fatalf("delete still projected host rule: %s", deleted.Body.String())
	}
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "https://app.example.com") {
		t.Fatalf("list kept deleted host rule: %s", listed.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].ID != "media" {
		t.Fatalf("http-rule-delete mutated apps=%#v", controller.Apps())
	}
}

func TestAppUIHTTPRuleDeleteFailureKeepsHostRule(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{deleteErr: errors.New("upstream rejected fixture-value")}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("seed rule status=%d rules=%#v body=%s", rule.Code, handle.rules, rule.Body.String())
	}
	ref := handle.rules[0].Ref
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule-delete", `{"rule_ref":`+jsonString(ref)+`}`))
	if deleted.Code != http.StatusInternalServerError {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if !strings.Contains(deleted.Body.String(), "HTTP 规则删除失败") || strings.Contains(deleted.Body.String(), "fixture-value") {
		t.Fatalf("delete failure is not actionable and safe: %s", deleted.Body.String())
	}
	if len(handle.rules) != 1 || handle.rules[0].Ref != ref {
		t.Fatalf("failed delete removed host rule: %#v", handle.rules)
	}
}

func TestAppUIHTTPRuleDeleteSucceedsWhenHostAlreadyRemovedRule(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{deleteErr: errors.New("upstream rejected fixture-value"), deleteDropsRule: true}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("seed rule status=%d rules=%#v body=%s", rule.Code, handle.rules, rule.Body.String())
	}
	ref := handle.rules[0].Ref
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule-delete", `{"rule_ref":`+jsonString(ref)+`}`))
	if deleted.Code != http.StatusOK {
		t.Fatalf("idempotent delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if len(handle.deletes) != 1 || handle.deletes[0].OperationID != "operation/ui-test" || len(handle.rules) != 0 {
		t.Fatalf("idempotent delete deletes=%#v rules=%#v", handle.deletes, handle.rules)
	}
	if strings.Contains(deleted.Body.String(), "https://app.example.com") {
		t.Fatalf("idempotent delete still projected host rule: %s", deleted.Body.String())
	}
}

func TestAppUIConfirmedDeleteRemovesListedHTTPRules(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if created.Code != http.StatusOK || !hasAppAction(decodeAppList(t, created.Body.Bytes())[0], OpsActionDelete) {
		t.Fatalf("running create omitted delete: status=%d body=%s", created.Code, created.Body.String())
	}
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("http-rule status=%d rules=%#v body=%s", rule.Code, handle.rules, rule.Body.String())
	}
	ref := handle.rules[0].Ref

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":""}`))
	if denied.Code != http.StatusBadRequest || len(controller.Apps()) != 1 || len(handle.rules) != 1 || len(handle.deletes) != 0 {
		t.Fatalf("unconfirmed delete mutated state apps=%#v rules=%#v deletes=%#v body=%s", controller.Apps(), handle.rules, handle.deletes, denied.Body.String())
	}

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("confirmed delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
	if len(handle.deletes) != 1 || handle.deletes[0] != (recordedHTTPRuleDelete{AgentID: "agent-1", RuleRef: ref, OperationID: "operation/ui-test"}) || len(handle.rules) != 0 {
		t.Fatalf("confirmed delete left host rules deletes=%#v rules=%#v", handle.deletes, handle.rules)
	}
	if strings.Contains(deleted.Body.String(), `"id":"media"`) || strings.Contains(deleted.Body.String(), "https://app.example.com") {
		t.Fatalf("confirmed delete still listed app or rule: %s", deleted.Body.String())
	}
}

func TestAppUICascadeHTTPRuleDeleteFailureKeepsApp(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{deleteErr: errors.New("upstream rejected fixture-value")}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("seed rule status=%d rules=%#v", rule.Code, handle.rules)
	}
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusInternalServerError || len(controller.Apps()) != 1 {
		t.Fatalf("cascade failure status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
	if !strings.Contains(deleted.Body.String(), "HTTP 规则删除失败") || strings.Contains(deleted.Body.String(), "fixture-value") {
		t.Fatalf("cascade failure is not actionable and safe: %s", deleted.Body.String())
	}
	if len(handle.rules) != 1 {
		t.Fatalf("cascade failure removed host rule: %#v", handle.rules)
	}
	if len(handle.deletes) != 1 || handle.deletes[0].OperationID != "operation/ui-test" {
		t.Fatalf("cascade delete omitted operation key: %#v", handle.deletes)
	}
}

func TestAppUIDeleteFailureMessageDependsOnHTTPRuleCleanup(t *testing.T) {
	t.Parallel()
	compose := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"

	t.Run("without-rules", func(t *testing.T) {
		t.Parallel()
		controller := newUIControllerWithOptions(t, uiControllerOptions{remove: failingAppRemove{err: errors.New("agent rejected fixture-value")}})
		created := httptest.NewRecorder()
		controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
		if created.Code != http.StatusOK {
			t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
		}
		deleted := httptest.NewRecorder()
		controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
		if deleted.Code != http.StatusInternalServerError || len(controller.Apps()) != 1 {
			t.Fatalf("delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
		}
		if !strings.Contains(deleted.Body.String(), "删除应用失败") || strings.Contains(deleted.Body.String(), "入口规则已按宿主结果删除") || strings.Contains(deleted.Body.String(), "fixture-value") {
			t.Fatalf("generic delete failure is not actionable and safe: %s", deleted.Body.String())
		}
	})

	t.Run("after-rules", func(t *testing.T) {
		t.Parallel()
		handle := &recordingHTTPRuleCreate{}
		controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle, remove: failingAppRemove{err: errors.New("agent rejected fixture-value")}})
		created := httptest.NewRecorder()
		controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
		rule := httptest.NewRecorder()
		controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
		if rule.Code != http.StatusOK || len(handle.rules) != 1 {
			t.Fatalf("seed rule status=%d rules=%#v", rule.Code, handle.rules)
		}
		deleted := httptest.NewRecorder()
		controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
		if deleted.Code != http.StatusInternalServerError || len(controller.Apps()) != 1 {
			t.Fatalf("delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
		}
		if !strings.Contains(deleted.Body.String(), "入口规则已按宿主结果删除") || strings.Contains(deleted.Body.String(), "fixture-value") {
			t.Fatalf("delete-after-rules is not actionable and safe: %s", deleted.Body.String())
		}
		if len(handle.rules) != 0 || len(handle.deletes) != 1 || handle.deletes[0].OperationID != "operation/ui-test" {
			t.Fatalf("rules after failed app delete deletes=%#v rules=%#v", handle.deletes, handle.rules)
		}
	})
}

func TestNormalizeHTTPRuleFrontendPreservesHTTPSAndRejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "app.example.com", want: "http://app.example.com"},
		{input: "https://app.example.com", want: "https://app.example.com"},
		{input: "https://app.example.com/path?q=1", want: "https://app.example.com"},
		{input: "https://app.example.com:8443/ingress", want: "https://app.example.com:8443"},
	} {
		got, ok := normalizeIngressDomain(test.input)
		if !ok || got != test.want {
			t.Fatalf("normalizeIngressDomain(%q)=(%q,%t) want %q", test.input, got, ok, test.want)
		}
	}
	for _, input := range []string{"", "   ", "https://", "ftp://app.example.com", "/app.example.com"} {
		if _, ok := normalizeIngressDomain(input); ok {
			t.Fatalf("normalizeIngressDomain(%q) was accepted", input)
		}
	}
}

func TestAppUIPublishesHTTPBackendOffersAfterDeployAndStop(t *testing.T) {
	t.Parallel()
	offers := &recordingHTTPBackendOffers{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpOffers: offers})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"hubproxy","agent_id":"agent-1","compose":"services:\n  hubproxy:\n    image: registry.example.test/hubproxy:latest\n    ports:\n      - \"5000:5000\"\n"}`))
	if created.Code != http.StatusOK || len(offers.offers) == 0 {
		t.Fatalf("deploy status=%d offers=%#v body=%s", created.Code, offers.offers, created.Body.String())
	}
	last := offers.offers[len(offers.offers)-1]
	if len(last) != 1 || last[0].ResourceID != "hubproxy" || last[0].AgentID != "agent-1" || last[0].Port != 5000 || last[0].DisplayName != "hubproxy" || !last[0].Available {
		t.Fatalf("deploy catalog=%#v", last)
	}

	stopped := httptest.NewRecorder()
	controller.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/hubproxy/stop", `{}`))
	if stopped.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", stopped.Code, stopped.Body.String())
	}
	stoppedOffers := offers.offers[len(offers.offers)-1]
	if len(stoppedOffers) != 1 || stoppedOffers[0].Available {
		t.Fatalf("stopped catalog=%#v", stoppedOffers)
	}
}

func TestAppUIPublishesHTTPBackendOffersAvailableWhenRuntimeOverlayIsMissing(t *testing.T) {
	t.Parallel()
	offers := &recordingHTTPBackendOffers{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		httpOffers: offers,
		config:     `{"apps":[{"id":"hubproxy","agent_id":"agent-1","compose":"services:\n  hubproxy:\n    image: registry.example.test/hubproxy:latest\n    ports:\n      - \"5000:5000\"\n","generation":"generation-1"}]}`,
	})
	if len(controller.Apps()) != 1 || controller.appIsRunning("hubproxy") != true {
		t.Fatalf("seeded app should project running without overlay: apps=%#v", controller.Apps())
	}
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK || len(offers.offers) == 0 {
		t.Fatalf("list status=%d offers=%#v body=%s", listed.Code, offers.offers, listed.Body.String())
	}
	last := offers.offers[len(offers.offers)-1]
	if len(last) != 1 || last[0].ResourceID != "hubproxy" || last[0].Port != 5000 || !last[0].Available {
		t.Fatalf("missing overlay catalog=%#v", last)
	}
}

func TestAppUIHTTPRuleListFailureDoesNotRecordLocalSuccess(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{listErr: errors.New("host list rejected fixture-value")}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusBadGateway {
		t.Fatalf("http-rule list status=%d body=%s", rule.Code, rule.Body.String())
	}
	if len(handle.specs) != 1 {
		t.Fatalf("list failure skipped create: %#v", handle.specs)
	}
	if !strings.Contains(rule.Body.String(), "HTTP 规则列表对账失败") || strings.Contains(rule.Body.String(), "fixture-value") || strings.Contains(rule.Body.String(), `"domain":"https://app.example.com"`) {
		t.Fatalf("list failure is not independent and safe: %s", rule.Body.String())
	}
}

func TestAppUIHTTPRuleFailureNamesStageWithoutLeakingCause(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{err: errors.New("upstream rejected fixture-value")}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	rule := httptest.NewRecorder()
	controller.ServeHTTP(rule, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"https://app.example.com","port":8080}`))
	if rule.Code != http.StatusInternalServerError {
		t.Fatalf("http-rule status=%d body=%s", rule.Code, rule.Body.String())
	}
	if !strings.Contains(rule.Body.String(), "HTTP 规则创建失败") || strings.Contains(rule.Body.String(), ErrOperationFailed.Error()) || strings.Contains(rule.Body.String(), "fixture-value") {
		t.Fatalf("http-rule response is not actionable and safe: %s", rule.Body.String())
	}
}

func TestAppUIDoesNotCreateHTTPRuleWithoutPortOrDomain(t *testing.T) {
	t.Parallel()
	handle := &recordingHTTPRuleCreate{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{httpRule: handle})
	seeded := httptest.NewRecorder()
	controller.ServeHTTP(seeded, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"}`))
	if seeded.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s", seeded.Code, seeded.Body.String())
	}
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"kept.example.com","port":8080}`))
	if created.Code != http.StatusOK || len(handle.rules) != 1 {
		t.Fatalf("seed rule status=%d rules=%#v body=%s", created.Code, handle.rules, created.Body.String())
	}
	existing := append([]HostHTTPRule(nil), handle.rules...)
	apps := controller.Apps()

	emptyDomain := httptest.NewRecorder()
	controller.ServeHTTP(emptyDomain, uiJSONRequest(http.MethodPost, "/api/apps/media/http-rule", `{"domain":"","port":8080}`))
	if emptyDomain.Code != http.StatusBadRequest || !strings.Contains(emptyDomain.Body.String(), ErrEmptyIngressDomain.Error()) {
		t.Fatalf("empty domain status=%d body=%s", emptyDomain.Code, emptyDomain.Body.String())
	}

	worker := httptest.NewRecorder()
	controller.ServeHTTP(worker, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"worker","agent_id":"agent-1","compose":"services:\n  job:\n    image: batch:latest\n"}`))
	if worker.Code != http.StatusOK {
		t.Fatalf("worker status=%d body=%s", worker.Code, worker.Body.String())
	}
	apps = controller.Apps()
	noPort := httptest.NewRecorder()
	controller.ServeHTTP(noPort, uiJSONRequest(http.MethodPost, "/api/apps/worker/http-rule", `{"domain":"app.example.com","port":8080}`))
	if noPort.Code != http.StatusBadRequest || !strings.Contains(noPort.Body.String(), ErrNoPublishedPort.Error()) {
		t.Fatalf("no-port status=%d body=%s", noPort.Code, noPort.Body.String())
	}

	if len(handle.specs) != 1 {
		t.Fatalf("denied creates still invoked host: %#v", handle.specs)
	}
	if len(handle.rules) != 1 || handle.rules[0] != existing[0] {
		t.Fatalf("denied creates changed rules: %#v", handle.rules)
	}
	got := controller.Apps()
	if len(got) != len(apps) || got[0].ID != apps[0].ID || got[0].Image != apps[0].Image || got[0].Compose != apps[0].Compose || got[1].ID != "worker" || got[1].Image != apps[1].Image {
		t.Fatalf("denied creates mutated apps=%#v want=%#v", got, apps)
	}
}

func TestAppUIPageOffersGroupHTTPIngressOnPublishedPorts(t *testing.T) {
	t.Parallel()
	page := httptest.NewRecorder()
	newUIController(t).ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	html := page.Body.String()
	scriptRec := httptest.NewRecorder()
	newUIController(t).ServeHTTP(scriptRec, uiRequest(http.MethodGet, "/app.js", ""))
	script := scriptRec.Body.String()
	if !strings.Contains(html, "入口域名") {
		t.Fatalf("page missing group HTTP ingress copy: %s", html)
	}
	if strings.Contains(html, `name="domain"`) && strings.Contains(html, `id="create-form"`) {
		t.Fatal("create form still requires an ingress domain")
	}
	for _, token := range []string{
		"入口域名",
		"无发布端口",
		"没有可挂的端口",
		"/http-rule",
		"/http-rule-delete",
		`name = "domain"`,
		`name = "port"`,
		"app.rules",
		"http-rules",
		"已取消，规则未更改",
		"app-actions-primary",
		"app-actions-secondary",
		"app-actions-danger",
		`isPrimary ? "btn-primary" : "btn-secondary"`,
	} {
		if !strings.Contains(script, token) {
			t.Fatalf("app.js missing %q", token)
		}
	}
	if strings.Contains(script, "挂 HTTP") {
		t.Fatal("HTTP create is still hidden behind a 挂 HTTP toggle")
	}
}

func TestAppUIRejectsMissingActor(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/apps", nil)
	controller.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	engine := httptest.NewRecorder()
	controller.ServeHTTP(engine, httptest.NewRequest(http.MethodGet, "/api/engine?agent_id=agent-1", nil))
	if engine.Code != http.StatusForbidden {
		t.Fatalf("engine status=%d body=%s", engine.Code, engine.Body.String())
	}
	cleanup := httptest.NewRecorder()
	controller.ServeHTTP(cleanup, httptest.NewRequest(http.MethodPost, "/api/disk-cleanup", strings.NewReader(`{"agent_id":"agent-1","confirm":true}`)))
	if cleanup.Code != http.StatusForbidden {
		t.Fatalf("disk-cleanup status=%d body=%s", cleanup.Code, cleanup.Body.String())
	}
}

func TestAppUIDiskCleanupPreviewConfirmAndUnconfirmedNoOp(t *testing.T) {
	t.Parallel()
	handle := &recordingDiskCleanup{
		preview: DiskCleanupReport{
			Accepted: true, Preview: true, Empty: false,
			Images: "untagged: nginx:old", BuilderCache: "Total: 4MB",
		},
		apply: DiskCleanupReport{
			Accepted: true, Preview: false, Empty: false,
			Images: "Deleted Images:\nuntagged: nginx:old", BuilderCache: "Total: 4MB",
		},
	}
	controller := newUIControllerWithOptions(t, uiControllerOptions{diskCleanup: handle})

	missing := httptest.NewRecorder()
	controller.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/api/disk-cleanup", strings.NewReader(`{"agent_id":"agent-1","confirm":true}`)))
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing actor status=%d body=%s", missing.Code, missing.Body.String())
	}

	preview := httptest.NewRecorder()
	controller.ServeHTTP(preview, uiRequest(http.MethodGet, "/api/disk-cleanup?agent_id=agent-1", ""))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"preview":true`) || !strings.Contains(preview.Body.String(), "untagged: nginx:old") {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}

	canceled := httptest.NewRecorder()
	controller.ServeHTTP(canceled, uiJSONRequest(http.MethodPost, "/api/disk-cleanup", `{"agent_id":"agent-1"}`))
	if canceled.Code != http.StatusOK || !strings.Contains(canceled.Body.String(), `"unchanged":true`) {
		t.Fatalf("unconfirmed status=%d body=%s", canceled.Code, canceled.Body.String())
	}

	applied := httptest.NewRecorder()
	controller.ServeHTTP(applied, uiJSONRequest(http.MethodPost, "/api/disk-cleanup", `{"agent_id":"agent-1","confirm":true}`))
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), "Deleted Images") || strings.Contains(applied.Body.String(), `"unchanged":true`) {
		t.Fatalf("confirmed status=%d body=%s", applied.Code, applied.Body.String())
	}

	handle.mu.Lock()
	defer handle.mu.Unlock()
	if len(handle.previews) != 1 || handle.previews[0] != "agent-1" {
		t.Fatalf("previews=%#v", handle.previews)
	}
	if len(handle.applies) != 2 || handle.applies[0] != false || handle.applies[1] != true {
		t.Fatalf("applies=%#v", handle.applies)
	}
	if strings.Contains(preview.Body.String(), "-v") || strings.Contains(preview.Body.String(), "--volumes") || strings.Contains(preview.Body.String(), "volume prune") {
		t.Fatalf("preview leaked volume deletion: %s", preview.Body.String())
	}
}

func TestAppUIInstallGuideBlocksDeployUntilEngineReady(t *testing.T) {
	t.Parallel()
	catalog := NewReportedEngineCatalog()
	if err := catalog.Consume([]byte(`{"id":"agent-1","online":true,"engine":{"installed":false}}`)); err != nil {
		t.Fatal(err)
	}
	controller := newUIControllerWithSource(t, catalog, `{"apps":[],"registry_mirror":"https://mirror.example"}`)
	compose := `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`

	unready := httptest.NewRecorder()
	controller.ServeHTTP(unready, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-1", ""))
	if unready.Code != http.StatusOK || !strings.Contains(unready.Body.String(), `"ready":false`) || !strings.Contains(unready.Body.String(), OfficialInstallScript) || !strings.Contains(unready.Body.String(), "registry-mirrors") {
		t.Fatalf("unready engine status=%d body=%s", unready.Code, unready.Body.String())
	}
	if strings.Contains(unready.Body.String(), `"ready":true`) {
		t.Fatalf("unready engine projected ready: %s", unready.Body.String())
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps", compose))
	if denied.Code != http.StatusServiceUnavailable || !strings.Contains(denied.Body.String(), ErrEngineNotReady.Error()) {
		t.Fatalf("unready deploy status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("unready deploy mutated apps: %#v", controller.Apps())
	}

	catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"})
	ready := httptest.NewRecorder()
	controller.ServeHTTP(ready, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-1", ""))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"ready":true`) || !strings.Contains(ready.Body.String(), `"version":"27.1.1"`) || strings.Contains(ready.Body.String(), OfficialInstallScript) {
		t.Fatalf("ready engine status=%d body=%s", ready.Code, ready.Body.String())
	}

	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", compose))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("ready deploy status=%d body=%s", created.Code, created.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].AgentID != "agent-1" {
		t.Fatalf("ready deploy apps=%#v", controller.Apps())
	}
}

func TestAppUIEngineReportFailureReturnsInstallGuideWithoutSDKText(t *testing.T) {
	t.Parallel()
	sdkText := ErrTypedHandlesUnavailable.Error()
	cases := []struct {
		name   string
		source AgentEngineSource
	}{
		{
			name: "typed-handles-unavailable",
			source: AgentEngineSourceFunc(func(context.Context, string) (AgentEngineReport, error) {
				return AgentEngineReport{}, ErrTypedHandlesUnavailable
			}),
		},
		{
			name: "generic-probe-error",
			source: AgentEngineSourceFunc(func(context.Context, string) (AgentEngineReport, error) {
				return AgentEngineReport{}, errors.New("engine probe failed")
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			controller := newUIControllerWithSource(t, tc.source, `{"apps":[]}`)
			engine := httptest.NewRecorder()
			controller.ServeHTTP(engine, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-1", ""))
			body := engine.Body.String()
			if engine.Code != http.StatusOK || !strings.Contains(body, `"ready":false`) || !strings.Contains(body, `"online":false`) {
				t.Fatalf("probe failure engine status=%d body=%s", engine.Code, body)
			}
			if strings.Contains(body, `"ready":true`) || strings.Contains(body, sdkText) || strings.Contains(body, OfficialInstallScript) {
				t.Fatalf("probe failure leaked readiness, SDK text, or install command: %s", body)
			}

			denied := httptest.NewRecorder()
			controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
			if denied.Code == http.StatusOK || strings.Contains(denied.Body.String(), sdkText) {
				t.Fatalf("probe failure deploy status=%d body=%s", denied.Code, denied.Body.String())
			}
			if len(controller.Apps()) != 0 {
				t.Fatalf("probe failure deploy mutated apps: %#v", controller.Apps())
			}
		})
	}
}

func TestAppUIUnavailableDoesNotLeakSDKTextOrInstallCommand(t *testing.T) {
	t.Parallel()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIEngineSource: AgentEngineSourceFunc(func(context.Context, string) (AgentEngineReport, error) {
			return AgentEngineReport{}, ErrTypedHandlesUnavailable
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := httptest.NewRecorder()
	controller.ServeHTTP(engine, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-1", ""))
	body := engine.Body.String()
	if engine.Code != http.StatusServiceUnavailable || !strings.Contains(body, appUnavailableMessage) {
		t.Fatalf("uiReady engine status=%d body=%s", engine.Code, body)
	}
	if strings.Contains(body, ErrTypedHandlesUnavailable.Error()) || strings.Contains(body, OfficialInstallScript) {
		t.Fatalf("uiReady engine leaked SDK text or install command: %s", body)
	}
	apps := httptest.NewRecorder()
	controller.ServeHTTP(apps, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if apps.Code != http.StatusServiceUnavailable || strings.Contains(apps.Body.String(), ErrTypedHandlesUnavailable.Error()) {
		t.Fatalf("uiReady apps status=%d body=%s", apps.Code, apps.Body.String())
	}
}

func TestAppUIRejectsSameAppIDOnAnotherAgent(t *testing.T) {
	t.Parallel()
	catalog := NewReportedEngineCatalog()
	catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"})
	catalog.Replace(AgentEngineReport{AgentID: "agent-2", Online: true, Installed: true, Version: "27.1.1"})
	controller := newUIControllerWithSource(t, catalog, `{"apps":[]}`)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"agent_id":"agent-1"`) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	stolen := httptest.NewRecorder()
	controller.ServeHTTP(stolen, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-2","compose":"services:\n  web:\n    image: nginx:1.28\n"}`))
	if stolen.Code != http.StatusConflict || !strings.Contains(stolen.Body.String(), ErrAppAgentConflict.Error()) {
		t.Fatalf("cross-agent deploy status=%d body=%s", stolen.Code, stolen.Body.String())
	}
	apps := controller.Apps()
	if len(apps) != 1 || apps[0].ID != "media" || apps[0].AgentID != "agent-1" || apps[0].Image != "nginx:1.27" {
		t.Fatalf("cross-agent deploy mutated apps=%#v", apps)
	}

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-2", ""))
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), `"id":"media"`) {
		t.Fatalf("agent-2 listed foreign app: %s", listed.Body.String())
	}
}

func TestAppUIRejectsOfflineAgentDeploy(t *testing.T) {
	t.Parallel()
	catalog := NewReportedEngineCatalog()
	catalog.Replace(AgentEngineReport{AgentID: "agent-2", Online: false, Installed: true, Version: "27.1.1"})
	controller := newUIControllerWithSource(t, catalog, `{"apps":[]}`)
	engine := httptest.NewRecorder()
	controller.ServeHTTP(engine, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-2", ""))
	if engine.Code != http.StatusOK || !strings.Contains(engine.Body.String(), `"online":false`) || strings.Contains(engine.Body.String(), `"ready":true`) {
		t.Fatalf("offline engine status=%d body=%s", engine.Code, engine.Body.String())
	}
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-2","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if denied.Code != http.StatusConflict || !strings.Contains(denied.Body.String(), ErrAgentOffline.Error()) {
		t.Fatalf("offline deploy status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("offline deploy mutated apps: %#v", controller.Apps())
	}
}

func TestAppUIDoesNotConfigurePluginOntoAgentOrOfferRemoteInstall(t *testing.T) {
	t.Parallel()
	page := httptest.NewRecorder()
	newUIController(t).ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	html := page.Body.String()
	scriptRec := httptest.NewRecorder()
	newUIController(t).ServeHTTP(scriptRec, uiRequest(http.MethodGet, "/app.js", ""))
	script := scriptRec.Body.String()
	combined := html + script
	for _, token := range []string{
		"/panel-api/plugins/docker-app/configure",
		"第一次部署会把本插件装到该节点",
		"由面板安装",
		"控制面安装",
		"一键安装",
		"id=\"engine-install\"",
		"data-action=\"install-engine\"",
	} {
		if strings.Contains(combined, token) {
			t.Fatalf("product page still has %q", token)
		}
	}
	if !strings.Contains(html, `id="engine-guide"`) || !strings.Contains(html, "复制命令") || !strings.Contains(script, "api/engine") || !strings.Contains(script, "api/apps") {
		t.Fatalf("install guide or plugin-local deploy path missing: html=%s", html)
	}
	if strings.Contains(script, "targets") && strings.Contains(script, "selectedAgentID") && strings.Contains(script, "configure") {
		t.Fatal("plugin page still configures docker-app onto the selected Agent")
	}
	if !strings.Contains(script, `agent.is_local !== true`) || !strings.Contains(script, `agent.mode !== "local"`) {
		t.Fatal("plugin page does not exclude the embedded local management Agent from execution targets")
	}
}

func TestAppUIRejectsInvalidComposeWithoutMutatingExisting(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	invalid := httptest.NewRecorder()
	controller.ServeHTTP(invalid, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"broken","agent_id":"agent-1","compose":"::: not yaml"}`))
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), ErrInvalidCompose.Error()) {
		t.Fatalf("invalid YAML status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	missing := httptest.NewRecorder()
	controller.ServeHTTP(missing, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"broken","agent_id":"agent-1","compose":"services:\n  web:\n    command: echo hi\n"}`))
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), ErrMissingComposeImage.Error()) {
		t.Fatalf("missing image status=%d body=%s", missing.Code, missing.Body.String())
	}

	apps := controller.Apps()
	if len(apps) != 1 || apps[0].ID != "media" || apps[0].Image != "nginx:1.27" {
		t.Fatalf("rejected compose mutated apps=%#v", apps)
	}
}

func TestAppUIDeploysRelativeBindsAgainstWorkDir(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./data:/data\n"
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("relative bind deploy status=%d body=%s", created.Code, created.Body.String())
	}
	apps := controller.Apps()
	if len(apps) != 1 || apps[0].ID != "media" {
		t.Fatalf("relative bind apps=%#v", apps)
	}
	if apps[0].WorkDir != "" {
		t.Fatalf("management-face deploy materialized a control-plane workdir: %#v", apps[0])
	}

	emptyRoot := newUIControllerWithOptions(t, uiControllerOptions{workDirRoot: stringPtr("")})
	accepted := httptest.NewRecorder()
	emptyRoot.ServeHTTP(accepted, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
	if accepted.Code != http.StatusOK {
		t.Fatalf("./ bind was rejected without workdir root: status=%d body=%s", accepted.Code, accepted.Body.String())
	}
}

func TestAppUIRejectsOfflineAgentMutations(t *testing.T) {
	t.Parallel()
	catalog := NewReportedEngineCatalog()
	catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"})
	controller := newUIControllerWithSource(t, catalog, `{"apps":[]}`)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK || len(controller.Apps()) != 1 {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: false, Installed: true, Version: "27.1.1"})

	for _, path := range []string{
		"/api/apps/media/stop",
		"/api/apps/media/start",
		"/api/apps/media/restart",
		"/api/apps/media/update",
	} {
		denied := httptest.NewRecorder()
		controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, path, `{}`))
		if denied.Code != http.StatusConflict || !strings.Contains(denied.Body.String(), ErrAgentOffline.Error()) {
			t.Fatalf("%s status=%d body=%s", path, denied.Code, denied.Body.String())
		}
	}
	logs := httptest.NewRecorder()
	controller.ServeHTTP(logs, uiJSONRequest(http.MethodPost, "/api/apps/media/logs", `{"service":"web"}`))
	if logs.Code != http.StatusConflict || !strings.Contains(logs.Body.String(), ErrAgentOffline.Error()) {
		t.Fatalf("logs status=%d body=%s", logs.Code, logs.Body.String())
	}
	files := httptest.NewRecorder()
	controller.ServeHTTP(files, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"list","path":"."}`))
	if files.Code != http.StatusConflict || !strings.Contains(files.Body.String(), ErrAgentOffline.Error()) {
		t.Fatalf("files status=%d body=%s", files.Code, files.Body.String())
	}
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusConflict || !strings.Contains(deleted.Body.String(), ErrAgentOffline.Error()) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].ID != "media" || controller.Apps()[0].Image != "nginx:1.27" {
		t.Fatalf("offline mutations changed apps=%#v", controller.Apps())
	}
}

func TestAppUIStartStopRestartLogsAndConfirmedDelete(t *testing.T) {
	t.Parallel()
	assertDetailWorkspacePage(t)
	controller := newUIController(t)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	listed := decodeAppList(t, created.Body.Bytes())
	if len(listed) != 1 || listed[0].Status != OpsStatusRunning || !hasAppAction(listed[0], OpsActionStop) || !hasAppAction(listed[0], OpsActionRestart) || !hasAppAction(listed[0], OpsActionDelete) {
		t.Fatalf("deployed view=%#v", listed)
	}

	stopped := httptest.NewRecorder()
	controller.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/media/stop", `{}`))
	if stopped.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", stopped.Code, stopped.Body.String())
	}
	listed = decodeAppList(t, stopped.Body.Bytes())
	if listed[0].Status != OpsStatusStopped || !hasAppAction(listed[0], OpsActionStart) || !hasAppAction(listed[0], OpsActionDelete) {
		t.Fatalf("stopped view=%#v", listed)
	}

	started := httptest.NewRecorder()
	controller.ServeHTTP(started, uiJSONRequest(http.MethodPost, "/api/apps/media/start", `{}`))
	if started.Code != http.StatusOK || decodeAppList(t, started.Body.Bytes())[0].Status != OpsStatusRunning {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}

	restarted := httptest.NewRecorder()
	controller.ServeHTTP(restarted, uiJSONRequest(http.MethodPost, "/api/apps/media/restart", `{}`))
	if restarted.Code != http.StatusOK {
		t.Fatalf("restart status=%d body=%s", restarted.Code, restarted.Body.String())
	}

	logs := httptest.NewRecorder()
	controller.ServeHTTP(logs, uiJSONRequest(http.MethodPost, "/api/apps/media/logs", `{"service":"web"}`))
	if logs.Code != http.StatusOK || !strings.Contains(logs.Body.String(), "listening on :80") {
		t.Fatalf("logs status=%d body=%s", logs.Code, logs.Body.String())
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":""}`))
	if denied.Code != http.StatusBadRequest || len(controller.Apps()) != 1 {
		t.Fatalf("unconfirmed delete status=%d apps=%#v body=%s", denied.Code, controller.Apps(), denied.Body.String())
	}
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("confirmed delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
}

func TestAppUIShowsImageVersionSeparateFromEngineAndManualUpdate(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	observer := &uiTestObserver{current: current, latest: latest}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		engineVersion: "27.1.1",
		observer:      observer,
		rollout:       &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	apps := decodeAppList(t, listed.Body.Bytes())
	if len(apps) != 1 || apps[0].Status != OpsStatusRunning || apps[0].Notice != OpsStatusUpdateAvailable || !hasAppAction(apps[0], OpsActionUpdate) {
		t.Fatalf("update view=%#v", apps)
	}
	if !hasAppAction(apps[0], OpsActionStop) || !hasAppAction(apps[0], OpsActionRestart) {
		t.Fatalf("digest drift dropped running ops: %#v", apps)
	}
	if hasAppAction(apps[0], OpsActionRollback) {
		t.Fatalf("app view offered rollback: %#v", apps)
	}
	if apps[0].Version != "nginx:latest sha256:0123456789ab" {
		t.Fatalf("app version = %q", apps[0].Version)
	}
	if strings.Contains(listed.Body.String(), "27.1.1") {
		t.Fatalf("engine version leaked into app list: %s", listed.Body.String())
	}

	engine := httptest.NewRecorder()
	controller.ServeHTTP(engine, uiRequest(http.MethodGet, "/api/engine?agent_id=agent-1", ""))
	if engine.Code != http.StatusOK || !strings.Contains(engine.Body.String(), `"version":"27.1.1"`) {
		t.Fatalf("engine status=%d body=%s", engine.Code, engine.Body.String())
	}

	again := httptest.NewRecorder()
	controller.ServeHTTP(again, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	unchanged := decodeAppList(t, again.Body.Bytes())
	if unchanged[0].Version != apps[0].Version || unchanged[0].Notice != OpsStatusUpdateAvailable || unchanged[0].Status != OpsStatusRunning {
		t.Fatalf("list without update changed image: %#v", unchanged)
	}
	record, ok := controllerDeployment(controller, "media")
	if !ok || record.ImageDigest != current || record.AvailableDigest != latest {
		t.Fatalf("digest mutated without confirm: %#v ok=%v", record, ok)
	}

	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	published := decodeAppList(t, updated.Body.Bytes())
	if published[0].Notice == OpsStatusUpdateAvailable || published[0].Status != OpsStatusRunning || !strings.Contains(published[0].Version, "sha256:fedcba987654") {
		t.Fatalf("confirm did not switch digest: %#v", published)
	}
	if !hasAppAction(published[0], OpsActionRollback) {
		t.Fatalf("confirmed update omitted rollback: %#v", published)
	}
	got, ok := controllerDeployment(controller, "media")
	if !ok || got.ImageDigest != latest || len(got.History) == 0 || got.History[0].ImageDigest != current {
		t.Fatalf("confirm digest=%#v ok=%v", got, ok)
	}
}

type blockingImageObserver struct {
	started chan struct{}
	release chan struct{}
}

func (observer *blockingImageObserver) ObserveImage(ctx context.Context, _ App) (UpdateObservation, error) {
	select {
	case observer.started <- struct{}{}:
	default:
	}
	select {
	case <-observer.release:
		return UpdateObservation{}, errors.New("registry unavailable")
	case <-ctx.Done():
		return UpdateObservation{}, ctx.Err()
	}
}

type delayedImageObserver struct {
	mu              sync.Mutex
	current, latest string
	block           bool
	started         chan struct{}
	release         chan struct{}
}

func (observer *delayedImageObserver) ObserveImage(ctx context.Context, _ App) (UpdateObservation, error) {
	observer.mu.Lock()
	block := observer.block
	observer.mu.Unlock()
	if block {
		select {
		case observer.started <- struct{}{}:
		default:
		}
		select {
		case <-observer.release:
		case <-ctx.Done():
			return UpdateObservation{}, ctx.Err()
		}
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return UpdateObservation{CurrentDigest: observer.current, LatestDigest: observer.latest}, nil
}

func TestAppUIDeployDoesNotWaitForRegistryObservation(t *testing.T) {
	observer := &blockingImageObserver{started: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(observer.release)
	controller := newUIControllerWithOptions(t, uiControllerOptions{observer: observer})
	created := httptest.NewRecorder()
	started := time.Now()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: registry.example.test/media:latest\n"}`))
	if created.Code != http.StatusOK || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("deploy waited for registry: status=%d elapsed=%s body=%s", created.Code, time.Since(started), created.Body.String())
	}
	select {
	case <-observer.started:
	case <-time.After(time.Second):
		t.Fatal("background registry observation did not start")
	}
}

func TestAppUIScriptReportsDeployBeforeRefreshingList(t *testing.T) {
	script, err := os.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	success := strings.Index(text, `showStatus(updating ? "已更新应用。" : "已部署应用。", false);`)
	refresh := -1
	if success >= 0 {
		if relative := strings.Index(text[success:], "await renderWorkspace();"); relative >= 0 {
			refresh = success + relative
		}
	}
	failure := strings.Index(text, "但列表刷新失败")
	if success < 0 || refresh < 0 || failure < 0 || success > refresh {
		t.Fatalf("deploy success/refresh ordering is missing: success=%d refresh=%d failure=%d", success, refresh, failure)
	}
	page, err := os.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `textarea name="env"`) || !strings.Contains(text, `env: String(data.get("env") || "")`) {
		t.Fatal("Compose .env input is not wired through the deployment form")
	}
}

func TestAppUIRollbackRequiresHistoryAndRestoresPrior(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	compose := "services:\n  web:\n    image: nginx:latest\n"
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(compose)+`}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	observed := httptest.NewRecorder()
	controller.ServeHTTP(observed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	listed := decodeAppList(t, observed.Body.Bytes())
	if observed.Code != http.StatusOK || len(listed) != 1 || hasAppAction(listed[0], OpsActionRollback) {
		t.Fatalf("unconfirmed view offered rollback: %#v body=%s", listed, observed.Body.String())
	}

	before := controller.Apps()[0]
	running := controller.appIsRunning("media")
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/rollback", `{}`))
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("missing history rollback status=%d body=%s", denied.Code, denied.Body.String())
	}
	after := controller.Apps()[0]
	if after.Compose != before.Compose || after.Image != before.Image || controller.appIsRunning("media") != running {
		t.Fatalf("rejected rollback mutated app: before=%#v after=%#v running=%v", before, after, controller.appIsRunning("media"))
	}
	record, ok := controllerDeployment(controller, "media")
	if !ok || record.ImageDigest != current || record.AvailableDigest != latest || len(record.History) != 0 {
		t.Fatalf("rejected rollback mutated deployment: %#v ok=%v", record, ok)
	}

	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	published := decodeAppList(t, updated.Body.Bytes())
	if len(published) != 1 || !hasAppAction(published[0], OpsActionRollback) {
		t.Fatalf("confirmed update omitted rollback: %#v", published)
	}
	got, ok := controllerDeployment(controller, "media")
	if !ok || got.ImageDigest != latest || len(got.History) == 0 || got.History[0].ImageDigest != current {
		t.Fatalf("confirm history=%#v ok=%v", got, ok)
	}

	restored := httptest.NewRecorder()
	controller.ServeHTTP(restored, uiJSONRequest(http.MethodPost, "/api/apps/media/rollback", `{}`))
	if restored.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", restored.Code, restored.Body.String())
	}
	rolled := decodeAppList(t, restored.Body.Bytes())
	if len(rolled) != 1 || rolled[0].Status != OpsStatusRunning {
		t.Fatalf("rollback view=%#v", rolled)
	}
	afterRoll, ok := controllerDeployment(controller, "media")
	if !ok || afterRoll.ImageDigest != current {
		t.Fatalf("rollback digest=%#v ok=%v", afterRoll, ok)
	}
	if controller.Apps()[0].Compose != before.Compose || controller.Apps()[0].Image != before.Image || !controller.appIsRunning("media") {
		t.Fatalf("rollback changed compose or running state: app=%#v running=%v", controller.Apps()[0], controller.appIsRunning("media"))
	}
}

func TestAppUIComposeSaveDropsRollbackHistory(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	if published := decodeAppList(t, updated.Body.Bytes()); len(published) != 1 || !hasAppAction(published[0], OpsActionRollback) {
		t.Fatalf("confirmed update omitted rollback: %#v", published)
	}

	saved := httptest.NewRecorder()
	controller.ServeHTTP(saved, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.28\n"}`))
	if saved.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	apps := decodeAppList(t, saved.Body.Bytes())
	if len(apps) != 1 || hasAppAction(apps[0], OpsActionRollback) {
		t.Fatalf("compose save still offered rollback: %#v", apps)
	}
	if record, exists := controllerDeployment(controller, "media"); exists && len(record.History) > 0 {
		t.Fatalf("compose save kept history: %#v", record)
	}
}

func TestAppUIComposeSaveBumpsEpochSkipsOverlappingStart(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	pullStarted := make(chan struct{}, 1)
	pullRelease := make(chan struct{})
	defer close(pullRelease)
	rollout := &blockingUIRollout{started: pullStarted, release: pullRelease}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  rollout,
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	select {
	case <-pullStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("auto_update pull did not start")
	}
	controller.mu.Lock()
	epochBefore := controller.imageDeleteEpoch["media"]
	controller.mu.Unlock()
	saved := httptest.NewRecorder()
	controller.ServeHTTP(saved, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.28\n","auto_update":true}`))
	if saved.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if !strings.Contains(controller.Apps()[0].Compose, "nginx:1.28") {
		t.Fatalf("catalog compose not saved: %q", controller.Apps()[0].Compose)
	}
	controller.mu.Lock()
	epochAfter := controller.imageDeleteEpoch["media"]
	controller.mu.Unlock()
	if epochAfter <= epochBefore {
		t.Fatalf("compose save did not bump delete epoch: before=%d after=%d", epochBefore, epochAfter)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if rolloutCallHas(rollout.calls, "start") {
			t.Fatalf("overlapping AutoUpdate restaged previous YAML: %v", rollout.calls)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAppUIConfirmUpdateAndRollbackMarkRunningAfterStop(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	stopped := httptest.NewRecorder()
	controller.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/media/stop", `{}`))
	if stopped.Code != http.StatusOK || decodeAppList(t, stopped.Body.Bytes())[0].Status != OpsStatusStopped {
		t.Fatalf("stop status=%d body=%s", stopped.Code, stopped.Body.String())
	}
	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	published := decodeAppList(t, updated.Body.Bytes())
	if len(published) != 1 || published[0].Status != OpsStatusRunning || !controller.appIsRunning("media") {
		t.Fatalf("confirm left stopped: %#v running=%v", published, controller.appIsRunning("media"))
	}

	controller.ServeHTTP(httptest.NewRecorder(), uiJSONRequest(http.MethodPost, "/api/apps/media/stop", `{}`))
	restored := httptest.NewRecorder()
	controller.ServeHTTP(restored, uiJSONRequest(http.MethodPost, "/api/apps/media/rollback", `{}`))
	if restored.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", restored.Code, restored.Body.String())
	}
	rolled := decodeAppList(t, restored.Body.Bytes())
	if len(rolled) != 1 || rolled[0].Status != OpsStatusRunning || !controller.appIsRunning("media") {
		t.Fatalf("rollback left stopped: %#v running=%v", rolled, controller.appIsRunning("media"))
	}
}

func TestAppUIAutoUpdatePublishMarksRunningAfterStop(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	newer := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	observer := &delayedImageObserver{current: current, latest: latest}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: observer,
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == latest && deployment.Phase == PhaseActive && controller.appIsRunning("media")
	})
	stopped := httptest.NewRecorder()
	controller.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/media/stop", `{}`))
	if stopped.Code != http.StatusOK || decodeAppList(t, stopped.Body.Bytes())[0].Status != OpsStatusStopped {
		t.Fatalf("stop status=%d body=%s", stopped.Code, stopped.Body.String())
	}
	observer.mu.Lock()
	observer.current = latest
	observer.latest = newer
	observer.mu.Unlock()
	controller.mu.Lock()
	delete(controller.imageCache, "media")
	controller.imageRefresh["media"] = false
	controller.mu.Unlock()
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		record, ok := controllerDeployment(controller, "media")
		if ok && record.ImageDigest == newer && record.Phase == PhaseActive && controller.appIsRunning("media") {
			refreshed := httptest.NewRecorder()
			controller.ServeHTTP(refreshed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
			apps := decodeAppList(t, refreshed.Body.Bytes())
			if refreshed.Code == http.StatusOK && len(apps) == 1 && apps[0].Status == OpsStatusRunning {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	record, _ := controllerDeployment(controller, "media")
	t.Fatalf("auto_update publish did not return to running: deployment=%#v running=%v", record, controller.appIsRunning("media"))
}

func TestAppUIRestoresPersistedRollbackHistoryAfterRestart(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	state := &uiMemoryAppState{}
	first := newUIControllerWithOptions(t, uiControllerOptions{
		appState: state,
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	first.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, first, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	updated := httptest.NewRecorder()
	first.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	got, ok := controllerDeployment(first, "media")
	if !ok || got.ImageDigest != latest || len(got.History) == 0 || got.History[0].ImageDigest != current {
		t.Fatalf("first confirm history=%#v ok=%v", got, ok)
	}
	if state.deployStores == 0 || !state.deployFound {
		t.Fatalf("confirm did not persist deployment snapshot: stores=%d found=%v", state.deployStores, state.deployFound)
	}

	restarted := newUIControllerWithOptions(t, uiControllerOptions{
		appState: state,
		rollout:  &uiTestRollout{},
	})
	listed := httptest.NewRecorder()
	restarted.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	apps := decodeAppList(t, listed.Body.Bytes())
	if listed.Code != http.StatusOK || len(apps) != 1 || !hasAppAction(apps[0], OpsActionRollback) {
		t.Fatalf("restored rollback action missing: %#v body=%s", apps, listed.Body.String())
	}
	restored := httptest.NewRecorder()
	restarted.ServeHTTP(restored, uiJSONRequest(http.MethodPost, "/api/apps/media/rollback", `{}`))
	if restored.Code != http.StatusOK {
		t.Fatalf("restarted rollback status=%d body=%s", restored.Code, restored.Body.String())
	}
	rolled, ok := controllerDeployment(restarted, "media")
	if !ok || rolled.ImageDigest != current {
		t.Fatalf("restarted rollback digest=%#v ok=%v", rolled, ok)
	}
}

func TestAppUIRollbackInFlightObserveAfterDeleteDoesNotRestoreHistory(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	observer := &delayedImageObserver{
		current: current, latest: latest,
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	state := &uiMemoryAppState{}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		appState: state,
		observer: observer,
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	got, ok := controllerDeployment(controller, "media")
	if !ok || len(got.History) == 0 || got.History[0].ImageDigest != current {
		t.Fatalf("precondition history=%#v ok=%v", got, ok)
	}

	observer.mu.Lock()
	observer.block = true
	observer.mu.Unlock()
	controller.mu.Lock()
	delete(controller.imageCache, "media")
	delete(controller.imageRefresh, "media")
	controller.mu.Unlock()
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	select {
	case <-observer.started:
	case <-time.After(time.Second):
		t.Fatal("in-flight ObserveImage did not start")
	}

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}

	close(observer.release)
	waitForImageObservation(t, controller, "media")
	if _, exists := controllerDeployment(controller, "media"); exists {
		t.Fatal("stale observe persisted a deployments record after delete")
	}

	recreated := httptest.NewRecorder()
	controller.ServeHTTP(recreated, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if recreated.Code != http.StatusOK {
		t.Fatalf("redeploy status=%d body=%s", recreated.Code, recreated.Body.String())
	}
	apps := decodeAppList(t, recreated.Body.Bytes())
	if len(apps) != 1 || hasAppAction(apps[0], OpsActionRollback) {
		t.Fatalf("same-id redeploy offered rollback: %#v", apps)
	}
	refreshed := httptest.NewRecorder()
	controller.ServeHTTP(refreshed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	listedApps := decodeAppList(t, refreshed.Body.Bytes())
	if refreshed.Code != http.StatusOK || len(listedApps) != 1 || hasAppAction(listedApps[0], OpsActionRollback) {
		t.Fatalf("list after same-id redeploy offered rollback: %#v body=%s", listedApps, refreshed.Body.String())
	}
	if record, exists := controllerDeployment(controller, "media"); exists && len(record.History) > 0 {
		t.Fatalf("same-id redeploy restored history: %#v", record)
	}
	got = waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest && len(deployment.History) == 0
	})
	if len(got.History) != 0 {
		t.Fatalf("same-id observe restored history: %#v", got)
	}
}

func TestAppUIDeleteOverlappingAutoUpdatePersistDoesNotRestoreHistory(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	newer := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	observer := &delayedImageObserver{current: current, latest: latest}
	store := &delayedDeploymentStore{
		base:    NewDeploymentStore(),
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer:    observer,
		rollout:     &uiTestRollout{},
		deployments: store,
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	updated := httptest.NewRecorder()
	controller.ServeHTTP(updated, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	got, ok := controllerDeployment(controller, "media")
	if !ok || len(got.History) == 0 || got.History[0].ImageDigest != current {
		t.Fatalf("precondition history=%#v ok=%v", got, ok)
	}

	observer.mu.Lock()
	observer.latest = newer
	observer.mu.Unlock()
	store.mu.Lock()
	store.block = true
	store.mu.Unlock()
	controller.mu.Lock()
	delete(controller.imageCache, "media")
	delete(controller.imageRefresh, "media")
	controller.mu.Unlock()
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("AutoUpdate persist did not start")
	}

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
	close(store.release)
	waitForImageObservation(t, controller, "media")
	if record, exists := controllerDeployment(controller, "media"); exists {
		t.Fatalf("overlapping AutoUpdate persist restored deployments: %#v", record)
	}
}

func TestAppUIDeleteInvalidatesObserveBeforeRemoveAppSkipsStart(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	pullStarted := make(chan struct{}, 1)
	pullRelease := make(chan struct{})
	removeStarted := make(chan struct{}, 1)
	removeRelease := make(chan struct{})
	rollout := &blockingUIRollout{started: pullStarted, release: pullRelease}
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  rollout,
		remove:   &blockingAppRemove{started: removeStarted, release: removeRelease},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	select {
	case <-pullStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("auto_update pull did not start")
	}
	controller.mu.Lock()
	observeToken := controller.imageObserveToken["media"]
	controller.mu.Unlock()
	deleted := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
		close(done)
	}()
	select {
	case <-removeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("RemoveApp did not start")
	}
	if apps := controller.Apps(); len(apps) != 1 || apps[0].ID != "media" {
		t.Fatalf("live catalog dropped before replaceApps: %#v", apps)
	}
	controller.mu.Lock()
	token := controller.imageObserveToken["media"]
	epoch := controller.imageDeleteEpoch["media"]
	controller.mu.Unlock()
	if token <= observeToken {
		t.Fatalf("observe token not bumped before RemoveApp: before=%d during=%d", observeToken, token)
	}
	if epoch == 0 {
		t.Fatal("delete epoch not bumped before RemoveApp")
	}
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	if listed.Code != http.StatusOK {
		t.Fatalf("list during compose down status=%d body=%s", listed.Code, listed.Body.String())
	}
	close(pullRelease)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if rolloutCallHas(rollout.calls, "start") {
			t.Fatalf("Start ran during compose down: %v", rollout.calls)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(removeRelease)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not finish")
	}
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
	if rolloutCallHas(rollout.calls, "start") {
		t.Fatalf("Start ran after delete: %v", rollout.calls)
	}
}

func TestAppUIFullSlotClearsRefreshOnlyWhenScheduleStillCurrent(t *testing.T) {
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: "sha256:0123456789abcdef0123456789abcdef", latest: "sha256:fedcba9876543210fedcba9876543210"},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForImageObservation(t, controller, "media")
	controller.imageSlots <- struct{}{}
	controller.imageSlots <- struct{}{}
	controller.mu.Lock()
	delete(controller.imageCache, "media")
	controller.imageRefresh["media"] = false
	controller.mu.Unlock()
	controller.scheduleImageObservation(controller.Apps()[0])
	controller.mu.Lock()
	if controller.imageRefresh["media"] {
		controller.mu.Unlock()
		t.Fatal("matching full-slot schedule left refresh pinned")
	}
	controller.mu.Unlock()

	controller.mu.Lock()
	delete(controller.imageCache, "media")
	controller.imageRefresh["media"] = false
	controller.mu.Unlock()
	controller.invalidateObservation("media")
	controller.mu.Lock()
	token := controller.imageObserveToken["media"]
	epoch := controller.imageDeleteEpoch["media"]
	controller.imageObserveToken["media"]++
	controller.imageDeleteEpoch["media"]++
	controller.clearImageRefreshIfCurrentLocked("media", token, epoch)
	if !controller.imageRefresh["media"] {
		controller.mu.Unlock()
		t.Fatal("full-slot path cleared refresh after delete epoch")
	}
	controller.mu.Unlock()
}

func rolloutCallHas(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func waitForImageObservation(t *testing.T, controller *Controller, appID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	idleSince := time.Time{}
	for time.Now().Before(deadline) {
		controller.mu.Lock()
		refreshing := controller.imageRefresh[appID]
		controller.mu.Unlock()
		if refreshing {
			idleSince = time.Time{}
			time.Sleep(time.Millisecond)
			continue
		}
		if idleSince.IsZero() {
			idleSince = time.Now()
		}
		if time.Since(idleSince) > 20*time.Millisecond {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("in-flight observation did not finish")
}

func TestPersistedDeploymentStoreWriteFailureKeepsPrior(t *testing.T) {
	t.Parallel()
	state := &uiMemoryAppState{}
	store := newPersistedDeploymentStore(state)
	ctx := context.Background()
	seed := Deployment{
		AppID: "media", AgentID: "agent-1", Image: "nginx:latest", Generation: "generation-1",
		Phase: PhaseActive, ImageDigest: "sha256:current",
		History: []DeploymentRevision{{Image: "nginx:latest", ImageDigest: "sha256:prior"}},
	}
	leased, err := store.AcquireLease(ctx, "media", 0, seed, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	active := leased.Value
	active.Lease, active.LeaseUntil = "", time.Time{}
	if _, err := store.CompareAndSwap(ctx, "media", leased.Version, leased.Value.FencingToken, active); err != nil {
		t.Fatal(err)
	}
	state.deployErr = errors.New("storage.write failed")
	mutated := active
	mutated.ImageDigest = "sha256:latest"
	if _, err := store.CompareAndSwap(ctx, "media", leased.Version+1, leased.Value.FencingToken, mutated); err == nil {
		t.Fatal("write failure still swapped deployment")
	}
	state.deployErr = nil
	got, ok, err := store.Load(ctx, "media")
	if err != nil || !ok || got.Value.ImageDigest != "sha256:current" || len(got.Value.History) != 1 || got.Value.History[0].ImageDigest != "sha256:prior" {
		t.Fatalf("failed write mutated history: %#v ok=%v err=%v", got, ok, err)
	}
}

func TestAppUIHighRiskComposeRequiresMatchingConfirm(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	highRisk := "services:\n  web:\n    image: nginx:latest\n    privileged: true\n    cap_add:\n      - NET_ADMIN\n    volumes:\n      - /host:/data\n"
	before := cloneApps(controller.Apps())

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(highRisk)+`}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), ErrInvalidPreview.Error()) {
		t.Fatalf("unconfirmed high-risk status=%d body=%s", denied.Code, denied.Body.String())
	}
	if len(controller.Apps()) != len(before) {
		t.Fatalf("unconfirmed high-risk mutated apps=%#v", controller.Apps())
	}
	var deniedPayload struct {
		Preview riskPreviewView `json:"preview"`
	}
	if err := json.Unmarshal(denied.Body.Bytes(), &deniedPayload); err != nil {
		t.Fatal(err)
	}
	if deniedPayload.Preview.Digest == "" || !previewHasRisk(deniedPayload.Preview, "privileged") || !previewHasRisk(deniedPayload.Preview, "host-mount") || !previewHasRisk(deniedPayload.Preview, "capability") {
		t.Fatalf("unconfirmed high-risk preview=%#v", deniedPayload.Preview)
	}

	preview := httptest.NewRecorder()
	controller.ServeHTTP(preview, uiJSONRequest(http.MethodPost, "/api/apps/preview", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(highRisk)+`}`))
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var previewPayload struct {
		Preview riskPreviewView `json:"preview"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &previewPayload); err != nil {
		t.Fatal(err)
	}
	if previewPayload.Preview.Digest == "" || previewPayload.Preview.Digest != deniedPayload.Preview.Digest {
		t.Fatalf("preview digest=%q denied=%q", previewPayload.Preview.Digest, deniedPayload.Preview.Digest)
	}

	mismatch := httptest.NewRecorder()
	controller.ServeHTTP(mismatch, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(highRisk)+`,"confirm":"deadbeef"}`))
	if mismatch.Code != http.StatusBadRequest || len(controller.Apps()) != len(before) {
		t.Fatalf("mismatched digest status=%d apps=%#v body=%s", mismatch.Code, controller.Apps(), mismatch.Body.String())
	}

	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(highRisk)+`,"confirm":`+jsonString(previewPayload.Preview.Digest)+`}`))
	if created.Code != http.StatusOK {
		t.Fatalf("confirmed high-risk status=%d body=%s", created.Code, created.Body.String())
	}
	listed := decodeAppList(t, created.Body.Bytes())
	if len(listed) != 1 || listed[0].ID != "media" || listed[0].Status != OpsStatusRunning {
		t.Fatalf("confirmed high-risk view=%#v", listed)
	}

	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	updating := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	seeded := httptest.NewRecorder()
	updating.ServeHTTP(seeded, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":`+jsonString(highRisk)+`,"confirm":`+jsonString(previewPayload.Preview.Digest)+`}`))
	if seeded.Code != http.StatusOK {
		t.Fatalf("update seed status=%d body=%s", seeded.Code, seeded.Body.String())
	}
	waitForDeployment(t, updating, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	unconfirmedUpdate := httptest.NewRecorder()
	updating.ServeHTTP(unconfirmedUpdate, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{}`))
	if unconfirmedUpdate.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed update status=%d body=%s", unconfirmedUpdate.Code, unconfirmedUpdate.Body.String())
	}
	record, ok := controllerDeployment(updating, "media")
	if !ok || record.ImageDigest != current || record.AvailableDigest != latest {
		t.Fatalf("unconfirmed update mutated digest: %#v ok=%v", record, ok)
	}
	var updatePreview struct {
		Preview riskPreviewView `json:"preview"`
	}
	if err := json.Unmarshal(unconfirmedUpdate.Body.Bytes(), &updatePreview); err != nil {
		t.Fatal(err)
	}
	confirmedUpdate := httptest.NewRecorder()
	updating.ServeHTTP(confirmedUpdate, uiJSONRequest(http.MethodPost, "/api/apps/media/update", `{"confirm":`+jsonString(updatePreview.Preview.Digest)+`}`))
	if confirmedUpdate.Code != http.StatusOK {
		t.Fatalf("confirmed update status=%d body=%s", confirmedUpdate.Code, confirmedUpdate.Body.String())
	}
	published, ok := controllerDeployment(updating, "media")
	if !ok || published.ImageDigest != latest {
		t.Fatalf("confirmed update digest=%#v ok=%v", published, ok)
	}
}

func previewHasRisk(preview riskPreviewView, kind string) bool {
	for _, item := range preview.Items {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func TestAppUIAutoUpdateTrueObserveFollowsDigest(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == latest
	})
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	apps := decodeAppList(t, listed.Body.Bytes())
	if len(apps) != 1 || apps[0].Notice == OpsStatusUpdateAvailable || !strings.Contains(apps[0].Version, "sha256:fedcba987654") {
		t.Fatalf("auto_update did not follow digest: %#v", apps)
	}
	got, ok := controllerDeployment(controller, "media")
	if !ok || got.ImageDigest != latest {
		t.Fatalf("auto_update digest=%#v ok=%v", got, ok)
	}
}

func TestAppUIAutoUpdateObserveDoesNotBlockManagementPage(t *testing.T) {
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &blockingUIRollout{started: started, release: release},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("auto_update observe did not start")
	}
	listed := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("management page blocked by auto_update observe")
	}
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
}

func TestAppUIKeepsComposeOpsWhenDigestDrifts(t *testing.T) {
	t.Parallel()
	current := "sha256:0123456789abcdef0123456789abcdef"
	latest := "sha256:fedcba9876543210fedcba9876543210"
	controller := newUIControllerWithOptions(t, uiControllerOptions{
		observer: &uiTestObserver{current: current, latest: latest},
		rollout:  &uiTestRollout{},
	})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if createdApps := decodeAppList(t, created.Body.Bytes()); len(createdApps) != 1 || createdApps[0].Status != OpsStatusRunning {
		t.Fatalf("create response did not return immediately: %#v", createdApps)
	}
	record := waitForDeployment(t, controller, "media", func(deployment Deployment) bool {
		return deployment.ImageDigest == current && deployment.AvailableDigest == latest
	})
	refreshed := httptest.NewRecorder()
	controller.ServeHTTP(refreshed, uiRequest(http.MethodGet, "/api/apps?agent_id=agent-1", ""))
	refreshedApps := decodeAppList(t, refreshed.Body.Bytes())
	if len(refreshedApps) != 1 || refreshedApps[0].Notice != OpsStatusUpdateAvailable {
		t.Fatalf("background observation did not publish update notice: %#v", refreshedApps)
	}
	_, ok := controllerDeployment(controller, "media")
	if !ok || record.ImageDigest != current || record.AvailableDigest != latest {
		t.Fatalf("digest drift published without confirm: %#v ok=%v", record, ok)
	}

	stopped := httptest.NewRecorder()
	controller.ServeHTTP(stopped, uiJSONRequest(http.MethodPost, "/api/apps/media/stop", `{}`))
	if stopped.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", stopped.Code, stopped.Body.String())
	}
	listed := decodeAppList(t, stopped.Body.Bytes())
	if len(listed) != 1 || listed[0].Status != OpsStatusStopped || listed[0].Notice != OpsStatusUpdateAvailable {
		t.Fatalf("stop with digest drift view=%#v", listed)
	}
	if !hasAppAction(listed[0], OpsActionStart) || !hasAppAction(listed[0], OpsActionDelete) || !hasAppAction(listed[0], OpsActionUpdate) {
		t.Fatalf("stopped update view dropped start/delete/update: %#v", listed)
	}
	if hasAppAction(listed[0], OpsActionRollback) {
		t.Fatalf("stopped update view offered rollback: %#v", listed)
	}

	started := httptest.NewRecorder()
	controller.ServeHTTP(started, uiJSONRequest(http.MethodPost, "/api/apps/media/start", `{}`))
	if started.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	running := decodeAppList(t, started.Body.Bytes())
	if running[0].Status != OpsStatusRunning || running[0].Notice != OpsStatusUpdateAvailable || !hasAppAction(running[0], OpsActionRestart) {
		t.Fatalf("start with digest drift view=%#v", running)
	}

	restarted := httptest.NewRecorder()
	controller.ServeHTTP(restarted, uiJSONRequest(http.MethodPost, "/api/apps/media/restart", `{}`))
	if restarted.Code != http.StatusOK {
		t.Fatalf("restart status=%d body=%s", restarted.Code, restarted.Body.String())
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":""}`))
	if denied.Code != http.StatusBadRequest || len(controller.Apps()) != 1 {
		t.Fatalf("unconfirmed delete status=%d apps=%#v body=%s", denied.Code, controller.Apps(), denied.Body.String())
	}
	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || len(controller.Apps()) != 0 {
		t.Fatalf("confirmed delete status=%d apps=%#v body=%s", deleted.Code, controller.Apps(), deleted.Body.String())
	}
}

func waitForDeployment(t *testing.T, controller *Controller, appID string, ready func(Deployment) bool) Deployment {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if record, ok := controllerDeployment(controller, appID); ok && ready(record) {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	record, _ := controllerDeployment(controller, appID)
	t.Fatalf("deployment observation did not reach expected state: %#v", record)
	return Deployment{}
}

func controllerDeployment(controller *Controller, appID string) (Deployment, bool) {
	if controller == nil || controller.uiRollout.Store == nil {
		return Deployment{}, false
	}
	record, ok, err := controller.uiRollout.Store.Load(context.Background(), appID)
	if err != nil || !ok {
		return Deployment{}, false
	}
	return record.Value, true
}

func TestProjectAppViewKeepsLifecycleOpsAlongsideUpdateNotice(t *testing.T) {
	t.Parallel()
	app := App{ID: "media", AgentID: "agent-1", Image: "nginx:latest", Compose: "services:\n  web:\n    image: nginx:latest\n"}
	deployment := Deployment{
		Phase: PhaseActive, ImageDigest: "sha256:current", AvailableDigest: "sha256:latest",
		History: []DeploymentRevision{{InstanceID: "old", Image: "old-image"}},
	}

	running := projectAppView(app, true, deployment, "sha256:latest")
	if running.Status != OpsStatusRunning || running.Notice != OpsStatusUpdateAvailable {
		t.Fatalf("running update view=%#v", running)
	}
	if !hasOpsAction(running.Actions, OpsActionUpdate) || !hasOpsAction(running.Actions, OpsActionStop) || !hasOpsAction(running.Actions, OpsActionRestart) || !hasOpsAction(running.Actions, OpsActionDelete) {
		t.Fatalf("running update dropped ops: %#v", running.Actions)
	}
	if !hasOpsAction(running.Actions, OpsActionRollback) {
		t.Fatalf("running update omitted rollback: %#v", running.Actions)
	}

	stopped := projectAppView(app, false, deployment, "sha256:latest")
	if stopped.Status != OpsStatusStopped || stopped.Notice != OpsStatusUpdateAvailable {
		t.Fatalf("stopped update view=%#v", stopped)
	}
	if !hasOpsAction(stopped.Actions, OpsActionStart) || !hasOpsAction(stopped.Actions, OpsActionDelete) || !hasOpsAction(stopped.Actions, OpsActionUpdate) {
		t.Fatalf("stopped update dropped start/delete/update: %#v", stopped.Actions)
	}
	if !hasOpsAction(stopped.Actions, OpsActionRollback) {
		t.Fatalf("stopped update omitted rollback: %#v", stopped.Actions)
	}

	withoutHistory := projectAppView(app, true, Deployment{Phase: PhaseActive, ImageDigest: "sha256:current", AvailableDigest: "sha256:latest"}, "sha256:latest")
	if hasOpsAction(withoutHistory.Actions, OpsActionRollback) {
		t.Fatalf("view without history offered rollback: %#v", withoutHistory.Actions)
	}

	enabled := true
	auto := app
	auto.AutoUpdate = &enabled
	ignored := projectAppView(auto, true, deployment, "sha256:latest")
	if ignored.Notice != OpsStatusUpdateAvailable || !hasOpsAction(ignored.Actions, OpsActionUpdate) {
		t.Fatalf("auto_update hid 有新版本: %#v", ignored)
	}
}

func TestAppUIPageSeparatesEngineStatusFromAppVersion(t *testing.T) {
	t.Parallel()
	page := httptest.NewRecorder()
	newUIController(t).ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	html := page.Body.String()
	scriptRec := httptest.NewRecorder()
	newUIController(t).ServeHTTP(scriptRec, uiRequest(http.MethodGet, "/app.js", ""))
	script := scriptRec.Body.String()
	if !strings.Contains(html, `id="engine-status"`) || !strings.Contains(html, "应用镜像版本") {
		t.Fatalf("page missing engine/app version split: %s", html)
	}
	for _, token := range []string{
		`className = "chip app-version"`,
		"api/apps/",
		"postAppAction",
		`dataset.action = "logs"`,
		"/logs",
		"有新版本",
		"app.notice",
		`className = "chip app-status-update"`,
		"确认高风险配置",
		"api/apps/preview",
		"privileged",
		"host-mount",
		"capability",
		`["start", "stop", "restart", "update"]`,
	} {
		if !strings.Contains(script, token) {
			t.Fatalf("app.js missing %q", token)
		}
	}
	if strings.Contains(script, "chip(engine") || strings.Contains(script, "engine.version") && strings.Contains(script, "app.version = engine") {
		t.Fatal("app.js still treats engine version as the app image version")
	}
}

func TestAppUIPageLabelsManagementAndAgentExecutionFaces(t *testing.T) {
	t.Parallel()
	html, err := appUIAssets.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := appUIAssets.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	js := string(script)
	if strings.Contains(page, "本地管理面") || strings.Contains(page, `class="face-summary"`) {
		t.Fatal("dedicated UI still leads with management/execution-face summary")
	}
	if strings.Contains(page, "Agent 执行面") {
		t.Fatal("first screen still presents Agent 执行面 as primary copy")
	}
	if !strings.Contains(page, `id="agent-select"`) || !strings.Contains(page, `data-agent-picker="workspace"`) || !strings.Contains(page, `class="page-head-agent"`) {
		t.Fatal("node picker is no longer in the page head")
	}
	if !strings.Contains(page, `id="app-list"`) || !strings.Contains(page, `data-card-wall="apps"`) || !strings.Contains(page, `id="app-detail"`) {
		t.Fatal("page is missing card wall / 详情 regions")
	}
	templateStart := strings.Index(page, `id="app-card-template"`)
	templateEnd := strings.Index(page, `id="app-files-template"`)
	if templateStart < 0 || templateEnd <= templateStart {
		t.Fatal("card wall template is missing")
	}
	cardTemplate := page[templateStart:templateEnd]
	for _, want := range []string{
		`data-app-name`, `data-app-status`, `data-action="open"`,
		`data-action="start"`, `data-action="stop"`, `data-action="restart"`,
		`data-action="update"`, `data-action="detail"`, "打开", "详情", "更新",
	} {
		if !strings.Contains(cardTemplate, want) {
			t.Fatalf("card template missing hook %q", want)
		}
	}
	for _, forbidden := range []string{"删除", "日志", "files-list", "compose-form", "http-form", "logs-view"} {
		if strings.Contains(cardTemplate, forbidden) {
			t.Fatalf("cards still expose %q as list primary", forbidden)
		}
	}
	if !strings.Contains(page, `id="app-execution-unavailable"`) || !strings.Contains(page, "该节点暂时无法执行应用") {
		t.Fatal("dedicated UI omits execution-unavailable guide")
	}
	if !strings.Contains(page, `id="app-node-empty"`) || !strings.Contains(page, `id="app-offline"`) || !strings.Contains(page, `id="engine-guide"`) {
		t.Fatal("dedicated UI omits node-first empty/offline/unready guides")
	}
	if !strings.Contains(js, "api/apps?agent_id=") {
		t.Fatal("list load is not node-scoped")
	}
	for _, marker := range []string{"Agent 执行面 · 节点离线", "Agent 执行面 · 引擎未就绪", "Agent 执行面 · 执行面未就绪", "Agent 执行面 · ${app.status}", "Agent 执行面 · 有新版本"} {
		if strings.Contains(js, marker) {
			t.Fatalf("dedicated UI still prefixes status with %q", marker)
		}
	}
	renderStart := strings.Index(js, "const renderApp = (app) => {")
	renderEnd := strings.Index(js, "const fillCompose = (app) => {")
	if renderStart < 0 || renderEnd <= renderStart {
		t.Fatal("card renderer is missing")
	}
	listRender := js[renderStart:renderEnd]
	if !strings.Contains(listRender, `className = "app-card"`) {
		t.Fatal("application list is not a card wall")
	}
	if !strings.Contains(listRender, "[data-app-name]") || !strings.Contains(listRender, "[data-app-status]") {
		t.Fatal("card renderer does not fill name/status hooks")
	}
	if !strings.Contains(listRender, `textContent = "详情"`) || !strings.Contains(listRender, `[data-action="detail"]`) || !strings.Contains(listRender, "showDetail(app.id") {
		t.Fatal("cards do not open detail from 详情 or click")
	}
	if !strings.Contains(listRender, "window.open") || !strings.Contains(listRender, `textContent = "打开"`) || !strings.Contains(listRender, `[data-action="open"]`) {
		t.Fatal("cards cannot open an enabled HTTP entry")
	}
	for _, action := range []string{"start", "stop", "restart", "update"} {
		if !strings.Contains(listRender, `[data-action="${id}"]`) && !strings.Contains(listRender, `[data-action="`+action+`"]`) {
			t.Fatalf("card renderer does not fill %s hook", action)
		}
	}
	if !strings.Contains(listRender, `["start", "stop", "restart", "update"]`) {
		t.Fatal("card wall does not expose start/stop/restart/update")
	}
	for _, forbidden := range []string{"删除", "日志", "mountAppFiles", "http-form", "openCreate("} {
		if strings.Contains(listRender, forbidden) {
			t.Fatalf("card wall still embeds %q", forbidden)
		}
	}
	runStart := strings.Index(js, "const runAppAction = async (app, action) => {")
	runEnd := strings.Index(js, "const actionGroups = (app, options = {}) => {")
	if runStart < 0 || runEnd <= runStart {
		t.Fatal("runAppAction is missing")
	}
	runFn := js[runStart:runEnd]
	logsGate := strings.Index(runFn, `action.id === "logs"`)
	logsOpen := strings.Index(runFn, `showDetail(app.id, "logs")`)
	logsPost := strings.Index(runFn, "postAppAction")
	if logsGate < 0 || logsOpen < 0 || logsOpen < logsGate {
		t.Fatal("logs action does not open the detail logs section")
	}
	if logsPost >= 0 && logsPost < logsGate {
		t.Fatal("logs still posts as a list RPC before opening detail")
	}
	logsReturn := strings.Index(runFn[logsOpen:], "return;")
	if logsReturn < 0 {
		t.Fatal("logs action does not return after opening detail")
	}
	logsBranch := runFn[logsGate : logsOpen+logsReturn]
	if strings.Contains(logsBranch, "已执行操作") || strings.Contains(logsBranch, "postAppAction") {
		t.Fatal("list page still treats logs as 已执行操作 RPC from the card")
	}
	if strings.Contains(js, "/panel-api/plugins/docker-app/configure") {
		t.Fatal("dedicated UI must not configure a second plugin instance")
	}
	if !strings.Contains(page, `id="detail-back"`) || !strings.Contains(page, "返回列表") {
		t.Fatal("detail view is missing a return to the card wall")
	}
}

func TestAppUIPageUsesSearchableAgentPickerAndViewportBreakpoints(t *testing.T) {
	t.Parallel()
	html, err := appUIAssets.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := appUIAssets.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := appUIAssets.ReadFile("assets/ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)
	js := string(script)
	stylesheet := string(css)
	if strings.Contains(page, `<select id="agent-select"`) {
		t.Fatal("management page still uses a native agent <select>")
	}
	if strings.Contains(page, `class="toolbar-bar"`) || strings.Contains(stylesheet, ".toolbar-bar") {
		t.Fatal("node picker is still in a toolbar-bar")
	}
	contextStart := strings.Index(page, `id="app-context"`)
	guideStart := strings.Index(page, `id="engine-guide"`)
	workspaceStart := strings.Index(page, `id="app-workspace"`)
	if contextStart < 0 || guideStart < 0 || workspaceStart < 0 || !(contextStart < guideStart && guideStart < workspaceStart) {
		t.Fatal("engine-guide is not a sibling between context and workspace")
	}
	if !strings.Contains(page, OfficialInstallScript) {
		t.Fatal("engine-guide markup is missing the official install command")
	}
	if !strings.Contains(js, OfficialInstallScript) || !strings.Contains(js, "command.script || OFFICIAL_INSTALL_SCRIPT") {
		t.Fatal("script does not fall back to the official install command")
	}
	if !strings.Contains(js, "showUnreadyGuide") {
		t.Fatal("deploy no longer reveals the install guide when the engine is unready")
	}
	if !strings.Contains(page, `data-lang="yaml"`) || !strings.Contains(page, `data-lang="env"`) {
		t.Fatal("compose YAML/.env editors are missing highlighter shells")
	}
	for _, want := range []string{"highlightYaml", "highlightEnv", "mountCodeEditor"} {
		if !strings.Contains(js, want) {
			t.Fatalf("script missing syntax highlighter %q", want)
		}
	}
	if !strings.Contains(stylesheet, "tok-key") || !strings.Contains(stylesheet, ".code-editor") {
		t.Fatal("stylesheet missing syntax highlighter colors")
	}
	if !strings.Contains(stylesheet, "max-height: 22rem") || !strings.Contains(stylesheet, "max-height: 14rem") || !strings.Contains(stylesheet, "field-sizing: fixed") {
		t.Fatal("YAML/.env editors can still grow with content instead of scrolling")
	}
	headStart := strings.Index(page, `class="page-head"`)
	headEnd := strings.Index(page, `id="app-loading"`)
	if headStart < 0 || headEnd < 0 || headEnd < headStart {
		t.Fatal("page is missing page-head / loading regions")
	}
	head := page[headStart:headEnd]
	for _, want := range []string{
		`id="agent-select"`,
		`data-agent-picker="workspace"`,
		`class="agent-search-select"`,
		`class="page-head-agent"`,
		`id="engine-status"`,
	} {
		if !strings.Contains(head, want) {
			t.Fatalf("page-head missing agent picker markup %q", want)
		}
	}
	for _, want := range []string{
		`id="app-context"`,
		`class="context-region"`,
		`class="state-panel"`,
		`id="app-node-empty"`,
		`id="app-offline"`,
		`id="app-execution-unavailable"`,
		`id="engine-guide"`,
		`id="app-workspace"`,
		`class="workspace-region"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page missing layout region %q", want)
		}
	}
	for _, want := range []string{
		"mountAgentSearchSelect",
		"搜索节点",
		"最近活跃",
		"/panel-api/agents",
		"agentPicker.onChange",
		"引擎就绪",
		"引擎未就绪",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("script missing agent picker behavior %q", want)
		}
	}
	for _, want := range []string{
		".agent-search-select",
		"@media (max-width: 720px)",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"width: calc(100% - 2.5rem)",
	} {
		if !strings.Contains(stylesheet, want) {
			t.Fatalf("stylesheet missing viewport rule %q", want)
		}
	}
	if strings.Contains(stylesheet, "min(52rem") || strings.Contains(stylesheet, "min(64rem") || strings.Contains(stylesheet, "min(880px") {
		t.Fatal("stylesheet still caps main at 52rem, 64rem, or 880px")
	}
	assertConsoleSkin(t, page, js, stylesheet)
	workspaceHead := cssRule(stylesheet, ".workspace-head")
	if strings.Contains(workspaceHead, "space-between") {
		t.Fatal(".workspace-head still uses space-between to fill main")
	}
	if !strings.Contains(workspaceHead, "justify-content: flex-start") {
		t.Fatal(".workspace-head is not a left-aligned operation group")
	}
	createForm := cssRule(stylesheet, "#create-form")
	if !strings.Contains(createForm, "max-width: min(46rem, 100%)") {
		t.Fatal("#create-form still fills main without a capped operation group")
	}
	appList := cssRule(stylesheet, ".app-list")
	if !strings.Contains(appList, "repeat(auto-fit, minmax(") {
		t.Fatal(".app-list is not a filling card grid")
	}
	if strings.Contains(appList, "auto-fill") {
		t.Fatal(".app-list still leaves empty auto-fill tracks")
	}
	if strings.Contains(appList, "grid-template-columns: minmax(0, 1fr)") {
		t.Fatal(".app-list is still a single column")
	}
	for _, want := range []string{
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
		"max-width: 72rem",
		"repeat(auto-fit, minmax(17.5rem, 22rem))",
		"repeat(auto-fit, minmax(18rem, 22rem))",
		"repeat(auto-fit, minmax(20rem, 22rem))",
	} {
		if !strings.Contains(stylesheet, want) {
			t.Fatalf("stylesheet missing wide-viewport rule %q", want)
		}
	}
	sdkText := ErrTypedHandlesUnavailable.Error()
	if strings.Contains(page, sdkText) || strings.Contains(js, sdkText) || strings.Contains(stylesheet, sdkText) {
		t.Fatal("management page still exposes the typed-handles SDK sentence")
	}
	renderStart := strings.Index(js, "const renderWorkspace = async () => {")
	loadEngineCall := strings.Index(js, "engine = await loadEngine();")
	if renderStart < 0 || loadEngineCall < 0 || loadEngineCall < renderStart {
		t.Fatal("renderWorkspace no longer loads the engine")
	}
	beforeLoad := js[renderStart:loadEngineCall]
	for _, want := range []string{
		"workspaceNode.hidden = true",
		"renderApps([])",
		"closeCreate()",
		`showStatus("", false)`,
	} {
		if !strings.Contains(beforeLoad, want) {
			t.Fatalf("app.js does not clear workspace before loadEngine: missing %q", want)
		}
	}
	catchStart := strings.Index(js[loadEngineCall:], "catch (error)")
	if catchStart < 0 {
		t.Fatal("loadEngine failure is not handled inside renderWorkspace")
	}
	loadCatch := js[loadEngineCall:]
	endCatch := strings.Index(loadCatch, "engineReady = engine?.ready === true;")
	if endCatch < 0 {
		t.Fatal("renderWorkspace lost the ready projection after loadEngine")
	}
	if strings.Contains(loadCatch[:endCatch], "showStatus(error.message") {
		t.Fatal("loadEngine failure still writes the error payload into #app-status")
	}
	if !strings.Contains(loadCatch[:endCatch], `showContext("execution-unavailable")`) {
		t.Fatal("loadEngine failure does not surface execution-face unavailability")
	}
}

func assertConsoleSkin(t *testing.T, page, script, style string) {
	t.Helper()
	if strings.Contains(style, "#d94880") || strings.Contains(style, "#f4a0c0") || strings.Contains(style, "#f5f4f2") {
		t.Fatal("stylesheet still contains sakura theme colors")
	}
	if strings.Contains(page, `data-theme="sakura-day"`) || strings.Contains(style, `[data-theme="sakura-day"]`) {
		t.Fatal("page still uses sakura-day as the rendered theme")
	}
	if !strings.Contains(page, `data-theme="light"`) {
		t.Fatal("page default theme is not light")
	}
	if !strings.Contains(style, `[data-theme="light"]`) || !strings.Contains(style, `[data-theme="dark"]`) {
		t.Fatal("stylesheet missing light/dark theme selectors")
	}
	if !strings.Contains(style, "#4f46e5") || !strings.Contains(style, "#f8fafc") {
		t.Fatal("stylesheet missing 晴空 light tokens")
	}
	if !strings.Contains(style, "#818cf8") {
		t.Fatal("stylesheet missing dark indigo accent")
	}
	if strings.Contains(script, `business: "sakura-day"`) || strings.Contains(script, `"fresh-green": "sakura-day"`) {
		t.Fatal("applyHostTheme still maps business or fresh-green to sakura-day")
	}
	if !strings.Contains(script, `business: "light"`) || !strings.Contains(script, `"fresh-green": "light"`) || !strings.Contains(script, `"sakura-day": "light"`) {
		t.Fatal("applyHostTheme does not map business, fresh-green, or sakura-day to light")
	}
	if !strings.Contains(script, `"sakura-night": "dark"`) || !strings.Contains(script, `"neko-dark": "dark"`) {
		t.Fatal("applyHostTheme does not map sakura-night or neko-dark to dark")
	}
}

func cssRule(css, selector string) string {
	needle := selector + " {"
	start := strings.Index(css, needle)
	if start < 0 {
		return ""
	}
	rest := css[start:]
	end := strings.Index(rest, "}")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func assertFilesManagerPage(t *testing.T) {
	t.Helper()
	htmlBytes, err := appUIAssets.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	scriptBytes, err := appUIAssets.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssBytes, err := appUIAssets.ReadFile("assets/ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	js := string(scriptBytes)
	style := string(cssBytes)

	templateStart := strings.Index(html, `id="app-files-template"`)
	if templateStart < 0 {
		t.Fatal("files template is missing")
	}
	template := html[templateStart:]
	toolbarStart := strings.Index(template, `class="files-toolbar"`)
	selectionStart := strings.Index(template, `id="files-selection"`)
	listStart := strings.Index(template, `id="files-list"`)
	editorStart := strings.Index(template, `id="files-editor"`)
	if toolbarStart < 0 || selectionStart < 0 || listStart < 0 || editorStart < 0 || !(toolbarStart < selectionStart && selectionStart < listStart && listStart < editorStart) {
		t.Fatal("files create toolbar is not separate from selection actions and the current directory list")
	}
	createToolbar := template[toolbarStart:selectionStart]
	if strings.Contains(createToolbar, `id="files-edit"`) || strings.Contains(createToolbar, `id="files-download"`) || strings.Contains(createToolbar, `id="files-delete"`) {
		t.Fatal("file toolbar still puts 编辑/下载/删除 next to blank mkdir/new-file inputs")
	}
	selection := template[selectionStart:listStart]
	for _, want := range []string{`id="files-selected"`, `id="files-edit"`, `id="files-download"`, `id="files-delete"`} {
		if !strings.Contains(selection, want) {
			t.Fatalf("selection actions missing %q", want)
		}
	}
	if !strings.Contains(template, `id="files-breadcrumb"`) || !strings.Contains(template, `aria-label="工作区路径"`) {
		t.Fatal("files browser is missing a path breadcrumb")
	}
	if !strings.Contains(template, `id="files-up"`) || !strings.Contains(template, "上一级") {
		t.Fatal("files breadcrumb is missing 上一级")
	}
	if !strings.Contains(template, `id="files-editor-close"`) || !strings.Contains(template, "关闭") {
		t.Fatal("text editor is missing a close control")
	}

	parentStart := strings.Index(js, "const parentWorkspacePath = (path) => {")
	parentEnd := strings.Index(js, "const looksLikeText = (value) => {")
	if parentStart < 0 || parentEnd <= parentStart {
		t.Fatal("parentWorkspacePath is missing")
	}
	parentFn := js[parentStart:parentEnd]
	if strings.Contains(parentFn, `".."`) || strings.Contains(parentFn, "'..'") {
		t.Fatal("breadcrumb up uses .. host paths")
	}

	crumbStart := strings.Index(js, "const renderBreadcrumb = () => {")
	crumbEnd := strings.Index(js, "const openFile = async (path, name) => {")
	if crumbStart < 0 || crumbEnd <= crumbStart {
		t.Fatal("renderBreadcrumb is missing")
	}
	crumbFn := js[crumbStart:crumbEnd]
	if !strings.Contains(crumbFn, `addCrumb("工作区", ".", parts.length === 0)`) {
		t.Fatal("breadcrumb is missing the workspace root")
	}
	if !strings.Contains(crumbFn, `button.addEventListener("click", () => requestList(path))`) {
		t.Fatal("breadcrumb cannot return to a parent directory")
	}
	if !strings.Contains(crumbFn, "upBtn.hidden = currentPath === \".\"") {
		t.Fatal("上一级 is not bound to the current breadcrumb path")
	}
	if !strings.Contains(js, "requestList(parentWorkspacePath(currentPath))") {
		t.Fatal("上一级 does not open the parent workspace directory")
	}

	loadStart := strings.Index(js, "const loadList = async (path) => {")
	loadEnd := strings.Index(js, "const requestList = async (path) => {")
	if loadStart < 0 || loadEnd <= loadStart {
		t.Fatal("loadList is missing")
	}
	loadFn := js[loadStart:loadEnd]
	if !strings.Contains(loadFn, "if (!entryPath) return;") {
		t.Fatal("file list does not skip non-relative paths")
	}
	if strings.Contains(loadFn, `textContent = "编辑"`) || strings.Contains(loadFn, `textContent = "下载"`) || strings.Contains(loadFn, `textContent = "删除"`) {
		t.Fatal("file list still repeats edit/download/delete on every row")
	}
	if !strings.Contains(loadFn, "selectEntry(entryPath") {
		t.Fatal("clicking a file no longer selects without reading")
	}
	if strings.Contains(loadFn, "openFile(") {
		t.Fatal("selecting a file still reads and opens the editor")
	}
	if !strings.Contains(loadFn, "if (entry.dir) requestList(entryPath)") {
		t.Fatal("directories cannot be opened from the current listing")
	}

	hideStart := strings.Index(js, "const hideEditor = () => {")
	hideEnd := strings.Index(js, "discardFileEditor = hideEditor")
	if hideStart < 0 || hideEnd <= hideStart {
		t.Fatal("hideEditor is missing")
	}
	hideFn := js[hideStart:hideEnd]
	if !strings.Contains(hideFn, "browser.hidden = false") || !strings.Contains(hideFn, "editor.hidden = true") {
		t.Fatal("closing the editor does not restore the current directory")
	}
	if strings.Contains(hideFn, "leaveDetail") || strings.Contains(hideFn, "setDetailSection") || strings.Contains(hideFn, "currentPath =") {
		t.Fatal("hideEditor leaves the files section or resets the current path")
	}

	showStart := strings.Index(js, "const showEditor = (path, name, content) => {")
	showEnd := strings.Index(js, "const renderBreadcrumb = () => {")
	if showStart < 0 || showEnd <= showStart {
		t.Fatal("showEditor is missing")
	}
	showFn := js[showStart:showEnd]
	if strings.Contains(showFn, "detail-head") || strings.Contains(showFn, "detailBack") || strings.Contains(showFn, "detailNav") || strings.Contains(showFn, "leaveDetail") {
		t.Fatal("opening the files editor hides detail chrome")
	}

	closeStart := strings.Index(js, "if (closeBtn) {")
	if closeStart < 0 {
		t.Fatal("files editor close is missing")
	}
	closeRest := js[closeStart:]
	closeEnd := strings.Index(closeRest, "if (editorInput)")
	if closeEnd <= 0 {
		t.Fatal("files editor close handler is missing")
	}
	closeFn := closeRest[:closeEnd]
	if !strings.Contains(closeFn, "confirmLeave") || !strings.Contains(closeFn, "browser.hidden = false") || !strings.Contains(closeFn, "loadList(currentPath)") {
		t.Fatal("closing the editor does not stay on the current files directory")
	}
	if strings.Contains(closeFn, "leaveDetail") || strings.Contains(closeFn, "setDetailSection") {
		t.Fatal("closing the editor leaves the files section")
	}

	for _, want := range []string{
		"请先选择一个文件再编辑",
		"请先选择一个文件再下载",
		"请先选择要删除的文件或目录",
		"syncSelectionActions",
		"relativeWorkspacePath",
		`id="files-edit"`,
		"openFile(",
	} {
		if !strings.Contains(html+js, want) {
			t.Fatalf("selection-based files manager missing %q", want)
		}
	}

	setBusyStart := strings.Index(js, "const setBusy = (next) => {")
	setBusyEnd := strings.Index(js, "const parseAgentTime = (value) => {")
	if setBusyStart < 0 || setBusyEnd <= setBusyStart {
		t.Fatal("setBusy is missing")
	}
	setBusyFn := js[setBusyStart:setBusyEnd]
	for _, id := range []string{`"files-edit"`, `"files-download"`, `"files-delete"`} {
		if !strings.Contains(setBusyFn, id) {
			t.Fatalf("setBusy(false) still enables %s with no file selected", id)
		}
	}
	if !strings.Contains(setBusyFn, "if (!next) syncSelectionActions()") {
		t.Fatal("setBusy(false) does not restore selection-based disabled flags")
	}
	if !strings.Contains(setBusyFn, "node.disabled = next") {
		t.Fatal("setBusy no longer toggles workspace controls")
	}

	syncBodyStart := strings.Index(js, "const hasFile = Boolean(selectedPath) && !selectedDir;")
	if syncBodyStart < 0 {
		t.Fatal("syncSelectionActions is missing")
	}
	syncBody := js[syncBodyStart:]
	if end := strings.Index(syncBody, "};"); end > 0 {
		syncBody = syncBody[:end]
	}
	if !strings.Contains(syncBody, "editBtn.disabled = !hasFile") || !strings.Contains(syncBody, "downloadBtn.disabled = !hasFile") || !strings.Contains(syncBody, "deleteBtn.disabled = !hasTarget") {
		t.Fatal("syncSelectionActions no longer disables edit/download/delete when nothing is selected")
	}
	if !strings.Contains(js, `let selectedPath = "";`) {
		t.Fatal("files manager does not start with no file selected")
	}
	for _, markup := range []string{
		`id="files-edit" type="button" class="btn-secondary" disabled`,
		`id="files-download" type="button" class="btn-secondary" disabled`,
		`id="files-delete" type="button" class="btn-link danger" disabled`,
	} {
		if !strings.Contains(template, markup) {
			t.Fatalf("selection action is not disabled before a file is selected: %s", markup)
		}
	}

	mkdirStart := strings.Index(js, "if (mkdirBtn) {")
	mkdirEnd := strings.Index(js, "if (newTextBtn) {")
	if mkdirStart < 0 || mkdirEnd <= mkdirStart {
		t.Fatal("mkdir handler is missing")
	}
	mkdirFn := js[mkdirStart:mkdirEnd]
	if !strings.Contains(mkdirFn, "openNamedDialog") && !strings.Contains(js, "showModal") {
		t.Fatal("new directory is not opened from a dialog")
	}
	mkdirPost := strings.Index(js, `action: "mkdir"`)
	if mkdirPost < 0 {
		t.Fatal("mkdir does not write a workspace directory")
	}
	start := mkdirPost - 400
	if start < 0 {
		start = 0
	}
	end := mkdirPost + 400
	if end > len(js) {
		end = len(js)
	}
	mkdirWindow := js[start:end]
	if !strings.Contains(mkdirWindow, "setBusy(true)") || !strings.Contains(mkdirWindow, "setBusy(false)") {
		t.Fatal("mkdir does not go through setBusy")
	}
	if !strings.Contains(js, "files-new-dialog") || !strings.Contains(js, "files-mkdir-dialog") {
		t.Fatal("new file/directory dialogs are missing")
	}

	uploadStart := strings.Index(js, "if (uploadBtn && uploadInput) {")
	uploadEnd := strings.Index(js, "if (downloadBtn) {")
	if uploadStart < 0 || uploadEnd <= uploadStart {
		t.Fatal("upload handler is missing")
	}
	uploadFn := js[uploadStart:uploadEnd]
	if !strings.Contains(uploadFn, "setBusy(true)") || !strings.Contains(uploadFn, "setBusy(false)") {
		t.Fatal("upload does not go through setBusy")
	}

	runStart := strings.Index(js, "const runAppAction = async (app, action) => {")
	runEnd := strings.Index(js, "const actionGroups = (app, options = {}) => {")
	if runStart < 0 || runEnd <= runStart {
		t.Fatal("runAppAction is missing")
	}
	runFn := js[runStart:runEnd]
	if !strings.Contains(runFn, "setBusy(true)") || !strings.Contains(runFn, "setBusy(false)") {
		t.Fatal("detail start/stop does not go through setBusy")
	}
	if !strings.Contains(js, "runAppAction(detailApp, action)") {
		t.Fatal("detail start/stop does not call runAppAction")
	}
	if strings.Contains(js, "/mnt/data/komga") {
		t.Fatal("files UI lists an absolute host mount")
	}
	for _, want := range []string{".files-breadcrumb", ".files-path", ".files-selection", ".files-browser", `li[aria-selected="true"]`} {
		if !strings.Contains(style, want) {
			t.Fatalf("stylesheet missing files-manager rule %q", want)
		}
	}
	if !strings.Contains(cssRule(style, `.files-list li[aria-selected="true"]`), "var(--color-primary") {
		t.Fatal("selected file row does not use theme variables")
	}
	if strings.Contains(cssRule(style, ".files-toolbar"), "flex-wrap: wrap") || strings.Contains(cssRule(style, ".files-toolbar label"), "flex: 1 1") {
		t.Fatal("files toolbar is still a wrapping junk drawer of fields")
	}
	if !strings.Contains(cssRule(style, ".files-selection"), "flex-wrap: nowrap") {
		t.Fatal("selection toolbar is not a contextual action row")
	}
	if !strings.Contains(cssRule(style, ".files-path"), "var(--color-bg-sunken)") || !strings.Contains(cssRule(style, ".files-browser"), "var(--color-bg-surface)") {
		t.Fatal("file browser chrome does not keep theme variables")
	}

	editorClose := strings.Index(template, `id="files-editor-close"`)
	templateEnd := strings.Index(template, "</template>")
	if editorClose < 0 || templateEnd <= editorClose {
		t.Fatal("files editor close is missing from the files template")
	}
	if strings.Contains(template[editorClose:templateEnd], "返回列表") {
		t.Fatal("files editor close is 返回列表 instead of returning to the current directory")
	}
	detailStart := strings.Index(html, `id="app-detail"`)
	filesPanel := strings.Index(html, `id="detail-files"`)
	if detailStart < 0 || filesPanel < 0 || filesPanel < detailStart {
		t.Fatal("files panel is not kept under persistent detail chrome")
	}
	detailChrome := html[detailStart:filesPanel]
	if !strings.Contains(detailChrome, `id="detail-back"`) || !strings.Contains(detailChrome, `id="detail-nav"`) {
		t.Fatal("files are not under the persistent detail identity bar")
	}
}

func TestPageWorkspaceFiles(t *testing.T) {
	t.Parallel()
	assertFilesManagerPage(t)
	if appID, action, ok := parseAppAPIPath("/api/apps/media/files"); !ok || appID != "media" || action != "files" {
		t.Fatalf("parseAppAPIPath files = %q %q %t", appID, action, ok)
	}
	page := httptest.NewRecorder()
	newUIController(t).ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	html := page.Body.String()
	scriptRec := httptest.NewRecorder()
	newUIController(t).ServeHTTP(scriptRec, uiRequest(http.MethodGet, "/app.js", ""))
	script := scriptRec.Body.String()
	combined := html + script
	for _, token := range []string{
		`id="app-files"`,
		`id="files-breadcrumb"`,
		`id="files-up"`,
		"上一级",
		`id="files-selection"`,
		`id="files-selected"`,
		`id="files-list"`,
		`id="files-mkdir"`,
		`id="files-upload"`,
		`id="files-download"`,
		`id="files-editor"`,
		`id="files-editor-close"`,
		`id="files-delete"`,
		`id="files-save"`,
		`id="files-edit"`,
		`id="files-new-text"`,
		"目录名称",
		"新建文本文件",
		"编辑",
		"/files",
		"postAppFiles",
		"relativeWorkspacePath",
		"parentWorkspacePath",
		`addCrumb("工作区", ".", parts.length === 0)`,
	} {
		if !strings.Contains(combined, token) {
			t.Fatalf("workspace files UI missing %q", token)
		}
	}
	if !strings.Contains(html, `id="create-form"`) || !strings.Contains(html, `name="compose"`) || !strings.Contains(html, `id="app-files-template"`) {
		t.Fatal("compose editor was replaced by the workspace files tree")
	}
	if strings.Contains(script, "/mnt/data/komga") {
		t.Fatal("files UI lists an absolute host mount")
	}
}

func assertDetailWorkspacePage(t *testing.T) {
	t.Helper()
	htmlBytes, err := appUIAssets.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	scriptBytes, err := appUIAssets.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	js := string(scriptBytes)

	detailStart := strings.Index(html, `id="app-detail"`)
	navStart := strings.Index(html, `id="detail-nav"`)
	sectionStart := strings.Index(html, `data-section-panel="overview"`)
	if detailStart < 0 || navStart <= detailStart || sectionStart <= navStart {
		t.Fatal("detail identity/return is not above section nav and panels")
	}
	detailHead := html[detailStart:navStart]
	for _, want := range []string{
		`id="detail-back"`,
		"返回列表",
		`id="detail-title"`,
		`id="detail-status"`,
		`id="detail-open"`,
		`id="detail-start"`,
		`id="detail-stop"`,
		`id="detail-restart"`,
		`data-action="open"`,
		`data-action="start"`,
		`data-action="stop"`,
		`data-action="restart"`,
	} {
		if !strings.Contains(detailHead, want) {
			t.Fatalf("detail any-section head missing %q", want)
		}
	}
	if strings.Contains(detailHead, "data-section-panel") {
		t.Fatal("detail identity/return is inside a section panel")
	}
	if strings.Contains(detailHead, "删除") {
		t.Fatal("detail head still exposes delete")
	}
	if strings.Contains(html, "同一时间只展示一个分区") {
		t.Fatal("detail still leads with 同一时间只展示一个分区")
	}

	paintStart := strings.Index(js, "const paintDetail = (app) => {")
	paintEnd := strings.Index(js, "const setDetailSection = async (section) => {")
	if paintStart < 0 || paintEnd <= paintStart {
		t.Fatal("paintDetail is missing")
	}
	paintFn := js[paintStart:paintEnd]
	if !strings.Contains(paintFn, "detailTitle.textContent = app.id") {
		t.Fatal("detail title does not show the app id")
	}
	if !strings.Contains(paintFn, "detailStatus") || !strings.Contains(paintFn, "detailOpen") {
		t.Fatal("detail head does not paint status or open")
	}

	setStart := strings.Index(js, "const setDetailSection = async (section) => {")
	setEnd := strings.Index(js, "const leaveDetail = async ({ force } = {}) => {")
	if setStart < 0 || setEnd <= setStart {
		t.Fatal("setDetailSection is missing")
	}
	setFn := js[setStart:setEnd]
	if !strings.Contains(setFn, `panel.hidden = panel.getAttribute("data-section-panel") !== next`) {
		t.Fatal("section switch no longer toggles only detail-section panels")
	}
	if strings.Contains(setFn, "detail-head") || strings.Contains(setFn, "detailBack.hidden") || strings.Contains(setFn, "detailTitle.hidden") {
		t.Fatal("switching sections hides 返回列表 or app identity")
	}

	runStart := strings.Index(js, "const runAppAction = async (app, action) => {")
	runEnd := strings.Index(js, "const actionGroups = (app, options = {}) => {")
	if runStart < 0 || runEnd <= runStart {
		t.Fatal("runAppAction is missing")
	}
	runFn := js[runStart:runEnd]
	logsGate := strings.Index(runFn, `action.id === "logs"`)
	logsOpen := strings.Index(runFn, `showDetail(app.id, "logs")`)
	if logsGate < 0 || logsOpen < 0 || logsOpen < logsGate {
		t.Fatal("logs entry does not open the detail logs section")
	}
	logsReturn := strings.Index(runFn[logsOpen:], "return;")
	if logsReturn < 0 {
		t.Fatal("logs entry does not return after opening the logs section")
	}
	logsBranch := runFn[logsGate : logsOpen+logsReturn]
	if strings.Contains(logsBranch, "已执行操作") || strings.Contains(logsBranch, "postAppAction") {
		t.Fatal("logs entry still treats logs as 已执行操作")
	}
	if !strings.Contains(js, "logsView.textContent = payload.logs") {
		t.Fatal("logs section does not display log text")
	}

	httpStart := strings.Index(js, "const renderHTTP = (app) => {")
	httpEnd := strings.Index(js, "const fillLogServices = (app) => {")
	if httpStart < 0 || httpEnd <= httpStart {
		t.Fatal("renderHTTP is missing")
	}
	httpFn := js[httpStart:httpEnd]
	if !strings.Contains(httpFn, `createElement("a")`) || !strings.Contains(httpFn, `target = "_blank"`) || !strings.Contains(httpFn, "link.href") {
		t.Fatal("HTTP entries are not openable links")
	}
	if strings.Contains(httpFn, `${domain}${port}`) {
		t.Fatal("HTTP rule rows still glue the backend published port onto the public URL")
	}
	if !strings.Contains(httpFn, "后端 ") || !strings.Contains(js, "publicURLFromRule") {
		t.Fatal("HTTP rule rows do not keep the public URL separate from the backend published port")
	}
	if !strings.Contains(httpFn, "确认删除入口") {
		t.Fatal("HTTP delete is missing confirmation")
	}

	if !strings.Contains(runFn, "确认删除 ${app.id}") {
		t.Fatal("app delete is missing confirmation in detail")
	}
	if !strings.Contains(runFn, "确认回滚 ${app.id}") {
		t.Fatal("rollback is missing confirmation")
	}
	if !strings.Contains(runFn, "确认更新 ${app.id}") {
		t.Fatal("update is missing confirmation")
	}
	overviewStart := strings.Index(js, "const renderOverview = (app) => {")
	overviewEnd := strings.Index(js, "const renderHTTP = (app) => {")
	if overviewStart < 0 || overviewEnd <= overviewStart {
		t.Fatal("renderOverview is missing")
	}
	if !strings.Contains(js[overviewStart:overviewEnd], "overview: true") {
		t.Fatal("delete is not offered from the detail overview")
	}
	cardStart := strings.Index(html, `id="app-card-template"`)
	cardEnd := strings.Index(html, `id="app-files-template"`)
	if cardStart < 0 || cardEnd <= cardStart {
		t.Fatal("card wall template is missing")
	}
	if strings.Contains(html[cardStart:cardEnd], "删除") {
		t.Fatal("delete is still on the card wall")
	}

	if !strings.Contains(html, `id="create-cancel"`) || !strings.Contains(html, "取消") {
		t.Fatal("deploy form is missing cancel")
	}
	if !strings.Contains(html, `id="create-back"`) || !strings.Contains(html, "返回") {
		t.Fatal("deploy form is missing 返回")
	}
	if !strings.Contains(js, `createCancel.addEventListener("click", closeCreate)`) {
		t.Fatal("deploy cancel is not wired back to the card wall")
	}
	if !strings.Contains(js, `createBack.addEventListener("click", closeCreate)`) {
		t.Fatal("deploy 返回 is not wired back to the card wall")
	}
	if strings.Count(html, `id="create-templates"`) != 1 {
		t.Fatal("optional templates are missing or duplicated")
	}
	for _, want := range []string{
		`data-template="blank"`,
		`data-template="site"`,
		`data-template="media"`,
		"空白",
		"静态站点",
		"媒体",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("optional template %q is missing", want)
		}
	}
	if !strings.Contains(js, "COMPOSE_TEMPLATES") || !strings.Contains(js, "applyCreateTemplate") || !strings.Contains(js, "composeInput.value = template.compose") {
		t.Fatal("optional templates do not fill YAML")
	}
	if strings.Contains(html, "应用商店目录") || strings.Contains(html, "应用市场") || strings.Contains(html, "上架") || strings.Contains(js, "应用商店目录") {
		t.Fatal("page grew an app store catalog")
	}
}

func TestAppUIListDetailFilesLogsAndConfirm(t *testing.T) {
	t.Parallel()
	assertDetailWorkspacePage(t)
	assertFilesManagerPage(t)
	htmlBytes, err := appUIAssets.ReadFile("assets/ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	scriptBytes, err := appUIAssets.ReadFile("assets/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssBytes, err := appUIAssets.ReadFile("assets/ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	js := string(scriptBytes)
	style := string(cssBytes)
	for _, want := range []string{
		`id="app-detail"`,
		`id="detail-back"`,
		"返回列表",
		`id="detail-title"`,
		`id="detail-status"`,
		`id="detail-open"`,
		`id="detail-start"`,
		`id="detail-stop"`,
		`id="detail-restart"`,
		`data-section="overview"`,
		`data-section="compose"`,
		`data-section="files"`,
		`data-section="logs"`,
		`data-section="http"`,
		"概览",
		"Compose",
		"HTTP 入口",
		"新建文本文件",
		`id="files-edit"`,
		"自动刷新",
		`id="compose-form"`,
		`id="create-cancel"`,
		"取消",
		`id="create-back"`,
		"返回",
		`id="create-templates"`,
		`data-template="blank"`,
		`data-template="site"`,
		`data-template="media"`,
		`data-template="files"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing list/detail markup %q", want)
		}
	}
	if strings.Contains(html, "同一时间只展示一个分区") {
		t.Fatal("detail still presents 同一时间只展示一个分区 as primary copy")
	}
	if strings.Contains(html, "应用商店目录") || strings.Contains(html, "应用市场") || strings.Contains(html, "上架") {
		t.Fatal("deploy form presents an application market")
	}
	templateCount := strings.Count(html, `data-template="`)
	if templateCount < 3 || templateCount > 5 {
		t.Fatalf("compose templates should stay a small fill-in set, got %d", templateCount)
	}
	for _, want := range []string{
		`id="app-card-template"`, `data-app-name`, `data-app-status`,
		`data-action="open"`, `data-action="start"`, `data-action="stop"`,
		`data-action="restart"`, `data-action="update"`, `data-action="detail"`, "详情",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing card-wall hook %q", want)
		}
	}
	renderStart := strings.Index(js, "const renderApp = (app) => {")
	renderEnd := strings.Index(js, "const fillCompose = (app) => {")
	if renderStart < 0 || renderEnd < 0 || renderEnd <= renderStart {
		t.Fatal("card wall renderer is missing")
	}
	listRender := js[renderStart:renderEnd]
	for _, forbidden := range []string{"mountAppFiles", "http-form", "app-logs", "查看日志", "openCreate("} {
		if strings.Contains(listRender, forbidden) {
			t.Fatalf("application list still embeds %q", forbidden)
		}
	}
	if !strings.Contains(listRender, `className = "app-card"`) {
		t.Fatal("application list is not a card wall")
	}
	if !strings.Contains(js, `textContent = "详情"`) || !strings.Contains(js, "无发布端口") {
		t.Fatal("application list is missing detail entry or published-port copy")
	}
	if strings.Contains(js, "openCreate(app)") || strings.Contains(js, `loadLogs.textContent = "查看日志"`) {
		t.Fatal("list still opens the deploy form for existing apps or gates logs behind 查看日志")
	}
	if strings.Contains(js, "else openFile(") {
		t.Fatal("selecting a file still reads and opens the editor")
	}
	if !strings.Contains(js, "openFile(") || !strings.Contains(html, `id="files-edit"`) {
		t.Fatal("workspace files are missing an explicit edit entry")
	}
	if !strings.Contains(js, "selectEntry(entryPath") {
		t.Fatal("clicking a file no longer selects without reading")
	}
	if !strings.Contains(js, "文本尚未保存") || !strings.Contains(js, "取消则留在当前编辑") {
		t.Fatal("unsaved editor leave confirmation is missing")
	}
	if !strings.Contains(js, "自动刷新失败，已保留上次快照") {
		t.Fatal("log refresh failure no longer keeps the previous snapshot copy")
	}
	if !strings.Contains(js, "LOG_REFRESH_MS = 4000") || !strings.Contains(js, "setInterval(fetchLogs, LOG_REFRESH_MS)") {
		t.Fatal("logs do not auto-refresh a snapshot every 4 seconds")
	}
	if !strings.Contains(js, `addEventListener("visibilitychange"`) || !strings.Contains(js, "clearInterval(logsTimer)") {
		t.Fatal("log polling is not stopped on hide or leave")
	}
	resetStart := strings.Index(js, "const resetLogsTerminal = () => {")
	if resetStart < 0 || !strings.Contains(js[resetStart:], `logsView.textContent = "";`) {
		t.Fatal("logs terminal reset does not clear #logs-view")
	}
	leaveStart := strings.Index(js, "const leaveDetail = async ({ force } = {}) => {")
	leaveEnd := strings.Index(js, "const showDetail = async (appID, section) => {")
	if leaveStart < 0 || leaveEnd <= leaveStart {
		t.Fatal("leaveDetail is missing")
	}
	leaveFn := js[leaveStart:leaveEnd]
	if !strings.Contains(leaveFn, "resetLogsTerminal();") {
		t.Fatal("leaveDetail does not reset the logs terminal")
	}
	paintStart := strings.Index(js, "const paintDetail = (app) => {")
	paintEnd := strings.Index(js, "const setDetailSection = async (section) => {")
	if paintStart < 0 || paintEnd <= paintStart {
		t.Fatal("paintDetail is missing")
	}
	paintFn := js[paintStart:paintEnd]
	if !strings.Contains(paintFn, "appChanged") || !strings.Contains(paintFn, "resetLogsTerminal();") {
		t.Fatal("changing apps does not reset the logs terminal")
	}
	if !strings.Contains(paintFn, "detailTitle.textContent = app.id") || !strings.Contains(paintFn, "detailStatus") {
		t.Fatal("detail head does not keep app id and status across sections")
	}
	for _, want := range []string{
		"detailTitle.textContent = app.id",
		"detailStatus.textContent",
		"firstEnabledRuleURL(app)",
		"detailOpen.hidden",
		`["start", detailStart]`,
		`["stop", detailStop]`,
		`["restart", detailRestart]`,
	} {
		if !strings.Contains(paintFn, want) {
			t.Fatalf("detail chrome missing %q", want)
		}
	}
	fetchStart := strings.Index(js, "const fetchLogs = async () => {")
	fetchEnd := strings.Index(js, "const startLogPolling = () => {")
	if fetchStart < 0 || fetchEnd <= fetchStart {
		t.Fatal("fetchLogs is missing")
	}
	fetchFn := js[fetchStart:fetchEnd]
	if !strings.Contains(fetchFn, `if (!service)`) || !strings.Contains(fetchFn, "resetLogsTerminal();") || !strings.Contains(fetchFn, "没有可查看的服务") {
		t.Fatal("fetchLogs does not clear #logs-view when there is no current service")
	}
	if !strings.Contains(fetchFn, "logsView.textContent = payload.logs") {
		t.Fatal("logs section does not display log text")
	}
	pollStart := strings.Index(js, "const startLogPolling = () => {")
	pollEnd := strings.Index(js, "const paintDetail = (app) => {")
	if pollStart < 0 || pollEnd <= pollStart {
		t.Fatal("startLogPolling is missing")
	}
	pollFn := js[pollStart:pollEnd]
	fetchCall := strings.Index(pollFn, "fetchLogs();")
	pauseGate := strings.Index(pollFn, "logsPaused")
	if fetchCall < 0 || pauseGate < 0 || fetchCall > pauseGate {
		t.Fatal("paused log polling skips the immediate snapshot fetch")
	}
	if strings.Contains(pollFn, "if (logsPaused || document.visibilityState === \"hidden\" || view !== \"detail\"") {
		t.Fatal("startLogPolling still returns before fetchLogs when paused")
	}
	if !strings.Contains(js, "panelJSON(`api/apps/${encodeURIComponent(appID)}`)") {
		t.Fatal("detail view does not load GET /api/apps/{id}")
	}
	if strings.Contains(js, "实时跟随") || strings.Contains(html, "实时跟随") {
		t.Fatal("page claims Docker follow")
	}
	if strings.Contains(js, "from \"react") || strings.Contains(js, "from 'vue") || strings.Contains(html, "react") && strings.Contains(html, "createRoot") {
		t.Fatal("management page imported a UI framework")
	}
	if strings.Contains(js, `if (action.id === "rollback") return;`) {
		t.Fatal("management page still skips rollback")
	}
	if !strings.Contains(js, `await postAppAction(app, action.id)`) || !strings.Contains(js, `action.id === "rollback"`) {
		t.Fatal("management page does not execute projected rollback")
	}
	if !strings.Contains(html, `id="disk-cleanup"`) || !strings.Contains(html, "清理磁盘") {
		t.Fatal("workspace is missing the node disk cleanup entry")
	}
	cleanupStart := strings.Index(js, "const runDiskCleanup = async () => {")
	cleanupEnd := strings.Index(js, "if (diskCleanup) {")
	if cleanupStart < 0 || cleanupEnd <= cleanupStart {
		t.Fatal("runDiskCleanup is missing")
	}
	cleanupFn := js[cleanupStart:cleanupEnd]
	ask := strings.Index(cleanupFn, "askConfirm")
	apply := strings.Index(cleanupFn, `confirm: true`)
	if ask < 0 || apply < 0 || apply < ask {
		t.Fatal("node cleanup does not require confirm before prune")
	}
	if strings.Contains(cleanupFn, "image prune") || strings.Contains(cleanupFn, "builder prune") || strings.Contains(cleanupFn, "--volumes") {
		t.Fatal("management page still issues prune commands from the browser")
	}
	if !strings.Contains(cleanupFn, `api/disk-cleanup?agent_id=`) || !strings.Contains(cleanupFn, `sendPluginJSON("api/disk-cleanup"`) {
		t.Fatal("node cleanup is not wired to PreviewDiskCleanup/ApplyDiskCleanup")
	}
	if !strings.Contains(cleanupFn, "if (!ok || empty)") {
		t.Fatal("unconfirmed node cleanup still applies prune")
	}
	for _, forbidden := range []string{"应用商店", "应用市场", "上架", "实时跟随", "容器终端", "docker exec"} {
		if strings.Contains(html, forbidden) || strings.Contains(js, forbidden) {
			t.Fatalf("management page grew %q copy", forbidden)
		}
	}
	for _, want := range []string{".app-card", ".detail-nav", ".logs-terminal", ".files-browser", ".files-breadcrumb", ".files-path", ".files-selection", `li[aria-selected="true"]`, "--shadow-focus", ".detail-head", ".http-rule-open", ".create-templates", `[data-theme="light"]`, `[data-theme="dark"]`} {
		if !strings.Contains(style, want) {
			t.Fatalf("stylesheet missing workspace rule %q", want)
		}
	}
	detailHeadCSS := cssRule(style, ".detail-head")
	if !strings.Contains(detailHeadCSS, "position: sticky") || !strings.Contains(detailHeadCSS, "background: var(--color-bg-surface)") {
		t.Fatal("detail header is not a persistent theme-aware chrome")
	}
	if !strings.Contains(style, `#app-workspace:has(#app-create:not([hidden])) #app-list-panel`) {
		t.Fatal("deploy form can still stack on the card wall")
	}
	setStart := strings.Index(js, "const setDetailSection = async (section) => {")
	setEnd := strings.Index(js, "const leaveDetail = async ({ force } = {}) => {")
	if setStart < 0 || setEnd <= setStart {
		t.Fatal("setDetailSection is missing")
	}
	setFn := js[setStart:setEnd]
	if !strings.Contains(setFn, "[data-section-panel]") {
		t.Fatal("section switch no longer keeps the detail head mounted")
	}
	if strings.Contains(setFn, "detail-head") && strings.Contains(setFn, ".hidden") {
		t.Fatal("switching sections hides the detail identity bar")
	}
	httpStart := strings.Index(js, "const renderHTTP = (app) => {")
	httpEnd := strings.Index(js, "const fillLogServices = (app) => {")
	if httpStart < 0 || httpEnd <= httpStart {
		t.Fatal("renderHTTP is missing")
	}
	httpFn := js[httpStart:httpEnd]
	if !strings.Contains(httpFn, `className = "http-rule-open"`) || !strings.Contains(httpFn, `createElement("a")`) || !strings.Contains(httpFn, "link.href") {
		t.Fatal("existing HTTP entries are not openable in markup")
	}
	if !strings.Contains(httpFn, `确认删除入口 ${domain || rule.ref}？取消不会更改规则。`) {
		t.Fatal("HTTP rule delete no longer requires confirmation")
	}
	runStart := strings.Index(js, "const runAppAction = async (app, action) => {")
	runEnd := strings.Index(js, "const actionGroups = (app, options = {}) => {")
	if runStart < 0 || runEnd <= runStart {
		t.Fatal("runAppAction is missing")
	}
	runFn := js[runStart:runEnd]
	logsGate := strings.Index(runFn, `action.id === "logs"`)
	logsOpen := strings.Index(runFn, `showDetail(app.id, "logs")`)
	if logsGate < 0 || logsOpen < 0 || logsOpen < logsGate {
		t.Fatal("named logs entry does not open the detail logs section")
	}
	logsReturn := strings.Index(runFn[logsOpen:], "return;")
	if logsReturn < 0 {
		t.Fatal("logs action does not return after opening detail")
	}
	if strings.Contains(runFn[logsGate:logsOpen+logsReturn], "已执行操作") || strings.Contains(runFn[logsGate:logsOpen+logsReturn], "postAppAction") {
		t.Fatal("logs still reports 已执行操作 without opening the logs section")
	}
	if !strings.Contains(runFn, `确认删除 ${app.id}？取消不会更改应用。`) {
		t.Fatal("app delete no longer requires confirmation")
	}
	if strings.Contains(listRender, "删除") {
		t.Fatal("card wall still exposes delete")
	}
	if !strings.Contains(js, `options.overview && (action.id === "start" || action.id === "stop" || action.id === "restart")`) {
		t.Fatal("detail overview still repeats start/stop/restart from the identity bar")
	}
	if !strings.Contains(js, "COMPOSE_TEMPLATES") || !strings.Contains(js, "applyCreateTemplate") || !strings.Contains(js, "composeInput.value = template.compose") {
		t.Fatal("deploy form cannot fill a small YAML template")
	}
	if !strings.Contains(js, `createCancel.addEventListener("click", closeCreate)`) {
		t.Fatal("deploy form cannot cancel back to the card wall")
	}
	if !strings.Contains(js, `createBack.addEventListener("click", closeCreate)`) {
		t.Fatal("deploy form cannot return back to the card wall")
	}
	syncStart := strings.Index(js, "const syncListPanel = () => {")
	syncEnd := strings.Index(js, "const parsePublishedPorts = (compose) => {")
	if syncStart < 0 || syncEnd <= syncStart {
		t.Fatal("syncListPanel is missing")
	}
	syncFn := js[syncStart:syncEnd]
	if !strings.Contains(syncFn, "listPanel.hidden = inDetail || creating") {
		t.Fatal("deploy form still stacks over the card wall as the main operation")
	}
	if !strings.Contains(fetchFn, "logsView.textContent = payload.logs") {
		t.Fatal("logs section does not display log text")
	}
}

func TestAppUIFilesListsRelativeWorkspaceAndRejectsAbsolutePath(t *testing.T) {
	t.Parallel()
	files := &recordingUIFiles{result: map[string]any{
		"path": ".",
		"entries": []map[string]any{
			{"name": "config.yaml", "path": "config.yaml", "dir": false, "size": 12},
			{"name": "data", "path": "data", "dir": true},
			{"name": "komga", "path": "/mnt/data/komga", "dir": true},
		},
	}}
	controller := newUIControllerWithOptions(t, uiControllerOptions{files: files})
	compose := "services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - ./config.yaml:/config.yaml\n      - /mnt/data/komga:/data\n"
	created := uiDeployCompose(t, controller, "media", "agent-1", compose)
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("compose deploy status=%d body=%s", created.Code, created.Body.String())
	}

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"list","path":"."}`))
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	body := listed.Body.String()
	if !strings.Contains(body, `"path":"."`) || !strings.Contains(body, `"name":"config.yaml"`) || !strings.Contains(body, `"path":"data"`) {
		t.Fatalf("list omitted relative workspace entries: %s", body)
	}
	if strings.Contains(body, "/mnt/data/komga") {
		t.Fatalf("list projected an absolute host mount: %s", body)
	}
	if len(files.calls) != 1 || files.calls[0].Payload["action"] != "list" || files.calls[0].Payload["path"] != "." || files.calls[0].App.ID != "media" {
		t.Fatalf("list files calls=%#v", files.calls)
	}

	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"list","path":"/mnt/data/komga"}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), errWorkspaceFilePath.Error()) {
		t.Fatalf("absolute list status=%d body=%s", denied.Code, denied.Body.String())
	}
	parent := httptest.NewRecorder()
	controller.ServeHTTP(parent, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"read","path":"../secret"}`))
	if parent.Code != http.StatusBadRequest || !strings.Contains(parent.Body.String(), errWorkspaceFilePath.Error()) {
		t.Fatalf("parent read status=%d body=%s", parent.Code, parent.Body.String())
	}
	if len(files.calls) != 1 {
		t.Fatalf("rejected paths still called Files: %#v", files.calls)
	}

	written := httptest.NewRecorder()
	files.result = map[string]any{"accepted": true}
	controller.ServeHTTP(written, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"write","path":"config.yaml","content":"listen: 80\n"}`))
	if written.Code != http.StatusOK || !strings.Contains(written.Body.String(), `"accepted":true`) {
		t.Fatalf("write status=%d body=%s", written.Code, written.Body.String())
	}
	if len(files.calls) != 2 || files.calls[1].Payload["action"] != "write" || files.calls[1].Payload["path"] != "config.yaml" || files.calls[1].Payload["content"] != "listen: 80\n" {
		t.Fatalf("write files calls=%#v", files.calls)
	}

	again := uiDeployCompose(t, controller, "media", "agent-1", compose)
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), `"id":"media"`) {
		t.Fatalf("compose post after files status=%d body=%s", again.Code, again.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].ID != "media" {
		t.Fatalf("files mutated apps=%#v", controller.Apps())
	}
	assertFilesManagerPage(t)
}

func TestAppUIFilesSurfacesHandleErrorWithoutHostPath(t *testing.T) {
	t.Parallel()
	files := &recordingUIFiles{err: errors.New("file path is not relative to app workdir")}
	controller := newUIControllerWithOptions(t, uiControllerOptions{files: files})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"read","path":"config.yaml"}`))
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), errWorkspaceFilePath.Error()) {
		t.Fatalf("files error status=%d body=%s", denied.Code, denied.Body.String())
	}
	if strings.Contains(denied.Body.String(), "/mnt/") || strings.Contains(denied.Body.String(), "fixture-value") {
		t.Fatalf("files error leaked a host path: %s", denied.Body.String())
	}
}

func TestAppUIFilesProductionHandleMapsOversizeReadToSizeError(t *testing.T) {
	t.Parallel()
	agentRoot := t.TempDir()
	agent := newCallController(t, agentRoot, unusedDockerRunner(t), nil)
	workdir, err := AppWorkDir(agentRoot, "media")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workdir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "huge.txt"), []byte(strings.Repeat("x", MaxConfigBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	client := hostCallFunc(func(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		request := decodePluginCallRequest(t, call)
		if request.Name != pluginCallFilesName {
			t.Fatalf("unexpected plugin.call name %q", request.Name)
		}
		raw, err := agent.Call(ctx, "generation-1", request.Name, request.Payload)
		if err != nil {
			return err
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return err
		}
		return copyHostResult(decoded, target)
	})
	controller := newUIControllerWithOptions(t, uiControllerOptions{files: newHostCapabilityRuntime(client)})
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	oversize := httptest.NewRecorder()
	controller.ServeHTTP(oversize, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"read","path":"huge.txt"}`))
	if oversize.Code != http.StatusBadRequest || !strings.Contains(oversize.Body.String(), "文件超过 1MiB 上限") {
		t.Fatalf("oversize read status=%d body=%s", oversize.Code, oversize.Body.String())
	}
	if strings.Contains(oversize.Body.String(), ErrTypedHandlesUnavailable.Error()) {
		t.Fatalf("oversize read leaked generic handle error: %s", oversize.Body.String())
	}

	directory := httptest.NewRecorder()
	controller.ServeHTTP(directory, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"read","path":"data"}`))
	if directory.Code != http.StatusBadRequest || !strings.Contains(directory.Body.String(), "路径是目录") {
		t.Fatalf("directory read status=%d body=%s", directory.Code, directory.Body.String())
	}

	missing := httptest.NewRecorder()
	controller.ServeHTTP(missing, uiJSONRequest(http.MethodPost, "/api/apps/media/files", `{"action":"read","path":"missing.txt"}`))
	if strings.Contains(missing.Body.String(), workdir) || strings.Contains(missing.Body.String(), agentRoot) {
		t.Fatalf("missing read leaked a host path: %s", missing.Body.String())
	}
}

type recordingUIFiles struct {
	calls  []recordedFilesCall
	result map[string]any
	err    error
}

type recordedFilesCall struct {
	App     App
	Payload map[string]any
}

func (files *recordingUIFiles) Files(_ context.Context, app App, payload map[string]any, result any) error {
	copied := map[string]any{}
	for key, value := range payload {
		copied[key] = value
	}
	files.calls = append(files.calls, recordedFilesCall{App: app, Payload: copied})
	if files.err != nil {
		return files.err
	}
	if result == nil || files.result == nil {
		return nil
	}
	raw, err := json.Marshal(files.result)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, result)
}

func TestProductionRuntimeWiresReportedEngineSource(t *testing.T) {
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	config := productionControllerConfig()
	if config.UIEngineSource == nil {
		t.Fatal("production runtime still treats a zero UIEngine as the only observation path")
	}
	controller, err := NewController(config)
	if err != nil {
		t.Fatal(err)
	}
	report, err := controller.observeAgent(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.Online || report.Installed || ProjectEngine(ObservationFromReport(report)).Ready {
		t.Fatalf("empty catalog leaked readiness: %#v", report)
	}
}

func newUIController(t *testing.T) *Controller {
	t.Helper()
	return newUIControllerWithOptions(t, uiControllerOptions{})
}

func newUIControllerWithSource(t *testing.T, source AgentEngineSource, config string) *Controller {
	t.Helper()
	return newUIControllerWithOptions(t, uiControllerOptions{source: source, config: config})
}

type uiControllerOptions struct {
	source        AgentEngineSource
	config        string
	engineVersion string
	workDirRoot   *string
	observer      ImageUpdateObserver
	rollout       RolloutExecutor
	httpRule      HTTPRuleCreateHandle
	httpRuleList  HTTPRuleListHandle
	httpOffers    HTTPBackendOfferReplaceHandle
	appState      AppStateStore
	deployments   DeploymentStateStore
	files         AppFilesHandle
	remove        AppRemoveExecutor
	diskCleanup   DiskCleanupHandle
}

func newUIControllerWithOptions(t *testing.T, opts uiControllerOptions) *Controller {
	t.Helper()
	source := opts.source
	if source == nil {
		catalog := NewReportedEngineCatalog()
		version := opts.engineVersion
		if version == "" {
			version = "test"
		}
		catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: version})
		source = catalog
	}
	config := opts.config
	if config == "" {
		config = `{"apps":[]}`
	}
	runtime := newUITestRuntime()
	workDirRoot := t.TempDir()
	if opts.workDirRoot != nil {
		workDirRoot = *opts.workDirRoot
	}
	runtime.filesRoot = workDirRoot
	filesHandle := opts.files
	if filesHandle == nil {
		filesHandle = runtime
	}
	removeHandle := opts.remove
	if removeHandle == nil {
		removeHandle = runtime
	}
	httpRuleList := opts.httpRuleList
	if httpRuleList == nil {
		if lister, ok := opts.httpRule.(HTTPRuleListHandle); ok {
			httpRuleList = lister
		}
	}
	deployments := opts.deployments
	if deployments == nil {
		if backend, ok := opts.appState.(deploymentSnapshotStore); ok {
			deployments = newPersistedDeploymentStore(backend)
		}
	}
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		}),
		UIEngineSource:     source,
		UIApply:            runtime,
		UIStart:            runtime,
		UIStop:             runtime,
		UIRestart:          runtime,
		UILogs:             runtime,
		UIFiles:            filesHandle,
		UIRemove:           removeHandle,
		UIDiskCleanup:      opts.diskCleanup,
		UIHTTPRule:         opts.httpRule,
		UIHTTPRuleList:     httpRuleList,
		UIHTTPBackendOffer: opts.httpOffers,
		UIWorkDirRoot:      workDirRoot,
		UIImageObserver:    opts.observer,
		UIRolloutExecutor:  opts.rollout,
		UIAppState:         opts.appState,
		UIDeploymentState:  deployments,
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
	req.Header.Set(appActorHeader, "panel/admin")
	req.Header.Set(appOperationHeader, "operation/ui-test")
	return req
}

func uiJSONRequest(method, path, body string) *http.Request {
	req := uiRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func jsonString(value string) string {
	encoded, _ := jsonQuote(value)
	return encoded
}

func uiDeployCompose(t *testing.T, controller *Controller, id, agentID, compose string) *httptest.ResponseRecorder {
	t.Helper()
	preview := httptest.NewRecorder()
	controller.ServeHTTP(preview, uiJSONRequest(http.MethodPost, "/api/apps/preview", `{"id":`+jsonString(id)+`,"agent_id":`+jsonString(agentID)+`,"compose":`+jsonString(compose)+`}`))
	confirm := ""
	if preview.Code == http.StatusOK {
		var payload struct {
			Preview riskPreviewView `json:"preview"`
		}
		if err := json.Unmarshal(preview.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode preview: %v body=%s", err, preview.Body.String())
		}
		confirm = payload.Preview.Digest
	}
	body := `{"id":` + jsonString(id) + `,"agent_id":` + jsonString(agentID) + `,"compose":` + jsonString(compose)
	if confirm != "" {
		body += `,"confirm":` + jsonString(confirm)
	}
	body += `}`
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", body))
	return created
}

func jsonQuote(value string) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

type uiAppView struct {
	ID      string
	Status  string
	Notice  string
	Version string
	Actions []OpsAction
}

func decodeAppList(t *testing.T, payload []byte) []uiAppView {
	t.Helper()
	var decoded struct {
		Apps []uiAppView `json:"apps"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode apps: %v body=%s", err, payload)
	}
	return decoded.Apps
}

func hasAppAction(view uiAppView, id string) bool {
	for _, action := range view.Actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

func stringPtr(value string) *string {
	return &value
}

type recordedHTTPRuleDelete struct {
	AgentID     string
	RuleRef     string
	OperationID string
}

type recordingHTTPRuleCreate struct {
	specs           []HTTPRuleSpec
	rules           []HostHTTPRule
	deletes         []recordedHTTPRuleDelete
	err             error
	listErr         error
	deleteErr       error
	deleteDropsRule bool
}

func (handle *recordingHTTPRuleCreate) Create(_ context.Context, spec HTTPRuleSpec) (HostHTTPRule, error) {
	handle.specs = append(handle.specs, spec)
	if handle.err != nil {
		return HostHTTPRule{}, handle.err
	}
	rule := HostHTTPRule{
		Ref:     fmt.Sprintf("rule-%s-%d", spec.AppID, spec.Port),
		Domain:  spec.Domain,
		Port:    spec.Port,
		Backend: "http://127.0.0.1:" + strconv.Itoa(int(spec.Port)),
		AppID:   spec.AppID,
		AgentID: spec.AgentID,
		Enabled: true,
	}
	handle.rules = append(handle.rules, rule)
	return rule, nil
}

func (handle *recordingHTTPRuleCreate) List(_ context.Context, agentID string) ([]HostHTTPRule, error) {
	if handle.listErr != nil {
		return nil, handle.listErr
	}
	listed := make([]HostHTTPRule, 0, len(handle.rules))
	for _, rule := range handle.rules {
		if rule.AgentID == "" || rule.AgentID == agentID {
			listed = append(listed, rule)
		}
	}
	return listed, nil
}

func (handle *recordingHTTPRuleCreate) Delete(ctx context.Context, agentID, ruleRef string) error {
	handle.deletes = append(handle.deletes, recordedHTTPRuleDelete{
		AgentID: agentID, RuleRef: ruleRef, OperationID: hostOperationKeyFromContext(ctx),
	})
	if handle.deleteErr != nil && !handle.deleteDropsRule {
		return handle.deleteErr
	}
	kept := make([]HostHTTPRule, 0, len(handle.rules))
	for _, rule := range handle.rules {
		if rule.Ref != ruleRef {
			kept = append(kept, rule)
		}
	}
	handle.rules = kept
	return handle.deleteErr
}

type failingAppRemove struct {
	err error
}

func (executor failingAppRemove) RemoveApp(context.Context, App) error {
	return executor.err
}

type blockingAppRemove struct {
	started chan struct{}
	release chan struct{}
}

func (executor *blockingAppRemove) RemoveApp(ctx context.Context, _ App) error {
	select {
	case executor.started <- struct{}{}:
	default:
	}
	select {
	case <-executor.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type recordingHTTPBackendOffers struct {
	offers [][]HTTPBackendCatalogOffer
	err    error
}

func (handle *recordingHTTPBackendOffers) ReplaceHTTPBackendOffers(_ context.Context, offers []HTTPBackendCatalogOffer) error {
	copied := append([]HTTPBackendCatalogOffer(nil), offers...)
	handle.offers = append(handle.offers, copied)
	return handle.err
}

type uiTestRuntime struct {
	applied   map[string]App
	running   map[string]bool
	restarts  map[string]int
	logs      map[string]string
	filesRoot string
}

func newUITestRuntime() *uiTestRuntime {
	return &uiTestRuntime{
		applied:  map[string]App{},
		running:  map[string]bool{},
		restarts: map[string]int{},
		logs:     map[string]string{},
	}
}

func (runtime *uiTestRuntime) ApplyApp(_ context.Context, app App) error {
	runtime.applied[app.ID] = app
	runtime.running[app.ID] = true
	runtime.logs[app.ID+"/web"] = "listening on :80\n"
	if runtime.filesRoot != "" {
		if dir, err := AppWorkDir(runtime.filesRoot, app.ID); err == nil {
			_ = os.MkdirAll(dir, 0o755)
		}
	}
	return nil
}

func (runtime *uiTestRuntime) Files(_ context.Context, app App, payload map[string]any, result any) error {
	if runtime == nil || strings.TrimSpace(runtime.filesRoot) == "" {
		return ErrTypedHandlesUnavailable
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var request filesCallRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return errors.New("files payload is invalid")
	}
	request.AppID = app.ID
	encoded, err := executeWorkspaceFiles(runtime.filesRoot, request)
	if err != nil {
		return err
	}
	if result == nil || len(encoded) == 0 {
		return nil
	}
	return json.Unmarshal(encoded, result)
}

func (runtime *uiTestRuntime) Start(_ context.Context, app App) error {
	if _, ok := runtime.applied[app.ID]; !ok {
		return errors.New("app is not deployed")
	}
	runtime.running[app.ID] = true
	return nil
}

func (runtime *uiTestRuntime) Stop(_ context.Context, app App) error {
	if _, ok := runtime.applied[app.ID]; !ok {
		return errors.New("app is not deployed")
	}
	runtime.running[app.ID] = false
	return nil
}

func (runtime *uiTestRuntime) Restart(_ context.Context, app App) error {
	if _, ok := runtime.applied[app.ID]; !ok {
		return errors.New("app is not deployed")
	}
	runtime.running[app.ID] = true
	runtime.restarts[app.ID]++
	return nil
}

func (runtime *uiTestRuntime) ReadLogs(_ context.Context, app App, service string) (string, error) {
	return runtime.logs[app.ID+"/"+service], nil
}

func (runtime *uiTestRuntime) RemoveApp(_ context.Context, app App) error {
	delete(runtime.applied, app.ID)
	delete(runtime.running, app.ID)
	delete(runtime.logs, app.ID+"/web")
	return nil
}

type recordingDiskCleanup struct {
	mu       sync.Mutex
	preview  DiskCleanupReport
	apply    DiskCleanupReport
	previews []string
	applies  []bool
	err      error
}

func (handle *recordingDiskCleanup) PreviewDiskCleanup(_ context.Context, agentID string) (DiskCleanupReport, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.previews = append(handle.previews, agentID)
	if handle.err != nil {
		return DiskCleanupReport{}, handle.err
	}
	return handle.preview, nil
}

func (handle *recordingDiskCleanup) ApplyDiskCleanup(_ context.Context, agentID string, confirm bool) (DiskCleanupReport, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.applies = append(handle.applies, confirm)
	if handle.err != nil {
		return DiskCleanupReport{}, handle.err
	}
	if !confirm {
		return DiskCleanupReport{Accepted: true, Unchanged: true, Empty: true}, nil
	}
	return handle.apply, nil
}

type uiTestObserver struct {
	current, latest string
}

func (observer *uiTestObserver) ObserveImage(context.Context, App) (UpdateObservation, error) {
	return UpdateObservation{CurrentDigest: observer.current, LatestDigest: observer.latest}, nil
}

type uiTestRollout struct {
	calls []string
}

func (fake *uiTestRollout) Pull(context.Context, uint64, App) error {
	fake.calls = append(fake.calls, "pull")
	return nil
}
func (fake *uiTestRollout) Start(_ context.Context, _ uint64, _ App) (string, error) {
	fake.calls = append(fake.calls, "start")
	return "new", nil
}
func (fake *uiTestRollout) Ready(context.Context, uint64, App, string) error {
	fake.calls = append(fake.calls, "ready")
	return nil
}
func (fake *uiTestRollout) Cutover(_ context.Context, _ uint64, _ string, target string) error {
	fake.calls = append(fake.calls, "cutover:"+target)
	return nil
}
func (fake *uiTestRollout) Drain(_ context.Context, _ uint64, _ App, target string) error {
	fake.calls = append(fake.calls, "drain:"+target)
	return nil
}
func (fake *uiTestRollout) Remove(_ context.Context, _ uint64, _ App, target string) error {
	fake.calls = append(fake.calls, "remove:"+target)
	return nil
}
func (fake *uiTestRollout) Inspect(context.Context, uint64, App, string) (RuntimeState, error) {
	return RuntimeState{Instances: map[string]bool{"new": true}}, nil
}

type blockingUIRollout struct {
	uiTestRollout
	started chan struct{}
	release chan struct{}
}

func (fake *blockingUIRollout) Pull(ctx context.Context, _ uint64, _ App) error {
	select {
	case fake.started <- struct{}{}:
	default:
	}
	select {
	case <-fake.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type delayedDeploymentStore struct {
	base    DeploymentStateStore
	mu      sync.Mutex
	block   bool
	started chan struct{}
	release chan struct{}
}

func (store *delayedDeploymentStore) wait() {
	store.mu.Lock()
	block := store.block
	store.mu.Unlock()
	if !block {
		return
	}
	select {
	case store.started <- struct{}{}:
	default:
	}
	<-store.release
}

func (store *delayedDeploymentStore) Load(ctx context.Context, id string) (DeploymentRecord, bool, error) {
	return store.base.Load(ctx, id)
}

func (store *delayedDeploymentStore) AcquireLease(ctx context.Context, id string, version uint64, value Deployment, until time.Time) (DeploymentRecord, error) {
	store.wait()
	return store.base.AcquireLease(ctx, id, version, value, until)
}

func (store *delayedDeploymentStore) CompareAndSwap(ctx context.Context, id string, version, fence uint64, value Deployment) (DeploymentRecord, error) {
	store.wait()
	return store.base.CompareAndSwap(ctx, id, version, fence, value)
}

func (store *delayedDeploymentStore) DeleteCAS(ctx context.Context, id string, version, fence uint64) error {
	return store.base.DeleteCAS(ctx, id, version, fence)
}
