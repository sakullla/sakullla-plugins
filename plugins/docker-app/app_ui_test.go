package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

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
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"id":"media"`) {
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
	if len(controller.Apps()) != 1 || len(controller.HostHTTPRules()) != 0 {
		t.Fatalf("empty domain mutated apps=%#v rules=%#v", controller.Apps(), controller.HostHTTPRules())
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

func TestAppUICreatesHTTPRuleFromPublishedPortAndDomain(t *testing.T) {
	t.Parallel()
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
	if len(handle.specs) != 1 || handle.specs[0].AppID != "media" || handle.specs[0].AgentID != "agent-1" || handle.specs[0].Domain != "app.example.com" || handle.specs[0].Port != 8080 {
		t.Fatalf("host create spec=%#v", handle.specs)
	}
	rules := controller.HostHTTPRules()
	if len(rules) != 1 || rules[0].Domain != "app.example.com" || rules[0].Port != 8080 || rules[0].AgentID != "agent-1" || rules[0].AppID != "media" {
		t.Fatalf("host rules=%#v", rules)
	}
	if rules[0].Backend != "agent-1:8080" {
		t.Fatalf("backend does not point at Agent port: %#v", rules[0])
	}
	if !strings.Contains(rule.Body.String(), `"domain":"app.example.com"`) || !strings.Contains(rule.Body.String(), `"backend":"agent-1:8080"`) {
		t.Fatalf("http-rule response omitted host rule: %s", rule.Body.String())
	}
	if len(controller.Apps()) != 1 || controller.Apps()[0].ID != "media" || controller.Apps()[0].Image != "nginx:1.27" {
		t.Fatalf("http-rule mutated apps=%#v", controller.Apps())
	}
	if controller.Apps()[0].RuleRef != "" {
		t.Fatalf("http-rule bound App.RuleRef=%q", controller.Apps()[0].RuleRef)
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
	if created.Code != http.StatusOK || len(controller.HostHTTPRules()) != 1 {
		t.Fatalf("seed rule status=%d rules=%#v body=%s", created.Code, controller.HostHTTPRules(), created.Body.String())
	}
	existing := controller.HostHTTPRules()
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
	if len(controller.HostHTTPRules()) != 1 || controller.HostHTTPRules()[0] != existing[0] {
		t.Fatalf("denied creates changed rules: %#v", controller.HostHTTPRules())
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
		"挂 HTTP",
		"入口域名",
		"无发布端口",
		"没有可挂的端口",
		"/http-rule",
		`name = "domain"`,
		`name = "port"`,
	} {
		if !strings.Contains(script, token) {
			t.Fatalf("app.js missing %q", token)
		}
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
	controller := newUIController(t)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:1.27\n"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	listed := decodeAppList(t, created.Body.Bytes())
	if len(listed) != 1 || listed[0].Status != OpsStatusRunning || !hasAppAction(listed[0], OpsActionStop) || !hasAppAction(listed[0], OpsActionRestart) {
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
	record, ok := controller.uiRollout.Store.(*DeploymentStore).Get("media")
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
	if hasAppAction(published[0], OpsActionRollback) {
		t.Fatalf("confirmed update offered rollback: %#v", published)
	}
	got, _ := controller.uiRollout.Store.(*DeploymentStore).Get("media")
	if got.ImageDigest != latest {
		t.Fatalf("confirm digest=%#v", got)
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
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","agent_id":"agent-1","compose":"services:\n  web:\n    image: nginx:latest\n","auto_update":true}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if createdApps := decodeAppList(t, created.Body.Bytes()); len(createdApps) != 1 || createdApps[0].Notice != OpsStatusUpdateAvailable || createdApps[0].Status != OpsStatusRunning {
		t.Fatalf("auto_update hid 有新版本: %#v", createdApps)
	}
	record, ok := controller.uiRollout.Store.(*DeploymentStore).Get("media")
	if !ok || record.ImageDigest != current || record.AvailableDigest != latest {
		t.Fatalf("auto_update published without confirm: %#v ok=%v", record, ok)
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
	if !hasOpsAction(running.Actions, OpsActionUpdate) || !hasOpsAction(running.Actions, OpsActionStop) || !hasOpsAction(running.Actions, OpsActionRestart) {
		t.Fatalf("running update dropped ops: %#v", running.Actions)
	}
	if hasOpsAction(running.Actions, OpsActionRollback) || hasOpsAction(running.Actions, OpsActionDelete) {
		t.Fatalf("running update offered rollback or delete: %#v", running.Actions)
	}

	stopped := projectAppView(app, false, deployment, "sha256:latest")
	if stopped.Status != OpsStatusStopped || stopped.Notice != OpsStatusUpdateAvailable {
		t.Fatalf("stopped update view=%#v", stopped)
	}
	if !hasOpsAction(stopped.Actions, OpsActionStart) || !hasOpsAction(stopped.Actions, OpsActionDelete) || !hasOpsAction(stopped.Actions, OpsActionUpdate) {
		t.Fatalf("stopped update dropped start/delete/update: %#v", stopped.Actions)
	}
	if hasOpsAction(stopped.Actions, OpsActionRollback) {
		t.Fatalf("stopped update offered rollback: %#v", stopped.Actions)
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
	if !strings.Contains(string(html), "本地管理面") || !strings.Contains(string(html), "Agent 执行面") {
		t.Fatalf("dedicated UI omits runtime face labels: %s", html)
	}
	for _, marker := range []string{"Agent 执行面 · 节点离线", "Agent 执行面 · 引擎未就绪", "Agent 执行面 · ${app.status}", "Agent 执行面 · 有新版本"} {
		if !strings.Contains(string(script), marker) {
			t.Fatalf("dedicated UI script omits face-specific state %q", marker)
		}
	}
	if strings.Contains(string(script), "/panel-api/plugins/docker-app/configure") {
		t.Fatal("dedicated UI must not configure a second plugin instance")
	}
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
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		}),
		UIEngineSource:    source,
		UIApply:           runtime,
		UIStart:           runtime,
		UIStop:            runtime,
		UIRestart:         runtime,
		UILogs:            runtime,
		UIRemove:          runtime,
		UIHTTPRule:        opts.httpRule,
		UIWorkDirRoot:     workDirRoot,
		UIImageObserver:   opts.observer,
		UIRolloutExecutor: opts.rollout,
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

type recordingHTTPRuleCreate struct {
	specs []HTTPRuleSpec
}

func (handle *recordingHTTPRuleCreate) Create(_ context.Context, spec HTTPRuleSpec) (HostHTTPRule, error) {
	handle.specs = append(handle.specs, spec)
	return HostHTTPRule{
		Ref:     fmt.Sprintf("rule-%s-%d", spec.AppID, spec.Port),
		Domain:  spec.Domain,
		Port:    spec.Port,
		Backend: spec.AgentID + ":" + strconv.Itoa(int(spec.Port)),
		AppID:   spec.AppID,
		AgentID: spec.AgentID,
	}, nil
}

type uiTestRuntime struct {
	applied  map[string]App
	running  map[string]bool
	restarts map[string]int
	logs     map[string]string
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
	return nil
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
