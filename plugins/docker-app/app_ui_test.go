package dockerapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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
	if strings.Contains(text, "host_scope: agent") || strings.Contains(text, "http.backend-provider") || strings.Contains(text, "http_backend_providers") {
		t.Fatal("docker-app must not use agent host_scope or install-time HTTP backend publish")
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

	deleted := httptest.NewRecorder()
	controller.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/apps/media/delete", `{"confirm":"media"}`))
	if deleted.Code != http.StatusOK || strings.Contains(deleted.Body.String(), `"id":"media"`) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("delete left apps: %#v", controller.Apps())
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
}

func TestProductionRuntimeWiresReportedEngineSource(t *testing.T) {
	t.Parallel()
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
	catalog := NewReportedEngineCatalog()
	catalog.Replace(AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "test"})
	return newUIControllerWithSource(t, catalog, `{"apps":[]}`)
}

func newUIControllerWithSource(t *testing.T, source AgentEngineSource, config string) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		}),
		UIEngineSource: source,
		UIApply:        AppApplyExecutorFunc(func(context.Context, App) error { return nil }),
		UIRemove:       AppRemoveExecutorFunc(func(context.Context, string) error { return nil }),
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
