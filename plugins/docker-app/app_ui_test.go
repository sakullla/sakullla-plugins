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
	if strings.Contains(text, "resource.group") || strings.Contains(text, "resource_group_id:") {
		t.Fatal("docker-app UI must not use a resource-group catalog")
	}
	if !strings.Contains(text, "assets/ui/index.html") || !strings.Contains(text, "assets/ui/app.js") {
		t.Fatal("plugin.yaml must declare frontend files below assets/")
	}
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("compose UI must not use host config ui_schema")
	}
}

func TestAppUIAuthorizedDeployListsAndRequiresDeleteConfirm(t *testing.T) {
	t.Parallel()
	controller := newUIController(t)
	compose := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n"
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/apps", `{"id":"media","compose":`+jsonString(compose)+`}`))
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"id":"media"`) {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if !strings.Contains(created.Body.String(), `"8080"`) && !strings.Contains(created.Body.String(), "8080") {
		t.Fatalf("create omitted published port: %s", created.Body.String())
	}

	page := httptest.NewRecorder()
	controller.ServeHTTP(page, uiRequest(http.MethodGet, "/", ""))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="app-workspace"`) || !strings.Contains(page.Body.String(), `id="deploy-toggle"`) || strings.Contains(page.Body.String(), "{{") {
		t.Fatalf("page status=%d body=%s", page.Code, page.Body.String())
	}

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/apps", ""))
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
}

func newUIController(t *testing.T) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{}, nil
		}),
		UIEngine: EngineObservation{Installed: true, Version: "test"},
		UIApply:  AppApplyExecutorFunc(func(context.Context, App) error { return nil }),
		UIRemove: AppRemoveExecutorFunc(func(context.Context, string) error { return nil }),
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
		Generation: "generation-1", Config: []byte(`{"apps":[]}`),
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
