package reversel4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestPluginYAMLDeclaresUIRouteAndNavMetadata(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"- ui.route",
		"ui_route_id: reverse-l4",
		"ui.nav.group: 网络",
		"ui.nav.label: 四层反向穿透",
		"- assets/ui/index.html",
		"- assets/ui/app.js",
		"- assets/ui/style.css",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin.yaml must declare %q: %s", want, text)
		}
	}
}

func newManagementController(t *testing.T) (*Controller, *fakeHostRuntime) {
	t.Helper()
	host := newFakeHostRuntime(t)
	runtime := bindHostRuntime(host)
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		State:       newDurableMappingState(runtime),
		Runtime:     runtime,
		BindRuntime: func() *hostRuntime { return runtime },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.prepare(t.Context(), nil, nil); err != nil {
		t.Fatal(err)
	}
	return controller, host
}

func managementRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set(mappingActorHeader, "panel/admin")
	request.Header.Set(mappingGroupHeader, DeclaredResourceGroupRef)
	request.Header.Set(mappingOperationHeader, "operation/ui-test")
	return request
}

func managementJSONRequest(method, path, body string) *http.Request {
	request := managementRequest(method, path, body)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func serveManagement(controller *Controller, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, request)
	return recorder
}

func TestManagementPageServesAssetsAndRequiresActorIdentity(t *testing.T) {
	t.Parallel()
	controller, _ := newManagementController(t)

	page := serveManagement(controller, managementRequest(http.MethodGet, "/", ""))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="map-workspace"`) || !strings.Contains(page.Body.String(), `id="create-toggle"`) {
		t.Fatalf("page status=%d body=%s", page.Code, page.Body.String())
	}
	script := serveManagement(controller, managementRequest(http.MethodGet, "/app.js", ""))
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "channel_state") {
		t.Fatalf("script status=%d", script.Code)
	}
	stylesheet := serveManagement(controller, managementRequest(http.MethodGet, "/style.css", ""))
	if stylesheet.Code != http.StatusOK || !strings.Contains(stylesheet.Body.String(), "chip-state-offline") {
		t.Fatalf("stylesheet status=%d", stylesheet.Code)
	}

	anonymous := serveManagement(controller, httptest.NewRequest(http.MethodGet, "/api/mappings", nil))
	if anonymous.Code != http.StatusForbidden || !strings.Contains(anonymous.Body.String(), ErrUnauthorized.Error()) {
		t.Fatalf("anonymous list status=%d body=%s", anonymous.Code, anonymous.Body.String())
	}
	anonymousWrite := serveManagement(controller, httptest.NewRequest(http.MethodPost, "/api/mappings/tcp-map/disable", nil))
	if anonymousWrite.Code != http.StatusForbidden {
		t.Fatalf("anonymous disable status=%d body=%s", anonymousWrite.Code, anonymousWrite.Body.String())
	}
}

func TestManagementPageCRUDWithChannelStateProjection(t *testing.T) {
	t.Parallel()
	controller, host := newManagementController(t)

	created := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings", `{"id":"tcp-map","name":"内网 Web","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":8443,"backend_host":"127.0.0.1","backend_port":9443}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	body := created.Body.String()
	for _, want := range []string{
		`"id":"tcp-map"`, `"entry_agent_id":"entry-agent"`, `"exit_agent_id":"exit-agent"`,
		`"protocol":"tcp"`, `"listen_port":8443`, `"enabled":true`, `"channel_state":"online"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("create response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "rule_ref") || strings.Contains(body, "session_ref") || strings.Contains(body, "bridge_host") {
		t.Fatalf("create response leaked host ownership references: %s", body)
	}

	fetched := serveManagement(controller, managementRequest(http.MethodGet, "/api/mappings/tcp-map", ""))
	if fetched.Code != http.StatusOK || !strings.Contains(fetched.Body.String(), `"channel_state":"online"`) {
		t.Fatalf("get status=%d body=%s", fetched.Code, fetched.Body.String())
	}

	invalid := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings", `{"id":"bad","unexpected":true}`))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field create status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	disabled := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/disable", `{}`))
	if disabled.Code != http.StatusOK || !strings.Contains(disabled.Body.String(), `"enabled":false`) || !strings.Contains(disabled.Body.String(), `"channel_state":"offline"`) {
		t.Fatalf("disable status=%d body=%s", disabled.Code, disabled.Body.String())
	}

	updated := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/update", `{"entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":9443,"backend_host":"127.0.0.1","backend_port":8080}`))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"listen_port":9443`) || !strings.Contains(updated.Body.String(), `"enabled":false`) {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}

	enabled := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/enable", `{}`))
	if enabled.Code != http.StatusOK || !strings.Contains(enabled.Body.String(), `"enabled":true`) || !strings.Contains(enabled.Body.String(), `"channel_state":"online"`) {
		t.Fatalf("enable status=%d body=%s", enabled.Code, enabled.Body.String())
	}

	// Dropping the host-side session must surface as a distinguishable
	// offline channel with the host-reported reason.
	session := host.session("channel/entry-agent/exit-agent")
	if session == nil {
		t.Fatal("enabled mapping has no host session")
	}
	host.dropChannel("channel/entry-agent/exit-agent")
	offline := serveManagement(controller, managementRequest(http.MethodGet, "/api/mappings", ""))
	if offline.Code != http.StatusOK || !strings.Contains(offline.Body.String(), `"channel_state":"offline"`) || !strings.Contains(offline.Body.String(), `"last_error"`) {
		t.Fatalf("offline projection status=%d body=%s", offline.Code, offline.Body.String())
	}

	unconfirmed := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/delete", `{}`))
	if unconfirmed.Code != http.StatusBadRequest || !strings.Contains(unconfirmed.Body.String(), ErrDeleteUnconfirmed.Error()) {
		t.Fatalf("unconfirmed delete status=%d body=%s", unconfirmed.Code, unconfirmed.Body.String())
	}

	deleted := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/delete", `{"confirm":"tcp-map"}`))
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"mappings":[]`) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}

	missing := serveManagement(controller, managementRequest(http.MethodGet, "/api/mappings/tcp-map", ""))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("deleted mapping get status=%d body=%s", missing.Code, missing.Body.String())
	}
}

func TestManagementPageRejectsMethodAndRouteMisuse(t *testing.T) {
	t.Parallel()
	controller, _ := newManagementController(t)

	put := serveManagement(controller, managementJSONRequest(http.MethodPut, "/api/mappings", `{}`))
	if put.Code != http.StatusMethodNotAllowed {
		t.Fatalf("put status=%d body=%s", put.Code, put.Body.String())
	}
	unknownAction := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/tcp-map/rotate", `{}`))
	if unknownAction.Code != http.StatusNotFound {
		t.Fatalf("unknown action status=%d body=%s", unknownAction.Code, unknownAction.Body.String())
	}
	unknownPath := serveManagement(controller, managementRequest(http.MethodGet, "/api/other", ""))
	if unknownPath.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d body=%s", unknownPath.Code, unknownPath.Body.String())
	}
}

func TestManagementPageServesAssetsBeforePrepareAndReportsUnavailableAPI(t *testing.T) {
	t.Parallel()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}

	page := serveManagement(controller, managementRequest(http.MethodGet, "/", ""))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="map-workspace"`) {
		t.Fatalf("asset page before prepare status=%d body=%s", page.Code, page.Body.String())
	}
	unavailable := serveManagement(controller, managementRequest(http.MethodGet, "/api/mappings", ""))
	if unavailable.Code != http.StatusServiceUnavailable || !strings.Contains(unavailable.Body.String(), ErrStateUnavailable.Error()) {
		t.Fatalf("api before prepare status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}

// failingStatusHost simulates a host whose channel status polls fail while the
// mutating channel and rule operations keep working.
type failingStatusHost struct {
	*fakeHostRuntime
}

func (host *failingStatusHost) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, result any) error {
	if call.Operation == pluginsdk.HostRuntimeChannelReverse && strings.Contains(string(call.Payload), `"status"`) {
		return &pluginsdk.RuntimeError{Code: pluginsdk.ErrorUnavailable, Message: "channel status is unavailable", Retryable: true}
	}
	return host.fakeHostRuntime.Call(ctx, call, result)
}

func TestStatusesDegradesPollFailureToUnknown(t *testing.T) {
	t.Parallel()
	host := &failingStatusHost{fakeHostRuntime: newFakeHostRuntime(t)}
	runtime := bindHostRuntime(host)
	service, err := NewService(newDurableMappingState(runtime), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(t.Context(), orchestrationMapping("tcp-map", ProtocolTCP)); err != nil {
		t.Fatal(err)
	}

	statuses, err := service.Statuses(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].ChannelState != ChannelUnknown || !statuses[0].Enabled {
		t.Fatalf("degraded statuses = %#v err=%v", statuses, err)
	}

	if _, err := service.Status(t.Context(), "tcp-map"); !errors.Is(err, ErrHostRuntimeUnavailable) {
		t.Fatalf("single status poll failure error = %v", err)
	}
}
