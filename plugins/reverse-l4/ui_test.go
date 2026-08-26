package reversel4

import (
	"context"
	"encoding/json"
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
	html := page.Body.String()
	if strings.Contains(html, `name="id"`) || strings.Contains(html, `input name="id"`) {
		t.Fatalf("create form still has a mapping id input: %s", html)
	}
	for _, want := range []string{
		`name="entry_agent_id"`,
		`name="exit_agent_id"`,
		`data-agent-picker="entry"`,
		`data-agent-picker="exit"`,
		`id="relay-hops"`,
		`id="relay-add"`,
		`class="route-guide"`,
		"公网入口",
		"出口侧内网服务",
		"127.0.0.1</code> 表示出口节点自身",
		"入口 → 第 1 跳",
		"从上到下就是实际转发顺序",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing %q: %s", want, html)
		}
	}
	if strings.Contains(html, `name="relay_chain"`) || strings.Contains(html, "逗号分隔") {
		t.Fatalf("create form still uses a free-text relay chain: %s", html)
	}
	script := serveManagement(controller, managementRequest(http.MethodGet, "/app.js", ""))
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "channel_state") {
		t.Fatalf("script status=%d", script.Code)
	}
	js := script.Body.String()
	for _, want := range []string{
		"/panel-api/agents",
		"/panel-api/relay-listeners",
		"搜索节点",
		"最近活跃",
		"mountAgentSearchSelect",
		"mountListenerSearchSelect",
		"搜索中继",
		"agentIdentity",
		"listenerIdentity",
		"流量路径",
		"技术标识",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("script missing catalog %q", want)
		}
	}
	if strings.Contains(html, `select name="entry_agent_id"`) || strings.Contains(html, `select name="exit_agent_id"`) {
		t.Fatal("create form still uses a native agent <select>")
	}
	if strings.Contains(js, `.split(",")`) {
		t.Fatal("script still parses relay hops from comma-separated text")
	}
	stylesheet := serveManagement(controller, managementRequest(http.MethodGet, "/style.css", ""))
	if stylesheet.Code != http.StatusOK || !strings.Contains(stylesheet.Body.String(), "chip-state-offline") {
		t.Fatalf("stylesheet status=%d", stylesheet.Code)
	}
	css := stylesheet.Body.String()
	for _, want := range []string{
		".route-guide",
		".form-stage",
		".map-route",
		".map-technical",
		"@media (max-width: 720px)",
		"grid-template-columns: 1fr",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"width: calc(100% - 2.5rem)",
		".agent-search-select",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("stylesheet missing viewport rule %q", want)
		}
	}
	if strings.Contains(css, "min(52rem") || strings.Contains(css, "min(64rem") || strings.Contains(css, "min(880px") {
		t.Fatal("stylesheet still caps main at 52rem, 64rem, or 880px")
	}
	assertConsoleSkin(t, html, js, css)
	toolbar := cssRule(css, ".toolbar-bar")
	if strings.Contains(toolbar, "space-between") {
		t.Fatal(".toolbar-bar still uses space-between to fill main")
	}
	if !strings.Contains(toolbar, "justify-content: flex-start") || !strings.Contains(toolbar, "max-width: min(46rem, 100%)") {
		t.Fatal(".toolbar-bar is not a capped operation group")
	}
	mappingForm := cssRule(css, "#mapping-form")
	if !strings.Contains(mappingForm, "max-width: min(46rem, 100%)") {
		t.Fatal("#mapping-form still fills main without a capped operation group")
	}
	for _, want := range []string{
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
		"repeat(2, minmax(0, 1fr))",
		"repeat(2, minmax(18rem, 1fr))",
		"repeat(3, minmax(18rem, 1fr))",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("stylesheet missing wide-viewport rule %q", want)
		}
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

func TestManagementMutationPropagatesRequestOperationKey(t *testing.T) {
	t.Parallel()
	controller, host := newManagementController(t)
	request := managementJSONRequest(http.MethodPost, "/api/mappings", `{"id":"tcp-map","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":8443,"backend_host":"127.0.0.1","backend_port":9443}`)
	request.Header.Set(mappingOperationHeader, "operation/ui/propagated")
	response := serveManagement(controller, request)
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}

	call := host.onlyCall(t, pluginsdk.HostRuntimeChannelReverse, pluginsdk.ChannelReverseActionEnsure)
	mapping := Mapping{
		ID: "tcp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolTCP, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443, Enabled: true,
	}
	expected := mutationOperationKey(withMutationOperationKey(t.Context(), "operation/ui/propagated"), "channel.ensure", mapping, 1)
	if call.OperationID != expected {
		t.Fatalf("create operation id = %q, want request-scoped %q", call.OperationID, expected)
	}
}

func TestManagementPageCreatesWithoutIDAndRejectsSameAgents(t *testing.T) {
	t.Parallel()
	controller, _ := newManagementController(t)

	created := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings", `{"name":"内网 Web","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":8443,"backend_host":"127.0.0.1","backend_port":9443}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create without id status=%d body=%s", created.Code, created.Body.String())
	}
	first := decodeManagement(t, created)
	if len(first.Mappings) != 1 || !validMappingID(first.Mappings[0].ID) {
		t.Fatalf("generated mapping = %#v", first.Mappings)
	}
	if first.Mappings[0].Name != "内网 Web" || len(first.Mappings[0].RelayChain) != 0 {
		t.Fatalf("created mapping = %#v", first.Mappings[0])
	}
	generatedID := first.Mappings[0].ID

	second := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings", `{"name":"第二","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":8444,"backend_host":"127.0.0.1","backend_port":9443}`))
	if second.Code != http.StatusOK {
		t.Fatalf("second create status=%d body=%s", second.Code, second.Body.String())
	}
	listed := decodeManagement(t, second)
	if len(listed.Mappings) != 2 {
		t.Fatalf("catalog after second create = %#v", listed.Mappings)
	}
	if listed.Mappings[0].ID == listed.Mappings[1].ID {
		t.Fatalf("generated mapping ids collided: %#v", listed.Mappings)
	}

	sameAgents := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings", `{"entry_agent_id":"entry-agent","exit_agent_id":"entry-agent","protocol":"tcp","listen_port":9000,"backend_host":"127.0.0.1","backend_port":9443}`))
	if sameAgents.Code != http.StatusBadRequest || !strings.Contains(sameAgents.Body.String(), ErrInvalidMapping.Error()) {
		t.Fatalf("same-agent create status=%d body=%s", sameAgents.Code, sameAgents.Body.String())
	}

	updated := serveManagement(controller, managementJSONRequest(http.MethodPost, "/api/mappings/"+generatedID+"/update", `{"id":"forged-id","name":"内网 Web","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":9443,"backend_host":"127.0.0.1","backend_port":8080,"relay_chain":[4,5]}`))
	if updated.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	afterUpdate := decodeManagement(t, updated)
	var found mappingView
	for _, mapping := range afterUpdate.Mappings {
		if mapping.ID == generatedID {
			found = mapping
		}
		if mapping.ID == "forged-id" {
			t.Fatalf("update changed mapping id: %#v", afterUpdate.Mappings)
		}
	}
	if found.ID != generatedID || found.ListenPort != 9443 || found.BackendPort != 8080 {
		t.Fatalf("updated mapping = %#v", found)
	}
	if len(found.RelayChain) != 2 || found.RelayChain[0] != 4 || found.RelayChain[1] != 5 {
		t.Fatalf("relay chain order = %v", found.RelayChain)
	}
}

func decodeManagement(t *testing.T, recorder *httptest.ResponseRecorder) mappingAPIResponse {
	t.Helper()
	var payload mappingAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode management response: %v body=%s", err, recorder.Body.String())
	}
	return payload
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
		return &pluginsdk.RuntimeError{
			Code:      pluginsdk.ErrorUnavailable,
			Message:   strings.Repeat("channel status is unavailable\n", 20),
			Retryable: true,
		}
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
	assertBoundedLastError(t, statuses[0].LastError)
	if !strings.HasPrefix(statuses[0].LastError, "host-error:") {
		t.Fatalf("poll-failure LastError = %q, want host-error prefix", statuses[0].LastError)
	}

	if _, err := service.Status(t.Context(), "tcp-map"); !errors.Is(err, ErrHostRuntimeUnavailable) {
		t.Fatalf("single status poll failure error = %v", err)
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
