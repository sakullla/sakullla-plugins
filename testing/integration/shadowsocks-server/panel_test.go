package shadowsocksserver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

func panelConfig() ss.Configuration {
	return ss.Configuration{Generation: "generation-1"}
}

func panelWire(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(panelConfig())
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func startPanelController(t *testing.T) (*ss.Controller, http.Handler) {
	t.Helper()
	controller, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: ss.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, ss.Configuration) (ss.PreparedAdmission, error) {
		return ss.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (ss.RuntimeAdapters, error) {
			return ss.RuntimeAdapters{}, nil
		}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	controller.BindLoopbackListenHost()
	t.Cleanup(func() {
		_ = controller.StopListen(context.Background(), "agent-1", nil)
	})
	if _, err = controller.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: panelWire(t)}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	return controller, controller
}

func panelMutateBody(extra string) string {
	body := `{"agent_id":"agent-1","ddns_domain":"ss.example.com","ipv4":"203.0.113.10"`
	if extra != "" {
		body += "," + extra
	}
	return body + "}"
}

func panelJSON(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/ui-test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodePanel(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json=%s err=%v", recorder.Body.String(), err)
	}
	return payload
}

func panelListens(t *testing.T, payload map[string]any) []map[string]any {
	t.Helper()
	raw, _ := payload["listens"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		listen, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("listen=%#v", item)
		}
		out = append(out, listen)
	}
	return out
}

func panelUsers(t *testing.T, listen map[string]any) []map[string]any {
	t.Helper()
	raw, _ := listen["users"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		user, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("user=%#v", item)
		}
		out = append(out, user)
	}
	return out
}

func TestShadowsocksAdminPanelCreatesListsAndSharesWithoutL4(t *testing.T) {
	_, handler := startPanelController(t)

	page := panelJSON(t, handler, http.MethodGet, "/", "")
	if page.Code != http.StatusOK {
		t.Fatalf("page=%d", page.Code)
	}
	html := page.Body.String()
	script := panelJSON(t, handler, http.MethodGet, "/app.js", "").Body.String()
	for _, fragment := range []string{"选择节点", "新增监听", "data-agent-picker", "/panel-api/agents"} {
		if !strings.Contains(html, fragment) && !strings.Contains(script, fragment) {
			t.Fatalf("page missing %q", fragment)
		}
	}
	if strings.Contains(html, "http.backend-provider") || strings.Contains(html, "plugin=") || strings.Contains(html, "订阅") || strings.Contains(html, "ss2022://") {
		t.Fatal("page must not present L4/HTTP provider, subscription, SIP003, or ss2022://")
	}

	unselected := panelJSON(t, handler, http.MethodPost, "/api/listens", `{}`)
	if unselected.Code != http.StatusConflict {
		t.Fatalf("unselected create=%d %s", unselected.Code, unselected.Body.String())
	}

	created := panelJSON(t, handler, http.MethodPost, "/api/listens", panelMutateBody(""))
	if created.Code != http.StatusOK {
		t.Fatalf("default create=%d %s", created.Code, created.Body.String())
	}
	createdPayload := decodePanel(t, created)
	listen, _ := createdPayload["listen"].(map[string]any)
	if listen["method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("default method=%#v", listen)
	}
	users := panelUsers(t, listen)
	if len(users) != 1 || users[0]["share_available"] != true {
		t.Fatalf("default users=%#v", users)
	}
	uri, _ := users[0]["uri"].(string)
	qr, _ := users[0]["qr_content"].(string)
	if uri == "" || qr != uri || !strings.HasPrefix(uri, "ss://") || strings.Contains(uri, "plugin=") || strings.Contains(uri, "ss2022://") {
		t.Fatalf("share=%#v", users[0])
	}
	userinfo, host, port := sip002UserinfoAndHostPort(t, uri)
	if host != "ss.example.com" {
		t.Fatalf("uri=%q", uri)
	}
	decoded := decodeStrictSIP002Userinfo(t, userinfo)
	if !strings.HasPrefix(decoded, "2022-blake3-aes-128-gcm:") || strings.Count(decoded, ":") != 2 {
		t.Fatalf("ss2022 decoded=%q uri=%q", decoded, uri)
	}
	pngB64, _ := users[0]["qr_png_base64"].(string)
	pngBytes, err := base64.StdEncoding.DecodeString(pngB64)
	if err != nil || len(pngBytes) == 0 {
		t.Fatalf("qr png=%v", err)
	}
	if _, err = png.Decode(bytes.NewReader(pngBytes)); err != nil {
		t.Fatalf("qr decode=%v", err)
	}

	listenID, _ := listen["id"].(string)
	dup := panelJSON(t, handler, http.MethodPost, "/api/listens", panelMutateBody(`"port":`+strconv.Itoa(port)))
	if dup.Code != http.StatusConflict || !strings.Contains(dup.Body.String(), "该节点已使用此端口") {
		t.Fatalf("duplicate port=%d %s", dup.Code, dup.Body.String())
	}

	appended := panelJSON(t, handler, http.MethodPost, "/api/listens/"+listenID+"/users", panelMutateBody(""))
	if appended.Code != http.StatusOK {
		t.Fatalf("append=%d %s", appended.Code, appended.Body.String())
	}
	two := panelUsers(t, decodePanel(t, appended)["listen"].(map[string]any))
	if len(two) != 2 {
		t.Fatalf("append users=%#v", two)
	}
	firstID, _ := users[0]["id"].(string)
	var peer map[string]any
	for _, user := range two {
		if user["id"] != firstID {
			peer = user
		}
	}
	if peer["share_available"] != true {
		t.Fatalf("peer=%#v", peer)
	}

	disabled := panelJSON(t, handler, http.MethodPost, "/api/users/"+firstID+"/disable", panelMutateBody(""))
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", disabled.Code, disabled.Body.String())
	}
	afterDisable := panelListens(t, decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/listens?agent_id=agent-1", "")))
	if len(afterDisable) != 1 {
		t.Fatalf("after disable listens=%#v", afterDisable)
	}
	var disabledView, enabledView map[string]any
	for _, user := range panelUsers(t, afterDisable[0]) {
		if user["id"] == firstID {
			disabledView = user
			continue
		}
		enabledView = user
	}
	if disabledView["enabled"] != false || disabledView["share_available"] == true || disabledView["uri"] != nil {
		t.Fatalf("disabled=%#v", disabledView)
	}
	if enabledView["enabled"] != true || enabledView["share_available"] != true {
		t.Fatalf("enabled=%#v", enabledView)
	}

	legacy := panelJSON(t, handler, http.MethodPost, "/api/listens", panelMutateBody(`"method":"aes-256-gcm"`))
	if legacy.Code != http.StatusOK {
		t.Fatalf("legacy create=%d %s", legacy.Code, legacy.Body.String())
	}
	legacyListen, _ := decodePanel(t, legacy)["listen"].(map[string]any)
	legacyID, _ := legacyListen["id"].(string)
	secondLegacy := panelJSON(t, handler, http.MethodPost, "/api/listens/"+legacyID+"/users", panelMutateBody(""))
	if secondLegacy.Code != http.StatusBadRequest || !strings.Contains(secondLegacy.Body.String(), "传统方法不能在同一端口追加用户") {
		t.Fatalf("traditional second user=%d %s", secondLegacy.Code, secondLegacy.Body.String())
	}

	deleted := panelJSON(t, handler, http.MethodPost, "/api/listens/"+listenID+"/delete", panelMutateBody(""))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete listen=%d %s", deleted.Code, deleted.Body.String())
	}
}

func TestShadowsocksAdminPanelKeepsAccountWhenShareHostMissing(t *testing.T) {
	_, handler := startPanelController(t)
	created := panelJSON(t, handler, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	listed := decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	listens := panelListens(t, listed)
	if len(listens) != 1 {
		t.Fatalf("listens=%#v", listens)
	}
	users := panelUsers(t, listens[0])
	if len(users) != 1 || users[0]["enabled"] != true || users[0]["share_available"] == true || users[0]["uri"] != nil {
		t.Fatalf("users=%#v", users)
	}
	if users[0]["reason"] != "缺少对外地址" {
		t.Fatalf("reason=%#v", users[0])
	}
}

func TestShadowsocksAdminPanelUnavailableUntilActivated(t *testing.T) {
	controller, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	page := panelJSON(t, controller, http.MethodGet, "/", "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Shadowsocks 服务") {
		t.Fatalf("page should still render: %d", page.Code)
	}
	api := panelJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", "")
	if api.Code != http.StatusServiceUnavailable || !strings.Contains(api.Body.String(), "服务未就绪") {
		t.Fatalf("inactive=%d %s", api.Code, api.Body.String())
	}
}

func TestShadowsocksPluginYAMLDeclaresUIRouteNotConfigSchema(t *testing.T) {
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("unable to locate panel test")
	}
	manifestPath := filepath.Join(filepath.Dir(file), "..", "..", "..", "plugins", "shadowsocks-server", "plugin.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: shadowsocks-server") {
		t.Fatalf("plugin.yaml must declare ui.route: %s", text)
	}
	if !strings.Contains(text, "ui.nav.group: 网络") || !strings.Contains(text, "ui.nav.label: Shadowsocks 账号") {
		t.Fatalf("plugin.yaml must declare host nav metadata: %s", text)
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: shadowsocks-server") {
		t.Fatalf("plugin.yaml must declare resource.group support: %s", text)
	}
	if !strings.Contains(text, "host_scope: control-plane") {
		t.Fatalf("plugin.yaml must declare control-plane host_scope: %s", text)
	}
	if !strings.Contains(text, "host_scopes:") || (!strings.Contains(text, "- agent") && !strings.Contains(text, "[agent]")) {
		t.Fatalf("plugin.yaml must declare host_scopes including agent: %s", text)
	}
	if regexp.MustCompile(`(?m)^[[:space:]]*host_scope:[[:space:]]*agent[[:space:]]*$`).MatchString(text) {
		t.Fatal("shadowsocks-server primary host_scope must not be agent")
	}
	if strings.Contains(text, "tunnel.provider") {
		t.Fatal("shadowsocks-server must not declare tunnel.provider")
	}
	if strings.Contains(text, "http.backend-provider") || strings.Contains(text, "http_backend_providers") {
		t.Fatal("admin panel must not register an HTTP backend provider")
	}
	if !strings.Contains(text, "assets/ui/index.html") || !strings.Contains(text, "assets/ui/app.js") || !strings.Contains(text, "assets/ui/style.css") {
		t.Fatal("plugin.yaml must declare frontend files below assets/")
	}
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("admin panel must not declare host config ui_schema")
	}
	for _, want := range []string{
		"resource.group.ref: resource-group/shadowsocks-server",
		"resource.group.label: Shadowsocks 服务",
		"resource.group.description: 在组内按节点管理 Shadowsocks 监听与账号",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin.yaml must declare %q: %s", want, text)
		}
	}
}
