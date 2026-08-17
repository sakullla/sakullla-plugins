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
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
	"github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server/web"
)

type panelRuntime struct {
	mu        sync.Mutex
	now       uint64
	refs      map[string]string
	rotations int
	node      ss.NodeAddresses
	listen    ss.ListenBinding
}

type panelReservation struct{}

func (panelReservation) Consume(context.Context, uint64) error { return nil }
func (panelReservation) Finish(context.Context) error          { return nil }
func (panelReservation) Abort(context.Context) error           { return nil }

func (r *panelRuntime) Verify(_ context.Context, ref, _ string, material []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refs[ref] != string(material) {
		return ss.ErrDenied
	}
	return nil
}

func (r *panelRuntime) Resolve(_ context.Context, ref, _ string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	material, ok := r.refs[ref]
	if !ok {
		return nil, ss.ErrDenied
	}
	return []byte(material), nil
}

func (*panelRuntime) Reserve(context.Context, string, uint64, string) (ss.TrafficReservation, error) {
	return panelReservation{}, nil
}

func (r *panelRuntime) Now(context.Context) (uint64, error) {
	if r.now != 0 {
		return r.now, nil
	}
	return 10, nil
}

func (*panelRuntime) Admit(context.Context, string, []byte) error { return nil }
func (*panelRuntime) Register(context.Context, string, *ss.Service) error {
	return nil
}
func (r *panelRuntime) ListenBinding(context.Context, string) (ss.ListenBinding, error) {
	return r.listen, nil
}
func (r *panelRuntime) NodeAddresses(context.Context) (ss.NodeAddresses, error) {
	return r.node, nil
}

func (r *panelRuntime) Rotate(_ context.Context, id, _, _, _ string) (*ss.SecretOnce, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotations++
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(r.rotations) ^ byte(i*17+3)
	}
	material := []byte(base64.StdEncoding.EncodeToString(raw))
	ref := "secret/account/" + id + "/" + strconv.Itoa(r.rotations)
	version := "v" + strconv.Itoa(r.rotations)
	if r.refs == nil {
		r.refs = map[string]string{}
	}
	r.refs[ref] = string(material)
	return ss.NewSecretOnce(ref, version, material), nil
}

func (*panelRuntime) Audit(context.Context, ss.AuditRecord) error { return nil }

func (r *panelRuntime) adapters() ss.RuntimeAdapters {
	return ss.RuntimeAdapters{Secrets: r, Traffic: r, Clock: r, Replay: r, Listener: r, Vault: r, Auditor: r}
}

func panelConfig() ss.Configuration {
	return ss.Configuration{Generation: "generation-1", ListenerRef: "listener/1", Cipher: "aes-256-gcm", MaxSessions: 16}
}

func panelWire(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(panelConfig())
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func startPanelController(t *testing.T, node ss.NodeAddresses, port int) (*ss.Controller, *web.Handler) {
	t.Helper()
	listen, err := ss.DualStackListen(port, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &panelRuntime{now: 10, refs: map[string]string{}, node: node, listen: listen}
	controller, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: ss.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, ss.Configuration) (ss.PreparedAdmission, error) {
		return ss.PreparedAdmissionFuncs{CommitFunc: func(context.Context) (ss.RuntimeAdapters, error) { return runtime.adapters(), nil }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Handshake(context.Background(), handshake(grants())); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: panelWire(t)}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	return controller, web.NewHandler(controller)
}

func panelJSON(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
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

func panelAccounts(t *testing.T, payload map[string]any) []map[string]any {
	t.Helper()
	raw, _ := payload["accounts"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		account, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("account=%#v", item)
		}
		out = append(out, account)
	}
	return out
}

func TestShadowsocksAdminPanelCreatesListsAndSharesWithoutL4(t *testing.T) {
	_, handler := startPanelController(t, ss.NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.10"}, 8388)

	page := panelJSON(t, handler, http.MethodGet, "/", "")
	if page.Code != http.StatusOK {
		t.Fatalf("page=%d", page.Code)
	}
	html := page.Body.String()
	for _, fragment := range []string{"生成传统 SS 账号", "生成 SS2022 账号", "不必先建 L4", "无需打开 L4", "SIP002", "二维码", "对外监听"} {
		if !strings.Contains(html, fragment) {
			t.Fatalf("page missing %q", fragment)
		}
	}
	if strings.Contains(html, "http.backend-provider") || strings.Contains(html, "plugin=") {
		t.Fatal("page must not present L4/HTTP provider or SIP003 as the main path")
	}

	legacy := panelJSON(t, handler, http.MethodPost, "/api/accounts", `{"family":"ss"}`)
	if legacy.Code != http.StatusOK {
		t.Fatalf("create ss=%d %s", legacy.Code, legacy.Body.String())
	}
	modern := panelJSON(t, handler, http.MethodPost, "/api/accounts", `{"family":"ss2022"}`)
	if modern.Code != http.StatusOK {
		t.Fatalf("create ss2022=%d %s", modern.Code, modern.Body.String())
	}

	listed := decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/panel", ""))
	if listed["ready"] != true {
		t.Fatalf("panel=%#v", listed)
	}
	listen, _ := listed["listen"].(map[string]any)
	if listen["available"] != true || listen["host"] != "ss.example.com" || listen["host_port"] != "ss.example.com:8388" || listen["tcp"] != true || listen["udp"] != true {
		t.Fatalf("listen=%#v", listen)
	}
	accounts := panelAccounts(t, listed)
	if len(accounts) != 2 {
		t.Fatalf("accounts=%#v", accounts)
	}
	seen := map[string]map[string]any{}
	for _, account := range accounts {
		family, _ := account["family"].(string)
		seen[family] = account
		if account["enabled"] != true || account["share_available"] != true {
			t.Fatalf("account=%#v", account)
		}
		uri, _ := account["uri"].(string)
		qr, _ := account["qr_content"].(string)
		if uri == "" || qr != uri || !strings.HasPrefix(uri, "ss://") || strings.Contains(uri, "plugin=") {
			t.Fatalf("share=%#v", account)
		}
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Hostname() != "ss.example.com" || parsed.Port() != "8388" {
			t.Fatalf("uri=%q err=%v", uri, err)
		}
		pngB64, _ := account["qr_png_base64"].(string)
		pngBytes, err := base64.StdEncoding.DecodeString(pngB64)
		if err != nil || len(pngBytes) == 0 {
			t.Fatalf("qr png=%v", err)
		}
		if _, err = png.Decode(bytes.NewReader(pngBytes)); err != nil {
			t.Fatalf("qr decode=%v", err)
		}
	}
	if seen["ss"] == nil || seen["ss2022"] == nil {
		t.Fatalf("families=%#v", seen)
	}
	if !strings.Contains(seen["ss2022"]["uri"].(string), "%") {
		t.Fatalf("ss2022 uri should percent-encode method/password: %q", seen["ss2022"]["uri"])
	}

	disabledID, _ := seen["ss"]["id"].(string)
	disabled := panelJSON(t, handler, http.MethodPost, "/api/accounts/"+disabledID+"/disable", "{}")
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", disabled.Code, disabled.Body.String())
	}
	afterDisable := panelAccounts(t, decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/panel", "")))
	var disabledView, enabledView map[string]any
	for _, account := range afterDisable {
		if account["id"] == disabledID {
			disabledView = account
			continue
		}
		enabledView = account
	}
	if disabledView["enabled"] != false || disabledView["share_available"] == true || disabledView["uri"] != nil {
		t.Fatalf("disabled=%#v", disabledView)
	}
	if enabledView["enabled"] != true || enabledView["share_available"] != true {
		t.Fatalf("enabled=%#v", enabledView)
	}

	enabled := panelJSON(t, handler, http.MethodPost, "/api/accounts/"+disabledID+"/enable", "{}")
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable=%d %s", enabled.Code, enabled.Body.String())
	}
	afterEnable := panelAccounts(t, decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/panel", "")))
	for _, account := range afterEnable {
		if account["id"] == disabledID && (account["enabled"] != true || account["share_available"] != true) {
			t.Fatalf("reenabled=%#v", account)
		}
	}

	oldURI, _ := seen["ss2022"]["uri"].(string)
	modernID, _ := seen["ss2022"]["id"].(string)
	rotated := panelJSON(t, handler, http.MethodPost, "/api/accounts/"+modernID+"/rotate", "{}")
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate=%d %s", rotated.Code, rotated.Body.String())
	}
	rotatedView := panelAccounts(t, decodePanel(t, rotated))
	if len(rotatedView) != 1 || rotatedView[0]["uri"] == oldURI || rotatedView[0]["share_available"] != true {
		t.Fatalf("rotated=%#v", rotatedView)
	}

	qr := panelJSON(t, handler, http.MethodGet, "/api/accounts/"+modernID+"/qr.png", "")
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() == 0 {
		t.Fatalf("qr image=%d %s", qr.Code, qr.Header().Get("Content-Type"))
	}
}

func TestShadowsocksAdminPanelKeepsAccountWhenShareHostMissing(t *testing.T) {
	_, handler := startPanelController(t, ss.NodeAddresses{}, 8488)
	created := panelJSON(t, handler, http.MethodPost, "/api/accounts", `{"family":"ss"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	listed := decodePanel(t, panelJSON(t, handler, http.MethodGet, "/api/panel", ""))
	listen, _ := listed["listen"].(map[string]any)
	if listen["available"] != false || listen["reason"] != "缺少对外地址" {
		t.Fatalf("listen=%#v", listen)
	}
	accounts := panelAccounts(t, listed)
	if len(accounts) != 1 || accounts[0]["enabled"] != true || accounts[0]["share_available"] == true || accounts[0]["uri"] != nil {
		t.Fatalf("accounts=%#v", accounts)
	}
	if accounts[0]["reason"] != "缺少对外地址" {
		t.Fatalf("reason=%#v", accounts[0])
	}
}

func TestShadowsocksAdminPanelUnavailableUntilActivated(t *testing.T) {
	controller, err := ss.NewController(ss.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	handler := web.NewHandler(controller)
	page := panelJSON(t, handler, http.MethodGet, "/", "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Shadowsocks 账号") {
		t.Fatalf("page should still render: %d", page.Code)
	}
	api := panelJSON(t, handler, http.MethodGet, "/api/panel", "")
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
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("admin panel must not declare host config ui_schema")
	}
	if strings.Contains(text, "http.backend-provider") {
		t.Fatal("admin panel must not register an HTTP backend provider")
	}
}
