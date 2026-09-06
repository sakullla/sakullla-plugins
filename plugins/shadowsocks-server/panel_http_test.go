package shadowsocksserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerServesPanelAssetsFromManifestTree(t *testing.T) {
	var _ http.Handler = (*Controller)(nil)
	controller := &Controller{}
	bodies := map[string]string{}
	for _, route := range []string{"/", "/app.js", "/style.css"} {
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("embedded route %q failed: status=%d", route, recorder.Code)
		}
		body := recorder.Body.String()
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Fatalf("embedded asset %q contains an external absolute dependency", route)
		}
		bodies[route] = body
	}
	policy := httptest.NewRecorder()
	controller.ServeHTTP(policy, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(policy.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("embedded page lacks self-contained content policy")
	}
	page := bodies["/"]
	script := bodies["/app.js"]
	for _, fragment := range []string{
		"Shadowsocks 服务",
		"选择节点",
		"新增监听",
		"追加用户",
		"id=\"append-dialog\"",
		"连接地址",
		"id=\"share-host\"",
		"恢复自动",
		"id=\"share-host-auto\"",
		"data-agent-picker=\"workspace\"",
		"id=\"agent-select\"",
		"复制 ss://",
		"二维码",
		"id=\"app-undeployed\"",
		"id=\"app-node-empty\"",
		"id=\"app-offline\"",
		"id=\"app-execution-unavailable\"",
		"该节点暂时无法执行监听",
		"还不能执行 Shadowsocks",
		"shadowsocks-server 插件状态",
		"请先到插件详情页部署执行面",
		"再回到本页新增或改动监听",
		"class=\"setup-hero\"",
	} {
		if !strings.Contains(page, fragment) && !strings.Contains(script, fragment) {
			t.Fatalf("panel missing %q", fragment)
		}
	}
	if strings.Contains(page, "ui.schema") || strings.Contains(page, "plugin=") || strings.Contains(page, "订阅") || strings.Contains(page, "ss2022://") {
		t.Fatal("panel page must not require config UI, SIP003, subscription, or ss2022://")
	}
	for _, fragment := range []string{"配额", "过期", "扫码", "SIP003", "ss2022://", "api/accounts", "api/server-psk/rotate"} {
		if strings.Contains(page, fragment) || strings.Contains(script, fragment) {
			t.Fatalf("panel still exposes excluded entry %q", fragment)
		}
	}
	for _, fragment := range []string{"/panel-api/agents", "/panel-api/plugins/shadowsocks-server", "api/listens", "api/execution", "api/share-host", "share_host_source", "mountAgentSearchSelect", "复制 ss://", "host_port", "二维码", "append-form", "已复制", "暂时无法执行", "请先在插件详情页部署执行面"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("panel script missing %q", fragment)
		}
	}
	assertLoadAgentsKeepsDeployedInstanceTargets(t, page, script)
	assertListenCardIsSummary(t, page, script)
	inactive := httptest.NewRecorder()
	controller.ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "/api/listens?agent_id=agent-1", nil))
	if inactive.Code != http.StatusServiceUnavailable || !strings.Contains(inactive.Body.String(), serviceNotReady) {
		t.Fatalf("inactive panel=%d %s", inactive.Code, inactive.Body.String())
	}
	style := bodies["/style.css"]
	for _, fragment := range []string{
		"width: calc(100% - 2.5rem)",
		"max-width: min(46rem, 100%)",
		"@media (max-width: 720px)",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
		".agent-search-select",
		".setup-hero",
		".setup-mark[data-kind=\"unavailable\"]",
		"repeat(2, minmax(0, 1fr))",
		"repeat(3, minmax(18rem, 1fr))",
	} {
		if !strings.Contains(style, fragment) {
			t.Fatalf("panel stylesheet missing %q", fragment)
		}
	}
	if strings.Contains(style, "min(52rem") || strings.Contains(style, "min(64rem") || strings.Contains(style, "min(880px") {
		t.Fatal("panel stylesheet still caps main at 52rem, 64rem, or 880px")
	}
	if !strings.Contains(cssRule(style, ".panel"), "max-width: min(46rem, 100%)") {
		t.Fatal(".panel still fills main without a capped operation group")
	}
	if strings.Contains(page, `class="backdrop"`) {
		t.Fatal("panel still includes decorative body backdrop")
	}
	if strings.Contains(style, "tunnel-glow") || strings.Contains(style, "radial-gradient(42rem 26rem") || strings.Contains(style, "radial-gradient(36rem 24rem") {
		t.Fatal("panel stylesheet still contains tunnel-glow backdrop")
	}
	if strings.Contains(style, "radial-gradient(circle at 32% 28%") {
		t.Fatal("setup-mark still uses radial highlight placeholders")
	}
	if !strings.Contains(style, "dialog::backdrop") {
		t.Fatal("panel stylesheet missing dialog::backdrop")
	}
}

func TestPanelAssetsMatchManifestTree(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "style.css"} {
		want, err := os.ReadFile(filepath.Join("assets", "ui", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := panelUIAssets.ReadFile("assets/ui/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("assets/ui/%s drifted from embedded panel asset", name)
		}
	}
}

func jsConstFunction(script, name string) string {
	sig := "const " + name + " = "
	start := strings.Index(script, sig)
	if start < 0 {
		return ""
	}
	rest := script[start:]
	arrow := strings.Index(rest, "=>")
	if arrow < 0 {
		return ""
	}
	body := rest[arrow:]
	open := strings.Index(body, "{")
	if open < 0 {
		return ""
	}
	depth := 0
	for i := open; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:arrow+i+1]
			}
		}
	}
	return ""
}

func assertListenCardIsSummary(t *testing.T, page, script string) {
	t.Helper()
	card := jsConstFunction(script, "renderListen")
	if card == "" {
		t.Fatal("renderListen is missing")
	}
	for _, want := range []string{"端口", "运行中", "未生效"} {
		if !strings.Contains(card, want) {
			t.Fatalf("listen card missing %q", want)
		}
	}
	for _, banned := range []string{"删除监听", "追加用户"} {
		if strings.Contains(card, banned) {
			t.Fatalf("listen card still contains %q", banned)
		}
	}
	if !strings.Contains(page, "新增监听") && !strings.Contains(script, "新增监听") {
		t.Fatal("workspace missing 新增监听 entry")
	}
	if !strings.Contains(page, `id="create-toggle"`) || !strings.Contains(page, `id="empty-create"`) {
		t.Fatal("workspace missing create entry")
	}
	detail := jsConstFunction(script, "listenFooterActions")
	if detail == "" {
		t.Fatal("listenFooterActions is missing")
	}
	if !strings.Contains(detail, "删除监听") || !strings.Contains(detail, "追加用户") {
		t.Fatal("detail path missing 删除监听 or 追加用户")
	}
}

func assertLoadAgentsKeepsDeployedInstanceTargets(t *testing.T, page, script string) {
	t.Helper()
	start := strings.Index(script, "const loadAgents = async () => {")
	end := strings.Index(script, "agentPicker.onChange")
	if start < 0 || end <= start {
		t.Fatal("loadAgents is missing")
	}
	load := script[start:end]
	for _, want := range []string{
		"/panel-api/agents",
		"/panel-api/plugins/shadowsocks-server",
		"plugin.instances",
		"instance.targets",
		`agent.is_local !== true`,
		`agent.mode !== "local"`,
		"agentsCache = remotes.filter((agent) => deployed.has(agent.id))",
	} {
		if !strings.Contains(load, want) {
			t.Fatalf("loadAgents missing %q", want)
		}
	}
	if strings.Contains(load, "configure") {
		t.Fatal("loadAgents still configures shadowsocks-server onto agents")
	}
	if strings.Contains(load, "? remotes") || strings.Contains(load, ": remotes") || strings.Contains(load, "|| remotes") {
		t.Fatal("loadAgents treats all remotes as operable when the deployed list is empty")
	}
	if !strings.Contains(script, `clearWorkspace(agentsCache.length ? "empty" : "undeployed")`) {
		t.Fatal("empty deployed list does not lock the picker and workspace")
	}
	if !strings.Contains(page, `id="app-undeployed"`) || !strings.Contains(page, "请先到插件详情页部署执行面") || !strings.Contains(page, "再回到本页新增或改动监听") {
		t.Fatal("empty copy does not tell the operator to deploy the execution face on the plugin detail page first")
	}
	if !strings.Contains(script, "请先在插件详情页部署执行面") {
		t.Fatal("empty picker copy does not point at the plugin detail page")
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
