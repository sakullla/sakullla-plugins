package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWebEmbeddedPageAndAssets(t *testing.T) {
	handler := NewHandler()
	bodies := map[string]string{}
	for _, route := range []string{"/", "/app.js", "/style.css", "/ui-kit.js", "/ui-kit.css"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("embedded route %q failed: status=%d", route, recorder.Code)
		}
		body := recorder.Body.String()
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Fatalf("embedded asset %q contains an external absolute dependency", route)
		}
		bodies[route] = body
	}
	removed := httptest.NewRecorder()
	handler.ServeHTTP(removed, httptest.NewRequest(http.MethodGet, "/theme.js", nil))
	if removed.Code != http.StatusNotFound {
		t.Fatalf("retired theme bootstrap is still embedded: status=%d", removed.Code)
	}
	policy := httptest.NewRecorder()
	handler.ServeHTTP(policy, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(policy.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("embedded page lacks self-contained content policy")
	}

	page := bodies["/"]
	script := bodies["/app.js"]
	style := bodies["/style.css"]
	kitScript := bodies["/ui-kit.js"]
	kitStyle := bodies["/ui-kit.css"]

	if !strings.Contains(kitScript, "data-theme-key") || !strings.Contains(kitScript, "standalone") {
		t.Fatal("ui-kit.js does not expose the standalone theme authority")
	}
	if !strings.Contains(kitStyle, `[data-theme="fresh-green"]`) || !strings.Contains(kitStyle, "[data-theme-family=") {
		t.Fatal("ui-kit.css does not ship the host themes and theme families")
	}

	assertStandaloneThemeAuthority(t, page, style)
	assertTwoPageDocsNav(t, page)
	assertPageCapabilityMarkup(t, page)
	assertSnippetCopyChrome(t, page)
	assertScriptSafeguards(t, script)
	assertStyleTokensAndViewports(t, style)
	assertMirrorStates(t, page, script, style)
}

func assertStandaloneThemeAuthority(t *testing.T, page, style string) {
	t.Helper()
	for _, want := range []string{
		`data-theme="light"`,
		`data-theme-mode="standalone"`,
		`data-theme-key="accelerator-sources.theme"`,
		`<script src="/ui-kit.js"></script>`,
		`<link rel="stylesheet" href="/ui-kit.css">`,
		`<link rel="stylesheet" href="/style.css">`,
		`id="theme-toggle"`,
		`data-ui-theme-toggle`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("visitor page missing %q", want)
		}
	}
	if strings.Contains(page, "/theme.js") {
		t.Fatal("visitor page still loads the retired theme.js bootstrap")
	}
	kitScript := strings.Index(page, `<script src="/ui-kit.js"></script>`)
	kitStyle := strings.Index(page, `<link rel="stylesheet" href="/ui-kit.css">`)
	pageStyle := strings.Index(page, `<link rel="stylesheet" href="/style.css">`)
	if kitScript < 0 || kitStyle < 0 || pageStyle < 0 || !(kitScript < kitStyle && kitStyle < pageStyle) {
		t.Fatal("page does not load ui-kit.js before ui-kit.css and style.css")
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, " onclick=") {
		t.Fatal("page must not depend on inline script or handlers under self-only CSP")
	}
	for _, class := range []string{"ui-page", "ui-page-head", "ui-tabs", "ui-tab", "ui-toolbar", "ui-card", "ui-empty", "ui-help"} {
		if !strings.Contains(page, class) {
			t.Fatalf("page is missing kit class %q", class)
		}
	}
	for _, banned := range []string{`[data-theme="dark"]`, `[data-theme="sakura-day"]`, `[data-theme="light"]`} {
		if strings.Contains(style, banned) {
			t.Fatalf("page stylesheet still owns the theme palette %q", banned)
		}
	}
	for _, token := range []string{"var(--ui-space-", "var(--ui-text-", "var(--ui-border", "var(--ui-primary)", "var(--ui-sunken)"} {
		if !strings.Contains(style, token) {
			t.Fatalf("page stylesheet is not using kit token %q", token)
		}
	}
}

func assertTwoPageDocsNav(t *testing.T, page string) {
	t.Helper()
	nav := htmlSection(page, `<nav class="primary ui-tabs accel-view-tabs"`, `</nav>`)
	if nav == "" {
		t.Fatal("visitor page missing the 用法 / 镜像 view switch")
	}
	if strings.Count(nav, "data-view=") != 2 {
		t.Fatal("view switch is not exactly two items")
	}
	if !strings.Contains(nav, ">用法<") || !strings.Contains(nav, ">镜像<") {
		t.Fatal("view switch is not 用法 / 镜像")
	}
	if strings.Contains(nav, "搜索") || strings.Contains(nav, "标签") || strings.Contains(nav, "离线包") {
		t.Fatal("view switch still lists 搜索, 标签, or 离线包 as top-level items")
	}
	for _, fragment := range []string{`data-view="search"`, `data-view="tags"`, `data-view="offline"`, `data-panel="search"`, `data-panel="tags"`, `data-panel="offline"`} {
		if strings.Contains(page, fragment) {
			t.Fatalf("visitor page still treats %q as a top-level view", fragment)
		}
	}
	if !strings.Contains(page, `data-panel="usage"`) || !strings.Contains(page, `data-panel="mirrors"`) {
		t.Fatal("visitor page is missing the usage / mirrors panels")
	}
}

func assertPageCapabilityMarkup(t *testing.T, page string) {
	t.Helper()
	for _, fragment := range []string{
		`data-example="docker-pull"`,
		`data-example="docker-mirror"`,
		`data-example="file-sample"`,
		`data-example="script-sample"`,
		`data-example="clone-sample"`,
		`data-example="offline-cli"`,
		`id="convert-input"`,
		`id="convert-result"`,
		`id="convert-copy"`,
		`id="search-form"`,
		`id="tags-form"`,
		`id="offline-form"`,
		`id="tag-filter"`,
		`id="platform"`,
		`id="compressed-layers"`,
		`option value=""`,
		`type="checkbox" checked`,
		`<h2 class="ui-card__title" id="search-heading">搜索</h2>`,
		`<h2 class="ui-card__title" id="tags-heading">标签</h2>`,
		`<h2 class="ui-card__title" id="offline-heading">离线包</h2>`,
		`<summary>Docker：拉取镜像与镜像源</summary>`,
		`<summary>GitHub 与 Hugging Face：下载、脚本与克隆</summary>`,
	} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("visitor page missing capability markup %q", fragment)
		}
	}
	if strings.Contains(page, "Accelerator Sources") || strings.Contains(page, `id="search-view"`) || strings.Contains(page, `id="offline-view"`) {
		t.Fatal("visitor page still uses the old tool-shell markup")
	}
}

func assertSnippetCopyChrome(t *testing.T, page string) {
	t.Helper()
	if strings.Contains(page, `class="wash"`) || strings.Contains(page, `class="ghost"`) || strings.Contains(page, `class="shell"`) {
		t.Fatal("visitor page still has wash, ghost copy buttons, or terminal shells")
	}
	for _, fragment := range []string{"复制加速链接", "复制拉取命令", "复制镜像配置", "复制示例"} {
		if strings.Contains(page, fragment) {
			t.Fatalf("standalone copy label %q remains outside snippet chrome", fragment)
		}
	}
	if !strings.Contains(page, `class="snippet-copy" id="convert-copy"`) {
		t.Fatal("#convert-copy is not on the convert result chrome")
	}
	convert := htmlSection(page, `id="convert-snippet"`, `id="convert-result"`)
	if !strings.Contains(convert, `id="convert-copy"`) || !strings.Contains(convert, `class="snippet-chrome"`) {
		t.Fatal("#convert-copy is not inside the convert snippet structure")
	}
	for _, name := range []string{"docker-pull", "docker-mirror", "file-sample"} {
		if !strings.Contains(page, `class="snippet-copy" data-copy="`+name+`"`) {
			t.Fatalf("command block missing in-chrome copy for %q", name)
		}
	}
}

func assertScriptSafeguards(t *testing.T, script string) {
	t.Helper()
	for _, fragment := range []string{
		"isSecureContext",
		`execCommand("copy")`,
		`method: "HEAD"`,
		"registryHosts",
		"release-assets.githubusercontent.com",
		"window.location.origin",
		"window.location.host",
		"#convert-input",
		"#convert-copy",
		"normalizeSourceUrl",
		"/api/search?q=",
		"/api/tags?image=",
		"/api/offline/prepare",
		"compressed_layers",
		`event.key === "Enter"`,
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("visitor script missing UX safeguard %q", fragment)
		}
	}
	if strings.Contains(script, "github-releases.githubusercontent.com") {
		t.Fatal("converter advertises a host that the service does not route")
	}
	for _, retired := range []string{"applyHostTheme", "window.parent", "aliases", `showView("tags")`, `showView("offline")`, `showView("search")`} {
		if strings.Contains(script, retired) {
			t.Fatalf("visitor script still contains retired behaviour %q", retired)
		}
	}
	if strings.Contains(script, `document.documentElement.setAttribute("data-theme"`) {
		t.Fatal("page script still resolves themes itself instead of ui-kit.js")
	}
}

func assertStyleTokensAndViewports(t *testing.T, style string) {
	t.Helper()
	for _, want := range []string{
		"@media (max-width: 768px)",
		"@media (max-width: 480px)",
		"@media (min-width: 720px)",
		"@media (min-width: 1100px)",
		"grid-template-columns: minmax(0, 1fr)",
		"grid-template-columns: repeat(2, minmax(0, 1fr))",
		"overflow-wrap: anywhere",
		"min-width: 0",
		".accel-converter",
		".accel-mirror-grid",
		".accel-help-grid",
		".snippet *::selection",
		"min-height: var(--ui-touch)",
	} {
		if !strings.Contains(style, want) {
			t.Fatalf("visitor stylesheet missing viewport/token rule %q", want)
		}
	}
	if strings.Contains(style, "max-width: 52rem") || strings.Contains(style, "max-width: 64rem") || strings.Contains(style, "max-width: 880px") {
		t.Fatal("visitor stylesheet still caps the main reading width")
	}
	if strings.Contains(style, "width: 100vw") || strings.Contains(style, "min-width: 60rem") {
		t.Fatal("visitor stylesheet forces a wider-than-viewport layout")
	}
	if strings.Contains(style, "#17202a") || strings.Contains(style, "#d94880") || strings.Contains(style, "#f4a0c0") || strings.Contains(style, "#f5f4f2") {
		t.Fatal("visitor stylesheet still contains a retired hard-coded palette")
	}
	snippet := cssRule(style, ".snippet")
	if snippet == "" {
		t.Fatal("command blocks are missing")
	}
	if !strings.Contains(snippet, "var(--ui-sunken)") {
		t.Fatal("command blocks are not using the kit sunken surface")
	}
	selection := cssRule(style, ".snippet *::selection")
	if !strings.Contains(selection, "color:") || !strings.Contains(selection, "var(--ui-active)") {
		t.Fatal("command blocks do not have their own token-based selection colours")
	}
}

func assertMirrorStates(t *testing.T, page, script, style string) {
	t.Helper()
	if !strings.Contains(page, `id="results" class="result-list"`) || !strings.Contains(page, `id="tag-results" class="tag-board"`) {
		t.Fatal("mirror view is missing the result and tag containers")
	}
	if strings.Count(page, `class="ui-empty"`) < 2 {
		t.Fatal("mirror view is missing the initial empty states")
	}
	for _, fragment := range []string{"renderLoading", "renderEmpty", "renderError", "ui-loading", "ui-spinner", "ui-skeleton", "ui-error-state"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("mirror state rendering is missing %q", fragment)
		}
	}
	if !strings.Contains(page, `id="tag-filter"`) || !strings.Contains(script, "tagFilter.addEventListener") {
		t.Fatal("mirror view is missing the tag filter")
	}
	if !strings.Contains(style, ".result-card[aria-pressed=\"true\"]") || !strings.Contains(style, ".tag-chip[aria-pressed=\"true\"]") {
		t.Fatal("mirror selection states are not styled")
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

func htmlSection(source, startMark, endMark string) string {
	start := strings.Index(source, startMark)
	if start < 0 {
		return ""
	}
	rest := source[start:]
	end := strings.Index(rest, endMark)
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func TestVisitorPageCorpusListsSelfContainedAssets(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to locate web package")
	}
	corpus := filepath.Join(filepath.Dir(file), "..", "..", "..", "testing", "corpus", "accelerator-sources", "web", "assets.json")
	body, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, `"views": ["usage", "search", "tags", "offline"]`) {
		t.Fatal("web corpus still lists four top-level views")
	}
	for _, fragment := range []string{
		`"/"`,
		`"/app.js"`,
		`"/style.css"`,
		`"/ui-kit.js"`,
		`"/ui-kit.css"`,
		`"/api/search"`,
		`"/api/tags"`,
		`"/api/offline/prepare"`,
		`"converter"`,
		`"#convert-input"`,
		`"#convert-copy"`,
		`"usage"`,
		`"mirrors"`,
		`"search"`,
		`"tags"`,
		`"offline"`,
		`"用法"`,
		`"镜像"`,
		`"standalone"`,
		`"accelerator-sources.theme"`,
		`"ui-loading"`,
		`"ui-empty"`,
		`"ui-error-state"`,
		`".snippet *::selection"`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("web corpus missing %q", fragment)
		}
	}
}
