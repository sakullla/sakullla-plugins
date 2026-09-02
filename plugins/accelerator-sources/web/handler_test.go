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
	for _, route := range []string{"/", "/app.js", "/style.css"} {
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
	if policy := httptest.NewRecorder(); func() bool {
		handler.ServeHTTP(policy, httptest.NewRequest(http.MethodGet, "/", nil))
		return !strings.Contains(policy.Header().Get("Content-Security-Policy"), "default-src 'self'")
	}() {
		t.Fatal("embedded page lacks self-contained content policy")
	}

	page := bodies["/"]
	script := bodies["/app.js"]
	style := bodies["/style.css"]
	for _, fragment := range []string{"资源加速", `data-panel="usage"`, `data-panel="mirrors"`} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("visitor page missing %q", fragment)
		}
	}
	if strings.Contains(page, "Accelerator Sources") || strings.Contains(page, `id="search-view"`) || strings.Contains(page, `id="offline-view"`) {
		t.Fatal("visitor page still uses the old tool-shell markup")
	}
	assertTwoPageDocsNav(t, page)
	for _, fragment := range []string{`data-example="docker-pull"`, `data-example="docker-mirror"`, `data-example="file-sample"`, `id="convert-input"`, `id="convert-result"`, `id="convert-copy"`, `id="search-form"`, `id="tags-form"`, `id="offline-form"`, `id="platform"`, `id="compressed-layers"`, `option value=""`, `type="checkbox" checked`, `<h2 id="search-heading">搜索</h2>`, `<h2 id="tags-heading">标签</h2>`, `<h2 id="offline-heading">离线包</h2>`} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("visitor page missing capability markup %q", fragment)
		}
	}
	assertSnippetCopyChrome(t, page)
	for _, fragment := range []string{"window.location.origin", "window.location.host", "#convert-input", "#convert-copy", "normalizeSourceUrl", "/api/search?q=", "/api/tags?image=", "/api/offline/prepare", "compressed_layers"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("visitor script missing %q", fragment)
		}
	}
	if strings.Contains(script, `showView("tags")`) || strings.Contains(script, `showView("offline")`) || strings.Contains(script, `showView("search")`) {
		t.Fatal("mirror page still switches top-level views for search, tags, or offline")
	}
	for _, fragment := range []string{"#17202a", "header { display: flex", "nav button[aria-pressed=\"true\"]", "--rust", "--paper"} {
		if strings.Contains(style, fragment) {
			t.Fatalf("visitor theme still contains a retired theme rule %q", fragment)
		}
	}
	if !strings.Contains(style, "--accent") || !strings.Contains(style, ".masthead") || !strings.Contains(style, ".snippet") || !strings.Contains(style, ".doc-section") {
		t.Fatal("visitor theme is not the two-page docs layout")
	}
	assertDocsSkin(t, page, script, style)
	if strings.Contains(cssRule(style, ".primary"), "999px") || strings.Contains(cssRule(style, ".primary button"), "999px") {
		t.Fatal("primary nav still uses a capsule selected state")
	}
	selected := cssRule(style, `.primary button[aria-pressed="true"]`)
	if !strings.Contains(selected, "background: var(--accent)") {
		t.Fatal("current nav item is not a solid selected state")
	}
	for _, fragment := range []string{
		"@media (max-width: 640px)",
		"grid-template-columns: 1fr",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"width: calc(100% - 2.5rem)",
		"overflow-wrap: anywhere",
	} {
		if !strings.Contains(style, fragment) {
			t.Fatalf("visitor stylesheet missing viewport rule %q", fragment)
		}
	}
	if strings.Contains(style, "min(52rem") || strings.Contains(style, "min(64rem") || strings.Contains(style, "min(880px") {
		t.Fatal("visitor stylesheet still caps main at 52rem, 64rem, or 880px")
	}
	if strings.Contains(style, "overflow: auto") {
		t.Fatal("visitor stylesheet still uses overflow: auto on reading content")
	}
	panel := cssRule(style, ".panel")
	if !strings.Contains(panel, "max-width: min(46rem, 100%)") {
		t.Fatal(".panel is not a single-column reading width")
	}
	if strings.Contains(style, ".usage-grid") || strings.Contains(style, ".converter-card") || strings.Contains(style, "repeat(2, minmax(") {
		t.Fatal("usage page still uses two equal cards or a two-column grid")
	}
	for _, want := range []string{
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
	} {
		if !strings.Contains(style, want) {
			t.Fatalf("visitor stylesheet missing wide-viewport rule %q", want)
		}
	}
}

func assertTwoPageDocsNav(t *testing.T, page string) {
	t.Helper()
	nav := htmlSection(page, `<nav class="primary"`, `</nav>`)
	if nav == "" {
		t.Fatal("visitor page missing primary navigation")
	}
	if strings.Count(nav, "data-view=") != 2 {
		t.Fatal("primary navigation is not exactly two items")
	}
	if !strings.Contains(nav, ">用法<") || !strings.Contains(nav, ">镜像<") {
		t.Fatal("primary navigation is not 用法 / 镜像")
	}
	if strings.Contains(nav, "搜索") || strings.Contains(nav, "标签") || strings.Contains(nav, "离线包") {
		t.Fatal("primary navigation still lists 搜索, 标签, or 离线包 as top-bar items")
	}
	for _, fragment := range []string{`data-view="search"`, `data-view="tags"`, `data-view="offline"`, `data-panel="search"`, `data-panel="tags"`, `data-panel="offline"`} {
		if strings.Contains(page, fragment) {
			t.Fatalf("visitor page still treats %q as a top-level view", fragment)
		}
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

func assertDocsSkin(t *testing.T, page, script, style string) {
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
	if strings.Contains(style, "var(--color-terminal)") || strings.Contains(style, "--color-terminal:") || strings.Contains(style, ".shell") || strings.Contains(style, ".wash") {
		t.Fatal("stylesheet still paints command blocks as light-theme terminals or keeps wash")
	}
	snippet := cssRule(style, ".snippet")
	if snippet == "" || strings.Contains(snippet, "--color-terminal") {
		t.Fatal("light-theme command blocks are missing or still use --color-terminal")
	}
	if !strings.Contains(snippet, "--color-code-bg") {
		t.Fatal("command blocks are not light-gray document snippets")
	}
	pageSel := cssRule(style, "::selection")
	if strings.Contains(pageSel, "--color-text-primary") {
		t.Fatal("page-wide ::selection still forces --color-text-primary onto snippets")
	}
	snippetSel := cssRule(style, ".snippet *::selection")
	if snippetSel == "" || !strings.Contains(snippetSel, "color:") || strings.Contains(snippetSel, "--color-text-primary") {
		t.Fatal("command blocks do not have their own 4.5:1 selection colors")
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
	for _, fragment := range []string{`"/"`, `"/app.js"`, `"/style.css"`, `"/api/search"`, `"/api/tags"`, `"/api/offline/prepare"`, `"converter"`, `"#convert-input"`, `"#convert-copy"`, `"640px"`, `"1920px"`, `"2560px"`, `"3840px"`, `"usage"`, `"mirrors"`, `"search"`, `"tags"`, `"offline"`, `"用法"`, `"镜像"`, `".snippet *::selection"`} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("web corpus missing %q", fragment)
		}
	}
}
