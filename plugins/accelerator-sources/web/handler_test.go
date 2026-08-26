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
	for _, fragment := range []string{"资源加速", `data-panel="usage"`, `data-panel="search"`, `data-panel="tags"`, `data-panel="offline"`} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("visitor page missing %q", fragment)
		}
	}
	if strings.Contains(page, "Accelerator Sources") || strings.Contains(page, "id=\"search-view\"") || strings.Contains(page, "id=\"offline-view\"") {
		t.Fatal("visitor page still uses the old tool-shell markup")
	}
	if !strings.Contains(page, ">用法<") || !strings.Contains(page, ">搜索<") || !strings.Contains(page, ">标签<") || !strings.Contains(page, ">离线包<") {
		t.Fatal("primary navigation is not the Chinese product sections")
	}
	for _, fragment := range []string{`data-example="docker-pull"`, `data-example="docker-mirror"`, `data-example="file-sample"`, `id="convert-input"`, `id="convert-result"`, `id="convert-copy"`, `>复制加速链接<`, `id="search-form"`, `id="tags-form"`, `id="offline-form"`, `id="platform"`, `id="compressed-layers"`, `option value=""`, `type="checkbox" checked`} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("visitor page missing capability markup %q", fragment)
		}
	}
	for _, fragment := range []string{"window.location.origin", "window.location.host", "#convert-input", "#convert-copy", "normalizeSourceUrl", "/api/search?q=", "/api/tags?image=", "/api/offline/prepare", "compressed_layers"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("visitor script missing %q", fragment)
		}
	}
	for _, fragment := range []string{"#17202a", "header { display: flex", "nav button[aria-pressed=\"true\"]", "--rust", "--paper"} {
		if strings.Contains(style, fragment) {
			t.Fatalf("visitor theme still contains a retired theme rule %q", fragment)
		}
	}
	if !strings.Contains(style, "--accent") || !strings.Contains(style, ".masthead") || !strings.Contains(style, ".usage-grid") || !strings.Contains(style, ".converter-card") {
		t.Fatal("visitor theme is not the replacement layout")
	}
	assertConsoleSkin(t, page, script, style)
	if strings.Contains(cssRule(style, ".primary"), "999px") || strings.Contains(cssRule(style, ".primary button"), "999px") {
		t.Fatal("primary nav still uses a capsule selected state")
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
	searchRow := cssRule(style, ".search-row")
	converter := cssRule(style, ".converter-card")
	if !strings.Contains(searchRow, "max-width: min(46rem, 100%)") {
		t.Fatal(".search-row still fills main without a capped operation group")
	}
	if !strings.Contains(converter, "max-width: min(46rem, 100%)") {
		t.Fatal(".converter-card still fills main without a capped operation group")
	}
	for _, want := range []string{
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
		"repeat(2, minmax(18rem, 1fr))",
		"repeat(2, minmax(22rem, 1fr))",
	} {
		if !strings.Contains(style, want) {
			t.Fatalf("visitor stylesheet missing wide-viewport rule %q", want)
		}
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
	for _, fragment := range []string{`"/"`, `"/app.js"`, `"/style.css"`, `"/api/search"`, `"/api/tags"`, `"/api/offline/prepare"`, `"converter"`, `"#convert-input"`, `"#convert-copy"`, `"640px"`, `"1920px"`, `"2560px"`, `"3840px"`, `"usage"`, `"search"`, `"tags"`, `"offline"`} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("web corpus missing %q", fragment)
		}
	}
}
