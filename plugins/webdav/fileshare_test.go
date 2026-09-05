package webdav

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	testSharePassword = "share-pass"
	testInsideName    = "visible-inside.txt"
	testOutsideName   = "nre-webdav-outside-secret.txt"
	testOutsideBody   = "LEAKME-OUTSIDE"
)

func TestMissingPasswordFailsPrepareWithoutListingFiles(t *testing.T) {
	owned := t.TempDir()
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound, pluginsdk.PermissionStorageWrite}, Generation: "no-password",
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{[]byte(`{}`), []byte(`{"password":""}`), nil} {
		result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "no-password", Config: config})
		if result.Error == nil {
			t.Fatalf("prepare accepted %#q", config)
		}
	}
	recorder := doShareRequest(t, controller, http.MethodGet, "http://provider.test/", "", nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), testInsideName) {
		t.Fatalf("unprepared response leaked file name: %q", recorder.Body.String())
	}
}

func TestWrongPasswordIs401WithoutFileNamesOrMutations(t *testing.T) {
	controller, owned := startShare(t, "")
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	page := doShareRequest(t, controller, http.MethodGet, "http://provider.test/", "wrong-pass", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d, want 200 body=%q", page.Code, page.Body.String())
	}
	assertNoBasicChallenge(t, page)
	if strings.Contains(page.Body.String(), testInsideName) {
		t.Fatalf("page leaked file name: %q", page.Body.String())
	}
	api := doShareRequest(t, controller, http.MethodGet, "http://provider.test/api/list?path=/", "wrong-pass", nil)
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("api status = %d, want 401 body=%q", api.Code, api.Body.String())
	}
	assertNoBasicChallenge(t, api)
	if strings.Contains(api.Body.String(), testInsideName) {
		t.Fatalf("api leaked file name: %q", api.Body.String())
	}
	dav := doShareRequest(t, controller, http.MethodGet, "http://provider.test/dav/", "wrong-pass", nil)
	if dav.Code != http.StatusUnauthorized {
		t.Fatalf("dav status = %d, want 401 body=%q", dav.Code, dav.Body.String())
	}
	assertDAVUnauthorized(t, dav)
	if strings.Contains(dav.Body.String(), testInsideName) {
		t.Fatalf("dav leaked file name: %q", dav.Body.String())
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://provider.test/dav/evil.txt", "wrong-pass", strings.NewReader("nope"))
	if put.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized put status = %d", put.Code)
	}
	assertDAVUnauthorized(t, put)
	if _, err := os.Stat(filepath.Join(owned, "evil.txt")); !os.IsNotExist(err) {
		t.Fatalf("unauthorized put wrote a file: %v", err)
	}
	entries, err := os.ReadDir(owned)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "user-") {
			t.Fatalf("wrong password created a namespace: %s", entry.Name())
		}
	}
}

func TestPageServesManagerAndDavMountInstructions(t *testing.T) {
	controller, owned := startShare(t, "")
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	page := doShareRequest(t, controller, http.MethodGet, "http://share.test/", "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d body=%q", page.Code, page.Body.String())
	}
	assertNoBasicChallenge(t, page)
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("page CSP = %q", page.Header().Get("Content-Security-Policy"))
	}
	body := page.Body.String()
	for _, fragment := range []string{
		"文件共享", "/dav/", "HTTP Basic", `id="dav-url"`, `id="upload-input"`, `id="mkdir-button"`,
		`<dialog id="mkdir-dialog"`, `id="mkdir-form"`, `id="mkdir-name"`, `id="mkdir-cancel"`, "目录名称",
		"用户名可自定", "隔离", "共享口令", `id="login-view"`, `id="login-form"`, `id="login-username"`,
		`id="login-password"`, `id="logout-button"`, `id="manager-view"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page missing %q", fragment)
		}
	}
	if strings.Contains(body, testInsideName) || strings.Contains(body, testSharePassword) {
		t.Fatal("page leaked share contents or password")
	}
	script := doShareRequest(t, controller, http.MethodGet, "http://share.test/static/app.js", "", nil)
	if script.Code != http.StatusOK {
		t.Fatalf("script = %d %q", script.Code, script.Body.String())
	}
	assertNoBasicChallenge(t, script)
	text := script.Body.String()
	for _, fragment := range []string{
		"window.location.origin", "/dav/", "sessionStorage", "Authorization", "encodeBasic",
		"saveCredentials", "clearCredentials", "restoreSession", "downloadFile",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("script missing %q", fragment)
		}
	}
	if strings.Contains(text, `href = "/api/download`) || strings.Contains(text, `href="/api/download`) {
		t.Fatal("script still uses a bare /api/download link")
	}
}

func TestManagerViewportLayout(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	for _, want := range []string{
		"width: calc(100% - 2.5rem)",
		"@media (max-width: 720px)",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"html { font-size: 17px; }",
		"html { font-size: 18px; }",
		"html { font-size: 20px; }",
		"max-width: min(46rem, 100%)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("stylesheet missing viewport rule %q", want)
		}
	}
	if strings.Contains(text, "min(52rem") || strings.Contains(text, "min(64rem") || strings.Contains(text, "min(880px") {
		t.Fatal("stylesheet still caps main at 52rem, 64rem, or 880px")
	}
	filesHead := cssRule(text, ".files-head")
	if strings.Contains(filesHead, "space-between") {
		t.Fatal(".files-head still uses space-between to stretch the action cluster")
	}
	if !strings.Contains(filesHead, "justify-content: flex-start") {
		t.Fatal(".files-head is not grouped at flex-start")
	}
	actions := cssRule(text, ".actions")
	if !strings.Contains(actions, "max-width: min(46rem, 100%)") {
		t.Fatal(".actions still fills main without a capped operation group")
	}
}

func TestLoginHeadingSize(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	heading := cssRule(string(css), "h1")
	if heading == "" {
		t.Fatal("missing h1 rule")
	}
	if strings.Contains(heading, "clamp(") || strings.Contains(heading, "2.45rem") || strings.Contains(heading, "1.75rem") {
		t.Fatalf("login heading still uses oversized fluid type: %s", heading)
	}
	if !strings.Contains(heading, "1.35rem") {
		t.Fatalf("login heading is not compact: %s", heading)
	}
}

func TestMobileManagerToolbar(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	if !strings.Contains(text, ".crumbs:empty") {
		t.Fatal("empty breadcrumbs still reserve space")
	}
	mobile := cssMedia(text, "(max-width: 720px)")
	if mobile == "" {
		t.Fatal("missing 720px manager stylesheet")
	}
	pathCluster := cssRule(mobile, ".files-head > div:not(.actions)")
	if !strings.Contains(pathCluster, "flex: 0 0 auto") {
		t.Fatalf("path cluster still grows on mobile: %s", pathCluster)
	}
	actions := cssRule(mobile, ".actions")
	if !strings.Contains(actions, "grid-template-columns: 1fr 1fr") {
		t.Fatalf("mobile actions are not a two-up row: %s", actions)
	}
	if strings.Contains(mobile, ".listing, .listing tbody, .listing tr, .listing td { display: block") {
		t.Fatal("listing cells still stack as full-width blocks on mobile")
	}
	row := cssRule(mobile, ".listing tbody tr")
	if !strings.Contains(row, "display: flex") {
		t.Fatalf("listing rows are not a compact flex row: %s", row)
	}
	typeCell := cssRule(mobile, ".listing td:nth-child(2)")
	if !strings.Contains(typeCell, "display: none") {
		t.Fatalf("type pills still occupy a mobile row: %s", typeCell)
	}
}

func TestManagerMkdirUsesInPageDialog(t *testing.T) {
	controller, _ := startShare(t, "")
	page := doShareRequest(t, controller, http.MethodGet, "http://share.test/", "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d body=%q", page.Code, page.Body.String())
	}
	assertNoBasicChallenge(t, page)
	body := page.Body.String()
	for _, fragment := range []string{
		`<dialog id="mkdir-dialog"`,
		`id="mkdir-title"`,
		`for="mkdir-name"`,
		`id="mkdir-error"`,
		"新建目录",
		"确定",
		"取消",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page missing mkdir dialog fragment %q", fragment)
		}
	}

	script := doShareRequest(t, controller, http.MethodGet, "http://share.test/static/app.js", "", nil)
	if script.Code != http.StatusOK {
		t.Fatalf("script status = %d body=%q", script.Code, script.Body.String())
	}
	assertNoBasicChallenge(t, script)
	text := script.Body.String()
	if strings.Contains(text, `window.prompt("目录名称")`) {
		t.Fatal("mkdir still uses the native prompt")
	}
	if !strings.Contains(text, `window.prompt("新名称"`) {
		t.Fatal("rename no longer uses the native prompt")
	}
	if !strings.Contains(text, `window.confirm("删除 "`) {
		t.Fatal("delete no longer uses the native confirm")
	}
	for _, fragment := range []string{
		"mkdirDialog.showModal()",
		"mkdirName.focus()",
		"mkdirName.value.trim()",
		`sendJSON("/api/mkdir"`,
		"mkdirDialog.close()",
		"已新建目录。",
		"event.preventDefault()",
		"setMkdirError(error.message)",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("script missing mkdir dialog behavior %q", fragment)
		}
	}
	if !strings.Contains(text, "if (!name)") {
		t.Fatal("script does not skip empty mkdir names")
	}

	css, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	style := string(css)
	dialog := cssRule(style, "#mkdir-dialog")
	for _, want := range []string{"var(--color-bg-surface)", "var(--color-text-primary)", "var(--shadow-md)"} {
		if !strings.Contains(dialog, want) {
			t.Fatalf("mkdir dialog missing theme token %q in %q", want, dialog)
		}
	}
	if cssRule(style, "#mkdir-dialog::backdrop") == "" {
		t.Fatal("mkdir dialog has no backdrop")
	}
	nameField := cssRule(style, "#mkdir-name")
	if !strings.Contains(nameField, "var(--color-bg-sunken)") || !strings.Contains(nameField, "var(--color-text-primary)") {
		t.Fatalf("mkdir name field does not follow theme tokens: %q", nameField)
	}
	if !strings.Contains(style, `[data-theme="dark"] #mkdir-dialog::backdrop`) {
		t.Fatal("mkdir dialog backdrop does not adapt to dark theme")
	}
	pageHTML, err := os.ReadFile(filepath.Join("static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	assertConsoleSkin(t, string(pageHTML), text, style)
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

func cssMedia(css, query string) string {
	needle := "@media " + query
	start := strings.Index(css, needle)
	if start < 0 {
		return ""
	}
	rest := css[start:]
	open := strings.Index(rest, "{")
	if open < 0 {
		return rest
	}
	depth := 0
	for i := open; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}

func TestFormatIECSize(t *testing.T) {
	tests := []struct {
		name string
		size int64
		want string
	}{
		{name: "zero bytes", size: 0, want: "0 B"},
		{name: "largest byte value", size: 1023, want: "1023 B"},
		{name: "one kibibyte", size: 1 << 10, want: "1 KiB"},
		{name: "fractional kibibytes", size: 1536, want: "1.5 KiB"},
		{name: "trailing zero removed", size: 10 << 10, want: "10 KiB"},
		{name: "below mebibyte threshold", size: 1<<20 - 1, want: "1024 KiB"},
		{name: "one mebibyte", size: 1 << 20, want: "1 MiB"},
		{name: "fractional mebibytes", size: 3 << 19, want: "1.5 MiB"},
		{name: "below gibibyte threshold", size: 1<<30 - 1, want: "1024 MiB"},
		{name: "one gibibyte", size: 1 << 30, want: "1 GiB"},
		{name: "below tebibyte threshold", size: 1<<40 - 1, want: "1024 GiB"},
		{name: "one tebibyte", size: 1 << 40, want: "1 TiB"},
		{name: "below pebibyte threshold", size: 1<<50 - 1, want: "1024 TiB"},
		{name: "one pebibyte", size: 1 << 50, want: "1 PiB"},
		{name: "below exbibyte threshold", size: 1<<60 - 1, want: "1024 PiB"},
		{name: "one exbibyte", size: 1 << 60, want: "1 EiB"},
		{name: "largest int64", size: 1<<63 - 1, want: "8 EiB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatIECSize(test.size); got != test.want {
				t.Fatalf("formatIECSize(%d) = %q, want %q", test.size, got, test.want)
			}
		})
	}
}

func TestPageUsesReadableExactSizes(t *testing.T) {
	controller, owned := startShare(t, "")
	if err := os.WriteFile(filepath.Join(owned, "sized.bin"), bytes.Repeat([]byte{'x'}, 1536), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "empty.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(owned, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}

	response := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/list?path=/", testSharePassword, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", response.Code, response.Body.String())
	}
	var payload struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	entries := make(map[string]map[string]json.RawMessage, len(payload.Entries))
	for _, entry := range payload.Entries {
		var name string
		if err := json.Unmarshal(entry["name"], &name); err != nil {
			t.Fatalf("decode entry name: %v", err)
		}
		entries[name] = entry
	}
	assertFileEntry := func(name string, wantSize int64, wantText, wantExact string) {
		t.Helper()
		fileEntry, ok := entries[name]
		if !ok {
			t.Fatalf("list response missing %s: %s", name, response.Body.String())
		}
		var size int64
		if err := json.Unmarshal(fileEntry["size"], &size); err != nil || size != wantSize {
			t.Fatalf("%s size = %d err=%v, want %d", name, size, err, wantSize)
		}
		var sizeText, sizeExact string
		if err := json.Unmarshal(fileEntry["size_text"], &sizeText); err != nil || sizeText != wantText {
			t.Fatalf("%s size_text = %q err=%v, want %q", name, sizeText, err, wantText)
		}
		if err := json.Unmarshal(fileEntry["size_exact"], &sizeExact); err != nil || sizeExact != wantExact {
			t.Fatalf("%s size_exact = %q err=%v, want %q", name, sizeExact, err, wantExact)
		}
	}
	assertFileEntry("sized.bin", 1536, "1.5 KiB", "1536")
	assertFileEntry("empty.bin", 0, "0 B", "0")
	dirEntry, ok := entries["folder"]
	if !ok {
		t.Fatalf("list response missing folder: %s", response.Body.String())
	}
	for _, field := range []string{"size", "size_text", "size_exact"} {
		if _, exists := dirEntry[field]; exists {
			t.Fatalf("directory unexpectedly includes %s: %s", field, response.Body.String())
		}
	}

	scriptResponse := doShareRequest(t, controller, http.MethodGet, "http://share.test/static/app.js", testSharePassword, nil)
	if scriptResponse.Code != http.StatusOK {
		t.Fatalf("script status = %d body=%q", scriptResponse.Code, scriptResponse.Body.String())
	}
	script := scriptResponse.Body.String()
	lineContains := func(fragments ...string) bool {
		for _, line := range strings.Split(script, "\n") {
			matched := true
			for _, fragment := range fragments {
				if !strings.Contains(line, fragment) {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
		return false
	}
	if !lineContains("const sizeText", "entry.size_text") || !lineContains("sizeCell.textContent", "sizeText") {
		t.Fatal("page does not render the API size_text for files")
	}
	if !lineContains("sizeCell.textContent", "—") {
		t.Fatal("page does not retain the directory dash")
	}
	if !lineContains("const sizeExact", "entry.size_exact") {
		t.Fatal("page does not consume the API size_exact field")
	}
	if !lineContains("sizeCell.title", "sizeExact", "bytes") {
		t.Fatal("page does not expose exact bytes in the size cell title")
	}
	if !lineContains("aria-label", "sizeExact", "字节") {
		t.Fatal("page does not expose exact bytes in a Chinese aria-label")
	}
	if strings.Contains(script, "String(entry.size || 0)") {
		t.Fatal("page still renders the legacy raw numeric size")
	}
}

func TestWebpageAPIsBrowseDownloadUploadMkdirRenameDelete(t *testing.T) {
	controller, owned := startShare(t, "")
	listed := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/list?path=/", testSharePassword, nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", listed.Code, listed.Body.String())
	}
	mkdir := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/mkdir", testSharePassword, strings.NewReader(`{"path":"docs"}`))
	if mkdir.Code != http.StatusCreated {
		t.Fatalf("mkdir status = %d body=%q", mkdir.Code, mkdir.Body.String())
	}
	upload := uploadShareFile(t, controller, "/docs", "notes.txt", "hello-web")
	if upload.Code != http.StatusCreated {
		t.Fatalf("upload status = %d body=%q", upload.Code, upload.Body.String())
	}
	download := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path="+url.QueryEscape("/docs/notes.txt"), testSharePassword, nil)
	if download.Code != http.StatusOK || download.Body.String() != "hello-web" {
		t.Fatalf("download = %d %q", download.Code, download.Body.String())
	}
	rename := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/rename", testSharePassword, strings.NewReader(`{"from":"/docs/notes.txt","to":"/docs/renamed.txt"}`))
	if rename.Code != http.StatusOK {
		t.Fatalf("rename status = %d body=%q", rename.Code, rename.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "docs", "renamed.txt")); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
	remove := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/delete", testSharePassword, strings.NewReader(`{"path":"/docs/renamed.txt"}`))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%q", remove.Code, remove.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "docs", "renamed.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file still present: %v", err)
	}
}

func TestWebDAVMethodsShareTheSameRoot(t *testing.T) {
	controller, owned := startShare(t, "")
	mkcol := doShareRequest(t, controller, "MKCOL", "http://share.test/dav/folder", testSharePassword, nil)
	if mkcol.Code != http.StatusCreated {
		t.Fatalf("mkcol status = %d body=%q", mkcol.Code, mkcol.Body.String())
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/folder/from-dav.txt", testSharePassword, strings.NewReader("via-dav"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	got := doShareRequest(t, controller, http.MethodGet, "http://share.test/dav/folder/from-dav.txt", testSharePassword, nil)
	if got.Code != http.StatusOK || got.Body.String() != "via-dav" {
		t.Fatalf("dav get = %d %q", got.Code, got.Body.String())
	}
	listed := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/list?path="+url.QueryEscape("/folder"), testSharePassword, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "from-dav.txt") {
		t.Fatalf("web list missing dav file: %d %q", listed.Code, listed.Body.String())
	}
	move := httptest.NewRequest("MOVE", "http://share.test/dav/folder/from-dav.txt", nil)
	setBearerAuth(move, testSharePassword)
	move.Header.Set("Destination", "http://share.test/dav/folder/moved.txt")
	move.Header.Set("Overwrite", "T")
	moved := httptest.NewRecorder()
	controller.ServeHTTP(moved, move)
	if moved.Code != http.StatusCreated && moved.Code != http.StatusNoContent {
		t.Fatalf("move status = %d body=%q", moved.Code, moved.Body.String())
	}
	propfind := httptest.NewRequest("PROPFIND", "http://share.test/dav/folder", http.NoBody)
	setBearerAuth(propfind, testSharePassword)
	propfind.Header.Set("Depth", "1")
	found := httptest.NewRecorder()
	controller.ServeHTTP(found, propfind)
	if found.Code != http.StatusMultiStatus || !strings.Contains(found.Body.String(), "moved.txt") {
		t.Fatalf("propfind = %d %q", found.Code, found.Body.String())
	}
	del := doShareRequest(t, controller, http.MethodDelete, "http://share.test/dav/folder/moved.txt", testSharePassword, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%q", del.Code, del.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "folder", "moved.txt")); !os.IsNotExist(err) {
		t.Fatalf("dav delete left file: %v", err)
	}
}

func TestWebDAVConditionalPut(t *testing.T) {
	conditionalPut := func(t *testing.T, handler http.Handler, target, contents string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, target, strings.NewReader(contents))
		request.Header.Set("If-None-Match", " * ")
		setBearerAuth(request, testSharePassword)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	t.Run("creates a missing resource", func(t *testing.T) {
		controller, owned := startShare(t, "")
		response := conditionalPut(t, controller, "http://share.test/dav/new.txt", "complete-body")
		if response.Code != http.StatusCreated {
			t.Fatalf("conditional put status = %d, want 201 body=%q", response.Code, response.Body.String())
		}
		body, err := os.ReadFile(filepath.Join(owned, "new.txt"))
		if err != nil || string(body) != "complete-body" {
			t.Fatalf("created file = %q err=%v", body, err)
		}
	})

	t.Run("rejects an existing file without changing it", func(t *testing.T) {
		controller, owned := startShare(t, "")
		target := filepath.Join(owned, "existing.txt")
		if err := os.WriteFile(target, []byte("original-body"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o640); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		response := conditionalPut(t, controller, "http://share.test/dav/existing.txt", "replacement-body")
		if response.Code != http.StatusPreconditionFailed {
			t.Fatalf("conditional put status = %d, want 412 body=%q", response.Code, response.Body.String())
		}
		body, err := os.ReadFile(target)
		if err != nil || string(body) != "original-body" {
			t.Fatalf("existing file = %q err=%v", body, err)
		}
		after, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if after.Mode() != before.Mode() {
			t.Fatalf("existing file mode = %v, want %v", after.Mode(), before.Mode())
		}
	})

	t.Run("rejects an existing directory", func(t *testing.T) {
		controller, owned := startShare(t, "")
		target := filepath.Join(owned, "existing-dir")
		if err := os.Mkdir(target, 0o750); err != nil {
			t.Fatal(err)
		}
		response := conditionalPut(t, controller, "http://share.test/dav/existing-dir", "replacement-body")
		if response.Code != http.StatusPreconditionFailed {
			t.Fatalf("conditional put status = %d, want 412 body=%q", response.Code, response.Body.String())
		}
		info, err := os.Stat(target)
		if err != nil || !info.IsDir() {
			t.Fatalf("existing directory changed: info=%v err=%v", info, err)
		}
	})

	t.Run("other conditions retain ordinary overwrite behavior", func(t *testing.T) {
		tests := []struct {
			name   string
			values []string
		}{
			{name: "missing header"},
			{name: "other etag", values: []string{`"other-etag"`}},
			{name: "combined value", values: []string{`*, "other-etag"`}},
			{name: "repeated wildcard", values: []string{"*", "*"}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				controller, owned := startShare(t, "")
				target := filepath.Join(owned, "ordinary.txt")
				if err := os.WriteFile(target, []byte("old-body"), 0o600); err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPut, "http://share.test/dav/ordinary.txt", strings.NewReader("new-body"))
				for _, value := range test.values {
					request.Header.Add("If-None-Match", value)
				}
				setBearerAuth(request, testSharePassword)
				response := httptest.NewRecorder()
				controller.ServeHTTP(response, request)
				if response.Code != http.StatusCreated {
					t.Fatalf("put with If-None-Match %q status = %d, want 201 body=%q", test.values, response.Code, response.Body.String())
				}
				body, err := os.ReadFile(target)
				if err != nil || string(body) != "new-body" {
					t.Fatalf("overwritten file = %q err=%v", body, err)
				}
			})
		}
	})

	t.Run("missing parent remains a filesystem conflict", func(t *testing.T) {
		controller, owned := startShare(t, "")
		response := conditionalPut(t, controller, "http://share.test/dav/missing/child.txt", "body")
		if response.Code == http.StatusPreconditionFailed {
			t.Fatalf("missing parent was reported as 412 body=%q", response.Body.String())
		}
		if response.Code != http.StatusConflict {
			t.Fatalf("conditional put status = %d, want 409 body=%q", response.Code, response.Body.String())
		}
		if _, err := os.Stat(filepath.Join(owned, "missing", "child.txt")); !os.IsNotExist(err) {
			t.Fatalf("missing-parent put created a file: %v", err)
		}
	})

	t.Run("competing creates have one winner", func(t *testing.T) {
		owned := t.TempDir()
		handlers := make([]http.Handler, 2)
		for index := range handlers {
			handler, err := NewHandler(owned, testSharePassword)
			if err != nil {
				t.Fatal(err)
			}
			handlers[index] = handler
		}
		contents := []string{"first-body", "second-body"}
		responses := make([]*httptest.ResponseRecorder, len(handlers))
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range handlers {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				request := httptest.NewRequest(http.MethodPut, "http://share.test/dav/race.txt", strings.NewReader(contents[index]))
				request.Header.Set("If-None-Match", "*")
				setBearerAuth(request, testSharePassword)
				response := httptest.NewRecorder()
				handlers[index].ServeHTTP(response, request)
				responses[index] = response
			}(index)
		}
		close(start)
		wait.Wait()

		winner := -1
		for index, response := range responses {
			switch response.Code {
			case http.StatusCreated:
				if winner != -1 {
					t.Fatalf("multiple conditional creates succeeded: statuses=%d,%d", responses[0].Code, responses[1].Code)
				}
				winner = index
			case http.StatusPreconditionFailed:
			default:
				t.Fatalf("conditional create %d status = %d body=%q", index, response.Code, response.Body.String())
			}
		}
		if winner == -1 {
			t.Fatalf("no conditional create succeeded: statuses=%d,%d", responses[0].Code, responses[1].Code)
		}
		body, err := os.ReadFile(filepath.Join(owned, "race.txt"))
		if err != nil || string(body) != contents[winner] {
			t.Fatalf("winning file = %q, want %q err=%v", body, contents[winner], err)
		}
	})
}

func TestRootPathSwitchAndCloseKeepExternalFiles(t *testing.T) {
	owned := t.TempDir()
	external := t.TempDir()
	externalController, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, externalController, "external-root", testShareConfig(testSharePassword, external))
	if externalController.Status().Root != external {
		t.Fatalf("root = %q, want %q", externalController.Status().Root, external)
	}
	put := doShareRequest(t, externalController, http.MethodPut, "http://share.test/dav/placed.txt", testSharePassword, strings.NewReader("external-bytes"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "placed.txt")); !os.IsNotExist(err) {
		t.Fatal("default owned root was written while root_path was set")
	}
	if result := externalController.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "external-root"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(external, "placed.txt")); err != nil {
		t.Fatalf("stop deleted root_path file: %v", err)
	}
	ownedController, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, ownedController, "owned-root", testShareConfig(testSharePassword, ""))
	if ownedController.Status().Root != owned {
		t.Fatalf("owned root = %q, want %q", ownedController.Status().Root, owned)
	}
	listed := doShareRequest(t, ownedController, http.MethodGet, "http://share.test/api/list?path=/", testSharePassword, nil)
	if strings.Contains(listed.Body.String(), "placed.txt") {
		t.Fatalf("default share still listed root_path file: %q", listed.Body.String())
	}
	rewrite := doShareRequest(t, ownedController, http.MethodPut, "http://share.test/dav/placed.txt", testSharePassword, strings.NewReader("owned-bytes"))
	if rewrite.Code != http.StatusCreated {
		t.Fatalf("owned put status = %d body=%q", rewrite.Code, rewrite.Body.String())
	}
	body, err := os.ReadFile(filepath.Join(external, "placed.txt"))
	if err != nil || string(body) != "external-bytes" {
		t.Fatalf("root_path file changed after switching back: %q err=%v", body, err)
	}
	if result := ownedController.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "owned-root"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(external, "placed.txt")); err != nil {
		t.Fatalf("later stop deleted root_path file: %v", err)
	}
}

func TestPathEscapeIsRejected(t *testing.T) {
	controller, owned := startShare(t, "")
	outside := filepath.Join(filepath.Dir(owned), testOutsideName)
	if err := os.WriteFile(outside, []byte(testOutsideBody), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(owned, "safe.txt")
	if err := os.WriteFile(inside, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	escapes := []string{
		"../" + testOutsideName,
		"..\\" + testOutsideName,
		filepath.ToSlash(outside),
	}
	if volume := filepath.VolumeName(outside); volume != "" {
		escapes = append(escapes, outside)
	}
	for _, path := range escapes {
		download := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path="+url.QueryEscape(path), testSharePassword, nil)
		if download.Code < 400 {
			t.Fatalf("escape download %q status = %d", path, download.Code)
		}
		if strings.Contains(download.Body.String(), testOutsideBody) || strings.Contains(download.Body.String(), testOutsideName) {
			t.Fatalf("escape download leaked outside file: %q", download.Body.String())
		}
		mkdir := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/mkdir", testSharePassword, strings.NewReader(`{"path":`+jsonString(path+"/escaped-dir")+`}`))
		if mkdir.Code < 400 {
			t.Fatalf("escape mkdir %q status = %d body=%q", path, mkdir.Code, mkdir.Body.String())
		}
	}
	dav := doShareRequest(t, controller, http.MethodGet, "http://share.test/dav/../"+testOutsideName, testSharePassword, nil)
	if strings.Contains(dav.Body.String(), testOutsideBody) {
		t.Fatalf("dav escape leaked outside file: %q", dav.Body.String())
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/../escaped-put.txt", testSharePassword, strings.NewReader("nope"))
	if _, err := os.Stat(filepath.Join(filepath.Dir(owned), "escaped-put.txt")); !os.IsNotExist(err) {
		t.Fatalf("dav escape created outside file: %v", err)
	}
	_ = put
	body, err := os.ReadFile(outside)
	if err != nil || string(body) != testOutsideBody {
		t.Fatalf("outside file changed: %q err=%v", body, err)
	}
	safe := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path=safe.txt", testSharePassword, nil)
	if safe.Code != http.StatusOK || safe.Body.String() != "safe" {
		t.Fatalf("in-root download = %d %q", safe.Code, safe.Body.String())
	}
}

func TestDefaultRootIsNotFilesystemRootAndStopKeepsFiles(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "cwd-share")
	root := controller.Status().Root
	if root != filepath.Join(cwd, OwnedShareName) || isVolumeRoot(root) {
		t.Fatalf("share root = %q", root)
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/kept.txt", testSharePassword, strings.NewReader("keep"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "cwd-share"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(root, "kept.txt")); err != nil {
		t.Fatalf("stop deleted owned share file: %v", err)
	}
}

func startShare(t *testing.T, rootPath string) (*Controller, string) {
	t.Helper()
	owned := t.TempDir()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, controller, "share", testShareConfig(testSharePassword, rootPath))
	return controller, owned
}

func testShareConfig(password, rootPath string) []byte {
	payload := map[string]string{"password": password}
	if rootPath != "" {
		payload["root_path"] = rootPath
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func doShareRequest(t *testing.T, handler http.Handler, method, target, password string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, body)
	if password != "" {
		setBearerAuth(request, password)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func uploadShareFile(t *testing.T, handler http.Handler, dir, name, contents string) *httptest.ResponseRecorder {
	t.Helper()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writer.WriteField("path", dir); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://share.test/api/upload", &buffer)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	setBearerAuth(request, testSharePassword)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func setBearerAuth(request *http.Request, token string) {
	request.Header.Set("Authorization", "Bearer "+token)
}

func jsonString(value string) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(payload)
}
