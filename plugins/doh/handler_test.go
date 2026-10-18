package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestHomepageServesChineseGuideWithoutDNS(t *testing.T) {
	service, calls := homepageService(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Accept", "application/dns-message")
	service.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	contentType := recorder.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("content-type=%q", contentType)
	}
	if strings.Contains(contentType, "application/dns-message") {
		t.Fatal("homepage returned DNS media type")
	}
	assertSelfOnlyUIHeaders(t, recorder)
	page := recorder.Body.String()
	for _, want := range []string{
		`lang="zh-CN"`,
		`data-theme="light"`,
		`data-theme-mode="standalone"`,
		`data-theme-key="doh.theme"`,
		"DNS over HTTPS",
		"/dns-query",
		"Chrome",
		"Edge",
		"Windows 11",
		"安全 DNS",
		"加密 DNS",
		`id="doh-url"`,
		`id="copy-doh-url"`,
		`id="copy-status"`,
		"复制地址",
		`href="ui-kit.css"`,
		`src="ui-kit.js"`,
		`href="style.css"`,
		`src="app.js"`,
		"<details",
		"ui-help",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("homepage missing %q", want)
		}
	}
	for _, banned := range []string{"私人 DNS", `<style`, "onclick=", `src="http`, `href="http`} {
		if strings.Contains(page, banned) {
			t.Fatalf("homepage must not contain %q", banned)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("homepage entered upstream calls=%d", calls.Load())
	}
}

func TestHomepageAssetsAndUnknownPaths(t *testing.T) {
	service, calls := homepageService(t)

	script := servePageAsset(t, service, "/app.js", "text/javascript")
	js := script.Body.String()
	for _, want := range []string{
		"window.location.origin",
		"window.location.pathname",
		`"/dns-query"`,
		"navigator.clipboard",
		"#copy-doh-url",
		"NREUI.copyText",
		"已复制地址。",
		"复制失败，请手动选择地址。",
		"selectUrl",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("script missing %q", want)
		}
	}

	stylesheet := servePageAsset(t, service, "/style.css", "text/css")
	css := stylesheet.Body.String()
	for _, want := range []string{
		"var(--ui-primary-soft",
		"var(--ui-text-secondary",
		"var(--ui-danger-text",
		"overflow-wrap: anywhere",
		"@media (max-width: 720px)",
		"@media (max-width: 480px)",
		".doh-endpoint__value",
		".doh-help",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("stylesheet missing %q", want)
		}
	}
	if strings.Contains(css, "[data-theme=") {
		t.Fatal("page stylesheet must not own theme palettes; use ui-kit tokens")
	}
	if strings.Contains(css, "#d94880") || strings.Contains(css, "#f4a0c0") || strings.Contains(css, "#f5f4f2") {
		t.Fatal("stylesheet still contains sakura theme colors")
	}

	kitCSS := servePageAsset(t, service, "/ui-kit.css", "text/css")
	for _, want := range []string{`[data-theme="fresh-green"]`, `[data-theme="dark"]`, "--ui-primary:", ".ui-help"} {
		if !strings.Contains(kitCSS.Body.String(), want) {
			t.Fatalf("ui-kit.css missing %q", want)
		}
	}
	kitJS := servePageAsset(t, service, "/ui-kit.js", "text/javascript")
	for _, want := range []string{"NREUI", "data-theme-mode", "resolveTheme", "copyText"} {
		if !strings.Contains(kitJS.Body.String(), want) {
			t.Fatalf("ui-kit.js missing %q", want)
		}
	}

	index := servePageAsset(t, service, "/index.html", "text/html")
	if !strings.Contains(index.Body.String(), "DNS over HTTPS") {
		t.Fatal("index.html served an unexpected page")
	}

	prefixed := servePageAsset(t, service, "/doh/", "text/html")
	if !strings.Contains(prefixed.Body.String(), "DNS over HTTPS") {
		t.Fatalf("prefixed homepage status=%d", prefixed.Code)
	}
	redirect := httptest.NewRecorder()
	service.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/doh", nil))
	if redirect.Code != http.StatusPermanentRedirect || redirect.Header().Get("Location") != "/doh/" {
		t.Fatalf("prefix redirect status=%d location=%q", redirect.Code, redirect.Header().Get("Location"))
	}
	prefixedKit := servePageAsset(t, service, "/doh/ui-kit.css", "text/css")
	if !strings.Contains(prefixedKit.Body.String(), "--ui-primary:") {
		t.Fatal("prefixed ui-kit.css served an unexpected body")
	}
	prefixedScript := servePageAsset(t, service, "/doh/app.js", "text/javascript")
	if !strings.Contains(prefixedScript.Body.String(), "window.location.pathname") {
		t.Fatalf("prefixed script status=%d", prefixedScript.Code)
	}

	post := httptest.NewRecorder()
	service.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(nil)))
	if post.Code != http.StatusMethodNotAllowed || calls.Load() != 0 {
		t.Fatalf("POST / status=%d calls=%d", post.Code, calls.Load())
	}
}

func TestDNSQueryPathStillRFC8484(t *testing.T) {
	service, calls := homepageService(t)

	get := httptest.NewRecorder()
	service.ServeHTTP(get, homepageDNSRequest(http.MethodGet, homepageDNSQuery(3, "open-get.example", 1)))
	if get.Code != http.StatusOK || get.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("GET /dns-query status=%d type=%q", get.Code, get.Header().Get("Content-Type"))
	}

	post := httptest.NewRecorder()
	service.ServeHTTP(post, homepageDNSRequest(http.MethodPost, homepageDNSQuery(4, "open-post.example", 1)))
	if post.Code != http.StatusOK || post.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("POST /dns-query status=%d type=%q", post.Code, post.Header().Get("Content-Type"))
	}
	if calls.Load() != 2 {
		t.Fatalf("resolver calls=%d", calls.Load())
	}

	invalid := httptest.NewRecorder()
	service.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/dns-query", nil))
	if invalid.Code < 400 || invalid.Code >= 500 || !strings.Contains(invalid.Body.String(), "Bad Request") {
		t.Fatalf("invalid /dns-query status=%d body=%q", invalid.Code, invalid.Body.String())
	}

	prefixed := homepageDNSRequest(http.MethodPost, homepageDNSQuery(5, "prefixed.example", 1))
	prefixed.URL.Path = "/doh/dns-query"
	prefixedPost := httptest.NewRecorder()
	service.ServeHTTP(prefixedPost, prefixed)
	if prefixedPost.Code != http.StatusOK || prefixedPost.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("POST /doh/dns-query status=%d type=%q", prefixedPost.Code, prefixedPost.Header().Get("Content-Type"))
	}
	if calls.Load() != 3 {
		t.Fatalf("resolver calls=%d", calls.Load())
	}
}

func TestClassifyPublicPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path     string
		kind     string
		redirect string
	}{
		{path: "/", kind: publicPathHTML},
		{path: "/index.html", kind: publicPathHTML},
		{path: "/app.js", kind: publicPathJS},
		{path: "/style.css", kind: publicPathCSS},
		{path: "/ui-kit.js", kind: publicPathKitJS},
		{path: "/ui-kit.css", kind: publicPathKitCSS},
		{path: "/dns-query", kind: publicPathDNS},
		{path: "/doh", kind: publicPathHTML, redirect: "/doh/"},
		{path: "/doh/", kind: publicPathHTML},
		{path: "/doh/index.html", kind: publicPathHTML},
		{path: "/doh/app.js", kind: publicPathJS},
		{path: "/doh/style.css", kind: publicPathCSS},
		{path: "/doh/ui-kit.js", kind: publicPathKitJS},
		{path: "/doh/ui-kit.css", kind: publicPathKitCSS},
		{path: "/doh/dns-query", kind: publicPathDNS},
		{path: "/gateway/v1/dns-query", kind: publicPathDNS},
	}
	for _, test := range cases {
		kind, redirect := classifyPublicPath(test.path)
		if kind != test.kind || redirect != test.redirect {
			t.Fatalf("path %q kind=%q redirect=%q want %q %q", test.path, kind, redirect, test.kind, test.redirect)
		}
	}
}

func TestPluginYAMLHasNoControlPlaneUI(t *testing.T) {
	data, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, banned := range []string{"ui.route", "ui_route_id", "ui.schema", "resource.group"} {
		if strings.Contains(text, banned) {
			t.Fatalf("plugin.yaml must not declare %q", banned)
		}
	}
}

func servePageAsset(t *testing.T, service *Service, target, wantContentType string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s status=%d", target, recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, wantContentType) {
		t.Fatalf("%s content-type=%q want prefix %q", target, got, wantContentType)
	}
	assertSelfOnlyUIHeaders(t, recorder)
	return recorder
}

func assertSelfOnlyUIHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got := recorder.Header().Get("Content-Security-Policy"); got != pluginsdk.PluginUIContentSecurityPolicy {
		t.Fatalf("content-security-policy=%q", got)
	}
	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("referrer-policy=%q", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x-content-type-options=%q", got)
	}
}

func homepageService(t *testing.T) (*Service, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	service, err := NewService(ConfigurationFromPlugin(PluginConfig{}), RuntimeAdapters{
		Resolver: ResolverFunc(func(_ context.Context, request ResolveRequest) ([]byte, error) {
			calls.Add(1)
			return homepagePositiveResponse(request.DNSMessage), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, &calls
}

func homepageDNSRequest(method string, query []byte) *http.Request {
	target := DNSQueryPath
	var body []byte
	if method == http.MethodGet {
		target += "?dns=" + base64.RawURLEncoding.EncodeToString(query)
	} else {
		body = query
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Accept", "application/dns-message")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/dns-message")
	}
	return request
}

func homepageDNSQuery(id uint16, name string, qtype uint16) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:2], id)
	binary.BigEndian.PutUint16(wire[2:4], 0x0100)
	binary.BigEndian.PutUint16(wire[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return wire
}

func homepagePositiveResponse(query []byte) []byte {
	offset := 12
	for offset < len(query) && query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	questionEnd := offset + 5
	response := append([]byte(nil), query[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	return append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
}
