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
	page := recorder.Body.String()
	for _, want := range []string{
		`lang="zh-CN"`,
		"DNS over HTTPS",
		"/dns-query",
		"Chrome",
		"Edge",
		"Firefox",
		"Windows 11",
		"安全 DNS",
		"加密 DNS",
		`id="doh-url"`,
		`id="copy-doh-url"`,
		"复制地址",
		`href="/style.css"`,
		`src="/app.js"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("homepage missing %q", want)
		}
	}
	if strings.Contains(page, "私人 DNS") {
		t.Fatal("homepage treats Android private DNS as a fill-in for this URL")
	}
	if calls.Load() != 0 {
		t.Fatalf("homepage entered upstream calls=%d", calls.Load())
	}
}

func TestHomepageAssetsAndUnknownPaths(t *testing.T) {
	service, calls := homepageService(t)
	script := httptest.NewRecorder()
	service.ServeHTTP(script, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if script.Code != http.StatusOK {
		t.Fatalf("script status=%d", script.Code)
	}
	js := script.Body.String()
	for _, want := range []string{
		"window.location.origin",
		`replace(/\/$/, "")`,
		`"/dns-query"`,
		"navigator.clipboard",
		"#copy-doh-url",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("script missing %q", want)
		}
	}

	stylesheet := httptest.NewRecorder()
	service.ServeHTTP(stylesheet, httptest.NewRequest(http.MethodGet, "/style.css", nil))
	if stylesheet.Code != http.StatusOK {
		t.Fatalf("stylesheet status=%d", stylesheet.Code)
	}
	css := stylesheet.Body.String()
	for _, want := range []string{
		"@media (max-width: 720px)",
		"grid-template-columns: 1fr",
		"@media (min-width: 1920px)",
		"@media (min-width: 2560px)",
		"@media (min-width: 3840px)",
		"min(52rem",
		"overflow-wrap: anywhere",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("stylesheet missing viewport rule %q", want)
		}
	}

	index := httptest.NewRecorder()
	service.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), "DNS over HTTPS") {
		t.Fatalf("index.html status=%d", index.Code)
	}

	unknown := httptest.NewRecorder()
	service.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/resolve", nil))
	if unknown.Code != http.StatusNotFound || calls.Load() != 0 {
		t.Fatalf("unknown status=%d calls=%d", unknown.Code, calls.Load())
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
	if calls.Load() != 2 {
		t.Fatalf("invalid query hit upstream calls=%d", calls.Load())
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
