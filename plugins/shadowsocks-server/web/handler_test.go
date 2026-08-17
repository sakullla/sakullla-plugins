package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEmbeddedPageAndAssets(t *testing.T) {
	handler := NewHandler(nil)
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
	policy := httptest.NewRecorder()
	handler.ServeHTTP(policy, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(policy.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("embedded page lacks self-contained content policy")
	}
	page := bodies["/"]
	script := bodies["/app.js"]
	for _, fragment := range []string{
		"Shadowsocks 账号",
		"生成传统 SS 账号",
		"生成 SS2022 账号",
		"不必先建 L4",
		"无需打开 L4",
		"SIP002",
		"二维码",
		"对外监听",
		"id=\"create-ss\" method=\"post\"",
		"id=\"create-ss2022\" method=\"post\"",
		"data-action=\"rotate-server\"",
	} {
		if !strings.Contains(page, fragment) {
			t.Fatalf("panel page missing %q", fragment)
		}
	}
	if strings.Contains(page, "ui.schema") || strings.Contains(page, "plugin=") || strings.Contains(page, "订阅") {
		t.Fatal("panel page must not require config UI, SIP003, or a subscription")
	}
	for _, fragment := range []string{"api/panel", "api/accounts", "api/server-psk/rotate", "复制 SIP002 URI", "再启用"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("panel script missing %q", fragment)
		}
	}
	inactive := httptest.NewRecorder()
	handler.ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "/api/panel", nil))
	if inactive.Code != http.StatusServiceUnavailable || !strings.Contains(inactive.Body.String(), serviceNotReady) {
		t.Fatalf("inactive panel=%d %s", inactive.Code, inactive.Body.String())
	}
}

func TestUITreeMatchesEmbeddedAssets(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to locate web package")
	}
	uiDir := filepath.Join(filepath.Dir(file), "..", "ui")
	for _, name := range []string{"index.html", "app.js", "style.css"} {
		want, err := os.ReadFile(filepath.Join(uiDir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("ui/%s drifted from embedded web asset", name)
		}
	}
}
