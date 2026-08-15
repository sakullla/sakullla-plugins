package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebEmbeddedPageAndAssets(t *testing.T) {
	handler := NewHandler()
	for _, route := range []string{"/", "/app.js", "/style.css"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("embedded route %q failed: status=%d", route, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "http://") || strings.Contains(recorder.Body.String(), "https://") {
			t.Fatalf("embedded asset %q contains an external absolute dependency", route)
		}
	}
	if policy := httptest.NewRecorder(); func() bool {
		handler.ServeHTTP(policy, httptest.NewRequest(http.MethodGet, "/", nil))
		return !strings.Contains(policy.Header().Get("Content-Security-Policy"), "default-src 'self'")
	}() {
		t.Fatal("embedded page lacks self-contained content policy")
	}
}
