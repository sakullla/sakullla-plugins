package shadowsocksserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControllerServesBoundPanel(t *testing.T) {
	var _ http.Handler = (*Controller)(nil)
	controller := &Controller{}
	missing := httptest.NewRecorder()
	controller.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/", nil))
	if missing.Code != http.StatusServiceUnavailable || !strings.Contains(missing.Body.String(), "Shadowsocks 管理页不可用") {
		t.Fatalf("unbound panel=%d %s", missing.Code, missing.Body.String())
	}
	BindPanel(func(*Controller) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		})
	})
	t.Cleanup(func() { panelFactory = nil })
	bound := httptest.NewRecorder()
	controller.ServeHTTP(bound, httptest.NewRequest(http.MethodGet, "/", nil))
	if bound.Code != http.StatusNoContent {
		t.Fatalf("bound panel=%d", bound.Code)
	}
}
