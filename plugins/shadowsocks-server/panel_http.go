package shadowsocksserver

import "net/http"

var panelFactory func(*Controller) http.Handler

// BindPanel registers the Host-mounted UI factory from package web so this
// package can ServeHTTP without importing web.
func BindPanel(factory func(*Controller) http.Handler) {
	if factory != nil {
		panelFactory = factory
	}
}

func (c *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if c == nil || panelFactory == nil {
		http.Error(writer, "Shadowsocks 管理页不可用", http.StatusServiceUnavailable)
		return
	}
	panelFactory(c).ServeHTTP(writer, request)
}
