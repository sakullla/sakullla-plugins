package web

import (
	"net/http"

	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

func init() {
	ss.BindPanel(func(controller *ss.Controller) http.Handler {
		return NewHandler(controller)
	})
}
