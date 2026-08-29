package shadowsocksserver

import (
	"embed"
	"net/http"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var panelUIAssets embed.FS

const (
	panelCSP          = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	serviceNotReady   = "服务未就绪"
	missingPublicHost = "缺少对外地址，暂时无法分享"
	disabledNoShare   = "停用后无法导入"
	shareUnavailable  = "暂时无法分享"
)

func (c *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeadersWithPolicy(writer.Header(), panelCSP)
	if pluginsdk.ServePluginUIAsset(writer, request, panelUIAssets, "assets/ui") {
		return
	}
	if !c.uiReady() {
		writeListenJSON(writer, http.StatusServiceUnavailable, listenAPIResponse{Error: serviceNotReady})
		return
	}
	if c.serveControlAPI(writer, request) {
		return
	}
	http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
}
