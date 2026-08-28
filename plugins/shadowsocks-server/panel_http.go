package shadowsocksserver

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var panelUIAssets embed.FS

const (
	panelCSP          = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	serviceNotReady   = "服务未就绪"
	missingPublicHost = "缺少对外地址"
	disabledNoShare   = "停用账号不提供可导入 URI"
	shareUnavailable  = "分享不可用"
)

type panelHandler struct {
	controller *Controller
}

type createAccountRequest struct {
	Family string `json:"family"`
	Method string `json:"method"`
}

type rotateRequest struct {
	ExpectedVersion string `json:"expected_version"`
}

type listenView struct {
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	HostPort  string `json:"host_port,omitempty"`
	Source    string `json:"source,omitempty"`
	TCP       bool   `json:"tcp"`
	UDP       bool   `json:"udp"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type accountView struct {
	ID             string `json:"id"`
	Family         string `json:"family"`
	Method         string `json:"method"`
	Enabled        bool   `json:"enabled"`
	SecretVersion  string `json:"secret_version,omitempty"`
	ShareAvailable bool   `json:"share_available"`
	URI            string `json:"uri,omitempty"`
	QRContent      string `json:"qr_content,omitempty"`
	QRPNGBase64    string `json:"qr_png_base64,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type panelResponse struct {
	Ready            bool          `json:"ready"`
	Listen           listenView    `json:"listen"`
	Accounts         []accountView `json:"accounts"`
	ServerPSKVersion string        `json:"server_psk_version,omitempty"`
	Error            string        `json:"error,omitempty"`
}

func (c *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeadersWithPolicy(writer.Header(), panelCSP)
	if pluginsdk.ServePluginUIAsset(writer, request, panelUIAssets, "assets/ui") {
		return
	}
	(&panelHandler{controller: c}).serveAPI(writer, request)
}

func (handler *panelHandler) serveAPI(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	if path == "/api/panel" {
		handler.servePanel(writer, request)
		return
	}
	if path == "/api/accounts" {
		handler.serveCreate(writer, request)
		return
	}
	if path == "/api/server-psk/rotate" {
		handler.serveRotateServerPSK(writer, request)
		return
	}
	id, action, ok := parseAccountAPI(path)
	if !ok {
		http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
		return
	}
	handler.serveAccount(writer, request, id, action)
}

func parseAccountAPI(path string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/accounts/")
	if !found || rest == "" {
		return "", "", false
	}
	id, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(id)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	switch action {
	case "disable", "enable", "rotate", "qr.png":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func (handler *panelHandler) servePanel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writePanelJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	panel, err := handler.panel(request.Context())
	if err != nil {
		writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writePanelJSON(writer, http.StatusOK, panel)
}

func (handler *panelHandler) serveCreate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writePanelJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	var body createAccountRequest
	if err := readPanelJSON(request, &body); err != nil {
		writePanelJSON(writer, http.StatusBadRequest, panelResponse{Error: publicError(err)})
		return
	}
	if handler.controller == nil {
		writePanelJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	user, _, err := handler.controller.CreateAccount(request.Context(), AccountSpec{Family: body.Family, Method: body.Method})
	if err != nil {
		writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	view, err := handler.accountView(request.Context(), user.ID)
	if err != nil {
		writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writePanelJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
}

func (handler *panelHandler) serveRotateServerPSK(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writePanelJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	var body rotateRequest
	if err := readPanelJSON(request, &body); err != nil {
		writePanelJSON(writer, http.StatusBadRequest, panelResponse{Error: publicError(err)})
		return
	}
	if handler.controller == nil {
		writePanelJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	if body.ExpectedVersion == "" {
		panel, err := handler.panel(request.Context())
		if err != nil {
			writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		body.ExpectedVersion = panel.ServerPSKVersion
	}
	if _, err := handler.controller.RotateServerPSK(request.Context(), body.ExpectedVersion); err != nil {
		writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	panel, err := handler.panel(request.Context())
	if err != nil {
		writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writePanelJSON(writer, http.StatusOK, panel)
}

func (handler *panelHandler) serveAccount(writer http.ResponseWriter, request *http.Request, id, action string) {
	if handler.controller == nil {
		if action == "qr.png" {
			http.Error(writer, serviceNotReady, http.StatusServiceUnavailable)
			return
		}
		writePanelJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writePanelJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
			return
		}
		view, err := handler.accountView(request.Context(), id)
		if err != nil {
			writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		writePanelJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
	case "qr.png":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		view, err := handler.accountView(request.Context(), id)
		if err != nil {
			http.Error(writer, publicError(err), panelStatus(err))
			return
		}
		if !view.ShareAvailable || view.QRPNGBase64 == "" {
			http.Error(writer, view.Reason, http.StatusConflict)
			return
		}
		png, err := base64.StdEncoding.DecodeString(view.QRPNGBase64)
		if err != nil || len(png) == 0 {
			http.Error(writer, shareUnavailable, http.StatusConflict)
			return
		}
		writer.Header().Set("Content-Type", "image/png")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = writer.Write(png)
		}
	case "disable", "enable", "rotate":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			writePanelJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
			return
		}
		if err := handler.mutateAccount(request, id, action); err != nil {
			writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		view, err := handler.accountView(request.Context(), id)
		if err != nil {
			writePanelJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		writePanelJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
	default:
		http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
	}
}

func (handler *panelHandler) mutateAccount(request *http.Request, id, action string) error {
	switch action {
	case "disable":
		return handler.controller.DisableAccount(request.Context(), id)
	case "enable":
		return handler.controller.EnableAccount(request.Context(), id)
	case "rotate":
		var body rotateRequest
		if err := readPanelJSON(request, &body); err != nil {
			return err
		}
		if body.ExpectedVersion == "" {
			view, err := handler.accountView(request.Context(), id)
			if err != nil {
				return err
			}
			body.ExpectedVersion = view.SecretVersion
		}
		_, err := handler.controller.RotateUserKey(request.Context(), id, body.ExpectedVersion)
		return err
	default:
		return ErrInvalid
	}
}

func (handler *panelHandler) panel(ctx context.Context) (panelResponse, error) {
	if handler.controller == nil {
		return panelResponse{}, ErrRevoked
	}
	endpoint, err := handler.controller.ShareEndpoint(ctx)
	if err != nil {
		return panelResponse{}, err
	}
	shares, err := handler.controller.ListShares(ctx)
	if err != nil {
		return panelResponse{}, err
	}
	accounts := make([]accountView, 0, len(shares))
	for _, share := range shares {
		accounts = append(accounts, projectAccount(share))
	}
	version := ""
	if snapshotErr := handler.controller.Use(ctx, func(_ context.Context, service *Service) error {
		version = service.Snapshot().ServerPSKVersion
		return nil
	}); snapshotErr != nil {
		return panelResponse{}, snapshotErr
	}
	return panelResponse{Ready: true, Listen: projectListen(endpoint), Accounts: accounts, ServerPSKVersion: version}, nil
}

func (handler *panelHandler) accountView(ctx context.Context, id string) (accountView, error) {
	if handler.controller == nil {
		return accountView{}, ErrRevoked
	}
	share, err := handler.controller.ShareAccount(ctx, id)
	if err != nil {
		return accountView{}, err
	}
	return projectAccount(share), nil
}

func projectListen(endpoint ShareEndpoint) listenView {
	view := listenView{
		Host:      endpoint.Host,
		Port:      endpoint.Port,
		HostPort:  endpoint.HostPort,
		Source:    endpoint.Source,
		TCP:       endpoint.TCP,
		UDP:       endpoint.UDP,
		Available: endpoint.Available,
	}
	if !endpoint.Available {
		view.Reason = missingPublicHost
		if endpoint.Reason != "" && endpoint.Reason != MissingShareHost {
			view.Reason = endpoint.Reason
		}
	}
	return view
}

func projectAccount(share AccountShare) accountView {
	view := accountView{
		ID:            share.Account.ID,
		Family:        share.Account.Family,
		Method:        share.Account.Method,
		Enabled:       share.Account.Enabled,
		SecretVersion: share.Account.SecretVersion,
	}
	if !share.Account.Enabled {
		view.Reason = disabledNoShare
		return view
	}
	if !share.Available || share.Share.URI == "" || share.Share.QR.Content != share.Share.URI || len(share.Share.QR.PNG) == 0 {
		view.Reason = missingPublicHost
		if share.Reason != "" && share.Reason != MissingShareHost {
			view.Reason = share.Reason
		}
		if share.Reason == "share unavailable" {
			view.Reason = shareUnavailable
		}
		return view
	}
	view.ShareAvailable = true
	view.URI = share.Share.URI
	view.QRContent = share.Share.QR.Content
	view.QRPNGBase64 = base64.StdEncoding.EncodeToString(share.Share.QR.PNG)
	return view
}

func readPanelJSON(request *http.Request, dest any) error {
	if request.Body == nil {
		return nil
	}
	defer request.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(request.Body, 4096))
	if err != nil {
		return ErrInvalid
	}
	if len(payload) == 0 {
		return nil
	}
	if err = json.Unmarshal(payload, dest); err != nil {
		return ErrInvalid
	}
	return nil
}

func writePanelJSON(writer http.ResponseWriter, status int, body panelResponse) {
	writer.Header().Set("Cache-Control", "no-store")
	_ = pluginsdk.WritePluginUIJSON(writer, status, body)
}

func panelStatus(err error) int {
	switch {
	case errors.Is(err, ErrRevoked):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrDenied):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func publicError(err error) string {
	switch {
	case errors.Is(err, ErrRevoked):
		return serviceNotReady
	case errors.Is(err, ErrMissingShareHost):
		return missingPublicHost
	case errors.Is(err, ErrDenied):
		return "账号不存在或操作被拒绝"
	case errors.Is(err, ErrInvalid):
		return "请求无效"
	default:
		return "操作失败"
	}
}
