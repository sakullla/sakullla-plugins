// Package web serves the Shadowsocks administrator panel.
package web

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

	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

//go:embed index.html app.js style.css
var assets embed.FS

const (
	panelCSP          = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	serviceNotReady   = "服务未就绪"
	missingPublicHost = "缺少对外地址"
	disabledNoShare   = "停用账号不提供可导入 URI"
	shareUnavailable  = "分享不可用"
)

type Handler struct {
	controller *ss.Controller
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

func NewHandler(controller *ss.Controller) *Handler {
	return &Handler{controller: controller}
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Security-Policy", panelCSP)
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	path := request.URL.Path
	if path == "/style.css" || path == "/app.js" || path == "/index.html" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(writer, request, assets, strings.TrimPrefix(path, "/"))
		return
	}
	if path == "/" || path == "" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFileFS(writer, request, assets, "index.html")
		return
	}
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

func (handler *Handler) servePanel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	panel, err := handler.panel(request.Context())
	if err != nil {
		writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writeJSON(writer, http.StatusOK, panel)
}

func (handler *Handler) serveCreate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	var body createAccountRequest
	if err := readJSON(request, &body); err != nil {
		writeJSON(writer, http.StatusBadRequest, panelResponse{Error: publicError(err)})
		return
	}
	if handler.controller == nil {
		writeJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	user, _, err := handler.controller.CreateAccount(request.Context(), ss.AccountSpec{Family: body.Family, Method: body.Method})
	if err != nil {
		writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	view, err := handler.accountView(request.Context(), user.ID)
	if err != nil {
		writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writeJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
}

func (handler *Handler) serveRotateServerPSK(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
		return
	}
	var body rotateRequest
	if err := readJSON(request, &body); err != nil {
		writeJSON(writer, http.StatusBadRequest, panelResponse{Error: publicError(err)})
		return
	}
	if handler.controller == nil {
		writeJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	if body.ExpectedVersion == "" {
		panel, err := handler.panel(request.Context())
		if err != nil {
			writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		body.ExpectedVersion = panel.ServerPSKVersion
	}
	if _, err := handler.controller.RotateServerPSK(request.Context(), body.ExpectedVersion); err != nil {
		writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	panel, err := handler.panel(request.Context())
	if err != nil {
		writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
		return
	}
	writeJSON(writer, http.StatusOK, panel)
}

func (handler *Handler) serveAccount(writer http.ResponseWriter, request *http.Request, id, action string) {
	if handler.controller == nil {
		if action == "qr.png" {
			http.Error(writer, serviceNotReady, http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusServiceUnavailable, panelResponse{Error: serviceNotReady})
		return
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
			return
		}
		view, err := handler.accountView(request.Context(), id)
		if err != nil {
			writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		writeJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
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
			writeJSON(writer, http.StatusMethodNotAllowed, panelResponse{Error: "method not allowed"})
			return
		}
		if err := handler.mutateAccount(request, id, action); err != nil {
			writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		view, err := handler.accountView(request.Context(), id)
		if err != nil {
			writeJSON(writer, panelStatus(err), panelResponse{Error: publicError(err)})
			return
		}
		writeJSON(writer, http.StatusOK, panelResponse{Ready: true, Accounts: []accountView{view}})
	default:
		http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
	}
}

func (handler *Handler) mutateAccount(request *http.Request, id, action string) error {
	switch action {
	case "disable":
		return handler.controller.DisableAccount(request.Context(), id)
	case "enable":
		return handler.controller.EnableAccount(request.Context(), id)
	case "rotate":
		var body rotateRequest
		if err := readJSON(request, &body); err != nil {
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
		return ss.ErrInvalid
	}
}

func (handler *Handler) panel(ctx context.Context) (panelResponse, error) {
	if handler.controller == nil {
		return panelResponse{}, ss.ErrRevoked
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
	if snapshotErr := handler.controller.Use(ctx, func(_ context.Context, service *ss.Service) error {
		version = service.Snapshot().ServerPSKVersion
		return nil
	}); snapshotErr != nil {
		return panelResponse{}, snapshotErr
	}
	return panelResponse{Ready: true, Listen: projectListen(endpoint), Accounts: accounts, ServerPSKVersion: version}, nil
}

func (handler *Handler) accountView(ctx context.Context, id string) (accountView, error) {
	if handler.controller == nil {
		return accountView{}, ss.ErrRevoked
	}
	share, err := handler.controller.ShareAccount(ctx, id)
	if err != nil {
		return accountView{}, err
	}
	return projectAccount(share), nil
}

func projectListen(endpoint ss.ShareEndpoint) listenView {
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
		if endpoint.Reason != "" && endpoint.Reason != ss.MissingShareHost {
			view.Reason = endpoint.Reason
		}
	}
	return view
}

func projectAccount(share ss.AccountShare) accountView {
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
		if share.Reason != "" && share.Reason != ss.MissingShareHost {
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

func readJSON(request *http.Request, dest any) error {
	if request.Body == nil {
		return nil
	}
	defer request.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(request.Body, 4096))
	if err != nil {
		return ss.ErrInvalid
	}
	if len(payload) == 0 {
		return nil
	}
	if err = json.Unmarshal(payload, dest); err != nil {
		return ss.ErrInvalid
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, body panelResponse) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func panelStatus(err error) int {
	switch {
	case errors.Is(err, ss.ErrRevoked):
		return http.StatusServiceUnavailable
	case errors.Is(err, ss.ErrDenied):
		return http.StatusNotFound
	case errors.Is(err, ss.ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func publicError(err error) string {
	switch {
	case errors.Is(err, ss.ErrRevoked):
		return serviceNotReady
	case errors.Is(err, ss.ErrMissingShareHost):
		return missingPublicHost
	case errors.Is(err, ss.ErrDenied):
		return "账号不存在或操作被拒绝"
	case errors.Is(err, ss.ErrInvalid):
		return "请求无效"
	default:
		return "操作失败"
	}
}
