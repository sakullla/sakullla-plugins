package shadowsocksserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	duplicatePortText = "该节点已使用此端口"
	agentRequiredText = "请先选择一台在线节点"
	offlineText       = "该节点离线，不能新增或改动监听"
	executionText     = "该节点暂时无法执行监听"
	bindFailedText    = "节点绑定失败，请改端口后重试"
)

type executionView struct {
	AgentID string `json:"agent_id"`
	Online  bool   `json:"online"`
	Ready   bool   `json:"ready"`
}

type listenUserView struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Family         string `json:"family"`
	Method         string `json:"method"`
	Enabled        bool   `json:"enabled"`
	ShareAvailable bool   `json:"share_available"`
	URI            string `json:"uri,omitempty"`
	QRContent      string `json:"qr_content,omitempty"`
	QRPNGBase64    string `json:"qr_png_base64,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type listenAPIView struct {
	ID      string           `json:"id"`
	AgentID string           `json:"agent_id"`
	Port    int              `json:"port"`
	Method  string           `json:"method"`
	Family  string           `json:"family"`
	Bound   bool             `json:"bound"`
	Users   []listenUserView `json:"users"`
}

type listenDefaultsView struct {
	Method    string `json:"method"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	ServerPSK string `json:"server_psk,omitempty"`
}

type listenWriteRequest struct {
	AgentID   string `json:"agent_id"`
	ListenID  string `json:"listen_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Method    string `json:"method,omitempty"`
	Port      int    `json:"port,omitempty"`
	Password  string `json:"password,omitempty"`
	ServerPSK string `json:"server_psk,omitempty"`
}

type listenAPIResponse struct {
	Ready     bool                `json:"ready"`
	Listens   []listenAPIView     `json:"listens,omitempty"`
	Listen    *listenAPIView      `json:"listen,omitempty"`
	User      *listenUserView     `json:"user,omitempty"`
	Defaults  *listenDefaultsView `json:"defaults,omitempty"`
	Execution *executionView      `json:"execution,omitempty"`
	Error     string              `json:"error,omitempty"`
	Access    struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	} `json:"access,omitempty"`
}

func (c *Controller) serveControlAPI(writer http.ResponseWriter, request *http.Request) bool {
	path := request.URL.Path
	if path == "/api/execution" {
		c.serveExecution(writer, request)
		return true
	}
	if path == "/api/defaults" {
		c.serveDefaults(writer, request)
		return true
	}
	if path == "/api/listens" {
		c.serveListenCollection(writer, request)
		return true
	}
	if listenID, action, ok := parseListenAPI(path); ok {
		c.serveListenItem(writer, request, listenID, action)
		return true
	}
	if userID, action, ok := parseUserAPI(path); ok {
		c.serveUserItem(writer, request, userID, action)
		return true
	}
	return false
}

func parseListenAPI(path string) (listenID, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/listens/")
	if !found || rest == "" {
		return "", "", false
	}
	listenID, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(listenID)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	if action == "users" || action == "delete" {
		return decoded, action, true
	}
	return "", "", false
}

func parseUserAPI(path string) (userID, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/users/")
	if !found || rest == "" {
		return "", "", false
	}
	userID, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(userID)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	switch action {
	case "enable", "disable", "delete", "qr.png":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func (c *Controller) uiReady() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch != nil && c.epoch.live.Load()
}

func (c *Controller) uiIdentity(request *http.Request) (string, error) {
	actor, ok := pluginsdk.PluginUIActor(request)
	if !ok {
		return "", ErrDenied
	}
	return actor, nil
}

func (c *Controller) serveExecution(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
	if !validAgentID(agentID) {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: agentRequiredText})
		return
	}
	view := executionView{AgentID: agentID}
	report, err := c.ReportListen(request.Context(), agentID)
	if err == nil {
		view.Online = report.Online
		view.Ready = report.Online
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Execution: &view, Access: readWriteAccess()})
}

func (c *Controller) serveDefaults(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
	if !validAgentID(agentID) {
		writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: agentRequiredText})
		return
	}
	defaults, err := c.listenDefaults(agentID, DefaultSS2022Method)
	if err != nil {
		writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
		return
	}
	writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Defaults: &defaults, Access: readWriteAccess()})
}

func (c *Controller) serveListenCollection(writer http.ResponseWriter, request *http.Request) {
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
		if !validAgentID(agentID) {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: agentRequiredText})
			return
		}
		views, err := c.projectListens(request.Context(), agentID)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Listens: views, Access: readWriteAccess()})
	case http.MethodPost:
		body, err := decodeListenWrite(request)
		if err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
		view, err := c.createListen(request.Context(), body)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Listen: &view, Access: readWriteAccess()})
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
	}
}

func (c *Controller) serveListenItem(writer http.ResponseWriter, request *http.Request, listenID, action string) {
	if _, err := c.uiIdentity(request); err != nil {
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
			return
		}
		view, err := c.projectListen(request.Context(), listenID)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Listen: &view, Access: readWriteAccess()})
	case "users":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
			return
		}
		body, err := decodeListenWrite(request)
		if err != nil {
			writeListenJSON(writer, http.StatusBadRequest, listenAPIResponse{Error: publicListenError(ErrInvalid)})
			return
		}
		view, err := c.appendListenUser(request.Context(), listenID, body)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Listen: &view, Access: readWriteAccess()})
	case "delete":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
			return
		}
		body, _ := decodeListenWrite(request)
		if err := c.deleteListen(request.Context(), listenID, body.AgentID); err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Access: readWriteAccess()})
	default:
		http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
	}
}

func (c *Controller) serveUserItem(writer http.ResponseWriter, request *http.Request, userID, action string) {
	if _, err := c.uiIdentity(request); err != nil {
		if action == "qr.png" {
			http.Error(writer, "无权访问", http.StatusForbidden)
			return
		}
		writeListenJSON(writer, http.StatusForbidden, listenAPIResponse{Error: "无权访问"})
		return
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
			return
		}
		view, err := c.projectUser(request.Context(), userID)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, User: &view, Access: readWriteAccess()})
	case "qr.png":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		view, err := c.projectUser(request.Context(), userID)
		if err != nil {
			http.Error(writer, publicListenError(err), listenStatus(err))
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
	case "enable", "disable", "delete":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			writeListenJSON(writer, http.StatusMethodNotAllowed, listenAPIResponse{Error: "method not allowed"})
			return
		}
		body, _ := decodeListenWrite(request)
		var err error
		if action == "delete" {
			err = c.deleteUser(request.Context(), userID, body.AgentID)
		} else {
			err = c.setUserEnabled(request.Context(), userID, body.AgentID, action == "enable")
		}
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		if action == "delete" {
			writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, Access: readWriteAccess()})
			return
		}
		view, err := c.projectUser(request.Context(), userID)
		if err != nil {
			writeListenJSON(writer, listenStatus(err), listenAPIResponse{Error: publicListenError(err)})
			return
		}
		writeListenJSON(writer, http.StatusOK, listenAPIResponse{Ready: true, User: &view, Access: readWriteAccess()})
	default:
		http.Error(writer, "Shadowsocks 管理面板未找到该页面", http.StatusNotFound)
	}
}

func (c *Controller) requireMutableAgent(ctx context.Context, agentID string) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	if c == nil || c.listenHost == nil {
		return ErrExecutionUnavailable
	}
	report, err := c.ReportListen(ctx, agentID)
	if err != nil {
		if errors.Is(err, ErrAgentOffline) {
			return err
		}
		return ErrExecutionUnavailable
	}
	if !report.Online {
		return ErrAgentOffline
	}
	return nil
}

func (c *Controller) directory() Configuration {
	c.mu.Lock()
	published := c.published
	cfg := clone(c.configuration)
	c.mu.Unlock()
	if published != nil {
		return published.Snapshot()
	}
	return cfg
}

func (c *Controller) commitDirectory(next Configuration) error {
	if err := next.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	published := c.published
	c.configuration = clone(next)
	c.mu.Unlock()
	if published != nil {
		return published.commitDirectory(next)
	}
	return nil
}

func (c *Controller) secrets() *issuedSecrets {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.published != nil {
		return c.published.issuedSecrets()
	}
	if c.controlSecrets == nil {
		c.controlSecrets = &issuedSecrets{items: map[string]string{}}
	}
	return c.controlSecrets
}

func (c *Controller) putSecret(ref, version, material string) {
	if ref == "" || version == "" {
		return
	}
	c.secrets().put(ref, version, material)
}

func (c *Controller) resolveMaterial(ctx context.Context, ref, version string) ([]byte, error) {
	if stored, ok := c.secrets().lookup(ref, version); ok {
		return []byte(stored), nil
	}
	c.mu.Lock()
	published := c.published
	c.mu.Unlock()
	if published == nil {
		return nil, ErrDenied
	}
	return published.resolveSecret(ctx, ref, version)
}

func (c *Controller) listenDefaults(agentID, method string) (listenDefaultsView, error) {
	if method == "" {
		method = DefaultSS2022Method
	}
	if !SupportedMethod(method) {
		return listenDefaultsView{}, ErrInvalid
	}
	userID, err := NewAccountID()
	if err != nil {
		return listenDefaultsView{}, err
	}
	port, err := c.directory().NextListenPort(agentID)
	if err != nil {
		return listenDefaultsView{}, err
	}
	view := listenDefaultsView{Method: method, Name: DefaultUserName(userID), Port: port}
	if SS2022Method(method) {
		serverPSK, userPSK, genErr := GenerateSS2022Identity(method)
		if genErr != nil {
			return listenDefaultsView{}, genErr
		}
		view.ServerPSK, view.Password = serverPSK, userPSK
		return view, nil
	}
	password, err := GenerateLegacyPassword()
	if err != nil {
		return listenDefaultsView{}, err
	}
	view.Password = password
	return view, nil
}

func (c *Controller) createListen(ctx context.Context, body listenWriteRequest) (listenAPIView, error) {
	if err := c.requireMutableAgent(ctx, body.AgentID); err != nil {
		return listenAPIView{}, err
	}
	spec := ListenSpec{AgentID: body.AgentID, Name: strings.TrimSpace(body.Name), Method: strings.TrimSpace(body.Method), Port: body.Port, Password: body.Password, ServerPSK: body.ServerPSK}
	method, err := spec.resolveMethod()
	if err != nil {
		return listenAPIView{}, err
	}
	spec.Method = method
	userID, err := NewAccountID()
	if err != nil {
		return listenAPIView{}, err
	}
	user := User{ID: userID, Name: spec.Name, SecretRef: AccountSecretRef(userID), SecretVersion: InitialSecretVersion(), Enabled: true}
	if user.Name == "" {
		user.Name = DefaultUserName(userID)
	}
	password, serverPSK, err := mintListenSecrets(method, spec.ServerPSK, spec.Password)
	if err != nil {
		return listenAPIView{}, err
	}
	current := c.directory()
	serverRef, serverVersion := "", ""
	if SS2022Method(method) {
		listenID, idErr := NewListenID()
		if idErr != nil {
			return listenAPIView{}, idErr
		}
		spec.ListenID = listenID
		serverRef, serverVersion = ServerPSKSecretRefFor(listenID), InitialSecretVersion()
	}
	next, listener, user, err := current.CreateListen(spec, user, serverRef, serverVersion)
	if err != nil {
		return listenAPIView{}, err
	}
	previous := current
	c.putSecret(user.SecretRef, user.SecretVersion, password)
	if SS2022Method(method) {
		c.putSecret(listener.ServerSecretRef, listener.ServerSecretVersion, serverPSK)
	}
	if err = c.commitDirectory(next); err != nil {
		return listenAPIView{}, err
	}
	if err = c.applyAgentListens(ctx, body.AgentID); err != nil {
		_ = c.commitDirectory(previous)
		return listenAPIView{}, err
	}
	return c.projectListen(ctx, listener.ID)
}

func (c *Controller) appendListenUser(ctx context.Context, listenID string, body listenWriteRequest) (listenAPIView, error) {
	current := c.directory()
	listener, ok := current.Listen(listenID)
	if !ok {
		return listenAPIView{}, ErrDenied
	}
	agentID := strings.TrimSpace(body.AgentID)
	if agentID == "" {
		agentID = listener.AgentID
	}
	if agentID != listener.AgentID {
		return listenAPIView{}, ErrDenied
	}
	if err := c.requireMutableAgent(ctx, agentID); err != nil {
		return listenAPIView{}, err
	}
	if !SS2022Method(listener.Method) {
		return listenAPIView{}, ErrTraditionalMultiUser
	}
	userID, err := NewAccountID()
	if err != nil {
		return listenAPIView{}, err
	}
	user := User{ID: userID, Name: strings.TrimSpace(body.Name), SecretRef: AccountSecretRef(userID), SecretVersion: InitialSecretVersion(), Enabled: true}
	if user.Name == "" {
		user.Name = DefaultUserName(userID)
	}
	serverPSK, err := c.resolveMappedPSK(ctx, listener.Method, listener.ServerSecretRef, listener.ServerSecretVersion)
	if err != nil {
		return listenAPIView{}, err
	}
	password, _, err := mintListenSecrets(listener.Method, serverPSK, body.Password)
	if err != nil {
		return listenAPIView{}, err
	}
	next, _, user, err := current.AppendListenUser(listenID, user)
	if err != nil {
		return listenAPIView{}, err
	}
	previous := current
	c.putSecret(user.SecretRef, user.SecretVersion, password)
	if err = c.commitDirectory(next); err != nil {
		return listenAPIView{}, err
	}
	if err = c.applyAgentListens(ctx, agentID); err != nil {
		_ = c.commitDirectory(previous)
		return listenAPIView{}, err
	}
	return c.projectListen(ctx, listenID)
}

func (c *Controller) setUserEnabled(ctx context.Context, userID, agentID string, enabled bool) error {
	current := c.directory()
	listener, _, ok := current.userListener(userID)
	if !ok {
		return ErrDenied
	}
	if agentID == "" {
		agentID = listener.AgentID
	}
	if agentID != listener.AgentID {
		return ErrDenied
	}
	if err := c.requireMutableAgent(ctx, agentID); err != nil {
		return err
	}
	next, err := current.SetAccountEnabled(userID, enabled)
	if err != nil {
		return err
	}
	previous := current
	if err = c.commitDirectory(next); err != nil {
		return err
	}
	if err = c.applyAgentListens(ctx, agentID); err != nil {
		_ = c.commitDirectory(previous)
		return err
	}
	return nil
}

func (c *Controller) deleteUser(ctx context.Context, userID, agentID string) error {
	current := c.directory()
	listener, _, ok := current.userListener(userID)
	if !ok {
		return ErrDenied
	}
	if agentID == "" {
		agentID = listener.AgentID
	}
	if agentID != listener.AgentID {
		return ErrDenied
	}
	if err := c.requireMutableAgent(ctx, agentID); err != nil {
		return err
	}
	next, _, err := current.DeleteUser(userID)
	if err != nil {
		return err
	}
	previous := current
	if err = c.commitDirectory(next); err != nil {
		return err
	}
	if err = c.applyAgentListens(ctx, agentID); err != nil {
		_ = c.commitDirectory(previous)
		return err
	}
	return nil
}

func (c *Controller) deleteListen(ctx context.Context, listenID, agentID string) error {
	current := c.directory()
	listener, ok := current.Listen(listenID)
	if !ok {
		return ErrDenied
	}
	if agentID == "" {
		agentID = listener.AgentID
	}
	if agentID != listener.AgentID {
		return ErrDenied
	}
	if err := c.requireMutableAgent(ctx, agentID); err != nil {
		return err
	}
	next, _, err := current.DeleteListen(listenID)
	if err != nil {
		return err
	}
	previous := current
	if err = c.commitDirectory(next); err != nil {
		return err
	}
	if err = c.applyAgentListens(ctx, agentID); err != nil {
		_ = c.commitDirectory(previous)
		return err
	}
	return nil
}

func (c *Controller) applyAgentListens(ctx context.Context, agentID string) error {
	if err := c.requireMutableAgent(ctx, agentID); err != nil {
		return err
	}
	items, err := c.listenApplyItems(ctx, agentID)
	if err != nil {
		return err
	}
	if err = c.ApplyListen(ctx, agentID, items); err != nil {
		if errors.Is(err, ErrAgentOffline) || errors.Is(err, ErrListenBind) || errors.Is(err, ErrExecutionUnavailable) {
			return err
		}
		if errors.Is(err, ErrTypedHandlesUnavailable) {
			return ErrExecutionUnavailable
		}
		return ErrListenBind
	}
	return nil
}

func (c *Controller) listenApplyItems(ctx context.Context, agentID string) ([]ListenApplyItem, error) {
	snapshot := c.directory()
	items := make([]ListenApplyItem, 0)
	for _, listener := range snapshot.Listeners {
		if listener.AgentID != agentID {
			continue
		}
		item := ListenApplyItem{ID: listener.ID, Port: listener.Port, Method: listener.Method}
		if SS2022Method(listener.Method) && listener.ServerSecretRef != "" {
			serverPSK, err := c.resolveMappedPSK(ctx, listener.Method, listener.ServerSecretRef, listener.ServerSecretVersion)
			if err != nil {
				return nil, err
			}
			item.ServerPSK = serverPSK
		}
		for _, user := range listener.Users {
			applyUser := ListenApplyUser{ID: user.ID, Enabled: user.Enabled}
			if user.Enabled {
				password, err := c.sharePassword(ctx, listener, user)
				if err != nil {
					return nil, err
				}
				if SS2022Method(listener.Method) {
					if _, userPSK, ok := splitSS2022ClientPassword([]byte(password)); ok {
						applyUser.Password = string(userPSK)
					} else {
						applyUser.Password = password
					}
				} else {
					applyUser.Password = password
				}
			}
			item.Users = append(item.Users, applyUser)
		}
		items = append(items, item)
	}
	return items, nil
}

func (c *Controller) projectListens(ctx context.Context, agentID string) ([]listenAPIView, error) {
	snapshot := c.directory()
	node := c.shareNode(ctx, agentID)
	views := make([]listenAPIView, 0)
	for _, listener := range snapshot.ListenersForAgent(agentID) {
		views = append(views, c.projectListenView(ctx, listener, node))
	}
	return views, nil
}

func (c *Controller) projectListen(ctx context.Context, listenID string) (listenAPIView, error) {
	listener, ok := c.directory().Listen(listenID)
	if !ok {
		return listenAPIView{}, ErrDenied
	}
	return c.projectListenView(ctx, listener, c.shareNode(ctx, listener.AgentID)), nil
}

func (c *Controller) projectUser(ctx context.Context, userID string) (listenUserView, error) {
	listener, user, ok := c.directory().userListener(userID)
	if !ok {
		return listenUserView{}, ErrDenied
	}
	return c.projectUserView(ctx, listener, user, c.shareNode(ctx, listener.AgentID)), nil
}

func (c *Controller) projectListenView(ctx context.Context, listener ListenRule, node NodeAddresses) listenAPIView {
	users := make([]listenUserView, 0, len(listener.Users))
	for _, user := range listener.Users {
		users = append(users, c.projectUserView(ctx, listener, user, node))
	}
	bound := false
	if c.listenHost != nil {
		bound = c.listenHost.HasLiveListen(listener.AgentID, listener.ID)
	}
	return listenAPIView{
		ID:      listener.ID,
		AgentID: listener.AgentID,
		Port:    listener.Port,
		Method:  listener.Method,
		Family:  AccountFamilyOf(listener.Method),
		Bound:   bound,
		Users:   users,
	}
}

func (c *Controller) projectUserView(ctx context.Context, listener ListenRule, user User, node NodeAddresses) listenUserView {
	view := listenUserView{
		ID:      user.ID,
		Name:    user.Name,
		Family:  AccountFamilyOf(listener.Method),
		Method:  listener.Method,
		Enabled: user.Enabled,
	}
	if !user.Enabled {
		view.Reason = disabledNoShare
		return view
	}
	endpoint := ProjectShareEndpoint(ListenBinding{Port: listener.Port, TCP: true, UDP: true}, node)
	if !endpoint.Available {
		view.Reason = missingPublicHost
		if endpoint.Reason != "" && endpoint.Reason != MissingShareHost {
			view.Reason = endpoint.Reason
		}
		return view
	}
	password, err := c.sharePassword(ctx, listener, user)
	if err != nil {
		view.Reason = shareUnavailable
		return view
	}
	account := SIP002Account{Method: listener.Method, Host: endpoint.Host, Port: listener.Port, Name: user.Name}
	if SS2022Method(listener.Method) {
		server, identity, ok := splitSS2022ClientPassword([]byte(password))
		if !ok {
			view.Reason = shareUnavailable
			return view
		}
		account.ServerPSK, account.IdentityPSK = string(server), string(identity)
	} else {
		account.Password = password
	}
	share, err := BuildSIP002(account)
	if err != nil || share.URI == "" || share.QR.Content != share.URI || len(share.QR.PNG) == 0 {
		view.Reason = shareUnavailable
		return view
	}
	view.ShareAvailable = true
	view.URI = share.URI
	view.QRContent = share.QR.Content
	view.QRPNGBase64 = base64.StdEncoding.EncodeToString(share.QR.PNG)
	return view
}

func (c *Controller) shareNode(ctx context.Context, agentID string) NodeAddresses {
	if c.listenHost != nil && validAgentID(agentID) {
		if report, err := c.ReportListen(ctx, agentID); err == nil {
			if report.DDNS != "" || report.IPv4 != "" || report.IPv6 != "" {
				return NodeAddresses{DDNS: report.DDNS, IPv4: report.IPv4, IPv6: report.IPv6}
			}
		}
	}
	c.mu.Lock()
	published := c.published
	c.mu.Unlock()
	if published != nil {
		return published.NodeAddresses()
	}
	return NodeAddresses{}
}

func (c *Controller) sharePassword(ctx context.Context, listener ListenRule, user User) (string, error) {
	material, err := c.resolveMaterial(ctx, user.SecretRef, user.SecretVersion)
	if err != nil {
		return "", err
	}
	if !SS2022Method(listener.Method) {
		password := string(append([]byte(nil), material...))
		clear(material)
		return password, nil
	}
	if _, _, ok := splitSS2022ClientPassword(material); ok {
		password := string(append([]byte(nil), material...))
		clear(material)
		return password, nil
	}
	server, err := c.resolveMaterial(ctx, listener.ServerSecretRef, listener.ServerSecretVersion)
	if err != nil {
		clear(material)
		return "", err
	}
	password, err := SS2022ClientPassword(listener.Method, server, material)
	clear(material)
	clear(server)
	return password, err
}

func (c *Controller) resolveMappedPSK(ctx context.Context, method, ref, version string) (string, error) {
	material, err := c.resolveMaterial(ctx, ref, version)
	if err != nil {
		return "", err
	}
	mapped, err := MapSS2022PSK(method, string(material))
	clear(material)
	return mapped, err
}

func mintListenSecrets(method, serverIn, userIn string) (userMaterial, serverMaterial string, err error) {
	if !SupportedMethod(method) {
		return "", "", ErrInvalid
	}
	if !SS2022Method(method) {
		password := strings.TrimSpace(userIn)
		if password == "" {
			password, err = GenerateLegacyPassword()
			if err != nil {
				return "", "", err
			}
		}
		return password, "", nil
	}
	serverPSK := strings.TrimSpace(serverIn)
	userPSK := strings.TrimSpace(userIn)
	if serverPSK != "" {
		serverPSK, err = MapSS2022PSK(method, serverPSK)
		if err != nil {
			return "", "", err
		}
	}
	if userPSK != "" {
		userPSK, err = MapSS2022PSK(method, userPSK)
		if err != nil {
			return "", "", err
		}
	}
	if serverPSK != "" && userPSK != "" {
		if serverPSK == userPSK {
			return "", "", ErrInvalid
		}
		return userPSK, serverPSK, nil
	}
	for range 8 {
		genServer, genUser, genErr := GenerateSS2022Identity(method)
		if genErr != nil {
			return "", "", genErr
		}
		if serverPSK == "" {
			serverPSK = genServer
		}
		if userPSK == "" {
			userPSK = genUser
		}
		if serverPSK != userPSK {
			return userPSK, serverPSK, nil
		}
		if strings.TrimSpace(serverIn) != "" {
			userPSK = ""
		} else {
			serverPSK = ""
		}
	}
	return "", "", ErrInvalid
}

func decodeListenWrite(request *http.Request) (listenWriteRequest, error) {
	var body listenWriteRequest
	if request.Body == nil {
		return body, nil
	}
	defer request.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(request.Body, 4096))
	if err != nil {
		return listenWriteRequest{}, ErrInvalid
	}
	if len(payload) == 0 {
		return body, nil
	}
	if err = json.Unmarshal(payload, &body); err != nil {
		return listenWriteRequest{}, ErrInvalid
	}
	return body, nil
}

func writeListenJSON(writer http.ResponseWriter, status int, body listenAPIResponse) {
	writer.Header().Set("Cache-Control", "no-store")
	_ = pluginsdk.WritePluginUIJSON(writer, status, body)
}

func readWriteAccess() struct {
	CanRead  bool `json:"can_read"`
	CanWrite bool `json:"can_write"`
} {
	return struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	}{CanRead: true, CanWrite: true}
}

func listenStatus(err error) int {
	switch {
	case errors.Is(err, ErrRevoked), errors.Is(err, ErrTypedHandlesUnavailable), errors.Is(err, ErrExecutionUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrDenied):
		return http.StatusNotFound
	case errors.Is(err, ErrAgentOffline), errors.Is(err, ErrPortConflict), errors.Is(err, ErrListenBind):
		return http.StatusConflict
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrTraditionalMultiUser):
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func publicListenError(err error) string {
	switch {
	case errors.Is(err, ErrRevoked):
		return serviceNotReady
	case errors.Is(err, ErrAgentOffline):
		return offlineText
	case errors.Is(err, ErrExecutionUnavailable), errors.Is(err, ErrTypedHandlesUnavailable):
		return executionText
	case errors.Is(err, ErrPortConflict):
		return duplicatePortText
	case errors.Is(err, ErrListenBind):
		return bindFailedText
	case errors.Is(err, ErrTraditionalMultiUser):
		return ErrTraditionalMultiUser.Error()
	case errors.Is(err, ErrDenied):
		return "账号不存在或操作被拒绝"
	case errors.Is(err, ErrMissingShareHost):
		return missingPublicHost
	case errors.Is(err, ErrInvalid):
		return "请求无效"
	default:
		if err != nil && (err.Error() == duplicatePortText || err.Error() == agentRequiredText) {
			return err.Error()
		}
		return "操作失败"
	}
}
