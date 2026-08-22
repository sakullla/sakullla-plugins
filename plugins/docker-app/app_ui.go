package dockerapp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"embed"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

//go:embed assets/ui/*
var appUIAssets embed.FS

const (
	appActorHeader     = pluginsdk.HeaderPluginActor
	appOperationHeader = pluginsdk.HeaderPluginOperationKey
)

type appView struct {
	ID      string      `json:"id"`
	AgentID string      `json:"agent_id,omitempty"`
	Name    string      `json:"name"`
	Status  string      `json:"status"`
	Version string      `json:"version"`
	Compose string      `json:"compose,omitempty"`
	Ports   []uint16    `json:"ports,omitempty"`
	Actions []OpsAction `json:"actions,omitempty"`
}

type appWriteRequest struct {
	ID         string `json:"id"`
	AgentID    string `json:"agent_id"`
	Compose    string `json:"compose"`
	AutoUpdate bool   `json:"auto_update"`
	Confirm    string `json:"confirm"`
	Domain     string `json:"domain"`
	Port       uint16 `json:"port"`
	Service    string `json:"service"`
}

type installCommandView struct {
	Script     string `json:"script"`
	DaemonJSON string `json:"daemon_json,omitempty"`
}

type engineAPIView struct {
	AgentID string              `json:"agent_id"`
	Online  bool                `json:"online"`
	Ready   bool                `json:"ready"`
	Version string              `json:"version,omitempty"`
	Command *installCommandView `json:"command,omitempty"`
}

type appAPIResponse struct {
	Apps   []appView      `json:"apps,omitempty"`
	App    *appView       `json:"app,omitempty"`
	Logs   string         `json:"logs,omitempty"`
	Error  string         `json:"error,omitempty"`
	Engine *engineAPIView `json:"engine,omitempty"`
	Access struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	} `json:"access,omitempty"`
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	if pluginsdk.ServePluginUIAsset(writer, request, appUIAssets, "assets/ui") {
		return
	}
	path := request.URL.Path
	if !controller.uiReady() {
		writeAppJSON(writer, http.StatusServiceUnavailable, appAPIResponse{Error: ErrTypedHandlesUnavailable.Error()})
		return
	}
	if path == "/api/engine" {
		controller.serveEngine(writer, request)
		return
	}
	if path == "/api/apps" {
		controller.serveAppCollection(writer, request)
		return
	}
	appID, action, ok := parseAppAPIPath(path)
	if !ok {
		http.Error(writer, "Docker 应用页未找到", http.StatusNotFound)
		return
	}
	controller.serveAppItem(writer, request, appID, action)
}

func (controller *Controller) uiReady() bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.epoch != nil && controller.epoch.live.Load()
}

func (controller *Controller) serveEngine(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
		return
	}
	agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
	if !validAgentID(agentID) {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "agent_id is required"})
		return
	}
	report, err := controller.observeAgent(request.Context(), agentID)
	if err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
		return
	}
	status := ProjectEngine(ObservationFromReport(report))
	view := engineAPIView{AgentID: agentID, Online: report.Online, Ready: report.Online && status.Ready, Version: status.Version}
	if !view.Ready {
		command, commandErr := InstallCommand(controller.RegistryMirror())
		if commandErr != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: commandErr.Error()})
			return
		}
		view.Command = &installCommandView{Script: command.Script, DaemonJSON: command.DaemonJSON}
	}
	writeAppJSON(writer, http.StatusOK, appAPIResponse{Engine: &view, Access: struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	}{CanRead: true, CanWrite: true}})
}

func (controller *Controller) serveAppCollection(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		if _, err := controller.uiIdentity(request); err != nil {
			writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
			return
		}
		agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(agentID), Access: struct {
			CanRead  bool `json:"can_read"`
			CanWrite bool `json:"can_write"`
		}{CanRead: true, CanWrite: true}})
	case http.MethodPost:
		if _, err := controller.uiIdentity(request); err != nil {
			writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
			return
		}
		body, err := decodeAppWrite(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrInvalidCompose.Error()})
			return
		}
		agentID := strings.TrimSpace(body.AgentID)
		if !validAgentID(agentID) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "agent_id is required"})
			return
		}
		report, err := controller.observeAgent(request.Context(), agentID)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		generation := controller.lifecycleGeneration()
		next, err := DeployComposeAppForAgent(request.Context(), controller.Apps(), ComposeDeploySpec{
			AppID: body.ID, Generation: generation, Compose: body.Compose,
		}, report, controller.uiApply, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		for index := range next {
			if next[index].ID == body.ID {
				next[index].AutoUpdate = cloneBool(&body.AutoUpdate)
				next[index].AgentID = agentID
			}
		}
		controller.replaceApps(next)
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(agentID)})
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
	}
}

func (controller *Controller) serveAppItem(writer http.ResponseWriter, request *http.Request, appID, action string) {
	if request.Method != http.MethodPost && action != "get" {
		writer.Header().Set("Allow", http.MethodPost)
		writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
		return
	}
	app, ok := controller.appByID(appID)
	if !ok {
		writeAppJSON(writer, http.StatusNotFound, appAPIResponse{Error: "app is unknown"})
		return
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
			return
		}
		view := projectAppView(app)
		writeAppJSON(writer, http.StatusOK, appAPIResponse{App: &view})
	case "delete":
		body, _ := decodeAppWrite(request)
		next, err := DeleteManagedApp(request.Context(), controller.Apps(), appID, body.Confirm == appID, controller.uiRemove, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		controller.replaceApps(next)
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(app.AgentID)})
	case "start":
		if err := StartManaged(request.Context(), app, controller.uiStart, controller.uiAuditor); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(app.AgentID)})
	case "restart":
		if err := RestartManaged(request.Context(), app, controller.uiRestart, controller.uiAuditor); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(app.AgentID)})
	case "http-rule":
		body, err := decodeAppWrite(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrEmptyIngressDomain.Error()})
			return
		}
		_, err = CreateHTTPRuleFromPublishedPort(request.Context(), controller.uiHTTPRule, nil, app, nil, body.Domain, body.Port, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Apps: controller.projectAppViews(app.AgentID)})
	case "logs":
		body, _ := decodeAppWrite(request)
		service := body.Service
		if service == "" {
			service = request.URL.Query().Get("service")
		}
		text, err := ReadServiceLogs(request.Context(), app, service, controller.uiLogs, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppError(err)})
			return
		}
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Logs: text})
	default:
		http.Error(writer, "Docker 应用页未找到", http.StatusNotFound)
	}
}

func (controller *Controller) uiIdentity(request *http.Request) (string, error) {
	actor, ok := pluginsdk.PluginUIActor(request)
	if !ok {
		return "", ErrUnauthorized
	}
	return actor, nil
}

func (controller *Controller) lifecycleGeneration() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.epoch == nil {
		return ""
	}
	return controller.epoch.generation
}

func (controller *Controller) replaceApps(apps []App) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.apps = cloneApps(apps)
}

func (controller *Controller) appByID(appID string) (App, bool) {
	for _, app := range controller.Apps() {
		if app.ID == appID {
			return app, true
		}
	}
	return App{}, false
}

func (controller *Controller) projectAppViews(agentID string) []appView {
	apps := controller.Apps()
	views := make([]appView, 0, len(apps))
	for _, app := range apps {
		if agentID != "" && app.AgentID != agentID {
			continue
		}
		views = append(views, projectAppView(app))
	}
	return views
}

func projectAppView(app App) appView {
	document := ProjectOpsDocument(app, AppStatusRunning)
	ports, _ := ListPublishedPorts(app, nil)
	return appView{
		ID: app.ID, AgentID: app.AgentID, Name: document.Name, Status: document.Status, Version: document.Version,
		Compose: app.Compose, Ports: ports, Actions: document.Actions,
	}
}

func parseAppAPIPath(path string) (appID, action string, ok bool) {
	rest, found := strings.CutPrefix(path, "/api/apps/")
	if !found || rest == "" {
		return "", "", false
	}
	appID, action, cut := strings.Cut(rest, "/")
	decoded, err := url.PathUnescape(appID)
	if err != nil || decoded == "" {
		return "", "", false
	}
	if !cut {
		return decoded, "get", true
	}
	switch action {
	case "delete", "start", "restart", "http-rule", "logs":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func decodeAppWrite(request *http.Request) (appWriteRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, MaxConfigBytes))
	decoder.DisallowUnknownFields()
	var body appWriteRequest
	if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return appWriteRequest{}, err
	}
	return body, nil
}

func writeAppJSON(writer http.ResponseWriter, status int, payload appAPIResponse) {
	_ = pluginsdk.WritePluginUIJSON(writer, status, payload)
}

func appStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, ErrDeleteUnconfirmed), errors.Is(err, ErrEmptyIngressDomain), errors.Is(err, ErrInvalidCompose), errors.Is(err, ErrMissingComposeImage), errors.Is(err, ErrNoPublishedPort), errors.Is(err, ErrUnknownService):
		return http.StatusBadRequest
	case errors.Is(err, ErrAgentOffline):
		return http.StatusConflict
	case errors.Is(err, ErrEngineNotReady), errors.Is(err, ErrTypedHandlesUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func publicAppError(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return ErrUnauthorized.Error()
	case errors.Is(err, ErrDeleteUnconfirmed):
		return ErrDeleteUnconfirmed.Error()
	case errors.Is(err, ErrEmptyIngressDomain):
		return ErrEmptyIngressDomain.Error()
	case errors.Is(err, ErrInvalidCompose), errors.Is(err, ErrMissingComposeImage):
		return err.Error()
	case errors.Is(err, ErrNoPublishedPort):
		return ErrNoPublishedPort.Error()
	case errors.Is(err, ErrUnknownService):
		return ErrUnknownService.Error()
	case errors.Is(err, ErrEngineNotReady):
		return ErrEngineNotReady.Error()
	case errors.Is(err, ErrAgentOffline):
		return ErrAgentOffline.Error()
	case errors.Is(err, ErrTypedHandlesUnavailable):
		return ErrTypedHandlesUnavailable.Error()
	default:
		return ErrOperationFailed.Error()
	}
}
