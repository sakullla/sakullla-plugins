package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	ID       string            `json:"id"`
	AgentID  string            `json:"agent_id,omitempty"`
	Name     string            `json:"name"`
	Status   string            `json:"status"`
	Notice   string            `json:"notice,omitempty"`
	Version  string            `json:"version"`
	Compose  string            `json:"compose,omitempty"`
	Ports    []uint16          `json:"ports,omitempty"`
	Services []string          `json:"services,omitempty"`
	Actions  []OpsAction       `json:"actions,omitempty"`
	Rules    []appHTTPRuleView `json:"rules,omitempty"`
}

type appHTTPRuleView struct {
	Ref     string `json:"ref,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Backend string `json:"backend,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Enabled bool   `json:"enabled"`
}

type appWriteRequest struct {
	ID         string `json:"id"`
	AgentID    string `json:"agent_id"`
	Compose    string `json:"compose"`
	Env        string `json:"env"`
	AutoUpdate bool   `json:"auto_update"`
	Confirm    string `json:"confirm"`
	Domain     string `json:"domain"`
	Port       uint16 `json:"port"`
	RuleRef    string `json:"rule_ref"`
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
	Rules  []HostHTTPRule `json:"rules,omitempty"`
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
		controller.publishHTTPBackendOffers(request.Context())
		views, listErr := controller.projectAppViews(request.Context(), agentID)
		response := appAPIResponse{Apps: views, Access: struct {
			CanRead  bool `json:"can_read"`
			CanWrite bool `json:"can_write"`
		}{CanRead: true, CanWrite: true}}
		if listErr != nil {
			response.Error = publicAppActionError(listErr, "http-rule-list")
		}
		writeAppJSON(writer, http.StatusOK, response)
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
		_, existing := controller.appByID(body.ID)
		if !existing || strings.TrimSpace(body.Env) != "" {
			if err := validateRequiredComposeVariables(body.Compose, body.Env); err != nil {
				writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
				return
			}
		}
		report, err := controller.observeAgent(request.Context(), agentID)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "engine")})
			return
		}
		generation := controller.lifecycleGeneration()
		next, err := DeployComposeAppForAgent(request.Context(), controller.Apps(), ComposeDeploySpec{
			AppID: body.ID, Generation: generation, Compose: body.Compose, WorkDirRoot: controller.uiWorkDirRoot, Env: body.Env,
		}, report, controller.uiApply, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "deploy")})
			return
		}
		for index := range next {
			if next[index].ID == body.ID {
				next[index].AutoUpdate = cloneBool(&body.AutoUpdate)
			}
			next[index].Env = ""
		}
		if err := controller.replaceApps(request.Context(), next); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		if err := controller.setAppRunning(request.Context(), body.ID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), agentID))
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
	if action != "get" && action != "http-rule" && action != "http-rule-delete" {
		if err := controller.requireMutableAgent(request.Context(), app); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, action)})
			return
		}
	}
	switch action {
	case "get":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
			return
		}
		listed, _ := controller.listHostHTTPRules(request.Context(), app.AgentID)
		view := controller.appViewFor(request.Context(), app, listed)
		writeAppJSON(writer, http.StatusOK, appAPIResponse{App: &view})
	case "delete":
		body, _ := decodeAppWrite(request)
		if body.Confirm != appID {
			writeAppJSON(writer, appStatus(ErrDeleteUnconfirmed), appAPIResponse{Error: publicAppActionError(ErrDeleteUnconfirmed, "delete")})
			return
		}
		if err := controller.deleteListedAppHTTPRules(request.Context(), app); err != nil {
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, "http-rule-delete")
			writeAppJSON(writer, appStatus(err), response)
			return
		}
		next, err := DeleteManagedApp(request.Context(), controller.Apps(), appID, true, controller.uiRemove, controller.uiAuditor)
		if err != nil {
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, "delete-after-rules")
			writeAppJSON(writer, appStatus(err), response)
			return
		}
		if err := controller.replaceApps(request.Context(), next); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		if err := controller.clearAppRuntime(request.Context(), appID); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), app.AgentID))
	case "start":
		if err := StartManaged(request.Context(), app, controller.uiStart, controller.uiAuditor); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "start")})
			return
		}
		if err := controller.setAppRunning(request.Context(), appID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), app.AgentID))
	case "stop":
		if err := StopManaged(request.Context(), app, controller.uiStop, controller.uiAuditor); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "stop")})
			return
		}
		if err := controller.setAppRunning(request.Context(), appID, false); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), app.AgentID))
	case "restart":
		if err := RestartManaged(request.Context(), app, controller.uiRestart, controller.uiAuditor); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "restart")})
			return
		}
		if err := controller.setAppRunning(request.Context(), appID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), app.AgentID))
	case "update":
		if err := controller.uiRollout.ConfirmUpdate(request.Context(), app); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "update")})
			return
		}
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(request.Context(), app.AgentID))
	case "http-rule":
		body, err := decodeAppWrite(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrEmptyIngressDomain.Error()})
			return
		}
		operationCtx := withHostOperationKey(request.Context(), request.Header.Get(appOperationHeader))
		rules, err := CreateHTTPRuleFromPublishedPort(operationCtx, controller.uiHTTPRule, controller.uiHTTPRuleList, app, nil, body.Domain, body.Port, controller.uiAuditor)
		if err != nil {
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, "http-rule")
			writeAppJSON(writer, appStatus(err), response)
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		response := controller.appCollectionResponse(request.Context(), app.AgentID)
		response.Rules = rules
		writeAppJSON(writer, http.StatusOK, response)
	case "http-rule-delete":
		body, err := decodeAppWrite(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrEmptyHTTPRuleRef.Error()})
			return
		}
		operationCtx := withHostOperationKey(request.Context(), request.Header.Get(appOperationHeader))
		rules, err := DeleteHTTPRule(operationCtx, controller.uiHTTPRuleDelete, controller.uiHTTPRuleList, app, nil, body.RuleRef, controller.uiAuditor)
		if err != nil {
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, "http-rule-delete")
			writeAppJSON(writer, appStatus(err), response)
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
		response := controller.appCollectionResponse(request.Context(), app.AgentID)
		response.Rules = rules
		writeAppJSON(writer, http.StatusOK, response)
	case "logs":
		body, _ := decodeAppWrite(request)
		service := body.Service
		if service == "" {
			service = request.URL.Query().Get("service")
		}
		text, err := ReadServiceLogs(request.Context(), app, service, controller.uiLogs, controller.uiAuditor)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "logs")})
			return
		}
		writeAppJSON(writer, http.StatusOK, appAPIResponse{Logs: text})
	default:
		http.Error(writer, "Docker 应用页未找到", http.StatusNotFound)
	}
}

func (controller *Controller) requireMutableAgent(ctx context.Context, app App) error {
	if !validAgentID(app.AgentID) {
		return ErrAgentOffline
	}
	report, err := controller.observeAgent(ctx, app.AgentID)
	if err != nil {
		return err
	}
	if !report.Online {
		return ErrAgentOffline
	}
	if !ProjectEngine(ObservationFromReport(report)).Ready {
		return ErrEngineNotReady
	}
	return nil
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

func (controller *Controller) replaceApps(ctx context.Context, apps []App) error {
	if controller.uiAppState != nil {
		if err := controller.uiAppState.StoreApps(ctx, apps); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.apps = cloneApps(apps)
	return nil
}

func (controller *Controller) setAppRunning(ctx context.Context, appID string, running bool) error {
	controller.mu.Lock()
	if controller.appRuntime == nil {
		controller.appRuntime = map[string]bool{}
	}
	next := cloneAppRuntime(controller.appRuntime)
	next[appID] = running
	controller.mu.Unlock()
	if controller.uiAppState != nil {
		if err := controller.uiAppState.StoreRuntime(ctx, next); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	controller.appRuntime = next
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) clearAppRuntime(ctx context.Context, appID string) error {
	controller.mu.Lock()
	next := cloneAppRuntime(controller.appRuntime)
	delete(next, appID)
	controller.mu.Unlock()
	if controller.uiAppState != nil {
		if err := controller.uiAppState.StoreRuntime(ctx, next); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	controller.appRuntime = next
	delete(controller.imageCache, appID)
	delete(controller.imageRefresh, appID)
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) appIsRunning(appID string) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	running, ok := controller.appRuntime[appID]
	if !ok {
		return true
	}
	return running
}

func (controller *Controller) appByID(appID string) (App, bool) {
	for _, app := range controller.Apps() {
		if app.ID == appID {
			return app, true
		}
	}
	return App{}, false
}

func (controller *Controller) appCollectionResponse(ctx context.Context, agentID string) appAPIResponse {
	views, listErr := controller.projectAppViews(ctx, agentID)
	response := appAPIResponse{Apps: views}
	if listErr != nil {
		response.Error = publicAppActionError(listErr, "http-rule-list")
	}
	return response
}

func (controller *Controller) projectAppViews(ctx context.Context, agentID string) ([]appView, error) {
	apps := controller.Apps()
	views := make([]appView, 0, len(apps))
	rulesByAgent := map[string][]HostHTTPRule{}
	var listErr error
	for _, app := range apps {
		if agentID != "" && app.AgentID != agentID {
			continue
		}
		listed := []HostHTTPRule(nil)
		if app.AgentID != "" {
			cached, ok := rulesByAgent[app.AgentID]
			if !ok {
				var err error
				cached, err = controller.listHostHTTPRules(ctx, app.AgentID)
				rulesByAgent[app.AgentID] = cached
				if err != nil && listErr == nil {
					listErr = err
				}
			}
			listed = cached
		}
		views = append(views, controller.appViewFor(ctx, app, listed))
	}
	return views, listErr
}

func (controller *Controller) listHostHTTPRules(ctx context.Context, agentID string) ([]HostHTTPRule, error) {
	if controller.uiHTTPRuleList == nil || !validAgentID(agentID) {
		return nil, nil
	}
	listed, err := controller.uiHTTPRuleList.List(ctx, agentID)
	if err != nil {
		return nil, safeFailure(ErrHTTPRuleListFailed, err)
	}
	return listed, nil
}

func (controller *Controller) publishHTTPBackendOffers(ctx context.Context) {
	if controller.uiHTTPBackendOffer == nil {
		return
	}
	controller.mu.Lock()
	running := cloneAppRuntime(controller.appRuntime)
	controller.mu.Unlock()
	offers, err := ProjectHTTPBackendCatalog(controller.Apps(), nil, running, true)
	if err != nil {
		return
	}
	_ = controller.uiHTTPBackendOffer.ReplaceHTTPBackendOffers(ctx, offers)
}

func (controller *Controller) appViewFor(ctx context.Context, app App, listed []HostHTTPRule) appView {
	running := controller.appIsRunning(app.ID)
	latest := controller.cachedLatestDigest(app)
	controller.scheduleImageObservation(app)
	var deployment Deployment
	if controller.uiRollout.Store != nil {
		if record, ok, err := controller.uiRollout.Store.Load(ctx, app.ID); err == nil && ok {
			deployment = record.Value
		}
	}
	view := projectAppView(app, running, deployment, latest)
	ports := view.Ports
	if len(ports) == 0 {
		ports, _ = ListPublishedPorts(app, nil)
	}
	view.Rules = projectAppHTTPRuleViews(FilterHTTPRulesForApp(listed, app, ports))
	return view
}

func projectAppHTTPRuleViews(rules []HostHTTPRule) []appHTTPRuleView {
	if len(rules) == 0 {
		return nil
	}
	views := make([]appHTTPRuleView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, appHTTPRuleView{
			Ref:     rule.Ref,
			Domain:  rule.Domain,
			Backend: rule.Backend,
			Port:    rule.Port,
			Enabled: rule.Enabled,
		})
	}
	return views
}

func (controller *Controller) cachedLatestDigest(app App) string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	cached, ok := controller.imageCache[app.ID]
	if !ok || cached.Image != app.Image {
		return ""
	}
	return cached.LatestDigest
}

func (controller *Controller) scheduleImageObservation(app App) {
	if controller.uiImageObserver == nil || app.ID == "" || app.Image == "" {
		return
	}
	controller.mu.Lock()
	cached, cachedOK := controller.imageCache[app.ID]
	if controller.imageRefresh[app.ID] || cachedOK && cached.Image == app.Image && time.Since(cached.ObservedAt) < 5*time.Minute {
		controller.mu.Unlock()
		return
	}
	controller.imageRefresh[app.ID] = true
	controller.mu.Unlock()
	select {
	case controller.imageSlots <- struct{}{}:
		go controller.observeImageInBackground(app)
	default:
		controller.mu.Lock()
		controller.imageRefresh[app.ID] = false
		controller.mu.Unlock()
	}
}

func (controller *Controller) observeImageInBackground(app App) {
	defer func() { <-controller.imageSlots }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	observed, err := controller.uiImageObserver.ObserveImage(ctx, app)
	if err == nil {
		_, _ = controller.uiRollout.AutoUpdate(ctx, app, nil, observed)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.imageRefresh[app.ID] = false
	if err != nil || !controller.hasCurrentAppLocked(app) {
		return
	}
	controller.imageCache[app.ID] = cachedImageObservation{Image: app.Image, LatestDigest: observed.LatestDigest, ObservedAt: time.Now()}
}

func (controller *Controller) hasCurrentAppLocked(app App) bool {
	for _, current := range controller.apps {
		if current.ID == app.ID {
			return current.Image == app.Image && current.Generation == app.Generation
		}
	}
	return false
}

func projectAppView(app App, running bool, deployment Deployment, latestDigest string) appView {
	name := app.ID
	if name == "" {
		name = "未命名应用"
	}
	status := ProjectPopularStatus(appLifecycleStatus(running, false, deployment))
	notice := ""
	if appImageUpdateAvailable(deployment, latestDigest) && status != OpsStatusPublishing {
		notice = OpsStatusUpdateAvailable
	}
	ports, _ := ListPublishedPorts(app, nil)
	return appView{
		ID: app.ID, AgentID: app.AgentID, Name: name, Status: status, Notice: notice,
		Version: displayImageVersion(app.Image, deployment.ImageDigest),
		Compose: app.Compose, Ports: ports, Services: composeServiceNames(app.Compose),
		Actions: appViewActions(status, notice),
	}
}

func appLifecycleStatus(running, unhealthy bool, deployment Deployment) AppStatus {
	if deployment.Phase != "" && deployment.Phase != PhaseActive {
		return AppStatusPublishing
	}
	if unhealthy {
		return AppStatusUnhealthy
	}
	if running {
		return AppStatusRunning
	}
	return AppStatusStopped
}

func appImageUpdateAvailable(deployment Deployment, latestDigest string) bool {
	digest := deployment.AvailableDigest
	if digest == "" {
		digest = latestDigest
	}
	return digest != "" && deployment.ImageDigest != "" && digest != deployment.ImageDigest
}

func appViewActions(status, notice string) []OpsAction {
	configure := OpsAction{ID: OpsActionConfigure, Label: OpsConfigEntry}
	var actions []OpsAction
	switch status {
	case OpsStatusRunning:
		actions = []OpsAction{{ID: OpsActionStop, Label: "停止"}, {ID: OpsActionRestart, Label: "重启"}, configure}
	case OpsStatusStopped:
		actions = []OpsAction{{ID: OpsActionStart, Label: "启动"}, configure}
	case OpsStatusPublishing:
		actions = []OpsAction{configure}
	case OpsStatusUnhealthy:
		actions = []OpsAction{{ID: OpsActionUpdate, Label: "恢复"}, {ID: OpsActionStop, Label: "停止"}, configure}
	default:
		actions = []OpsAction{configure}
	}
	if notice == OpsStatusUpdateAvailable && !hasOpsAction(actions, OpsActionUpdate) {
		actions = append([]OpsAction{{ID: OpsActionUpdate, Label: "更新"}}, actions...)
	}
	if status != OpsStatusPublishing {
		actions = appendDeleteAction(actions)
	}
	return actions
}

func hasOpsAction(actions []OpsAction, id string) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

func appendDeleteAction(actions []OpsAction) []OpsAction {
	if hasOpsAction(actions, OpsActionDelete) {
		return actions
	}
	return append(actions, OpsAction{ID: OpsActionDelete, Label: "删除"})
}

func (controller *Controller) deleteListedAppHTTPRules(ctx context.Context, app App) error {
	listed, err := controller.listHostHTTPRules(ctx, app.AgentID)
	if err != nil {
		return err
	}
	view := controller.appViewFor(ctx, app, listed)
	refs := make([]string, 0, len(view.Rules))
	for _, rule := range view.Rules {
		if strings.TrimSpace(rule.Ref) != "" {
			refs = append(refs, rule.Ref)
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return DeleteListedHTTPRules(ctx, controller.uiHTTPRuleDelete, controller.uiHTTPRuleList, app, nil, refs, controller.uiAuditor)
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
	case "delete", "start", "stop", "restart", "update", "http-rule", "http-rule-delete", "logs":
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
	case errors.Is(err, ErrDeleteUnconfirmed), errors.Is(err, ErrEmptyIngressDomain), errors.Is(err, ErrEmptyHTTPRuleRef), errors.Is(err, ErrUnknownHTTPRule), errors.Is(err, ErrInvalidCompose), errors.Is(err, ErrMissingComposeImage), errors.Is(err, ErrMissingComposeVariable), errors.Is(err, ErrNoPublishedPort), errors.Is(err, ErrUnknownService), errors.Is(err, ErrInvalidPreview):
		return http.StatusBadRequest
	case errors.Is(err, ErrAgentOffline), errors.Is(err, ErrAppAgentConflict):
		return http.StatusConflict
	case errors.Is(err, ErrEngineNotReady), errors.Is(err, ErrTypedHandlesUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrHTTPRuleListFailed):
		return http.StatusBadGateway
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
	case errors.Is(err, ErrEmptyHTTPRuleRef):
		return ErrEmptyHTTPRuleRef.Error()
	case errors.Is(err, ErrUnknownHTTPRule):
		return ErrUnknownHTTPRule.Error()
	case errors.Is(err, ErrHTTPRuleListFailed):
		return appendPublicCause("HTTP 规则列表对账失败，请刷新页面后重试", err)
	case errors.Is(err, ErrInvalidCompose), errors.Is(err, ErrMissingComposeImage):
		return err.Error()
	case errors.Is(err, ErrMissingComposeVariable):
		return err.Error()
	case errors.Is(err, ErrNoPublishedPort):
		return ErrNoPublishedPort.Error()
	case errors.Is(err, ErrUnknownService):
		return ErrUnknownService.Error()
	case errors.Is(err, ErrInvalidPreview):
		return ErrInvalidPreview.Error()
	case errors.Is(err, ErrEngineNotReady):
		return ErrEngineNotReady.Error()
	case errors.Is(err, ErrAgentOffline):
		return ErrAgentOffline.Error()
	case errors.Is(err, ErrAppAgentConflict):
		return ErrAppAgentConflict.Error()
	case errors.Is(err, ErrTypedHandlesUnavailable):
		return ErrTypedHandlesUnavailable.Error()
	default:
		return ErrOperationFailed.Error()
	}
}

func publicAppActionError(err error, action string) string {
	if errors.Is(err, ErrHTTPRuleListFailed) {
		return appendPublicCause("HTTP 规则列表对账失败，请刷新页面后重试", err)
	}
	if !errors.Is(err, ErrOperationFailed) && !errors.Is(err, ErrTypedHandlesUnavailable) {
		return publicAppError(err)
	}
	staged := ""
	switch action {
	case "engine":
		staged = "读取目标 Agent 的 Docker 状态失败，请确认 Agent 在线并重试"
	case "deploy":
		staged = "Docker Compose 部署失败，请检查镜像、.env 必填变量和目标 Agent 的 Docker 状态"
	case "persist":
		staged = "Docker 操作已完成，但应用状态保存失败，请刷新页面后重试"
	case "start":
		staged = "启动应用失败，请检查目标 Agent 的 Docker 状态和 Compose 服务"
	case "stop":
		staged = "停止应用失败，请检查目标 Agent 的 Docker 状态和 Compose 服务"
	case "restart":
		staged = "重启应用失败，请检查目标 Agent 的 Docker 状态和 Compose 服务"
	case "delete":
		staged = "删除应用失败，请检查目标 Agent 的 Docker 状态和 Compose 工作目录"
	case "delete-after-rules":
		staged = "入口规则已按宿主结果删除，但应用仍在。请刷新后重试删除应用"
	case "update":
		staged = "更新应用失败，请检查镜像拉取结果和目标 Agent 的 Docker 状态"
	case "http-rule":
		staged = "HTTP 规则创建失败，请检查域名冲突、发布端口和目标 Agent 状态"
	case "http-rule-delete":
		staged = "HTTP 规则删除失败，请检查规则是否仍存在和目标 Agent 状态"
	case "http-rule-list":
		staged = "HTTP 规则列表对账失败，请刷新页面后重试"
	case "logs":
		staged = "读取 Docker Compose 日志失败，请检查服务名和目标 Agent 状态"
	default:
		return ErrOperationFailed.Error()
	}
	return appendPublicCause(staged, err)
}

func appendPublicCause(staged string, err error) string {
	cause := publicCause(err)
	if cause == "" || cause == staged || cause == ErrOperationFailed.Error() || cause == ErrTypedHandlesUnavailable.Error() || cause == ErrHTTPRuleListFailed.Error() {
		return staged
	}
	return staged + "：" + cause
}
