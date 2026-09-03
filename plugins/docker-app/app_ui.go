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
	appActorHeader                      = pluginsdk.HeaderPluginActor
	appOperationHeader                  = pluginsdk.HeaderPluginOperationKey
	appUnavailableMessage               = "暂时无法管理 Docker 应用。"
	diskCleanupUnavailableMessage       = "磁盘清理执行面不可用，请确认目标 Agent 在线后重试"
	diskCleanupDockerUnavailableMessage = "无法连接目标节点的 Docker，请确认 Docker 已启动后重试"
	diskCleanupReadonlyStatsMessage     = "读取节点磁盘占用失败，请稍后重试"
	diskCleanupAgentIDRequiredError     = "agent_id is required"
	diskCleanupAgentIDInvalidError      = "agent_id is invalid"
	imageObservationTTL                 = 5 * time.Minute
)

func diskCleanupFailurePublicMessage(kind string) string {
	switch strings.TrimSpace(kind) {
	case diskCleanupFailureDockerUnavailable:
		return diskCleanupDockerUnavailableMessage
	case diskCleanupFailureReadonlyStats:
		return diskCleanupReadonlyStatsMessage
	default:
		return ""
	}
}

type appView struct {
	ID            string            `json:"id"`
	AgentID       string            `json:"agent_id,omitempty"`
	Name          string            `json:"name"`
	Status        string            `json:"status"`
	Notice        string            `json:"notice,omitempty"`
	Version       string            `json:"version"`
	Compose       string            `json:"compose,omitempty"`
	AutoUpdate    bool              `json:"auto_update,omitempty"`
	Ports         []uint16          `json:"ports,omitempty"`
	Services      []string          `json:"services,omitempty"`
	ServiceImages []appServiceView  `json:"service_images,omitempty"`
	Actions       []OpsAction       `json:"actions,omitempty"`
	Rules         []appHTTPRuleView `json:"rules,omitempty"`
}

type appHTTPRuleView struct {
	Ref     string `json:"ref,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Backend string `json:"backend,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Enabled bool   `json:"enabled"`
}

type appWriteRequest struct {
	ID         string             `json:"id"`
	AgentID    string             `json:"agent_id"`
	Compose    string             `json:"compose"`
	Env        string             `json:"env"`
	AutoUpdate bool               `json:"auto_update"`
	Confirm    string             `json:"confirm"`
	Domain     string             `json:"domain"`
	Port       uint16             `json:"port"`
	RuleRef    string             `json:"rule_ref"`
	Service    string             `json:"service"`
	Services   []appServiceUpdate `json:"services"`
	Ignore     []appIgnoredUpdate `json:"ignore"`
	Locks      map[string]string  `json:"locks"`
}

type appFilesRequest struct {
	Action  string `json:"action"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

var errWorkspaceFilePath = errors.New("只能使用应用工作区内的相对路径")

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
	Apps     []appView            `json:"apps,omitempty"`
	App      *appView             `json:"app,omitempty"`
	Logs     string               `json:"logs,omitempty"`
	Error    string               `json:"error,omitempty"`
	Engine   *engineAPIView       `json:"engine,omitempty"`
	Rules    []HostHTTPRule       `json:"rules,omitempty"`
	Path     string               `json:"path,omitempty"`
	Content  string               `json:"content,omitempty"`
	Entries  []workspaceFileEntry `json:"entries,omitempty"`
	Accepted bool                 `json:"accepted,omitempty"`
	Preview  *riskPreviewView     `json:"preview,omitempty"`
	Cleanup  *DiskCleanupReport   `json:"cleanup,omitempty"`
	Access   struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	} `json:"access,omitempty"`
}

type riskPreviewView struct {
	Digest string         `json:"digest,omitempty"`
	Items  []riskItemView `json:"items,omitempty"`
}

type riskItemView struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	if pluginsdk.ServePluginUIAsset(writer, request, appUIAssets, "assets/ui") {
		return
	}
	path := request.URL.Path
	if !controller.uiReady() {
		writeAppJSON(writer, http.StatusServiceUnavailable, appAPIResponse{Error: appUnavailableMessage})
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
	if path == "/api/apps/preview" {
		controller.serveComposePreview(writer, request)
		return
	}
	if path == "/api/disk-cleanup" {
		controller.serveDiskCleanup(writer, request)
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
		controller.writeEngineView(writer, engineAPIView{AgentID: agentID})
		return
	}
	status := ProjectEngine(ObservationFromReport(report))
	controller.writeEngineView(writer, engineAPIView{
		AgentID: agentID,
		Online:  report.Online,
		Ready:   report.Online && status.Ready,
		Version: status.Version,
	})
}

func (controller *Controller) writeEngineView(writer http.ResponseWriter, view engineAPIView) {
	command, commandErr := UnreadyInstallCommand(view.Ready, controller.RegistryMirror())
	if commandErr != nil {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: commandErr.Error()})
		return
	}
	if view.Online && !view.Ready {
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
		views, listErr := controller.projectAppViews(request.Context(), agentID, false)
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
		existingApp, existing := controller.appByID(body.ID)
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
		if !report.Online {
			writeAppJSON(writer, appStatus(ErrAgentOffline), appAPIResponse{Error: publicAppActionError(ErrAgentOffline, "engine")})
			return
		}
		if !ProjectEngine(ObservationFromReport(report)).Ready {
			writeAppJSON(writer, appStatus(ErrEngineNotReady), appAPIResponse{Error: publicAppActionError(ErrEngineNotReady, "engine")})
			return
		}
		generation := controller.lifecycleGeneration()
		preview, previewErr := PreviewComposeDocument(body.ID, generation, body.Compose, "")
		if previewErr != nil {
			writeAppJSON(writer, appStatus(previewErr), appAPIResponse{Error: publicAppActionError(previewErr, "deploy")})
			return
		}
		if RequiresRiskConfirmation(preview) && body.Confirm != preview.Digest {
			writeRiskDenied(writer, preview, ErrInvalidPreview, "deploy")
			return
		}
		controller.pinComposeSaveObservation(body.ID)
		next, err := DeployComposeAppForAgent(request.Context(), controller.Apps(), ComposeDeploySpec{
			AppID: body.ID, Generation: generation, Compose: body.Compose, WorkDirRoot: controller.uiWorkDirRoot, Env: body.Env, Confirm: body.Confirm,
		}, report, controller.uiApply, controller.uiAuditor)
		if err != nil {
			controller.allowImageObservation(body.ID)
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "deploy")})
			return
		}
		for index := range next {
			if next[index].ID == body.ID {
				next[index].ImageLocks = cloneStringMap(existingApp.ImageLocks)
				next[index].IgnoredUpdates = cloneStringSlicesMap(existingApp.IgnoredUpdates)
				next[index].AutoUpdate = cloneBool(&body.AutoUpdate)
				if err := next[index].normalizeServicePolicies(); err != nil {
					controller.allowImageObservation(body.ID)
					writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
					return
				}
			}
			next[index].Env = ""
		}
		if err := controller.replaceApps(request.Context(), next); err != nil {
			controller.allowImageObservation(body.ID)
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.allowImageObservation(body.ID)
		if err := controller.setAppRunning(request.Context(), body.ID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		if err := controller.clearAppDeployment(request.Context(), body.ID); err != nil {
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
		view := controller.appViewFor(request.Context(), app, listed, false)
		writeAppJSON(writer, http.StatusOK, appAPIResponse{App: &view})
	case "delete":
		body, _ := decodeAppWrite(request)
		if body.Confirm != appID {
			writeAppJSON(writer, appStatus(ErrDeleteUnconfirmed), appAPIResponse{Error: publicAppActionError(ErrDeleteUnconfirmed, "delete")})
			return
		}
		operationCtx := withHostOperationKey(request.Context(), request.Header.Get(appOperationHeader))
		droppedRules, err := controller.deleteListedAppHTTPRules(operationCtx, app)
		if err != nil {
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, "http-rule-delete")
			writeAppJSON(writer, appStatus(err), response)
			return
		}
		controller.invalidateObservation(appID)
		next, err := DeleteManagedApp(request.Context(), controller.Apps(), appID, true, controller.uiRemove, controller.uiAuditor)
		if err != nil {
			controller.allowImageObservation(appID)
			stage := "delete"
			if droppedRules {
				stage = "delete-after-rules"
			}
			response := controller.appCollectionResponse(request.Context(), app.AgentID)
			response.Error = publicAppActionError(err, stage)
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
		if err := controller.clearAppDeployment(request.Context(), appID); err != nil {
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
		body, err := decodeAppWrite(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrInvalidCompose.Error()})
			return
		}
		if err := controller.applyManualServiceUpdate(request.Context(), writer, app, body); err != nil {
			return
		}
	case "rollback":
		if err := controller.uiRollout.Rollback(request.Context(), app); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "rollback")})
			return
		}
		if err := controller.setAppRunning(request.Context(), appID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return
		}
		controller.publishHTTPBackendOffers(request.Context())
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
	case "files":
		controller.serveAppFiles(writer, request, app)
	default:
		http.Error(writer, "Docker 应用页未找到", http.StatusNotFound)
	}
}

func (controller *Controller) applyManualServiceUpdate(ctx context.Context, writer http.ResponseWriter, app App, body appWriteRequest) error {
	updated := cloneApp(app)
	locks, err := mergeImageLocks(updated.ImageLocks, body.Locks)
	if err != nil {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
		return err
	}
	ignores, err := mergeIgnoredUpdates(updated.IgnoredUpdates, body.Ignore)
	if err != nil {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
		return err
	}
	updated.ImageLocks = locks
	updated.IgnoredUpdates = ignores
	for _, item := range body.Ignore {
		if !knownComposeService(updated, item.Service) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrUnknownService.Error()})
			return ErrUnknownService
		}
	}
	for service := range body.Locks {
		if !knownComposeService(updated, service) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrUnknownService.Error()})
			return ErrUnknownService
		}
	}
	serviceTags := make(map[string]string, len(body.Services))
	for _, item := range body.Services {
		name := strings.TrimSpace(item.Name)
		tag := strings.TrimSpace(item.Tag)
		if name == "" && tag == "" {
			continue
		}
		if !knownComposeService(updated, name) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrUnknownService.Error()})
			return ErrUnknownService
		}
		if !boundedText(tag, 128) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "image tag is invalid"})
			return ErrInvalidCompose
		}
		serviceTags[name] = tag
	}
	nextCompose := rewriteComposeServiceTags(updated.Compose, serviceTags)
	composeChanged := nextCompose != updated.Compose
	policyChanged := !mapsEqualString(updated.ImageLocks, app.ImageLocks) || !ignoredUpdatesEqual(updated.IgnoredUpdates, app.IgnoredUpdates)
	digestRequested := floatingDigestUpdateRequested(updated, serviceTags)
	if !composeChanged && !policyChanged && !digestRequested {
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(ctx, app.AgentID))
		return nil
	}
	if composeChanged {
		preview, previewErr := PreviewComposeDocument(app.ID, app.Generation, nextCompose, app.RuleRef)
		if previewErr != nil {
			writeAppJSON(writer, appStatus(previewErr), appAPIResponse{Error: publicAppActionError(previewErr, "update")})
			return previewErr
		}
		if RequiresRiskConfirmation(preview) && body.Confirm != preview.Digest {
			writeRiskDenied(writer, preview, ErrInvalidPreview, "update")
			return ErrInvalidPreview
		}
		if err := controller.reconcileAppUpdate(ctx, app.ID); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "update")})
			return err
		}
		report, err := controller.observeAgent(ctx, app.AgentID)
		if err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "update")})
			return err
		}
		controller.pinComposeSaveObservation(app.ID)
		next, err := DeployComposeAppForAgent(ctx, controller.Apps(), ComposeDeploySpec{
			AppID: app.ID, AgentID: app.AgentID, Generation: app.Generation, Compose: nextCompose,
			WorkDirRoot: controller.uiWorkDirRoot, Confirm: body.Confirm,
		}, report, controller.uiApply, controller.uiAuditor)
		if err != nil {
			controller.allowImageObservation(app.ID)
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "update")})
			return err
		}
		for index := range next {
			if next[index].ID != app.ID {
				continue
			}
			next[index].ImageLocks = cloneStringMap(updated.ImageLocks)
			next[index].IgnoredUpdates = cloneStringSlicesMap(updated.IgnoredUpdates)
			next[index].AutoUpdate = cloneBool(app.AutoUpdate)
			next[index].Env = ""
			if err := next[index].normalizeServicePolicies(); err != nil {
				controller.allowImageObservation(app.ID)
				writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
				return err
			}
		}
		if err := controller.replaceApps(ctx, next); err != nil {
			controller.allowImageObservation(app.ID)
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return err
		}
		controller.allowImageObservation(app.ID)
		if err := controller.setAppRunning(ctx, app.ID, true); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return err
		}
		if err := controller.clearAppDeployment(ctx, app.ID); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return err
		}
		controller.publishHTTPBackendOffers(ctx)
		writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(ctx, app.AgentID))
		return nil
	}
	if policyChanged {
		apps := cloneApps(controller.Apps())
		for index := range apps {
			if apps[index].ID != app.ID {
				continue
			}
			apps[index].ImageLocks = cloneStringMap(updated.ImageLocks)
			apps[index].IgnoredUpdates = cloneStringSlicesMap(updated.IgnoredUpdates)
			if err := apps[index].normalizeServicePolicies(); err != nil {
				writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: err.Error()})
				return err
			}
		}
		if err := controller.replaceApps(ctx, apps); err != nil {
			writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
			return err
		}
		if current, ok := controller.appByID(app.ID); ok {
			app = current
		}
		if !digestRequested {
			writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(ctx, app.AgentID))
			return nil
		}
	}
	if err := controller.uiRollout.ConfirmUpdate(ctx, app); err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "update")})
		return err
	}
	if err := controller.setAppRunning(ctx, app.ID, true); err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "persist")})
		return err
	}
	controller.publishHTTPBackendOffers(ctx)
	writeAppJSON(writer, http.StatusOK, controller.appCollectionResponse(ctx, app.AgentID))
	return nil
}

func mapsEqualString(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func ignoredUpdatesEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, values := range left {
		other := right[key]
		if len(values) != len(other) {
			return false
		}
		for index, value := range values {
			if other[index] != value {
				return false
			}
		}
	}
	return true
}

func (controller *Controller) reconcileAppUpdate(ctx context.Context, appID string) error {
	if controller.uiRollout.Store == nil {
		return nil
	}
	record, found, err := controller.uiRollout.Store.Load(ctx, appID)
	if err != nil || !found || record.Value.Phase == "" || record.Value.Phase == PhaseActive {
		return err
	}
	if record.Value.Lease != "" && record.Value.LeaseUntil.After(controller.uiRollout.now()) {
		return ErrReconcilePending
	}
	return controller.uiRollout.Reconcile(ctx, appID)
}

func (controller *Controller) serveAppFiles(writer http.ResponseWriter, request *http.Request, app App) {
	body, err := decodeAppFiles(request)
	if err != nil {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "文件超过 1MiB 上限"})
			return
		}
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "files payload is invalid"})
		return
	}
	action := strings.TrimSpace(body.Action)
	switch action {
	case "list", "mkdir", "read", "write", "delete":
	default:
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "未知的文件操作"})
		return
	}
	filePath := strings.TrimSpace(body.Path)
	if filePath == "" {
		filePath = "."
	}
	if rejectedWorkspaceAPIPath(filePath) {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: errWorkspaceFilePath.Error()})
		return
	}
	if controller.uiFiles == nil {
		writeAppJSON(writer, appStatus(ErrTypedHandlesUnavailable), appAPIResponse{Error: publicAppActionError(ErrTypedHandlesUnavailable, "files")})
		return
	}
	payload := map[string]any{"action": action, "path": filePath}
	if action == "write" {
		if len(body.Content) > MaxConfigBytes {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: "文件超过 1MiB 上限"})
			return
		}
		payload["content"] = body.Content
	}
	var result map[string]any
	if err := controller.uiFiles.Files(request.Context(), app, payload, &result); err != nil {
		writeAppJSON(writer, filesStatus(err), appAPIResponse{Error: publicAppActionError(filesCallError(err), "files")})
		return
	}
	writeAppJSON(writer, http.StatusOK, projectAppFilesResponse(result))
}

func rejectedWorkspaceAPIPath(filePath string) bool {
	trimmed := strings.TrimSpace(filePath)
	if trimmed == "" || strings.Contains(trimmed, "..") {
		return true
	}
	_, err := normalizeWorkspaceRelativePath(trimmed)
	return err != nil
}

func projectAppFilesResponse(result map[string]any) appAPIResponse {
	if len(result) == 0 {
		return appAPIResponse{}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return appAPIResponse{}
	}
	var decoded struct {
		Path     string               `json:"path"`
		Content  string               `json:"content"`
		Entries  []workspaceFileEntry `json:"entries"`
		Accepted bool                 `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return appAPIResponse{}
	}
	path := strings.TrimSpace(decoded.Path)
	if path != "" && rejectedWorkspaceAPIPath(path) {
		path = ""
	}
	entries := make([]workspaceFileEntry, 0, len(decoded.Entries))
	for _, entry := range decoded.Entries {
		entryPath := strings.TrimSpace(entry.Path)
		if entryPath == "" {
			entryPath = strings.TrimSpace(entry.Name)
		}
		if rejectedWorkspaceAPIPath(entryPath) || rejectedWorkspaceAPIPath(entry.Name) {
			continue
		}
		entry.Path = entryPath
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		entries = nil
	}
	return appAPIResponse{Path: path, Content: decoded.Content, Entries: entries, Accepted: decoded.Accepted}
}

func filesStatus(err error) int {
	if filesPublicMessage(err) != "" {
		return http.StatusBadRequest
	}
	return appStatus(err)
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

func (controller *Controller) invalidateObservation(appID string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	delete(controller.imageCache, appID)
	controller.imageRefresh[appID] = true
	controller.imageObserveToken[appID]++
	controller.imageDeleteEpoch[appID]++
}

func (controller *Controller) allowImageObservation(appID string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.imageRefresh[appID] = false
}

func (controller *Controller) pinComposeSaveObservation(appID string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	delete(controller.imageCache, appID)
	controller.imageDeleteEpoch[appID]++
	controller.imageRefresh[appID] = true
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
	controller.imageObserveToken[appID]++
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) clearAppDeployment(ctx context.Context, appID string) error {
	if controller.uiRollout.Store == nil {
		return nil
	}
	record, ok, err := controller.uiRollout.Store.Load(ctx, appID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return controller.uiRollout.Store.DeleteCAS(ctx, appID, record.Version, record.Value.FencingToken)
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
	views, listErr := controller.projectAppViews(ctx, agentID, true)
	response := appAPIResponse{Apps: views}
	if listErr != nil {
		response.Error = publicAppActionError(listErr, "http-rule-list")
	}
	return response
}

func (controller *Controller) projectAppViews(ctx context.Context, agentID string, refreshTags bool) ([]appView, error) {
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
		view := controller.appViewFor(ctx, app, listed, refreshTags)
		view.Rules = projectOpenHTTPRuleViews(view.Rules)
		views = append(views, view)
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

func (controller *Controller) appViewFor(ctx context.Context, app App, listed []HostHTTPRule, refreshTags bool) appView {
	running := controller.appIsRunning(app.ID)
	latest := controller.cachedLatestDigest(app)
	controller.scheduleImageObservation(app)
	var deployment Deployment
	if controller.uiRollout.Store != nil {
		if record, ok, err := controller.uiRollout.Store.Load(ctx, app.ID); err == nil && ok {
			deployment = record.Value
		}
	}
	view := projectAppView(app, running, deployment, latest, controller.tagsForApp(ctx, app, refreshTags))
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

func projectOpenHTTPRuleViews(rules []appHTTPRuleView) []appHTTPRuleView {
	if len(rules) == 0 {
		return nil
	}
	views := make([]appHTTPRuleView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, appHTTPRuleView{
			Domain:  rule.Domain,
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

func (controller *Controller) tagsForApp(ctx context.Context, app App, refresh bool) map[string][]string {
	images := appServiceImages(app)
	if len(images) == 0 {
		return nil
	}
	lister := asImageTagLister(controller.uiImageObserver)
	result := make(map[string][]string, len(images))
	for _, service := range images {
		if tags, ok := controller.cachedImageTags(app.ID, service.Image); ok {
			result[service.Name] = tags
			continue
		}
		if !refresh || lister == nil {
			continue
		}
		listed, err := lister.ListImageTags(ctx, App{ID: app.ID, AgentID: app.AgentID, Image: service.Image})
		if err != nil {
			continue
		}
		controller.storeImageTags(app.ID, service.Image, listed)
		result[service.Name] = listed
	}
	return result
}

func appServiceImages(app App) []ServiceImage {
	if len(app.ServiceImages) > 0 {
		return app.ServiceImages
	}
	return composeServiceImages(app.Compose)
}

func tagsByServiceName(app App, listed map[string][]string) map[string][]string {
	if len(listed) == 0 {
		return nil
	}
	result := make(map[string][]string)
	for _, service := range appServiceImages(app) {
		tags, ok := listed[service.Image]
		if !ok {
			continue
		}
		result[service.Name] = append([]string(nil), tags...)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (controller *Controller) persistCatalogCompose(ctx context.Context, appID, compose string) error {
	if strings.TrimSpace(appID) == "" || strings.TrimSpace(compose) == "" {
		return nil
	}
	apps := cloneApps(controller.Apps())
	found := false
	for index := range apps {
		if apps[index].ID != appID {
			continue
		}
		apps[index].Compose = compose
		if err := apps[index].bindCompose(); err != nil {
			return err
		}
		found = true
		break
	}
	if !found {
		return nil
	}
	return controller.replaceApps(ctx, apps)
}

func (controller *Controller) listAppImageTags(ctx context.Context, app App) (listed map[string][]string, failed []string) {
	lister := asImageTagLister(controller.uiImageObserver)
	if lister == nil {
		return nil, nil
	}
	images := appServiceImages(app)
	if len(images) == 0 && strings.TrimSpace(app.Image) != "" {
		images = []ServiceImage{{Image: app.Image}}
	}
	listed = map[string][]string{}
	seen := map[string]struct{}{}
	for _, service := range images {
		image := strings.TrimSpace(service.Image)
		if image == "" {
			continue
		}
		if _, dup := seen[image]; dup {
			continue
		}
		seen[image] = struct{}{}
		tags, err := lister.ListImageTags(ctx, App{ID: app.ID, AgentID: app.AgentID, Image: image})
		if err != nil {
			failed = append(failed, image)
			continue
		}
		listed[image] = append([]string(nil), tags...)
	}
	return listed, failed
}

func (controller *Controller) cachedImageTags(appID, image string) ([]string, bool) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	cached, ok := controller.imageCache[appID]
	if !ok || cached.TagsByImage == nil || imageObservationExpired(cached.ObservedAt) {
		return nil, false
	}
	tags, ok := cached.TagsByImage[image]
	if !ok {
		return nil, false
	}
	return append([]string(nil), tags...), true
}

func (controller *Controller) storeImageTags(appID, image string, tags []string) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	cached := controller.imageCache[appID]
	if cached.TagsByImage == nil {
		cached.TagsByImage = map[string][]string{}
	}
	cached.TagsByImage[image] = append([]string(nil), tags...)
	if cached.ObservedAt.IsZero() {
		cached.ObservedAt = time.Now()
	}
	controller.imageCache[appID] = cached
}

func imageObservationExpired(observed time.Time) bool {
	return observed.IsZero() || time.Since(observed) >= imageObservationTTL
}

func (controller *Controller) scheduleImageObservation(app App) {
	if controller.uiImageObserver == nil || app.ID == "" || app.Image == "" {
		return
	}
	controller.mu.Lock()
	cached, cachedOK := controller.imageCache[app.ID]
	if controller.imageRefresh[app.ID] || cachedOK && cached.Image == app.Image && !imageObservationExpired(cached.ObservedAt) {
		controller.mu.Unlock()
		return
	}
	controller.imageRefresh[app.ID] = true
	controller.imageObserveToken[app.ID]++
	token := controller.imageObserveToken[app.ID]
	epoch := controller.imageDeleteEpoch[app.ID]
	controller.mu.Unlock()
	select {
	case controller.imageSlots <- struct{}{}:
		go controller.observeImageInBackground(app, token, epoch)
	default:
		controller.mu.Lock()
		controller.clearImageRefreshIfCurrentLocked(app.ID, token, epoch)
		controller.mu.Unlock()
	}
}

func (controller *Controller) observeImageInBackground(app App, token, epoch uint64) {
	defer func() { <-controller.imageSlots }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	observed, err := controller.uiImageObserver.ObserveImage(ctx, app)
	controller.mu.Lock()
	_, ok := controller.snapshotObservationLocked(app, token, epoch)
	if err != nil || !ok {
		controller.clearImageRefreshIfCurrentLocked(app.ID, token, epoch)
		controller.mu.Unlock()
		return
	}
	controller.mu.Unlock()
	ctx = withObservationPersistGuard(ctx, func() (App, bool) {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return controller.snapshotObservationLocked(app, token, epoch)
	})
	controller.mu.Lock()
	live, ok := controller.snapshotObservationLocked(app, token, epoch)
	controller.mu.Unlock()
	if !ok {
		controller.mu.Lock()
		controller.clearImageRefreshIfCurrentLocked(app.ID, token, epoch)
		controller.mu.Unlock()
		return
	}
	listed, failed := controller.listAppImageTags(ctx, live)
	if tags := tagsByServiceName(live, listed); len(tags) > 0 {
		observed.TagsByService = tags
	}
	view, autoErr := controller.uiRollout.AutoUpdate(ctx, live, live.AutoUpdate, observed)
	controller.mu.Lock()
	controller.clearImageRefreshIfCurrentLocked(app.ID, token, epoch)
	_, still := controller.snapshotObservationLocked(app, token, epoch)
	keepRecord := still || controller.catalogHasAppIDLocked(app.ID)
	if still {
		cached := controller.imageCache[app.ID]
		cached.Image = live.Image
		cached.LatestDigest = observed.LatestDigest
		cached.ObservedAt = time.Now()
		if listed != nil || len(failed) > 0 {
			if cached.TagsByImage == nil {
				cached.TagsByImage = map[string][]string{}
			}
			for image, tags := range listed {
				cached.TagsByImage[image] = append([]string(nil), tags...)
			}
			for _, image := range failed {
				delete(cached.TagsByImage, image)
			}
		}
		controller.imageCache[app.ID] = cached
	}
	controller.mu.Unlock()
	if still && autoErr == nil && view.Published && view.Compose != "" && view.Compose != live.Compose {
		_ = controller.persistCatalogCompose(ctx, live.ID, view.Compose)
	}
	if !keepRecord {
		_ = controller.clearAppDeployment(ctx, app.ID)
	} else if autoErr == nil && view.Published {
		_ = controller.setAppRunning(ctx, live.ID, true)
		controller.publishHTTPBackendOffers(ctx)
	}
}

func (controller *Controller) snapshotObservationLocked(app App, token, epoch uint64) (App, bool) {
	if controller.imageObserveToken[app.ID] != token || controller.imageDeleteEpoch[app.ID] != epoch {
		return App{}, false
	}
	return controller.currentCatalogAppLocked(app)
}

func (controller *Controller) clearImageRefreshIfCurrentLocked(appID string, token, epoch uint64) {
	if controller.imageObserveToken[appID] == token && controller.imageDeleteEpoch[appID] == epoch {
		controller.imageRefresh[appID] = false
	}
}

func (controller *Controller) currentCatalogAppLocked(app App) (App, bool) {
	for _, current := range controller.apps {
		if current.ID == app.ID && current.Image == app.Image && current.Generation == app.Generation {
			return current, true
		}
	}
	return App{}, false
}

func (controller *Controller) catalogHasAppIDLocked(appID string) bool {
	for _, current := range controller.apps {
		if current.ID == appID {
			return true
		}
	}
	return false
}

func projectAppView(app App, running bool, deployment Deployment, latestDigest string, tagsByService map[string][]string) appView {
	name := app.ID
	if name == "" {
		name = "未命名应用"
	}
	status := ProjectPopularStatus(appLifecycleStatus(running, false, deployment))
	digestAvailable := appImageUpdateAvailable(deployment, latestDigest)
	services, hasUpdate := projectServiceViews(app, tagsByService, digestAvailable)
	if !hasUpdate && len(services) == 0 && appHasFloatingImage(app) && digestAvailable {
		hasUpdate = true
	}
	notice := ""
	if hasUpdate && status != OpsStatusPublishing {
		notice = OpsStatusUpdateAvailable
	}
	ports, _ := ListPublishedPorts(app, nil)
	return appView{
		ID: app.ID, AgentID: app.AgentID, Name: name, Status: status, Notice: notice,
		Version: displayAppVersion(app, deployment.ImageDigest, hasUpdate),
		Compose: app.Compose, AutoUpdate: AutoUpdateEnabled(app.AutoUpdate),
		Ports: ports, Services: composeServiceNames(app.Compose),
		ServiceImages: services,
		Actions:       appViewActions(status, notice, deployment),
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

func appViewActions(status, notice string, deployment Deployment) []OpsAction {
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
	if status != OpsStatusPublishing && len(deployment.History) > 0 && !hasOpsAction(actions, OpsActionRollback) {
		actions = append(actions, OpsAction{ID: OpsActionRollback, Label: "回滚"})
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

func (controller *Controller) deleteListedAppHTTPRules(ctx context.Context, app App) (bool, error) {
	listed, err := controller.listHostHTTPRules(ctx, app.AgentID)
	if err != nil {
		return false, err
	}
	view := controller.appViewFor(ctx, app, listed, false)
	refs := make([]string, 0, len(view.Rules))
	for _, rule := range view.Rules {
		if strings.TrimSpace(rule.Ref) != "" {
			refs = append(refs, rule.Ref)
		}
	}
	if len(refs) == 0 {
		return false, nil
	}
	if err := DeleteListedHTTPRules(ctx, controller.uiHTTPRuleDelete, controller.uiHTTPRuleList, app, nil, refs, controller.uiAuditor); err != nil {
		return false, err
	}
	return true, nil
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
	case "delete", "start", "stop", "restart", "update", "rollback", "http-rule", "http-rule-delete", "logs", "files":
		return decoded, action, true
	default:
		return "", "", false
	}
}

func decodeAppFiles(request *http.Request) (appFilesRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, MaxConfigBytes))
	decoder.DisallowUnknownFields()
	var body appFilesRequest
	if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return appFilesRequest{}, err
	}
	return body, nil
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

type diskCleanupWriteRequest struct {
	AgentID string `json:"agent_id"`
	Confirm bool   `json:"confirm"`
}

func decodeDiskCleanup(request *http.Request) (diskCleanupWriteRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, MaxConfigBytes))
	decoder.DisallowUnknownFields()
	var body diskCleanupWriteRequest
	if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return diskCleanupWriteRequest{}, err
	}
	return body, nil
}

func (controller *Controller) serveDiskCleanup(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		writer.Header().Set("Allow", "GET, HEAD, POST")
		writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
		return
	}
	agentID := strings.TrimSpace(request.URL.Query().Get("agent_id"))
	confirm := false
	if request.Method == http.MethodPost {
		body, err := decodeDiskCleanup(request)
		if err != nil {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: diskCleanupAgentIDRequiredError})
			return
		}
		if agentID == "" {
			agentID = strings.TrimSpace(body.AgentID)
		}
		confirm = body.Confirm
	}
	if agentID == "" {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: diskCleanupAgentIDRequiredError})
		return
	}
	if !validAgentID(agentID) {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: diskCleanupAgentIDInvalidError})
		return
	}
	if err := controller.requireReadyAgent(request.Context(), agentID); err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "disk-cleanup")})
		return
	}
	if controller.uiDiskCleanup == nil {
		writeAppJSON(writer, appStatus(ErrTypedHandlesUnavailable), appAPIResponse{Error: publicAppActionError(ErrTypedHandlesUnavailable, "disk-cleanup")})
		return
	}
	var (
		report DiskCleanupReport
		err    error
	)
	if request.Method == http.MethodPost {
		report, err = controller.uiDiskCleanup.ApplyDiskCleanup(request.Context(), agentID, confirm)
	} else {
		report, err = controller.uiDiskCleanup.PreviewDiskCleanup(request.Context(), agentID)
	}
	if err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "disk-cleanup")})
		return
	}
	view := report
	writeAppJSON(writer, http.StatusOK, appAPIResponse{Cleanup: &view, Accepted: view.Accepted, Access: struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	}{CanRead: true, CanWrite: true}})
}

func (controller *Controller) requireReadyAgent(ctx context.Context, agentID string) error {
	return controller.requireMutableAgent(ctx, App{AgentID: agentID})
}

func (controller *Controller) serveComposePreview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeAppJSON(writer, http.StatusMethodNotAllowed, appAPIResponse{Error: "method not allowed"})
		return
	}
	if _, err := controller.uiIdentity(request); err != nil {
		writeAppJSON(writer, http.StatusForbidden, appAPIResponse{Error: ErrUnauthorized.Error()})
		return
	}
	body, err := decodeAppWrite(request)
	if err != nil {
		writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrInvalidCompose.Error()})
		return
	}
	compose := body.Compose
	generation := controller.lifecycleGeneration()
	if strings.TrimSpace(compose) == "" {
		existing, ok := controller.appByID(body.ID)
		if !ok {
			writeAppJSON(writer, http.StatusBadRequest, appAPIResponse{Error: ErrInvalidCompose.Error()})
			return
		}
		compose = existing.Compose
		generation = existing.Generation
	}
	preview, err := PreviewComposeDocument(body.ID, generation, compose, "")
	if err != nil {
		writeAppJSON(writer, appStatus(err), appAPIResponse{Error: publicAppActionError(err, "preview")})
		return
	}
	writeAppJSON(writer, http.StatusOK, appAPIResponse{Preview: projectRiskPreview(preview), Access: struct {
		CanRead  bool `json:"can_read"`
		CanWrite bool `json:"can_write"`
	}{CanRead: true, CanWrite: true}})
}

func writeRiskDenied(writer http.ResponseWriter, preview RiskPreview, err error, action string) {
	writeAppJSON(writer, appStatus(err), appAPIResponse{
		Error:   publicAppActionError(err, action),
		Preview: projectRiskPreview(preview),
	})
}

func projectRiskPreview(preview RiskPreview) *riskPreviewView {
	if preview.Digest == "" && len(preview.Items) == 0 {
		return nil
	}
	items := make([]riskItemView, 0, len(preview.Items))
	for _, item := range preview.Items {
		items = append(items, riskItemView{Kind: string(item.Kind), Target: item.Target})
	}
	if len(items) == 0 {
		items = nil
	}
	return &riskPreviewView{Digest: preview.Digest, Items: items}
}

func writeAppJSON(writer http.ResponseWriter, status int, payload appAPIResponse) {
	_ = pluginsdk.WritePluginUIJSON(writer, status, payload)
}

func appStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(err, ErrDeleteUnconfirmed), errors.Is(err, ErrEmptyIngressDomain), errors.Is(err, ErrEmptyHTTPRuleRef), errors.Is(err, ErrUnknownHTTPRule), errors.Is(err, ErrInvalidCompose), errors.Is(err, ErrMissingComposeImage), errors.Is(err, ErrMissingComposeVariable), errors.Is(err, ErrNoPublishedPort), errors.Is(err, ErrUnknownService), errors.Is(err, ErrInvalidPreview), errors.Is(err, errWorkspaceFilePath):
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
	case errors.Is(err, errWorkspaceFilePath):
		return errWorkspaceFilePath.Error()
	case errors.Is(err, ErrEngineNotReady):
		return ErrEngineNotReady.Error()
	case errors.Is(err, ErrAgentOffline):
		return ErrAgentOffline.Error()
	case errors.Is(err, ErrAppAgentConflict):
		return ErrAppAgentConflict.Error()
	case errors.Is(err, ErrTypedHandlesUnavailable):
		return "读取目标 Agent 的 Docker 状态失败，请确认 Agent 在线并重试"
	default:
		return ErrOperationFailed.Error()
	}
}

func publicAppActionError(err error, action string) string {
	if errors.Is(err, ErrHTTPRuleListFailed) {
		return appendPublicCause("HTTP 规则列表对账失败，请刷新页面后重试", err)
	}
	if action == "files" {
		if msg := filesPublicMessage(err); msg != "" {
			return msg
		}
	}
	if action == "disk-cleanup" && errors.Is(err, ErrTypedHandlesUnavailable) {
		return diskCleanupUnavailableMessage
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
	case "rollback":
		staged = "回滚应用失败，请检查上一版本是否仍可用和目标 Agent 的 Docker 状态"
	case "http-rule":
		staged = "HTTP 规则创建失败，请检查域名冲突、发布端口和目标 Agent 状态"
	case "http-rule-delete":
		staged = "HTTP 规则删除失败，请检查规则是否仍存在和目标 Agent 状态"
	case "http-rule-list":
		staged = "HTTP 规则列表对账失败，请刷新页面后重试"
	case "logs":
		staged = "读取 Docker Compose 日志失败，请检查服务名和目标 Agent 状态"
	case "files":
		staged = "工作区文件操作失败，请检查相对路径和目标 Agent 状态"
	case "disk-cleanup":
		staged = "清理节点磁盘失败，请检查目标 Agent 的 Docker 状态"
	default:
		return ErrOperationFailed.Error()
	}
	return appendPublicCause(staged, err)
}

func filesCallError(err error) error {
	if err == nil {
		return nil
	}
	if filesPublicMessage(err) != "" || errors.Is(err, ErrAgentOffline) || errors.Is(err, ErrTypedHandlesUnavailable) || errors.Is(err, ErrEngineNotReady) || errors.Is(err, errWorkspaceFilePath) || errors.Is(err, ErrBoundExceeded) {
		return err
	}
	return safeFailure(ErrOperationFailed, err)
}

func filesPublicMessage(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errWorkspaceFilePath) {
		return errWorkspaceFilePath.Error()
	}
	if errors.Is(err, ErrBoundExceeded) {
		return "文件超过 1MiB 上限"
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "file path is not relative"), strings.Contains(text, "relative bind escapes"):
		return errWorkspaceFilePath.Error()
	case strings.Contains(text, "file exceeds"):
		return "文件超过 1MiB 上限"
	case strings.Contains(text, "file content is invalid"):
		return "文件内容无效"
	case strings.Contains(text, "path is not a directory"):
		return "路径不是目录"
	case strings.Contains(text, "path is a directory"):
		return "路径是目录"
	case strings.Contains(text, "app workdir cannot be deleted"):
		return "不能删除应用工作区根目录"
	case strings.Contains(text, "files action"):
		return "未知的文件操作"
	default:
		return ""
	}
}

func appendPublicCause(staged string, err error) string {
	cause := publicCause(err)
	if cause == "" || cause == staged || cause == ErrOperationFailed.Error() || cause == ErrTypedHandlesUnavailable.Error() || cause == ErrHTTPRuleListFailed.Error() {
		return staged
	}
	return staged + "：" + cause
}
