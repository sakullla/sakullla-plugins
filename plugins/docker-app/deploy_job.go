package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	deployPhasePreparing = "preparing"
	deployPhasePulling   = "pulling"
	deployPhaseStarting  = "starting"
	deployPhaseSucceeded = "succeeded"
	deployPhaseFailed    = "failed"
	deployPhaseCancelled = "cancelled"

	deployLogName    = "deploy.log"
	deployStatusName = "deploy-status.json"
	deployLogTail    = 12 << 10
)

// DeployProgress is the public state of one Compose apply. The log is the
// tail of `docker compose up`, so a slow registry stays visible instead of
// looking like a stuck request.
type DeployProgress struct {
	AppID   string `json:"app_id,omitempty"`
	Phase   string `json:"phase"`
	Message string `json:"message,omitempty"`
	Logs    string `json:"logs,omitempty"`
	Error   string `json:"error,omitempty"`
}

// DeploySupervisor starts and watches a Compose apply on the target Agent.
// The apply keeps running after the plugin call that started it returns.
type DeploySupervisor interface {
	StartDeploy(context.Context, App) (DeployProgress, error)
	DeployStatus(context.Context, App) (DeployProgress, error)
	CancelDeploy(context.Context, App) error
}

type deployProcessStarter func(dir string, output io.Writer) (wait func() error, stop func(), err error)

type activeDeploy struct {
	stop     func()
	cancel   bool
	finished chan struct{}
}

type deployStatusFile struct {
	Phase string `json:"phase"`
	Error string `json:"error,omitempty"`
}

// pendingDeploy remembers a Compose document until the background apply
// finishes, so the catalog is not marked running while the image is still pulling.
type pendingDeploy struct {
	spec       ComposeDeploySpec
	report     AgentEngineReport
	autoUpdate bool
	existing   App
}

type redactingWriter struct {
	dst io.Writer
}

func (writer redactingWriter) Write(payload []byte) (int, error) {
	_, err := io.WriteString(writer.dst, redactDeployLog(string(payload)))
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

var deploySecretPattern = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|access_key)\s*[:=]\s*\S+`)

func redactDeployLog(text string) string {
	return deploySecretPattern.ReplaceAllString(text, "$1=***")
}

func deployPhaseMessage(phase string) string {
	switch phase {
	case deployPhasePulling:
		return "正在拉取镜像。仓库较慢时会一直停留在这一步，日志会继续刷新。"
	case deployPhaseStarting:
		return "镜像已就绪，正在创建并启动容器。"
	case deployPhaseSucceeded:
		return "部署完成。"
	case deployPhaseFailed:
		return "部署失败。"
	case deployPhaseCancelled:
		return "已停止这次部署。节点上未完成的拉取已中止。"
	default:
		return "正在准备应用工作区。"
	}
}

func refineDeployPhase(phase, logs string) string {
	switch phase {
	case deployPhaseSucceeded, deployPhaseFailed, deployPhaseCancelled:
		return phase
	}
	lines := strings.Split(logs, "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		line := lines[index]
		if strings.Contains(line, "Started") || strings.Contains(line, "Creating") || strings.Contains(line, "Recreated") {
			return deployPhaseStarting
		}
		if strings.Contains(line, "Pulling") || strings.Contains(line, "Downloading") || strings.Contains(line, "Extracting") || strings.Contains(line, "Waiting") {
			return deployPhasePulling
		}
	}
	if phase == "" {
		return deployPhasePreparing
	}
	return phase
}

func (controller *Controller) deployRunMap() map[string]*activeDeploy {
	if controller.deployRuns == nil {
		controller.deployRuns = map[string]*activeDeploy{}
	}
	return controller.deployRuns
}

func deployTerminal(phase string) bool {
	switch phase {
	case deployPhaseSucceeded, deployPhaseFailed, deployPhaseCancelled:
		return true
	default:
		return false
	}
}

func (controller *Controller) startComposeDeploy(root string, request composeCallRequest) ([]byte, error) {
	previous := existingWorkspaceImages(root, request.AppID)
	workspace, err := PrepareAppWorkspace(root, request.AppID, request.Compose)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Env) != "" {
		if err := writeAppEnvironment(workspace.Dir, request.Env); err != nil {
			return nil, err
		}
	}
	current := composeImageRefs(request.Compose)
	recordUsedImages(root, request.AppID, append(previous, current...))

	controller.deployMu.Lock()
	defer controller.deployMu.Unlock()
	if progress, ok := controller.currentDeployLocked(request.AppID, workspace.Dir); ok && !deployTerminal(progress.Phase) {
		return json.Marshal(progress)
	}
	logFile, err := os.Create(filepath.Join(workspace.Dir, deployLogName))
	if err != nil {
		return nil, err
	}
	if err := writeDeployStatus(workspace.Dir, deployStatusFile{Phase: deployPhasePreparing}); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	starter := controller.deployStarter
	if starter == nil {
		starter = defaultDeployStarter
	}
	wait, stop, err := starter(workspace.Dir, redactingWriter{dst: logFile})
	if err != nil || wait == nil || stop == nil {
		_ = logFile.Close()
		_ = writeDeployStatus(workspace.Dir, deployStatusFile{Phase: deployPhaseFailed, Error: "未能启动 docker compose"})
		if err == nil {
			err = errors.New("compose deploy did not start")
		}
		return nil, err
	}
	run := &activeDeploy{stop: stop, finished: make(chan struct{})}
	controller.deployRunMap()[request.AppID] = run
	_ = writeDeployStatus(workspace.Dir, deployStatusFile{Phase: deployPhasePulling})
	go controller.finishComposeDeploy(run, wait, logFile, root, workspace.Dir, request.AppID, previous, current, request.KeepImages)
	return json.Marshal(controller.readDeployProgress(request.AppID, workspace.Dir))
}

func (controller *Controller) finishComposeDeploy(run *activeDeploy, wait func() error, logFile *os.File, root, dir, appID string, previous, current, keep []string) {
	err := wait()
	_ = logFile.Close()
	controller.deployMu.Lock()
	cancelled := run.cancel
	if currentRun, ok := controller.deployRunMap()[appID]; ok && currentRun == run {
		delete(controller.deployRuns, appID)
	}
	controller.deployMu.Unlock()
	status := deployStatusFile{Phase: deployPhaseSucceeded}
	if cancelled {
		status.Phase = deployPhaseCancelled
	} else if err != nil {
		status.Phase = deployPhaseFailed
		status.Error = "部署失败"
	} else if recErr := recordPublishedImages(dir); recErr != nil {
		status.Phase = deployPhaseFailed
		status.Error = "容器已启动，但记录发布镜像失败"
	} else {
		retained := append(append([]string{}, current...), keep...)
		controller.reclaimUnusedImages(context.Background(), root, "", staleImageRefs(previous, current), retained)
		rewriteUsedImages(root, appID, current)
	}
	_ = writeDeployStatus(dir, status)
	close(run.finished)
}

func (controller *Controller) composeDeployStatus(root string, request composeCallRequest) ([]byte, error) {
	dir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, err
	}
	controller.deployMu.Lock()
	defer controller.deployMu.Unlock()
	return json.Marshal(controller.readDeployProgress(request.AppID, dir))
}

func (controller *Controller) cancelComposeDeploy(root string, request composeCallRequest) ([]byte, error) {
	dir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, err
	}
	controller.deployMu.Lock()
	defer controller.deployMu.Unlock()
	if run := controller.deployRunMap()[request.AppID]; run != nil && !run.cancel {
		run.cancel = true
		if run.stop != nil {
			run.stop()
		}
	}
	progress := controller.readDeployProgress(request.AppID, dir)
	if !deployTerminal(progress.Phase) {
		_ = writeDeployStatus(dir, deployStatusFile{Phase: deployPhaseCancelled})
		progress = controller.readDeployProgress(request.AppID, dir)
	}
	return json.Marshal(progress)
}

func (controller *Controller) currentDeployLocked(appID, dir string) (DeployProgress, bool) {
	if _, err := os.Stat(filepath.Join(dir, deployStatusName)); err != nil {
		return DeployProgress{}, false
	}
	return controller.readDeployProgress(appID, dir), true
}

func (controller *Controller) readDeployProgress(appID, dir string) DeployProgress {
	status := deployStatusFile{Phase: deployPhasePreparing}
	if payload, err := os.ReadFile(filepath.Join(dir, deployStatusName)); err == nil {
		_ = json.Unmarshal(payload, &status)
	}
	logs := tailDeployLog(filepath.Join(dir, deployLogName))
	phase := refineDeployPhase(status.Phase, logs)
	progress := DeployProgress{
		AppID:   appID,
		Phase:   phase,
		Message: deployPhaseMessage(phase),
		Logs:    logs,
		Error:   strings.TrimSpace(status.Error),
	}
	if phase == deployPhaseFailed && progress.Error == "" {
		progress.Error = "部署失败"
	}
	return progress
}

func writeDeployStatus(dir string, status deployStatusFile) error {
	payload, err := json.Marshal(status)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, deployStatusName)
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, target)
}

func tailDeployLog(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	start := int64(0)
	if info.Size() > deployLogTail {
		start = info.Size() - deployLogTail
	}
	buffer := make([]byte, info.Size()-start)
	if _, err := file.ReadAt(buffer, start); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	text := redactDeployLog(string(buffer))
	if start > 0 {
		if index := strings.IndexByte(text, '\n'); index >= 0 {
			text = text[index+1:]
		}
		text = "…\n" + text
	}
	return text
}

func defaultDeployStarter(dir string, output io.Writer) (func() error, func(), error) {
	command := exec.Command("docker", "compose", "up", "-d")
	command.Dir = dir
	command.Stdout = output
	command.Stderr = output
	detachProcess(command)
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	return command.Wait, func() { stopProcess(command) }, nil
}
