package dockerapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var (
	_                  pluginsdk.RPCPluginCaller = (*Controller)(nil)
	removeAppWorkspace                           = os.RemoveAll
)

// CommandRunner executes Agent-local commands for the execution face.
// Tests inject a fake; production defaults to the process PATH.
type CommandRunner interface {
	Run(ctx context.Context, dir, name string, args ...string) ([]byte, error)
}

// CommandRunnerFunc adapts a function to CommandRunner.
type CommandRunnerFunc func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

func (function CommandRunnerFunc) Run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	return function(ctx, dir, name, args...)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

type composeCallRequest struct {
	Action     string   `json:"action"`
	AgentID    string   `json:"agent_id"`
	AppID      string   `json:"app_id"`
	Compose    string   `json:"compose"`
	Env        string   `json:"env"`
	WorkDir    string   `json:"workdir"`
	Service    string   `json:"service"`
	Fence      uint64   `json:"fence"`
	Image      string   `json:"image"`
	Images     []string `json:"images"`
	KeepImages []string `json:"keep_images"`
	InstanceID string   `json:"instance_id"`
	RuleRef    string   `json:"rule_ref"`
}

type imageCallRequest struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	AppID   string `json:"app_id"`
	Image   string `json:"image"`
	Confirm bool   `json:"confirm"`
}

type filesCallRequest struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	AppID   string `json:"app_id"`
	WorkDir string `json:"workdir"`
	Path    string `json:"path"`
	Content []byte `json:"content"`
}

type fileListEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
}

const (
	localImageDigestFormat      = "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}"
	registryImagetoolsFormat    = "{{.Manifest.Digest}}"
	emptyImageDigestMessage     = "image digest is empty"
	imageObserveRequiredMessage = "image is required"
)

// Call is the Agent execution face. Host forwards plugin.call Name+Payload here.
func (controller *Controller) Call(ctx context.Context, generation, name string, payload []byte) ([]byte, error) {
	if controller == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = generation
	switch strings.TrimSpace(name) {
	case pluginCallEngineName:
		return controller.callEngineReport(ctx, payload)
	case pluginCallComposeName:
		return controller.callCompose(ctx, payload)
	case pluginCallImageName:
		return controller.callImage(ctx, payload)
	case pluginCallFilesName:
		return controller.callFiles(ctx, payload)
	default:
		return nil, fmt.Errorf("%w: plugin call name %q is unknown", ErrTypedHandlesUnavailable, name)
	}
}

func (controller *Controller) callEngineReport(ctx context.Context, payload []byte) ([]byte, error) {
	agentID, err := agentIDFromPayload(payload)
	if err != nil {
		return nil, err
	}
	report := AgentEngineReport{AgentID: agentID, Online: true}
	version, err := controller.dockerServerVersion(ctx)
	if err == nil {
		report.Installed = true
		report.Version = version
	}
	return json.Marshal(map[string]any{
		"agent_id": report.AgentID,
		"online":   report.Online,
		"engine": map[string]any{
			"installed": report.Installed,
			"version":   report.Version,
		},
	})
}

func (controller *Controller) callCompose(ctx context.Context, payload []byte) ([]byte, error) {
	var request composeCallRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, errors.New("compose payload is invalid")
	}
	if !validID(request.AppID) {
		return nil, errors.New("compose app id is invalid")
	}
	action := strings.TrimSpace(request.Action)
	root := controller.callWorkDirRoot(request.WorkDir)
	switch action {
	case "apply":
		if strings.TrimSpace(request.Compose) == "" {
			return nil, ErrInvalidCompose
		}
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
		if output, err := controller.runCommand(ctx, workspace.Dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, composeCallFailure("apply", output, err)
		}
		controller.reclaimUnusedImages(ctx, root, "", staleImageRefs(previous, current), append(append([]string{}, current...), request.KeepImages...))
		rewriteUsedImages(root, request.AppID, current)
		return json.Marshal(map[string]any{"accepted": true, "workdir": workspace.Dir})
	case "drain":
		return controller.callComposeDrain(ctx, root, request)
	case "start":
		dir, err := controller.composeActionWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		// Compose up creates missing containers, starts stopped containers, and
		// recreates services whose image or configuration changed. Unlike
		// restart, it also applies the current Compose declaration.
		if output, err := controller.runCommand(ctx, dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, composeCallFailure("start", output, err)
		}
		return json.Marshal(map[string]any{"accepted": true})
	case "stop", "restart", "remove", "pull", "ready", "remove-instance":
		dir, err := controller.composeActionWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		args, err := composeCommandArgs(action)
		if err != nil {
			return nil, err
		}
		var reclaimCandidates []string
		if action == "remove" {
			reclaimCandidates = request.reclaimImageRefs(root, dir)
		}
		if output, err := controller.runCommand(ctx, dir, "docker", args...); err != nil {
			return nil, composeCallFailure(action, output, err)
		}
		if action == "remove" {
			_ = removeAppWorkspace(dir)
			removeUsedImagesFile(root, request.AppID)
			controller.reclaimUnusedImages(ctx, root, request.AppID, reclaimCandidates, request.KeepImages)
		}
		return json.Marshal(map[string]any{"accepted": true})
	case "logs":
		dir, err := controller.composeActionWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		args := []string{"compose", "logs", "--no-color"}
		if strings.TrimSpace(request.Service) != "" {
			args = append(args, request.Service)
		}
		output, err := controller.runCommand(ctx, dir, "docker", args...)
		if err != nil {
			return nil, composeCallFailure("logs", output, err)
		}
		return json.Marshal(map[string]any{"logs": string(output)})
	case "start-instance":
		dir, err := controller.prepareComposeCallWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		if output, err := controller.runCommand(ctx, dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, composeCallFailure("start-instance", output, err)
		}
		instanceID := strings.TrimSpace(request.InstanceID)
		if instanceID == "" {
			instanceID = request.AppID
		}
		return json.Marshal(map[string]any{"accepted": true, "instance_id": instanceID})
	case "inspect":
		dir, err := controller.prepareComposeCallWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		if output, err := controller.runCommand(ctx, dir, "docker", "compose", "ps"); err != nil {
			return nil, composeCallFailure("inspect", output, err)
		}
		instanceID := strings.TrimSpace(request.InstanceID)
		if instanceID == "" {
			instanceID = request.AppID
		}
		return json.Marshal(RuntimeState{
			CandidateInstance: instanceID,
			Instances:         map[string]bool{instanceID: true},
		})
	default:
		return nil, fmt.Errorf("compose action %q is unknown", action)
	}
}

func (controller *Controller) composeActionWorkspace(root string, request composeCallRequest) (string, error) {
	if !composeRestageAction(request.Action) {
		return AppWorkDir(root, request.AppID)
	}
	return controller.prepareComposeCallWorkspace(root, request)
}

func composeRestageAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "apply", "pull", "start-instance", "inspect", "remove":
		return true
	default:
		return false
	}
}

func (controller *Controller) callComposeDrain(ctx context.Context, root string, request composeCallRequest) ([]byte, error) {
	dir, err := AppWorkDir(root, request.AppID)
	if err != nil {
		return nil, err
	}
	reclaimCandidates := request.reclaimImageRefs(root, dir)
	current := request.currentImageRefs(dir)
	keep := append(append([]string{}, current...), request.KeepImages...)
	if len(keep) > 0 {
		controller.reclaimUnusedImages(ctx, root, "", reclaimCandidates, keep)
		if len(current) > 0 {
			rewriteUsedImages(root, request.AppID, current)
		}
	}
	return json.Marshal(map[string]any{"accepted": true})
}

func (controller *Controller) prepareComposeCallWorkspace(root string, request composeCallRequest) (string, error) {
	request.Compose = request.composeForWorkspace(root)
	previous := existingWorkspaceImages(root, request.AppID)
	if strings.TrimSpace(request.Compose) == "" {
		recordUsedImages(root, request.AppID, previous)
		return AppWorkDir(root, request.AppID)
	}
	workspace, err := PrepareAppWorkspace(root, request.AppID, request.Compose)
	if err != nil {
		if strings.TrimSpace(request.Action) == "remove" {
			if dir, dirErr := existingComposeWorkDir(root, request.AppID); dirErr == nil {
				recordUsedImages(root, request.AppID, previous)
				return dir, nil
			}
		}
		return "", err
	}
	if strings.TrimSpace(request.Env) != "" {
		if err := writeAppEnvironment(workspace.Dir, request.Env); err != nil {
			if strings.TrimSpace(request.Action) == "remove" {
				recordUsedImages(root, request.AppID, append(previous, composeImageRefs(request.Compose)...))
				return workspace.Dir, nil
			}
			return "", err
		}
	}
	recordUsedImages(root, request.AppID, append(previous, composeImageRefs(request.Compose)...))
	return workspace.Dir, nil
}

func existingComposeWorkDir(root, appID string) (string, error) {
	dir, err := AppWorkDir(root, appID)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, ComposeFileName)); err != nil {
		return "", err
	}
	return dir, nil
}

func composeCommandArgs(action string) ([]string, error) {
	switch action {
	case "stop":
		return []string{"compose", "stop"}, nil
	case "restart":
		return []string{"compose", "restart"}, nil
	case "remove":
		return []string{"compose", "down"}, nil
	case "pull":
		return []string{"compose", "pull"}, nil
	case "ready":
		return []string{"compose", "ps"}, nil
	case "remove-instance":
		return []string{"compose", "rm", "-f"}, nil
	default:
		return nil, fmt.Errorf("compose action %q is unknown", action)
	}
}

func (request composeCallRequest) composeForWorkspace(root string) string {
	compose := request.Compose
	digest := imageDigestSuffix(request.Image)
	if digest == "" {
		return compose
	}
	if strings.TrimSpace(compose) == "" {
		if dir, err := AppWorkDir(root, request.AppID); err == nil {
			if payload, err := os.ReadFile(filepath.Join(dir, ComposeFileName)); err == nil {
				compose = string(payload)
			}
		}
	}
	return pinComposeImages(compose, digest)
}

func (request composeCallRequest) reclaimImageRefs(root, dir string) []string {
	images := append([]string{}, request.Images...)
	if strings.TrimSpace(request.Image) != "" {
		images = append(images, request.Image)
	}
	images = append(images, composeImageRefs(request.Compose)...)
	if dir != "" {
		if payload, err := os.ReadFile(filepath.Join(dir, ComposeFileName)); err == nil {
			images = append(images, composeImageRefs(string(payload))...)
		}
	}
	images = append(images, existingWorkspaceImages(root, request.AppID)...)
	return uniqueImageRefs(images)
}

func (request composeCallRequest) currentImageRefs(dir string) []string {
	images := composeImageRefs(request.Compose)
	if dir != "" {
		if payload, err := os.ReadFile(filepath.Join(dir, ComposeFileName)); err == nil {
			images = append(images, composeImageRefs(string(payload))...)
		}
	}
	if strings.TrimSpace(request.Image) != "" {
		images = append(images, request.Image)
	}
	return uniqueImageRefs(images)
}

func (controller *Controller) reclaimUnusedImages(ctx context.Context, root, excludeAppID string, candidates, keep []string) {
	candidates = uniqueImageRefs(candidates)
	if len(candidates) == 0 {
		return
	}
	keepSet := make(map[string]struct{})
	for _, image := range uniqueImageRefs(append(append([]string{}, keep...), siblingComposeImages(root, excludeAppID)...)) {
		keepSet[image] = struct{}{}
	}
	for _, image := range candidates {
		if _, kept := keepSet[image]; kept {
			continue
		}
		if controller.imageReferencedByContainer(ctx, image) {
			continue
		}
		_, _ = controller.runCommand(ctx, "", "docker", "image", "rm", image)
	}
}

func (controller *Controller) imageReferencedByContainer(ctx context.Context, image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return true
	}
	output, err := controller.runCommand(ctx, "", "docker", "ps", "-a", "--filter", "ancestor="+image, "--format", "{{.ID}}")
	if err != nil {
		return true
	}
	for _, line := range strings.Split(normalizeCommandOutput(output), "\n") {
		if containerReferenceLine(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func containerReferenceLine(line string) bool {
	if line == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(line), "sha256:") {
		return digestCore(line) != ""
	}
	if len(line) < 12 {
		return false
	}
	return isHexDigest(line)
}

func (controller *Controller) callDiskPrune(ctx context.Context, preview, confirm bool) ([]byte, error) {
	if !preview && !confirm {
		return json.Marshal(map[string]any{
			"accepted":  true,
			"unchanged": true,
			"empty":     true,
			"preview":   false,
		})
	}
	imageOut, imageErr := controller.runCommand(ctx, "", "docker", imagePruneArgs(preview)...)
	builderOut, builderErr := controller.runCommand(ctx, "", "docker", builderPruneArgs(preview)...)
	if imageErr != nil || builderErr != nil {
		return nil, pruneCallFailure(imageOut, builderOut, imageErr, builderErr)
	}
	imageText := sanitizePruneReport(normalizeCommandOutput(imageOut))
	builderText := sanitizePruneReport(normalizeCommandOutput(builderOut))
	empty := pruneOutputEmpty(imageText) && pruneOutputEmpty(builderText)
	return json.Marshal(map[string]any{
		"accepted":      true,
		"preview":       preview,
		"empty":         empty,
		"images":        imageText,
		"builder_cache": builderText,
	})
}

func imagePruneArgs(dryRun bool) []string {
	args := []string{"image", "prune", "-a"}
	if dryRun {
		return append(args, "--dry-run")
	}
	return append(args, "-f")
}

func builderPruneArgs(dryRun bool) []string {
	args := []string{"builder", "prune"}
	if dryRun {
		return append(args, "--dry-run")
	}
	return append(args, "-f")
}

func pruneOutputEmpty(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" || lower == "ok" {
		return true
	}
	if strings.Contains(lower, "untagged:") || strings.Contains(lower, "deleted:") {
		return false
	}
	if strings.Contains(lower, "nothing to") {
		return true
	}
	return pruneOutputZeroTotal(lower)
}

func pruneOutputZeroTotal(lower string) bool {
	if strings.Contains(lower, "total reclaimed space: 0") {
		return true
	}
	for _, line := range strings.Split(lower, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "total:" {
			continue
		}
		for index, field := range fields[1:] {
			if field == "0b" || field == "0ib" {
				return true
			}
			if field == "0" && index+2 < len(fields) {
				unit := fields[index+2]
				if unit == "b" || strings.HasPrefix(unit, "b") {
					return true
				}
			}
		}
	}
	return false
}

func sanitizePruneReport(text string) string {
	text = secretAssignmentPattern.ReplaceAllString(strings.TrimSpace(text), "${1}***")
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			continue
		}
		if containsLocalDockerMarker(strings.ToLower(line)) {
			continue
		}
		kept = append(kept, line)
	}
	report := strings.Join(kept, "\n")
	if len(report) > 4096 {
		report = strings.TrimSpace(report[:4096])
	}
	return report
}

func pruneCallFailure(imageOut, builderOut []byte, imageErr, builderErr error) error {
	cause := sanitizePruneReport(strings.TrimSpace(string(imageOut) + "\n" + string(builderOut)))
	if cause == "" {
		if imageErr != nil {
			cause = publicCause(imageErr)
		} else if builderErr != nil {
			cause = publicCause(builderErr)
		}
	}
	if cause == "" {
		return errors.New("disk prune failed")
	}
	if strings.Contains(cause, "\n") {
		cause = strings.SplitN(cause, "\n", 2)[0]
	}
	return fmt.Errorf("disk prune failed: %s", cause)
}

func commandHasVolumeDeletion(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	if strings.Contains(lower, "volume prune") || strings.Contains(lower, "--volumes") {
		return true
	}
	for _, field := range strings.Fields(lower) {
		if field == "-v" {
			return true
		}
	}
	return false
}

func (controller *Controller) callImage(ctx context.Context, payload []byte) ([]byte, error) {
	var request imageCallRequest
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, errors.New("image payload is invalid")
		}
	}
	switch strings.TrimSpace(request.Action) {
	case "", "observe":
		return controller.callImageObserve(ctx, request)
	case "preview", "preview-prune":
		return controller.callDiskPrune(ctx, true, false)
	case "prune":
		return controller.callDiskPrune(ctx, false, request.Confirm)
	default:
		return nil, fmt.Errorf("image action %q is unknown", request.Action)
	}
}

func (controller *Controller) callImageObserve(ctx context.Context, request imageCallRequest) ([]byte, error) {
	if controller.callImages != nil {
		observed, err := controller.callImages.ObserveImage(ctx, App{
			ID: request.AppID, AgentID: request.AgentID, Image: request.Image,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{
			"current_digest": observed.CurrentDigest,
			"latest_digest":  observed.LatestDigest,
		})
	}
	if strings.TrimSpace(request.Image) == "" {
		return nil, errors.New(imageObserveRequiredMessage)
	}
	current, err := controller.dockerImageDigest(ctx, request.Image)
	if err != nil {
		return nil, err
	}
	latest := current
	if registry := controller.dockerRegistryDigest(ctx, request.Image); registry != "" {
		if formed := sameFormDigest(current, registry); formed != "" {
			latest = formed
		}
	}
	return json.Marshal(map[string]any{
		"current_digest": current,
		"latest_digest":  latest,
	})
}

func (controller *Controller) callFiles(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var request filesCallRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, errors.New("files payload is invalid")
	}
	if !validID(request.AppID) {
		return nil, errors.New("files app id is invalid")
	}
	output, err := executeWorkspaceFiles(controller.callWorkDirRoot(request.WorkDir), request)
	if err != nil {
		return nil, filesCallFailure(request.Action, err)
	}
	return output, nil
}

func executeWorkspaceFiles(root string, request filesCallRequest) ([]byte, error) {
	action := strings.TrimSpace(request.Action)
	workdir, resolved, err := resolveWorkspaceFilePath(root, request.AppID, request.Path)
	if err != nil {
		return nil, err
	}
	switch action {
	case "list":
		return marshalWorkspaceList(workdir, resolved)
	case "mkdir":
		return marshalFilesAccepted(mkdirWorkspacePath(resolved))
	case "read":
		content, err := readWorkspaceFile(resolved)
		if err != nil {
			return nil, err
		}
		display, err := workspaceDisplayPath(workdir, resolved)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"path": display, "content": content})
	case "write":
		if len(request.Content) > MaxConfigBytes {
			return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
		}
		return marshalFilesAccepted(writeWorkspaceFile(workdir, resolved, request.Content))
	case "delete":
		return marshalFilesAccepted(deleteWorkspacePath(workdir, resolved))
	default:
		return nil, fmt.Errorf("files action %q is unknown", action)
	}
}

func marshalFilesAccepted(err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"accepted": true})
}

func marshalWorkspaceList(workdir, resolved string) ([]byte, error) {
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file path is not relative to app workdir")
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	items, err := os.ReadDir(resolved)
	if err != nil {
		return nil, err
	}
	display, err := workspaceDisplayPath(workdir, resolved)
	if err != nil {
		return nil, err
	}
	entries := make([]workspaceFileEntry, 0, len(items))
	for _, item := range items {
		child := filepath.Join(resolved, item.Name())
		childRel, err := workspaceDisplayPath(workdir, child)
		if err != nil {
			return nil, err
		}
		entry := workspaceFileEntry{Name: item.Name(), Path: childRel, Dir: item.IsDir()}
		if !item.IsDir() {
			if details, err := item.Info(); err == nil {
				entry.Size = details.Size()
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return json.Marshal(map[string]any{"path": display, "entries": entries})
}

func mkdirWorkspacePath(resolved string) error {
	info, err := os.Lstat(resolved)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("file path is not relative to app workdir")
		}
		if info.IsDir() {
			return nil
		}
		return errors.New("path is not a directory")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(resolved, 0o755)
}

func readWorkspaceFile(resolved string) ([]byte, error) {
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file path is not relative to app workdir")
	}
	if info.IsDir() {
		return nil, errors.New("path is a directory")
	}
	if info.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	payload, err := os.ReadFile(resolved)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrBoundExceeded, MaxConfigBytes)
	}
	return payload, nil
}

func writeWorkspaceFile(workdir, resolved string, content []byte) error {
	if filepath.Clean(resolved) == filepath.Clean(workdir) {
		return errors.New("path is a directory")
	}
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("file path is not relative to app workdir")
		}
		if info.IsDir() {
			if err := ensureBindFilePath(resolved); err != nil {
				return errors.New("path is a directory")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(resolved)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".nre-files-*")
	if err != nil {
		return err
	}
	tmpName := temporary.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		if removeErr := os.Remove(resolved); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpName, resolved); err != nil {
			return err
		}
	}
	success = true
	return nil
}

func deleteWorkspacePath(workdir, resolved string) error {
	if filepath.Clean(resolved) == filepath.Clean(workdir) {
		return errors.New("app workdir cannot be deleted")
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("file path is not relative to app workdir")
	}
	return os.RemoveAll(resolved)
}

func (controller *Controller) dockerServerVersion(ctx context.Context) (string, error) {
	output, err := controller.runCommand(ctx, "", "docker", "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return "", err
	}
	return parseDockerServerVersion(output)
}

func parseDockerServerVersion(output []byte) (string, error) {
	text := normalizeCommandOutput(output)
	if text == "" {
		return "", errors.New("docker server version is missing")
	}
	line := text
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		line = strings.TrimSpace(text[:i])
	}
	if unusableDockerVersion(line) {
		return "", errors.New("docker server version is missing")
	}
	return strings.TrimPrefix(line, "v"), nil
}

func unusableDockerVersion(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" || lower == "<no value>" {
		return true
	}
	if containsLocalDockerMarker(lower) || strings.Contains(lower, "cannot connect") {
		return true
	}
	return false
}

func (controller *Controller) dockerImageDigest(ctx context.Context, image string) (string, error) {
	output, err := controller.runCommand(ctx, "", "docker", "image", "inspect", "--format", localImageDigestFormat, image)
	if err != nil {
		return "", sanitizeDockerError(err, emptyImageDigestMessage)
	}
	digest := parseLocalImageDigest(output)
	if digest == "" {
		return "", errors.New(emptyImageDigestMessage)
	}
	return digest, nil
}

func (controller *Controller) dockerRegistryDigest(ctx context.Context, image string) string {
	output, err := controller.runCommand(ctx, "", "docker", "buildx", "imagetools", "inspect", "--format", registryImagetoolsFormat, image)
	if err == nil {
		if digest := parseRegistryDigest(output); digest != "" {
			return digest
		}
	}
	output, err = controller.runCommand(ctx, "", "docker", "manifest", "inspect", "--verbose", image)
	if err == nil {
		if digest := parseRegistryDigest(output); digest != "" {
			return digest
		}
	}
	return ""
}

func (controller *Controller) runCommand(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	runner := controller.commandRunner
	if runner == nil {
		runner = execCommandRunner{}
	}
	return runner.Run(ctx, dir, name, args...)
}

func (controller *Controller) callWorkDirRoot(payloadWorkDir string) string {
	if strings.TrimSpace(payloadWorkDir) != "" {
		return payloadWorkDir
	}
	return controller.executionWorkDirRoot()
}

func (controller *Controller) executionWorkDirRoot() string {
	if controller != nil && strings.TrimSpace(controller.uiWorkDirRoot) != "" {
		return controller.uiWorkDirRoot
	}
	return defaultExecutionWorkDirRoot()
}

func defaultExecutionWorkDirRoot() string {
	if env := strings.TrimSpace(os.Getenv("NRE_PLUGIN_APP_WORKDIR")); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil {
		if home = strings.TrimSpace(home); home != "" {
			// Linux RPC plugin sandboxes deliberately use /nonexistent as HOME.
			// Compose files are only staging input there: the Agent's Docker
			// proxy persists them below its managed workspace root. Keep the
			// staging copy in the sandbox's writable temporary directory.
			if root, ok := sandboxExecutionWorkDirRoot(runtime.GOOS, home, os.TempDir()); ok {
				return root
			}
			return filepath.Join(home, ".nre", "docker-app")
		}
	}
	if runtime.GOOS == "windows" {
		base := strings.TrimSpace(os.Getenv("ProgramData"))
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "nre-docker-app")
	}
	return "/var/lib/nre-docker-app"
}

func sandboxExecutionWorkDirRoot(goos, home, temporary string) (string, bool) {
	if goos == "windows" || strings.TrimSpace(home) != "/nonexistent" {
		return "", false
	}
	temporary = strings.TrimSpace(temporary)
	if temporary == "" {
		return "", false
	}
	return filepath.Join(temporary, "nre-docker-app"), true
}

func composeCallFailure(action string, output []byte, err error) error {
	cause := sanitizePublicText(string(output))
	if cause == "" {
		cause = publicCause(err)
	}
	if cause == "" {
		return fmt.Errorf("compose %s failed", action)
	}
	return fmt.Errorf("compose %s failed: %s", action, cause)
}

func filesCallFailure(action string, err error) error {
	if err == nil {
		return nil
	}
	text := sanitizePublicText(err.Error())
	if strings.HasPrefix(text, "files ") {
		return err
	}
	cause := publicFilesCause(err)
	action = strings.TrimSpace(action)
	if action == "" {
		action = "call"
	}
	if cause == "" {
		return fmt.Errorf("files %s failed", action)
	}
	return fmt.Errorf("files %s failed: %s", action, cause)
}

func publicFilesCause(err error) string {
	if err == nil {
		return ""
	}
	text := sanitizePublicText(err.Error())
	if text == "" {
		return ""
	}
	if strings.HasPrefix(text, "files ") || filesPublicCauseAllowed(text) {
		return text
	}
	return ""
}

func filesPublicCauseAllowed(text string) bool {
	return strings.Contains(text, "file path is not relative") ||
		strings.Contains(text, "relative bind escapes") ||
		strings.Contains(text, "file exceeds") ||
		strings.Contains(text, "file content is invalid") ||
		strings.Contains(text, "path is not a directory") ||
		strings.Contains(text, "path is a directory") ||
		strings.Contains(text, "app workdir cannot be deleted")
}

func writeAppEnvironment(dir, value string) error {
	if len(value) > MaxConfigBytes || strings.ContainsRune(value, '\x00') {
		return errors.New("compose environment is invalid")
	}
	temporary, err := os.CreateTemp(dir, ".env-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer func() { _ = os.Remove(path) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(dir, ".env"))
}

func agentIDFromPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("agent id is invalid")
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return "", errors.New("engine report payload is invalid")
	}
	agentID := stringField(raw, "agent_id")
	if agentID == "" {
		agentID = stringField(raw, "id")
	}
	if !validAgentID(agentID) {
		return "", errors.New("agent id is invalid")
	}
	return agentID, nil
}

func parseLocalImageDigest(output []byte) string {
	text := normalizeCommandOutput(output)
	if digest := imageDigestValue(text); digest != "" {
		return digest
	}
	var payload any
	if json.Unmarshal([]byte(text), &payload) == nil {
		if digest := localDigestFromInspectJSON(payload); digest != "" {
			return digest
		}
	}
	return firstLineDigest(text)
}

func parseRegistryDigest(output []byte) string {
	text := normalizeCommandOutput(output)
	if digest := imageDigestValue(text); digest != "" {
		return digest
	}
	var payload any
	if json.Unmarshal([]byte(text), &payload) == nil {
		if _, isArray := payload.([]any); isArray {
			return ""
		}
		if digest := registryDigestFromJSON(payload); digest != "" {
			return digest
		}
	}
	return firstLineDigest(text)
}

func localDigestFromInspectJSON(payload any) string {
	switch typed := payload.(type) {
	case []any:
		for _, item := range typed {
			if digest := localDigestFromInspectJSON(item); digest != "" {
				return digest
			}
		}
	case map[string]any:
		if digest := firstRepoDigest(typed["RepoDigests"]); digest != "" {
			return digest
		}
		if digest := firstRepoDigest(typed["repoDigests"]); digest != "" {
			return digest
		}
		if digest := imageDigestValue(stringField(typed, "Id")); digest != "" {
			return digest
		}
		if digest := imageDigestValue(stringField(typed, "id")); digest != "" {
			return digest
		}
	}
	return ""
}

func firstRepoDigest(value any) string {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				continue
			}
			if digest := imageDigestValue(text); digest != "" {
				return digest
			}
		}
	case []string:
		for _, text := range typed {
			if digest := imageDigestValue(text); digest != "" {
				return digest
			}
		}
	case string:
		return imageDigestValue(typed)
	}
	return ""
}

func registryDigestFromJSON(payload any) string {
	switch typed := payload.(type) {
	case []any:
		// Verbose multi-arch inspect is a platform descriptor array, not the tag digest.
		return ""
	case map[string]any:
		for _, key := range []string{"Manifest", "manifest"} {
			nested, ok := typed[key].(map[string]any)
			if !ok {
				continue
			}
			if digest := registryDigestFromJSON(nested); digest != "" {
				return digest
			}
		}
		for _, key := range []string{"Descriptor", "descriptor"} {
			nested, ok := typed[key].(map[string]any)
			if !ok {
				continue
			}
			if digest := imageDigestValue(stringField(nested, "digest")); digest != "" {
				return digest
			}
			if digest := imageDigestValue(stringField(nested, "Digest")); digest != "" {
				return digest
			}
		}
		if digest := imageDigestValue(stringField(typed, "digest")); digest != "" {
			return digest
		}
		if digest := imageDigestValue(stringField(typed, "Digest")); digest != "" {
			return digest
		}
	case string:
		return imageDigestValue(typed)
	}
	return ""
}

func sameFormDigest(current, latest string) string {
	core := digestCore(latest)
	if core == "" {
		return ""
	}
	if at := strings.LastIndex(current, "@"); at >= 0 {
		prefix := strings.TrimSpace(current[:at])
		if prefix != "" && imageDigestValue(prefix+"@"+core) != "" {
			return prefix + "@" + core
		}
	}
	return core
}

func firstLineDigest(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if digest := imageDigestValue(lines[i]); digest != "" {
			return digest
		}
	}
	return ""
}

func imageDigestValue(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	if value == "" || value == "<no value>" {
		return ""
	}
	if containsLocalDockerMarker(strings.ToLower(value)) {
		return ""
	}
	if digestCore(value) == "" {
		return ""
	}
	if at := strings.LastIndex(value, "@"); at >= 0 {
		prefix := strings.TrimSpace(value[:at])
		if prefix == "" {
			return digestCore(value)
		}
		return prefix + "@" + digestCore(value)
	}
	return digestCore(value)
}

func digestCore(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	algo, hex, ok := strings.Cut(value, ":")
	if !ok {
		return ""
	}
	algo = strings.ToLower(strings.TrimSpace(algo))
	hex = strings.ToLower(strings.TrimSpace(hex))
	if algo != "sha256" || len(hex) < 8 || !isHexDigest(hex) {
		return ""
	}
	return algo + ":" + hex
}

func isHexDigest(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return false
	}
	return true
}

func normalizeCommandOutput(output []byte) string {
	return strings.ReplaceAll(string(bytes.TrimSpace(output)), "\r\n", "\n")
}

func sanitizeDockerError(err error, fallback string) error {
	if err == nil {
		return errors.New(fallback)
	}
	if containsLocalDockerMarker(strings.ToLower(err.Error())) {
		return errors.New(fallback)
	}
	return err
}
