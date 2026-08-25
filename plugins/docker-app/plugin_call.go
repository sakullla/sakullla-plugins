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
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var _ pluginsdk.RPCPluginCaller = (*Controller)(nil)

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
	Action     string `json:"action"`
	AgentID    string `json:"agent_id"`
	AppID      string `json:"app_id"`
	Compose    string `json:"compose"`
	Env        string `json:"env"`
	WorkDir    string `json:"workdir"`
	Service    string `json:"service"`
	Fence      uint64 `json:"fence"`
	Image      string `json:"image"`
	InstanceID string `json:"instance_id"`
	RuleRef    string `json:"rule_ref"`
}

type imageCallRequest struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	AppID   string `json:"app_id"`
	Image   string `json:"image"`
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
	root := controller.executionWorkDirRoot()
	if strings.TrimSpace(request.WorkDir) != "" {
		root = request.WorkDir
	}
	switch action {
	case "apply":
		if strings.TrimSpace(request.Compose) == "" {
			return nil, ErrInvalidCompose
		}
		workspace, err := PrepareAppWorkspace(root, request.AppID, request.Compose)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(request.Env) != "" {
			if err := writeAppEnvironment(workspace.Dir, request.Env); err != nil {
				return nil, err
			}
		}
		if output, err := controller.runCommand(ctx, workspace.Dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, composeCallFailure("apply", output, err)
		}
		return json.Marshal(map[string]any{"accepted": true, "workdir": workspace.Dir})
	case "start", "stop", "restart", "remove", "pull", "ready", "drain", "remove-instance":
		dir, err := controller.prepareComposeCallWorkspace(root, request)
		if err != nil {
			return nil, err
		}
		args, err := composeCommandArgs(action)
		if err != nil {
			return nil, err
		}
		if output, err := controller.runCommand(ctx, dir, "docker", args...); err != nil {
			return nil, composeCallFailure(action, output, err)
		}
		return json.Marshal(map[string]any{"accepted": true})
	case "logs":
		dir, err := controller.prepareComposeCallWorkspace(root, request)
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

func (controller *Controller) prepareComposeCallWorkspace(root string, request composeCallRequest) (string, error) {
	if strings.TrimSpace(request.Compose) == "" {
		return AppWorkDir(root, request.AppID)
	}
	workspace, err := PrepareAppWorkspace(root, request.AppID, request.Compose)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(request.Env) != "" {
		if err := writeAppEnvironment(workspace.Dir, request.Env); err != nil {
			return "", err
		}
	}
	return workspace.Dir, nil
}

func composeCommandArgs(action string) ([]string, error) {
	switch action {
	case "start":
		return []string{"compose", "start"}, nil
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
	case "drain":
		return []string{"compose", "stop"}, nil
	case "remove-instance":
		return []string{"compose", "rm", "-f"}, nil
	default:
		return nil, fmt.Errorf("compose action %q is unknown", action)
	}
}

func (controller *Controller) callImage(ctx context.Context, payload []byte) ([]byte, error) {
	var request imageCallRequest
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, errors.New("image payload is invalid")
		}
	}
	action := strings.TrimSpace(request.Action)
	if action != "" && action != "observe" {
		return nil, fmt.Errorf("image action %q is unknown", action)
	}
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

func (controller *Controller) executionWorkDirRoot() string {
	if controller != nil && strings.TrimSpace(controller.uiWorkDirRoot) != "" {
		return controller.uiWorkDirRoot
	}
	return defaultExecutionWorkDirRoot()
}

func defaultExecutionWorkDirRoot() string {
	if env := strings.TrimSpace(os.Getenv("NRE_DOCKER_APP_WORKDIR")); env != "" {
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
