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
	if err == nil && strings.TrimSpace(version) != "" {
		report.Installed = true
		report.Version = strings.TrimSpace(version)
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
		if _, err := controller.runCommand(ctx, workspace.Dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"accepted": true, "workdir": workspace.Dir})
	case "start", "stop", "restart", "remove", "pull", "ready", "drain", "remove-instance":
		dir, err := AppWorkDir(root, request.AppID)
		if err != nil {
			return nil, err
		}
		args, err := composeCommandArgs(action)
		if err != nil {
			return nil, err
		}
		if _, err := controller.runCommand(ctx, dir, "docker", args...); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"accepted": true})
	case "logs":
		dir, err := AppWorkDir(root, request.AppID)
		if err != nil {
			return nil, err
		}
		args := []string{"compose", "logs", "--no-color"}
		if strings.TrimSpace(request.Service) != "" {
			args = append(args, request.Service)
		}
		output, err := controller.runCommand(ctx, dir, "docker", args...)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"logs": string(output)})
	case "start-instance":
		dir, err := AppWorkDir(root, request.AppID)
		if err != nil {
			return nil, err
		}
		if _, err := controller.runCommand(ctx, dir, "docker", "compose", "up", "-d"); err != nil {
			return nil, err
		}
		instanceID := strings.TrimSpace(request.InstanceID)
		if instanceID == "" {
			instanceID = request.AppID
		}
		return json.Marshal(map[string]any{"accepted": true, "instance_id": instanceID})
	case "inspect":
		dir, err := AppWorkDir(root, request.AppID)
		if err != nil {
			return nil, err
		}
		if _, err := controller.runCommand(ctx, dir, "docker", "compose", "ps"); err != nil {
			return nil, err
		}
		return json.Marshal(RuntimeState{})
	default:
		return nil, fmt.Errorf("compose action %q is unknown", action)
	}
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
		return nil, errors.New("image is required")
	}
	digest, err := controller.dockerImageDigest(ctx, request.Image)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"current_digest": digest,
		"latest_digest":  digest,
	})
}

func (controller *Controller) dockerServerVersion(ctx context.Context) (string, error) {
	output, err := controller.runCommand(ctx, "", "docker", "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes.TrimSpace(output))), nil
}

func (controller *Controller) dockerImageDigest(ctx context.Context, image string) (string, error) {
	output, err := controller.runCommand(ctx, "", "docker", "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(bytes.TrimSpace(output)))
	if digest == "" {
		return "", errors.New("image digest is empty")
	}
	return digest, nil
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
	if env := strings.TrimSpace(os.Getenv("NRE_DOCKER_APP_WORKDIR")); env != "" {
		return env
	}
	return filepath.Join(os.TempDir(), "nre-docker-app")
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
