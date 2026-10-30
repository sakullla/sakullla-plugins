package dockerapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestComposeDeployStreamsLogUntilComplete(t *testing.T) {
	controller := newCallController(t, t.TempDir(), CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("background deploy bookkeeping invoked docker")
		return nil, nil
	}), nil)
	release := make(chan struct{})
	controller.deployStarter = func(_ string, output io.Writer) (func() error, func(), error) {
		_, _ = io.WriteString(output, "Image halo Pulling\npassword=open-secret\n")
		return func() error {
			<-release
			_, _ = io.WriteString(output, "Container halo Started\n")
			return nil
		}, func() {}, nil
	}
	raw, err := controller.Call(context.Background(), "generation-1", pluginCallComposeName, []byte(`{"action":"deploy-start","app_id":"halo","compose":"services:\n  halo:\n    image: nginx:1.27\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	var progress DeployProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		t.Fatal(err)
	}
	if progress.Phase != deployPhasePulling || !strings.Contains(progress.Logs, "Pulling") || strings.Contains(progress.Logs, "open-secret") {
		t.Fatalf("progress=%#v", progress)
	}
	if !strings.Contains(progress.Logs, "password=***") {
		t.Fatalf("secret was not redacted: %q", progress.Logs)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for progress.Phase != deployPhaseSucceeded {
		if time.Now().After(deadline) {
			t.Fatalf("deploy did not finish: %#v", progress)
		}
		time.Sleep(10 * time.Millisecond)
		raw, err = controller.Call(context.Background(), "generation-1", pluginCallComposeName, []byte(`{"action":"deploy-status","app_id":"halo"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &progress); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(progress.Logs, "Started") {
		t.Fatalf("finished log=%q", progress.Logs)
	}
}

func TestDeployJobStaysPendingUntilComposeFinishes(t *testing.T) {
	controller := newUIController(t)
	scripted := &scriptedDeploy{}
	controller.uiDeploy = scripted
	started := httptest.NewRecorder()
	controller.ServeHTTP(started, uiJSONRequest(http.MethodPost, "/api/deploy-jobs", `{"id":"halo","agent_id":"agent-1","compose":"services:\n  halo:\n    image: nginx:1.27\n"}`))
	var first struct {
		Deploy *DeployProgress `json:"deploy"`
		Apps   []appView       `json:"apps"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if started.Code != http.StatusOK || first.Error != "" || first.Deploy == nil || first.Deploy.Phase != deployPhasePulling {
		t.Fatalf("start status=%d body=%s", started.Code, started.Body.String())
	}
	if len(controller.Apps()) != 0 {
		t.Fatalf("running catalog changed before compose finished: %#v", controller.Apps())
	}
	polled := httptest.NewRecorder()
	controller.ServeHTTP(polled, uiJSONRequest(http.MethodPost, "/api/deploy-jobs", `{"action":"status","id":"halo","agent_id":"agent-1"}`))
	var second struct {
		Deploy *DeployProgress `json:"deploy"`
		Apps   []appView       `json:"apps"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(polled.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if polled.Code != http.StatusOK || second.Error != "" || second.Deploy == nil || second.Deploy.Phase != deployPhaseSucceeded || len(second.Apps) != 1 {
		t.Fatalf("status=%d body=%s", polled.Code, polled.Body.String())
	}
	if !strings.Contains(second.Deploy.Logs, "Started") {
		t.Fatalf("logs=%q", second.Deploy.Logs)
	}
}

func TestDeployJobWithoutSupervisorStillApplies(t *testing.T) {
	controller := newUIController(t)
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, uiJSONRequest(http.MethodPost, "/api/deploy-jobs", `{"id":"halo","agent_id":"agent-1","compose":"services:\n  halo:\n    image: nginx:1.27\n"}`))
	var payload struct {
		Deploy *DeployProgress `json:"deploy"`
		Apps   []appView       `json:"apps"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || payload.Error != "" || payload.Deploy == nil || payload.Deploy.Phase != deployPhaseSucceeded || len(payload.Apps) != 1 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type scriptedDeploy struct {
	mu    sync.Mutex
	phase string
	logs  string
}

func (deploy *scriptedDeploy) StartDeploy(context.Context, App) (DeployProgress, error) {
	deploy.mu.Lock()
	defer deploy.mu.Unlock()
	deploy.phase = deployPhasePulling
	deploy.logs = "Image halo Pulling\n"
	return DeployProgress{Phase: deploy.phase, Message: deployPhaseMessage(deploy.phase), Logs: deploy.logs}, nil
}

func (deploy *scriptedDeploy) DeployStatus(context.Context, App) (DeployProgress, error) {
	deploy.mu.Lock()
	defer deploy.mu.Unlock()
	deploy.phase = deployPhaseSucceeded
	deploy.logs += "Container halo Started\n"
	return DeployProgress{Phase: deploy.phase, Message: deployPhaseMessage(deploy.phase), Logs: deploy.logs}, nil
}

func (deploy *scriptedDeploy) CancelDeploy(context.Context, App) error {
	deploy.mu.Lock()
	defer deploy.mu.Unlock()
	deploy.phase = deployPhaseCancelled
	return nil
}
