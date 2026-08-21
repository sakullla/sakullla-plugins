package dockerapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestComposeOverlayRejectsImageRuleRefAndInvalidYAML(t *testing.T) {
	existing := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27\n","generation":"generation-1"}]}`)
	got, err := dockerapp.ParseConfiguration(existing)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].ID != "media" || got.Apps[0].Image != "nginx:1.27" {
		t.Fatalf("valid overlay got=%#v err=%v", got, err)
	}

	for _, document := range []string{
		`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1"}]}`,
		`{"apps":[{"id":"media","image":"nginx:latest","generation":"generation-1"}]}`,
		`{"apps":[{"id":"media","rule_ref":"rule-media","generation":"generation-1"}]}`,
		`{"apps":[{"id":"media","compose":"::: not yaml","generation":"generation-1"}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    command: echo hi\n","generation":"generation-1"}]}`,
		`{"apps":[{"id":"media","compose":"","generation":"generation-1"}]}`,
	} {
		if _, err := dockerapp.ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("document %s was accepted", document)
		}
		unchanged, parseErr := dockerapp.ParseConfiguration(existing)
		if parseErr != nil || len(unchanged.Apps) != 1 || unchanged.Apps[0].Image != "nginx:1.27" {
			t.Fatalf("existing overlay changed after reject: %#v err=%v", unchanged, parseErr)
		}
	}
}

func TestComposeAppDeployStartStopRestartLogsAndConfirmedDelete(t *testing.T) {
	engine := dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	runtime := newLifecycleRuntime()
	original := []dockerapp.App{{ID: "kept", Compose: testComposeYAML("busybox:1.36"), Image: "busybox:1.36", Generation: "generation-0"}}

	invalid := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: "::: not yaml"}
	apps, err := dockerapp.DeployComposeApp(context.Background(), original, invalid, engine, runtime, auditor)
	if !errors.Is(err, dockerapp.ErrInvalidCompose) || !sameAppIDs(apps, original) || runtime.containerExists("media") {
		t.Fatalf("invalid YAML mutated state apps=%#v err=%v containers=%v", apps, err, runtime.containers)
	}

	missingImage := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: "services:\n  web:\n    command: echo hi\n"}
	apps, err = dockerapp.DeployComposeApp(context.Background(), original, missingImage, engine, runtime, auditor)
	if !errors.Is(err, dockerapp.ErrMissingComposeImage) || !sameAppIDs(apps, original) || runtime.containerExists("media") {
		t.Fatalf("missing image mutated state apps=%#v err=%v", apps, err)
	}

	unready := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: testComposeYAML("nginx:1.27")}
	apps, err = dockerapp.DeployComposeApp(context.Background(), original, unready, dockerapp.EngineObservation{}, runtime, auditor)
	if !errors.Is(err, dockerapp.ErrEngineNotReady) || !sameAppIDs(apps, original) {
		t.Fatalf("engine-not-ready mutated state apps=%#v err=%v", apps, err)
	}

	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: testComposeYAML("nginx:1.27")}
	apps, err = dockerapp.DeployComposeApp(context.Background(), original, spec, engine, runtime, auditor)
	if err != nil || len(apps) != 2 {
		t.Fatalf("deploy err=%v apps=%#v", err, apps)
	}
	media := findApp(apps, "media")
	if media.Image != "nginx:1.27" || media.Compose == "" || !runtime.running["media"] || !runtime.containerExists("media") {
		t.Fatalf("deployed app=%#v runtime=%#v", media, runtime)
	}
	view := projectCatalog(t, runtime.observations(), runtime.runtimes(), apps)
	if len(view.Managed) != 2 || !managedRunning(view, "media") {
		t.Fatalf("catalog after deploy = %#v", view)
	}
	if len(findManaged(view, "media").Services) != 1 || findManaged(view, "media").Services[0] != "web" {
		t.Fatalf("service list = %#v", findManaged(view, "media").Services)
	}

	updated := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-2", Compose: testComposeYAML("nginx:1.28")}
	apps, err = dockerapp.DeployComposeApp(context.Background(), apps, updated, engine, runtime, auditor)
	if err != nil {
		t.Fatal(err)
	}
	media = findApp(apps, "media")
	if media.Image != "nginx:1.28" || media.Generation != "generation-2" || findApp(apps, "kept").Image != "busybox:1.36" {
		t.Fatalf("redeploy apps=%#v", apps)
	}

	if err := dockerapp.StopManaged(context.Background(), media, runtime, auditor); err != nil || runtime.running["media"] || !runtime.containerExists("media") {
		t.Fatalf("stop running=%v exists=%v err=%v", runtime.running["media"], runtime.containerExists("media"), err)
	}
	view = projectCatalog(t, runtime.observations(), runtime.runtimes(), apps)
	if managedRunning(view, "media") || findManaged(view, "media").Status != dockerapp.AppStatusStopped {
		t.Fatalf("stopped catalog = %#v", findManaged(view, "media"))
	}

	if err := dockerapp.StartManaged(context.Background(), media, runtime, auditor); err != nil || !runtime.running["media"] {
		t.Fatalf("start running=%v err=%v", runtime.running["media"], err)
	}
	view = projectCatalog(t, runtime.observations(), runtime.runtimes(), apps)
	if !managedRunning(view, "media") {
		t.Fatalf("started catalog = %#v", findManaged(view, "media"))
	}

	if err := dockerapp.RestartManaged(context.Background(), media, runtime, auditor); err != nil || !runtime.running["media"] || runtime.restarts["media"] != 1 {
		t.Fatalf("restart running=%v restarts=%v err=%v", runtime.running["media"], runtime.restarts, err)
	}

	logs, err := dockerapp.ReadServiceLogs(context.Background(), media, "web", runtime, auditor)
	if err != nil || !strings.Contains(logs, "listening on :80") {
		t.Fatalf("logs=%q err=%v", logs, err)
	}
	if _, err := dockerapp.ReadServiceLogs(context.Background(), media, "missing", runtime, auditor); !errors.Is(err, dockerapp.ErrUnknownService) {
		t.Fatalf("unknown service err=%v", err)
	}

	snapshot := cloneAppIDs(apps)
	apps, err = dockerapp.DeleteManagedApp(context.Background(), apps, media.ID, false, runtime, auditor)
	if !errors.Is(err, dockerapp.ErrDeleteUnconfirmed) || !sameIDs(apps, snapshot) || !runtime.containerExists("media") || !runtime.running["media"] {
		t.Fatalf("unconfirmed delete apps=%#v err=%v exists=%v", apps, err, runtime.containerExists("media"))
	}

	apps, err = dockerapp.DeleteManagedApp(context.Background(), apps, media.ID, true, runtime, auditor)
	if err != nil || findApp(apps, "media").ID != "" || runtime.containerExists("media") || runtime.running["media"] {
		t.Fatalf("confirmed delete apps=%#v err=%v exists=%v", apps, err, runtime.containerExists("media"))
	}
	view = projectCatalog(t, runtime.observations(), runtime.runtimes(), apps)
	if len(view.Managed) != 1 || view.Managed[0].App.ID != "kept" {
		t.Fatalf("catalog after delete = %#v", view)
	}
}

func TestComposeAppLifecycleFailClosedWithoutExecutorOrAuditor(t *testing.T) {
	app := testApp("")
	apps := []dockerapp.App{app}
	runtime := newLifecycleRuntime()
	if _, err := dockerapp.DeployComposeApp(context.Background(), apps, dockerapp.ComposeDeploySpec{AppID: app.ID, Generation: app.Generation, Compose: app.Compose}, dockerapp.EngineObservation{Installed: true}, runtime, nil); !errors.Is(err, dockerapp.ErrAuditRequired) {
		t.Fatalf("missing deploy auditor err=%v", err)
	}
	if _, err := dockerapp.DeployComposeApp(context.Background(), apps, dockerapp.ComposeDeploySpec{AppID: app.ID, Generation: app.Generation, Compose: app.Compose}, dockerapp.EngineObservation{Installed: true}, nil, dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("missing deploy executor err=%v", err)
	}
	if err := dockerapp.StartManaged(context.Background(), app, runtime, nil); !errors.Is(err, dockerapp.ErrAuditRequired) {
		t.Fatalf("missing start auditor err=%v", err)
	}
	if err := dockerapp.RestartManaged(context.Background(), app, nil, dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("missing restart executor err=%v", err)
	}
	if _, err := dockerapp.ReadServiceLogs(context.Background(), app, "web", nil, dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("missing log reader err=%v", err)
	}
	if _, err := dockerapp.DeleteManagedApp(context.Background(), apps, app.ID, true, runtime, nil); !errors.Is(err, dockerapp.ErrAuditRequired) {
		t.Fatalf("missing delete auditor err=%v", err)
	}
}

func TestComposeOverlayPrepareProjectsManagedApps(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
			return dockerapp.PreparedAdmissionFuncs{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n","generation":"generation-1"}]}`)
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: document}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	apps := controller.Apps()
	if len(apps) != 1 || apps[0].ID != "media" || apps[0].Image != "nginx:1.27" || apps[0].Compose == "" {
		t.Fatalf("prepared apps = %#v", apps)
	}
	payload, err := json.Marshal(apps)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"image"`) || strings.Contains(string(payload), `"rule_ref"`) {
		t.Fatalf("overlay snapshot still serializes image/rule_ref: %s", payload)
	}
}

type lifecycleRuntime struct {
	mu         sync.Mutex
	applied    map[string]dockerapp.App
	running    map[string]bool
	restarts   map[string]int
	containers map[string]string
	logs       map[string]string
}

func newLifecycleRuntime() *lifecycleRuntime {
	return &lifecycleRuntime{
		applied:    map[string]dockerapp.App{},
		running:    map[string]bool{},
		restarts:   map[string]int{},
		containers: map[string]string{},
		logs:       map[string]string{},
	}
}

func (runtime *lifecycleRuntime) ApplyApp(_ context.Context, app dockerapp.App) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.applied[app.ID] = app
	runtime.containers[app.ID] = "ctr-" + app.ID
	runtime.running[app.ID] = true
	runtime.logs[app.ID+"/web"] = "listening on :80\n"
	return nil
}

func (runtime *lifecycleRuntime) Start(_ context.Context, appID string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.containers[appID] == "" {
		return errors.New("app is not deployed")
	}
	runtime.running[appID] = true
	return nil
}

func (runtime *lifecycleRuntime) Stop(_ context.Context, appID string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.containers[appID] == "" {
		return errors.New("app is not deployed")
	}
	runtime.running[appID] = false
	return nil
}

func (runtime *lifecycleRuntime) Restart(_ context.Context, appID string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.containers[appID] == "" {
		return errors.New("app is not deployed")
	}
	runtime.running[appID] = true
	runtime.restarts[appID]++
	return nil
}

func (runtime *lifecycleRuntime) ReadLogs(_ context.Context, appID, service string) (string, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.logs[appID+"/"+service], nil
}

func (runtime *lifecycleRuntime) RemoveApp(_ context.Context, appID string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	delete(runtime.applied, appID)
	delete(runtime.running, appID)
	delete(runtime.containers, appID)
	delete(runtime.logs, appID+"/web")
	return nil
}

func (runtime *lifecycleRuntime) containerExists(appID string) bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.containers[appID] != ""
}

func (runtime *lifecycleRuntime) observations() []dockerapp.ContainerObservation {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	observations := make([]dockerapp.ContainerObservation, 0, len(runtime.containers))
	for appID, containerID := range runtime.containers {
		observations = append(observations, dockerapp.ContainerObservation{
			ID:           containerID,
			Labels:       map[string]string{dockerapp.AppLabel: appID},
			ExposedPorts: []uint16{8080},
		})
	}
	return observations
}

func (runtime *lifecycleRuntime) runtimes() []dockerapp.RuntimeObservation {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtimes := make([]dockerapp.RuntimeObservation, 0, len(runtime.containers))
	for appID, containerID := range runtime.containers {
		runtimes = append(runtimes, dockerapp.RuntimeObservation{ContainerID: containerID, Running: runtime.running[appID]})
	}
	return runtimes
}

func findApp(apps []dockerapp.App, id string) dockerapp.App {
	for _, app := range apps {
		if app.ID == id {
			return app
		}
	}
	return dockerapp.App{}
}

func findManaged(view dockerapp.CatalogView, id string) dockerapp.CatalogItem {
	for _, item := range view.Managed {
		if item.App.ID == id {
			return item
		}
	}
	return dockerapp.CatalogItem{}
}

func managedRunning(view dockerapp.CatalogView, id string) bool {
	item := findManaged(view, id)
	return item.Running && item.Status == dockerapp.AppStatusRunning
}

func sameAppIDs(got, want []dockerapp.App) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index].ID != want[index].ID || got[index].Image != want[index].Image {
			return false
		}
	}
	return true
}

func cloneAppIDs(apps []dockerapp.App) []string {
	ids := make([]string, 0, len(apps))
	for _, app := range apps {
		ids = append(ids, app.ID)
	}
	return ids
}

func sameIDs(apps []dockerapp.App, ids []string) bool {
	if len(apps) != len(ids) {
		return false
	}
	for index := range ids {
		if apps[index].ID != ids[index] {
			return false
		}
	}
	return true
}
