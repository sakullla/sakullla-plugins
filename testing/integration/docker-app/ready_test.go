package dockerapp_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

type installSpy struct{ called bool }

func (spy *installSpy) Install() error {
	spy.called = true
	return nil
}

func TestDockerGenericAgentReportFeedsEngineStatusWithoutRemoteInstall(t *testing.T) {
	installer := &installSpy{}
	catalog := dockerapp.NewReportedEngineCatalog()
	if err := catalog.Consume([]byte(`{"id":"agent-1","online":true,"engine":{"installed":false,"version":"stale"}}`)); err != nil {
		t.Fatal(err)
	}
	missing, err := catalog.Report(context.Background(), "agent-1")
	if err != nil || !missing.Online || missing.Installed {
		t.Fatalf("uninstalled report=%#v err=%v", missing, err)
	}
	if dockerapp.ProjectEngine(dockerapp.ObservationFromReport(missing)).Ready {
		t.Fatalf("uninstalled report projected ready: %#v", missing)
	}
	got, err := dockerapp.ProjectEngineReady(dockerapp.ObservationFromReport(missing), []byte(`{"apps":[]}`), installer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Ready || got.Command.Script != dockerapp.OfficialInstallScript || installer.called {
		t.Fatalf("uninstalled report invoked install or skipped guide: %#v called=%v", got, installer.called)
	}

	if err := catalog.Consume([]byte(`{"agent_id":"agent-2","status":"online","engine":{"installed":true,"version":"27.1.1"}}`)); err != nil {
		t.Fatal(err)
	}
	ready, err := catalog.Report(context.Background(), "agent-2")
	if err != nil || !ready.Online || !ready.Installed || ready.Version != "27.1.1" {
		t.Fatalf("ready report=%#v err=%v", ready, err)
	}
	if err := catalog.Consume([]byte(`{"id":"agent-3","online":false,"engine":{"installed":true,"version":"27.1.1"}}`)); err != nil {
		t.Fatal(err)
	}
	offline, err := catalog.Report(context.Background(), "agent-3")
	if err != nil || offline.Online || offline.Installed || offline.Version != "" {
		t.Fatalf("offline report reused cached engine: %#v err=%v", offline, err)
	}
	if _, err := dockerapp.DeployComposeAppForAgent(context.Background(), nil, dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: "services:\n  web:\n    image: nginx:1.27\n"}, offline, nil, dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); !errors.Is(err, dockerapp.ErrAgentOffline) {
		t.Fatalf("offline deploy err=%v", err)
	}
	if installer.called {
		t.Fatal("generic agent report path invoked remote install")
	}
}

func TestDockerAppUIDoesNotConfigureInstanceOntoSelectedAgent(t *testing.T) {
	pluginDir := filepath.Join("..", "..", "..", "plugins", "docker-app")
	script, err := os.ReadFile(filepath.Join(pluginDir, "assets", "ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(pluginDir, "assets", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	js := string(script)
	page := string(html)
	combined := page + js
	for _, token := range []string{
		"/panel-api/plugins/docker-app/configure",
		"第一次部署会把本插件装到该节点",
		"由面板安装",
		"控制面安装",
		"一键安装",
		"data-action=\"install-engine\"",
	} {
		if strings.Contains(combined, token) {
			t.Fatalf("plugin page still has %q", token)
		}
	}
	if !strings.Contains(page, `id="engine-guide"`) || !strings.Contains(js, "api/engine") || strings.Contains(js, "/configure") {
		t.Fatal("plugin page still configures docker-app onto the selected Agent or lacks the install guide")
	}
}

func TestDockerReadyInstalledProjectsEngineReady(t *testing.T) {
	installer := &installSpy{}
	got, err := dockerapp.ProjectEngineReady(dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}, []byte(`{"apps":[],"registry_mirror":"https://mirror.example"}`), installer)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Status.Ready || got.Status.Version != "27.1.1" || got.Status.RequestsInstall() {
		t.Fatalf("ready = %#v", got.Status)
	}
	if got.Command.Script != "" || got.Command.DaemonJSON != "" {
		t.Fatalf("installed engine still projected an install command: %#v", got.Command)
	}
	if installer.called {
		t.Fatal("installed observation invoked install action")
	}
}

func TestDockerReadyMissingEngineDoesNotCallInstallAction(t *testing.T) {
	installer := &installSpy{}
	got, err := dockerapp.ProjectEngineReady(dockerapp.EngineObservation{}, []byte(`{"apps":[]}`), installer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Ready || got.Status.Version != "" || got.Status.RequestsInstall() {
		t.Fatalf("missing engine projected ready: %#v", got.Status)
	}
	if got.Command.Script != dockerapp.OfficialInstallScript || !strings.Contains(got.Command.Script, "get.docker.com") {
		t.Fatalf("command = %#v", got.Command)
	}
	if strings.Contains(got.Command.Script, "registry-mirrors") || got.Command.DaemonJSON != "" {
		t.Fatalf("empty mirror leaked registry-mirrors: %#v", got.Command)
	}
	if installer.called {
		t.Fatal("missing engine invoked install action")
	}
}

func TestDockerInstallCommandOmitsRegistryMirrorsWithoutAccelerator(t *testing.T) {
	defaultDocument, err := os.ReadFile(filepath.Join("..", "..", "..", "plugins", "docker-app", "config.default.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range [][]byte{
		[]byte(`{"apps":[]}`),
		[]byte(`{"apps":[],"registry_mirror":""}`),
		defaultDocument,
	} {
		got, err := dockerapp.InstallCommandForDocument(document)
		if err != nil {
			t.Fatalf("document %s err=%v", document, err)
		}
		if got.Script != dockerapp.OfficialInstallScript || !strings.Contains(got.Script, "get.docker.com") {
			t.Fatalf("document %s command = %#v", document, got)
		}
		if strings.Contains(got.Script, "registry-mirrors") || strings.Contains(got.DaemonJSON, "registry-mirrors") || got.DaemonJSON != "" {
			t.Fatalf("document %s leaked registry-mirrors: %#v", document, got)
		}
	}
}

func TestDockerInstallCommandIncludesHTTPSRegistryMirror(t *testing.T) {
	const mirror = "https://mirror.example"
	got, err := dockerapp.InstallCommandForDocument([]byte(`{"apps":[],"registry_mirror":"https://mirror.example"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Script != dockerapp.OfficialInstallScript || !strings.Contains(got.Script, "get.docker.com") {
		t.Fatalf("command = %#v", got)
	}
	if strings.Contains(got.Script, "registry-mirrors") {
		t.Fatalf("official script included registry-mirrors: %#v", got)
	}
	if !strings.Contains(got.DaemonJSON, "registry-mirrors") || !strings.Contains(got.DaemonJSON, mirror) {
		t.Fatalf("daemon suggestion missing %s: %#v", mirror, got)
	}
}

func TestDockerRegistryMirrorInvalidOverlayIsRejected(t *testing.T) {
	installer := &installSpy{}
	for _, document := range []string{
		`{"apps":[],"registry_mirror":"http://insecure.example"}`,
		`{"apps":[],"registry_mirror":"ftp://mirror.example"}`,
		`{"apps":[],"registry_mirror":"https://user:pass@mirror.example"}`,
		`{"apps":[],"registry_mirror":"https://mirror.example?q=1"}`,
		`{"apps":[],"registry_mirror":"https://ok.example","extra":true}`,
		`{"registry_mirror":"https://ok.example"}`,
	} {
		if _, err := dockerapp.InstallCommandForDocument([]byte(document)); err == nil {
			t.Fatalf("document %s was accepted", document)
		}
		if _, err := dockerapp.ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("parse %s was accepted", document)
		}
		if _, err := dockerapp.ProjectEngineReady(dockerapp.EngineObservation{}, []byte(document), installer); err == nil {
			t.Fatalf("ready document %s was accepted", document)
		}
	}
	if installer.called {
		t.Fatal("rejected overlay invoked install action")
	}
}

func TestDockerRegistryMirrorPrepareAcceptsHTTPSOverlay(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatal(err)
	}
	const mirror = "https://mirror.example"
	document := []byte(`{"apps":[],"registry_mirror":"https://mirror.example"}`)
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: document}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if controller.RegistryMirror() != mirror {
		t.Fatalf("effective registry_mirror = %q", controller.RegistryMirror())
	}
	got, err := dockerapp.InstallCommand(controller.RegistryMirror())
	if err != nil {
		t.Fatal(err)
	}
	if got.Script != dockerapp.OfficialInstallScript || !strings.Contains(got.DaemonJSON, mirror) {
		t.Fatalf("accepted overlay did not yield agent-effective install command: %#v", got)
	}
}

func TestDockerRegistryMirrorPrepareRejectsInvalidOverlay(t *testing.T) {
	for _, document := range []string{
		`{"apps":[],"registry_mirror":"http://insecure.example"}`,
		`{"apps":[],"registry_mirror":"ftp://mirror.example"}`,
		`{"apps":[],"registry_mirror":"https://user:pass@mirror.example"}`,
		`{"apps":[],"registry_mirror":"https://mirror.example?q=1"}`,
		`{"apps":[],"registry_mirror":"https://ok.example","extra":true}`,
		`{"registry_mirror":"https://ok.example"}`,
	} {
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshake(requiredGrants())); err != nil {
			t.Fatal(err)
		}
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: []byte(document)}); response.Error == nil {
			t.Fatalf("prepare accepted %s", document)
		}
		if len(controller.Apps()) != 0 || controller.RegistryMirror() != "" {
			t.Fatalf("rejected overlay became effective: apps=%#v mirror=%q", controller.Apps(), controller.RegistryMirror())
		}
	}
}
