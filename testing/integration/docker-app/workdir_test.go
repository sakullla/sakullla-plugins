package dockerapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestRelativeWorkdirBindsDeployWithoutHostMountConfirmation(t *testing.T) {
	root := t.TempDir()
	compose := strings.Join([]string{
		"services:",
		"  web:",
		"    image: nginx:1.27",
		"    volumes:",
		"      - ./data:/data",
		"      - ./config.yml:/app/config.yml",
		"      - cache:/var/cache",
		"",
	}, "\n")

	plan, _, err := dockerapp.ParseComposeDocument(compose, "media", "generation-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Services) != 1 {
		t.Fatalf("services = %#v", plan.Services)
	}
	service := plan.Services[0]
	if len(service.HostMounts) != 0 {
		t.Fatalf("relative binds classified as host mounts: %#v", service.HostMounts)
	}
	if !stringSetEqual(service.RelativeBinds, []string{"./data:/data", "./config.yml:/app/config.yml"}) {
		t.Fatalf("relative binds = %#v", service.RelativeBinds)
	}
	if !stringSetEqual(service.Volumes, []string{"cache"}) {
		t.Fatalf("named volumes = %#v", service.Volumes)
	}
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil {
		t.Fatal(err)
	}
	if hasRiskKind(preview, dockerapp.RiskHostMount) {
		t.Fatalf("relative binds required host-mount confirmation: %#v", preview.Items)
	}

	sourcePlan, err := dockerapp.PlanFromSource(dockerapp.ManageSpec{AppID: "media", Generation: "generation-1", Source: compose})
	if err != nil {
		t.Fatal(err)
	}
	if len(sourcePlan.Services) != 1 || len(sourcePlan.Services[0].HostMounts) != 0 || hasRiskKind(mustPreview(t, sourcePlan), dockerapp.RiskHostMount) {
		t.Fatalf("PlanFromSource treated ./ as host mount: %#v", sourcePlan)
	}

	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	runtime := newLifecycleRuntime()
	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: compose, WorkDirRoot: root}
	apps, err := dockerapp.DeployComposeApp(context.Background(), nil, spec, dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}, runtime, auditor)
	if err != nil || len(apps) != 1 {
		t.Fatalf("relative bind deploy err=%v apps=%#v", err, apps)
	}
	if apps[0].WorkDir != "" {
		t.Fatalf("management-face deploy materialized workdir %q", apps[0].WorkDir)
	}
	if _, err := os.Stat(filepath.Join(root, "media", dockerapp.ComposeFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("management-face deploy wrote Agent workspace: %v", err)
	}

	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		UIWorkDirRoot: root,
		CommandRunner: dockerapp.CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
			return []byte("ok"), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"action": "apply", "app_id": "media", "compose": compose})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", "compose", payload); err != nil {
		t.Fatal(err)
	}

	workdir := filepath.Join(root, "media")
	if _, err := os.Stat(filepath.Join(workdir, dockerapp.ComposeFileName)); err != nil {
		t.Fatalf("compose file: %v", err)
	}
	dataDir := filepath.Join(workdir, "data")
	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("data dir = %#v err=%v", info, err)
	}
	binds, err := dockerapp.ResolveComposeBinds(workdir, compose)
	if err != nil {
		t.Fatal(err)
	}

	dataBind := findVolumeBind(binds, "/data")
	if !dataBind.Relative || dataBind.HostPath != dataDir {
		t.Fatalf("container /data bind = %#v want host %q", dataBind, dataDir)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "note.txt"), []byte("from-agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	visible, err := os.ReadFile(filepath.Join(dataBind.HostPath, "note.txt"))
	if err != nil || string(visible) != "from-agent" {
		t.Fatalf("workdir data file visible via /data mapping: %q err=%v", visible, err)
	}

	configHost := filepath.Join(workdir, "config.yml")
	if err := os.WriteFile(configHost, []byte("listen: 80\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configBind := findVolumeBind(binds, "/app/config.yml")
	if !configBind.Relative || configBind.HostPath != configHost {
		t.Fatalf("container file bind = %#v want host %q", configBind, configHost)
	}
	content, err := os.ReadFile(configBind.HostPath)
	if err != nil || string(content) != "listen: 80\n" {
		t.Fatalf("container file content = %q err=%v", content, err)
	}
}

func TestRelativeBindLongFormIsNotHostMount(t *testing.T) {
	compose := strings.Join([]string{
		"services:",
		"  web:",
		"    image: nginx:1.27",
		"    volumes:",
		"      - type: bind",
		"        source: ./data",
		"        target: /data",
		"",
	}, "\n")
	plan, err := dockerapp.PlanFromSource(dockerapp.ManageSpec{AppID: "media", Generation: "generation-1", Source: compose})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Services) != 1 || len(plan.Services[0].HostMounts) != 0 || !stringSetEqual(plan.Services[0].RelativeBinds, []string{"./data:/data"}) {
		t.Fatalf("long-form relative bind = %#v", plan.Services)
	}
	if hasRiskKind(mustPreview(t, plan), dockerapp.RiskHostMount) {
		t.Fatal("long-form ./ bind required host-mount confirmation")
	}
}

func TestAbsoluteAndParentBindsRemainHostMounts(t *testing.T) {
	compose := strings.Join([]string{
		"services:",
		"  web:",
		"    image: nginx:1.27",
		"    volumes:",
		"      - /host:/data",
		"      - ../escape:/escape",
		"      - ./data:/var/data",
		"",
	}, "\n")
	plan, _, err := dockerapp.ParseComposeDocument(compose, "media", "generation-1", "")
	if err != nil {
		t.Fatal(err)
	}
	service := plan.Services[0]
	if !stringSetEqual(service.RelativeBinds, []string{"./data:/var/data"}) {
		t.Fatalf("relative binds = %#v", service.RelativeBinds)
	}
	if !stringSetEqual(service.HostMounts, []string{"/host:/data", "../escape:/escape"}) {
		t.Fatalf("host mounts = %#v", service.HostMounts)
	}
	preview := mustPreview(t, plan)
	if !hasRiskKind(preview, dockerapp.RiskHostMount) {
		t.Fatalf("absolute/parent binds lost host-mount risk: %#v", preview.Items)
	}
}

func mustPreview(t *testing.T, plan dockerapp.ComposePlan) dockerapp.RiskPreview {
	t.Helper()
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func hasRiskKind(preview dockerapp.RiskPreview, kind dockerapp.RiskKind) bool {
	for _, item := range preview.Items {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func findVolumeBind(binds []dockerapp.VolumeBind, containerPath string) dockerapp.VolumeBind {
	for _, bind := range binds {
		if bind.ContainerPath == containerPath {
			return bind
		}
	}
	return dockerapp.VolumeBind{}
}
