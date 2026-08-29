package dockerapp

import (
	"context"
	"errors"
	"testing"
)

func TestDeployComposeAppForAgentBindsAgentBeforeApplyAndRejectsForeignID(t *testing.T) {
	t.Parallel()
	auditor := AuditorFunc(func(AuditRecord) {})
	var applied App
	executor := AppApplyExecutorFunc(func(_ context.Context, app App) error {
		applied = app
		return nil
	})
	report := AgentEngineReport{AgentID: "agent-1", Online: true, Installed: true, Version: "27.1.1"}
	spec := ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: "services:\n  web:\n    image: nginx:1.27\n"}

	apps, err := DeployComposeAppForAgent(context.Background(), nil, spec, report, executor, auditor)
	if err != nil {
		t.Fatal(err)
	}
	if applied.ID != "media" || applied.AgentID != "agent-1" {
		t.Fatalf("apply saw %#v", applied)
	}
	if len(apps) != 1 || apps[0].ID != "media" || apps[0].AgentID != "agent-1" {
		t.Fatalf("upserted apps=%#v", apps)
	}

	applied = App{}
	other := AgentEngineReport{AgentID: "agent-2", Online: true, Installed: true, Version: "27.1.1"}
	next, err := DeployComposeAppForAgent(context.Background(), apps, spec, other, executor, auditor)
	if !errors.Is(err, ErrAppAgentConflict) {
		t.Fatalf("foreign deploy err=%v", err)
	}
	if applied.ID != "" {
		t.Fatalf("foreign deploy applied %#v", applied)
	}
	if len(next) != 1 || next[0].ID != "media" || next[0].AgentID != "agent-1" {
		t.Fatalf("foreign deploy mutated apps=%#v", next)
	}

	spec.Generation = "generation-2"
	applied = App{}
	next, err = DeployComposeAppForAgent(context.Background(), apps, spec, report, executor, auditor)
	if err != nil || applied.AgentID != "agent-1" || len(next) != 1 || next[0].AgentID != "agent-1" || next[0].Generation != "generation-2" {
		t.Fatalf("same-agent update apps=%#v applied=%#v err=%v", next, applied, err)
	}
}

func TestDeployComposeAppRequiresHighRiskConfirmation(t *testing.T) {
	t.Parallel()
	auditor := AuditorFunc(func(AuditRecord) {})
	var applied []App
	executor := AppApplyExecutorFunc(func(_ context.Context, app App) error {
		applied = append(applied, app)
		return nil
	})
	engine := EngineObservation{Installed: true, Version: "27.1.1"}
	original := []App{{ID: "kept", Image: "nginx:keep", Generation: "generation-0", Compose: "services:\n  keep:\n    image: nginx:keep\n"}}
	highRisk := "services:\n  web:\n    image: nginx:latest\n    privileged: true\n    cap_add:\n      - NET_ADMIN\n    volumes:\n      - /host:/data\n"
	spec := ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: highRisk}

	apps, err := DeployComposeApp(context.Background(), original, spec, engine, executor, auditor)
	if !errors.Is(err, ErrInvalidPreview) || len(applied) != 0 || len(apps) != 1 || apps[0].ID != "kept" {
		t.Fatalf("unconfirmed high-risk deploy apps=%#v applied=%#v err=%v", apps, applied, err)
	}

	preview, err := PreviewComposeDocument(spec.AppID, spec.Generation, spec.Compose, "")
	if err != nil || !RequiresRiskConfirmation(preview) || preview.Digest == "" {
		t.Fatalf("high-risk preview=%#v err=%v", preview, err)
	}
	kinds := map[RiskKind]bool{}
	for _, item := range preview.Items {
		kinds[item.Kind] = true
	}
	if !kinds[RiskPrivileged] || !kinds[RiskHostMount] || !kinds[RiskCapability] {
		t.Fatalf("preview missing blocking risks: %#v", preview.Items)
	}

	spec.Confirm = "not-the-digest"
	apps, err = DeployComposeApp(context.Background(), original, spec, engine, executor, auditor)
	if !errors.Is(err, ErrInvalidPreview) || len(applied) != 0 || len(apps) != 1 || apps[0].ID != "kept" {
		t.Fatalf("mismatched digest deploy apps=%#v applied=%#v err=%v", apps, applied, err)
	}

	spec.Confirm = preview.Digest
	apps, err = DeployComposeApp(context.Background(), original, spec, engine, executor, auditor)
	if err != nil || len(applied) != 1 || len(apps) != 2 {
		t.Fatalf("confirmed high-risk deploy apps=%#v applied=%#v err=%v", apps, applied, err)
	}

	networkOnly := ComposeDeploySpec{AppID: "front", Generation: "generation-1", Compose: "services:\n  web:\n    image: nginx:latest\n    networks: [front]\n"}
	networkPreview, err := PreviewComposeDocument(networkOnly.AppID, networkOnly.Generation, networkOnly.Compose, "")
	if err != nil || RequiresRiskConfirmation(networkPreview) {
		t.Fatalf("network-only preview required confirm: %#v err=%v", networkPreview, err)
	}
	apps, err = DeployComposeApp(context.Background(), original, networkOnly, engine, executor, auditor)
	if err != nil || len(apps) != 2 {
		t.Fatalf("network-only deploy apps=%#v err=%v", apps, err)
	}
}
