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
