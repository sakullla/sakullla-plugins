package dockerapp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestDockerAutoUpdateDefaultDigestTriggersCutoverAndRollback(t *testing.T) {
	if dockerapp.DefaultAutoUpdate != true {
		t.Fatal("auto_update must default on")
	}
	if !dockerapp.AutoUpdateEnabled(nil) || !dockerapp.AutoUpdateEnabled(boolPtr(true)) || dockerapp.AutoUpdateEnabled(boolPtr(false)) {
		t.Fatal("omitted auto_update must default to enabled")
	}

	t.Run("same-digest", func(t *testing.T) {
		store, fake, rollout, app, old := updateHarness(t, "")
		view, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:current"})
		got, _ := store.Get(app.ID)
		if err != nil || view.HasUpdate || view.Published || !view.AutoUpdate || len(fake.calls) != 0 {
			t.Fatalf("same digest view=%#v calls=%v err=%v", view, fake.calls, err)
		}
		if got.InstanceID != old.InstanceID || got.Image != old.Image || got.RuleTarget != old.RuleTarget {
			t.Fatalf("same digest mutated deployment: %#v", got)
		}
	})

	t.Run("default-and-explicit", func(t *testing.T) {
		for _, policy := range []*bool{nil, boolPtr(true)} {
			store, fake, rollout, app, old := updateHarness(t, "")
			view, err := rollout.AutoUpdate(context.Background(), app, policy, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
			got, _ := store.Get(app.ID)
			if err != nil || !view.AutoUpdate || !view.HasUpdate || !view.Published {
				t.Fatalf("policy=%v view=%#v err=%v", policy, view, err)
			}
			if got.InstanceID != "new" || got.Image != app.Image || got.RuleTarget != "new" || got.Phase != dockerapp.PhaseActive {
				t.Fatalf("policy=%v cutover got=%#v", policy, got)
			}
			if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
				t.Fatalf("policy=%v calls=%v", policy, fake.calls)
			}
			if err := rollout.Rollback(context.Background(), app.ID); err != nil {
				t.Fatal(err)
			}
			restored, _ := store.Get(app.ID)
			if restored.InstanceID != old.InstanceID || restored.Image != old.Image || restored.RuleTarget != old.RuleTarget || restored.Generation != old.Generation || restored.Phase != dockerapp.PhaseActive {
				t.Fatalf("policy=%v rollback got=%#v", policy, restored)
			}
		}
	})
}

func TestDockerAutoUpdateDisabledOnlyProjectsNewVersionUntilConfirm(t *testing.T) {
	store, fake, rollout, app, old := updateHarness(t, "")
	view, err := rollout.AutoUpdate(context.Background(), app, boolPtr(false), dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
	got, _ := store.Get(app.ID)
	if err != nil || view.AutoUpdate || !view.HasUpdate || view.Published || len(fake.calls) != 0 {
		t.Fatalf("disabled auto-update view=%#v calls=%v err=%v", view, fake.calls, err)
	}
	if got.InstanceID != old.InstanceID || got.Image != old.Image || got.RuleTarget != old.RuleTarget || got.Phase != dockerapp.PhaseActive {
		t.Fatalf("disabled auto-update published: %#v", got)
	}

	if err := rollout.ConfirmUpdate(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	published, _ := store.Get(app.ID)
	if published.InstanceID != "new" || published.Image != app.Image || published.RuleTarget != "new" || published.Phase != dockerapp.PhaseActive {
		t.Fatalf("confirm did not publish: %#v", published)
	}
	if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
		t.Fatalf("confirm calls=%v", fake.calls)
	}
}

func TestDockerHealthRecoverRepublishesAndPreservesOldOnFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, fake, rollout, app, _ := updateHarness(t, "")
		if err := rollout.HealthRecover(context.Background(), app); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(app.ID)
		if got.InstanceID != "new" || got.RuleTarget != "new" || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("health recover got=%#v", got)
		}
		if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
			t.Fatalf("health recover calls=%v", fake.calls)
		}
	})
	t.Run("failure-keeps-old", func(t *testing.T) {
		store, fake, rollout, app, old := updateHarness(t, "ready")
		err := rollout.HealthRecover(context.Background(), app)
		got, _ := store.Get(app.ID)
		if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) || strings.Contains(err.Error(), "update-secret") {
			t.Fatalf("health recover err=%v", err)
		}
		if got.InstanceID != old.InstanceID || got.RuleTarget != old.RuleTarget || got.Image != old.Image {
			t.Fatalf("failed recover dropped old: %#v", got)
		}
		if contains(fake.calls, "cutover:new") || contains(fake.calls, "drain:old") {
			t.Fatalf("failed recover cut over: %v", fake.calls)
		}
	})
	t.Run("disabled-auto-update-still-recovers", func(t *testing.T) {
		store, fake, rollout, app, old := updateHarness(t, "")
		view, err := rollout.AutoUpdate(context.Background(), app, boolPtr(false), dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
		if err != nil || view.Published || len(fake.calls) != 0 {
			t.Fatalf("precondition view=%#v calls=%v err=%v", view, fake.calls, err)
		}
		if err := rollout.HealthRecover(context.Background(), app); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(app.ID)
		if got.InstanceID != "new" || got.RuleTarget != "new" {
			t.Fatalf("health recover honored auto_update=false: %#v old=%#v", got, old)
		}
	})
}

func updateHarness(t *testing.T, fail string) (*dockerapp.DeploymentStore, *rolloutFake, dockerapp.Rollout, dockerapp.App, dockerapp.Deployment) {
	t.Helper()
	app := testApp("update-secret")
	store := dockerapp.NewDeploymentStore()
	old := dockerapp.Deployment{
		AppID: app.ID, InstanceID: "old", Image: "old-image", RuleRef: app.RuleRef,
		RuleTarget: "old", Generation: "generation-0", Phase: dockerapp.PhaseActive,
	}
	store.Put(old)
	fake := &rolloutFake{fail: fail, secret: "update-secret"}
	rollout := dockerapp.Rollout{
		Store:    store,
		Executor: fake,
		Auditor:  dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {}),
	}
	return store, fake, rollout, app, old
}

func boolPtr(value bool) *bool {
	return &value
}
