package dockerapp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestDockerAppOverlayPersistsAutoUpdate(t *testing.T) {
	omitted := []byte(`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1"}]}`)
	got, err := dockerapp.ParseConfiguration(omitted)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate != nil || !dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) {
		t.Fatalf("omitted auto_update got=%#v err=%v", got, err)
	}

	disabled := []byte(`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1","auto_update":false}]}`)
	got, err = dockerapp.ParseConfiguration(disabled)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate == nil || *got.Apps[0].AutoUpdate || dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) {
		t.Fatalf("false auto_update got=%#v err=%v", got, err)
	}

	enabled := []byte(`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1","auto_update":true}]}`)
	got, err = dockerapp.ParseConfiguration(enabled)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate == nil || !*got.Apps[0].AutoUpdate || !dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) {
		t.Fatalf("true auto_update got=%#v err=%v", got, err)
	}

	for _, document := range []string{
		`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1","auto_update":"no"}]}`,
		`{"apps":[{"id":"media","image":"nginx:latest","rule_ref":"rule-media","generation":"generation-1","autoupdate":false}]}`,
	} {
		if _, err := dockerapp.ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("document %s was accepted", document)
		}
	}
}

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

func TestDockerRollbackPreservesCurrentOnEffectFailure(t *testing.T) {
	t.Run("cutover-failure", func(t *testing.T) {
		store, fake, rollout, app, published := publishUpdate(t)
		historyID := publishedHistoryInstance(t, published)
		fake.failRestore = true
		err := rollout.Rollback(context.Background(), app.ID)
		got, _ := store.Get(app.ID)
		if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) || strings.Contains(err.Error(), "update-secret") {
			t.Fatalf("rollback cutover err=%v", err)
		}
		if got.InstanceID != published.InstanceID || got.Image != published.Image || got.RuleRef != published.RuleRef || got.RuleTarget != published.RuleTarget || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("cutover failure dropped current: %#v", got)
		}
		if got.Image == "" || got.RuleRef == "" {
			t.Fatalf("cutover failure persisted empty active: %#v", got)
		}
		if contains(fake.calls, "remove:new") || contains(fake.calls, "drain:new") || contains(fake.calls, "remove:"+historyID) {
			t.Fatalf("cutover failure touched serving or history instance: %v", fake.calls)
		}
		assertHistoryInstance(t, got, historyID)
		fake.failRestore = false
		fake.calls = nil
		if err := rollout.Rollback(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		restored, _ := store.Get(app.ID)
		if restored.InstanceID != historyID || restored.Phase != dockerapp.PhaseActive {
			t.Fatalf("retry after cutover failure did not restore history: %#v", restored)
		}
	})

	t.Run("drain-failure", func(t *testing.T) {
		store, fake, rollout, app, published := publishUpdate(t)
		historyID := publishedHistoryInstance(t, published)
		fake.fail = "drain"
		err := rollout.Rollback(context.Background(), app.ID)
		got, _ := store.Get(app.ID)
		if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) || strings.Contains(err.Error(), "update-secret") {
			t.Fatalf("rollback drain err=%v", err)
		}
		if got.InstanceID != published.InstanceID || got.Image != published.Image || got.RuleRef != published.RuleRef || got.RuleTarget != published.RuleTarget || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("drain failure dropped current: %#v", got)
		}
		if got.Image == "" || got.RuleRef == "" {
			t.Fatalf("drain failure persisted empty active: %#v", got)
		}
		if contains(fake.calls, "remove:new") || contains(fake.calls, "remove:"+historyID) {
			t.Fatalf("drain failure removed serving or history instance: %v", fake.calls)
		}
		if !contains(fake.calls, "cutover:new") {
			t.Fatalf("drain failure did not restore current rule: %v", fake.calls)
		}
		assertHistoryInstance(t, got, historyID)
		fake.fail = ""
		fake.calls = nil
		if err := rollout.Rollback(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		restored, _ := store.Get(app.ID)
		if restored.InstanceID != historyID || restored.Phase != dockerapp.PhaseActive {
			t.Fatalf("retry after drain failure did not restore history: %#v", restored)
		}
	})
}

func TestDockerRollbackLeaseExpireReconcilePreservesHistoryInstance(t *testing.T) {
	store, fake, rollout, app, published := publishUpdate(t)
	historyID := publishedHistoryInstance(t, published)
	intent := published
	intent.Phase = dockerapp.PhaseCutover
	intent.PendingInstance = historyID
	intent.DesiredRuleTarget = historyID
	intent.PriorInstance = published.InstanceID
	intent.PriorImage = published.Image
	intent.PriorGeneration = published.Generation
	intent.PriorRuleRef = published.RuleRef
	intent.PriorRuleTarget = published.RuleTarget
	intent.PriorDigest = published.ImageDigest
	intent.PriorAbsent = false
	intent.Image = published.History[0].Image
	intent.RuleRef = published.History[0].RuleRef
	intent.Generation = published.History[0].Generation
	intent.ImageDigest = published.History[0].ImageDigest
	intent.AvailableDigest = ""
	intent.Lease = ""
	store.Put(intent)
	fake.calls = nil

	if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(app.ID)
	if got.InstanceID != published.InstanceID || got.Image != published.Image || got.RuleRef != published.RuleRef || got.RuleTarget != published.RuleTarget || got.Phase != dockerapp.PhaseActive {
		t.Fatalf("lease-expire reconcile dropped current: %#v", got)
	}
	if contains(fake.calls, "remove:"+historyID) || contains(fake.calls, "remove:"+published.InstanceID) {
		t.Fatalf("lease-expire reconcile removed an instance: %v", fake.calls)
	}
	assertHistoryInstance(t, got, historyID)

	fake.calls = nil
	if err := rollout.Rollback(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	restored, _ := store.Get(app.ID)
	if restored.InstanceID != historyID || restored.Image != published.History[0].Image || restored.Phase != dockerapp.PhaseActive {
		t.Fatalf("later rollback cutovered to a removed instance: %#v calls=%v", restored, fake.calls)
	}
	if contains(fake.calls, "pull") {
		t.Fatalf("history instance still existed but rollback republished: %v", fake.calls)
	}
}

func TestDockerRollbackMissingHistoryInstanceRepublishes(t *testing.T) {
	store, fake, rollout, app, published := publishUpdate(t)
	historyID := publishedHistoryInstance(t, published)
	delete(fake.state.Instances, historyID)
	fake.calls = nil

	if err := rollout.Rollback(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(app.ID)
	if got.Phase != dockerapp.PhaseActive || got.Image == "" || got.RuleRef == "" {
		t.Fatalf("missing history republish got=%#v", got)
	}
	if contains(fake.calls, "cutover:"+historyID) {
		t.Fatalf("missing history instance was still the cutover target: %v", fake.calls)
	}
	if !contains(fake.calls, "pull") || !contains(fake.calls, "start") || !contains(fake.calls, "ready") {
		t.Fatalf("missing history instance did not republish: %v", fake.calls)
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

func publishUpdate(t *testing.T) (*dockerapp.DeploymentStore, *rolloutFake, dockerapp.Rollout, dockerapp.App, dockerapp.Deployment) {
	t.Helper()
	store, fake, rollout, app, _ := updateHarness(t, "")
	if _, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"}); err != nil {
		t.Fatal(err)
	}
	published, ok := store.Get(app.ID)
	if !ok || published.InstanceID != "new" || published.Image == "" || published.RuleRef == "" {
		t.Fatalf("precondition published=%#v ok=%v", published, ok)
	}
	fake.calls = nil
	return store, fake, rollout, app, published
}

func publishedHistoryInstance(t *testing.T, published dockerapp.Deployment) string {
	t.Helper()
	if len(published.History) == 0 || published.History[0].InstanceID == "" {
		t.Fatalf("precondition history=%#v", published.History)
	}
	return published.History[0].InstanceID
}

func assertHistoryInstance(t *testing.T, got dockerapp.Deployment, instanceID string) {
	t.Helper()
	if len(got.History) == 0 || got.History[0].InstanceID != instanceID {
		t.Fatalf("history instance not preserved: %#v want=%s", got.History, instanceID)
	}
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
