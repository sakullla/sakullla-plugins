package dockerapp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestDockerAppOverlayPersistsAutoUpdate(t *testing.T) {
	omitted := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:latest\n","generation":"generation-1"}]}`)
	got, err := dockerapp.ParseConfiguration(omitted)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate != nil || dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) || got.Apps[0].Image != "nginx:latest" {
		t.Fatalf("omitted auto_update got=%#v err=%v", got, err)
	}

	disabled := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:latest\n","generation":"generation-1","auto_update":false}]}`)
	got, err = dockerapp.ParseConfiguration(disabled)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate == nil || *got.Apps[0].AutoUpdate || dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) {
		t.Fatalf("false auto_update got=%#v err=%v", got, err)
	}

	enabled := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:latest\n","generation":"generation-1","auto_update":true}]}`)
	got, err = dockerapp.ParseConfiguration(enabled)
	if err != nil || len(got.Apps) != 1 || got.Apps[0].AutoUpdate == nil || !*got.Apps[0].AutoUpdate || !dockerapp.AutoUpdateEnabled(got.Apps[0].AutoUpdate) {
		t.Fatalf("true auto_update got=%#v err=%v", got, err)
	}

	for _, document := range []string{
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:latest\n","generation":"generation-1","auto_update":"no"}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:latest\n","generation":"generation-1","autoupdate":false}]}`,
	} {
		if _, err := dockerapp.ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("document %s was accepted", document)
		}
	}
}

func TestDockerManualUpdateDefaultProjectsUntilConfirm(t *testing.T) {
	if dockerapp.DefaultAutoUpdate {
		t.Fatal("auto_update must default off")
	}
	if dockerapp.AutoUpdateEnabled(nil) || !dockerapp.AutoUpdateEnabled(boolPtr(true)) || dockerapp.AutoUpdateEnabled(boolPtr(false)) {
		t.Fatal("omitted auto_update must default to disabled")
	}

	t.Run("same-digest", func(t *testing.T) {
		store, fake, rollout, app, old := updateHarness(t, "")
		view, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:current"})
		got, _ := store.Get(app.ID)
		if err != nil || view.HasUpdate || view.Published || view.AutoUpdate || len(fake.calls) != 0 {
			t.Fatalf("same digest view=%#v calls=%v err=%v", view, fake.calls, err)
		}
		if got.InstanceID != old.InstanceID || got.Image != old.Image || got.RuleTarget != old.RuleTarget || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("same digest mutated deployment: %#v", got)
		}
		if got.ImageDigest != "sha256:current" || got.AvailableDigest != "" {
			t.Fatalf("same digest should keep current digest without available: %#v", got)
		}
		if err := rollout.ConfirmUpdate(context.Background(), app); !errors.Is(err, dockerapp.ErrInvalidPreview) {
			t.Fatalf("same digest confirm err=%v", err)
		}
		unchanged, _ := store.Get(app.ID)
		if unchanged.InstanceID != old.InstanceID || unchanged.Phase != dockerapp.PhaseActive || len(fake.calls) != 0 {
			t.Fatalf("same digest confirm tore down: %#v calls=%v", unchanged, fake.calls)
		}
	})

	t.Run("default-and-explicit-false", func(t *testing.T) {
		for _, policy := range []*bool{nil, boolPtr(false)} {
			store, fake, rollout, app, old := updateHarness(t, "")
			view, err := rollout.AutoUpdate(context.Background(), app, policy, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
			got, _ := store.Get(app.ID)
			if err != nil || view.AutoUpdate || !view.HasUpdate || view.Published || view.Digest != "sha256:latest" || len(fake.calls) != 0 {
				t.Fatalf("policy=%v view=%#v calls=%v err=%v", policy, view, fake.calls, err)
			}
			if got.InstanceID != old.InstanceID || got.Image != old.Image || got.RuleTarget != old.RuleTarget || got.Phase != dockerapp.PhaseActive {
				t.Fatalf("policy=%v published without confirm: %#v", policy, got)
			}
			if got.ImageDigest != "sha256:current" || got.AvailableDigest != "sha256:latest" {
				t.Fatalf("policy=%v digest projection got=%#v", policy, got)
			}

			if err := rollout.ConfirmUpdate(context.Background(), app); err != nil {
				t.Fatal(err)
			}
			published, _ := store.Get(app.ID)
			if published.InstanceID != "new" || published.Image != app.Image || published.RuleTarget != "new" || published.Phase != dockerapp.PhaseActive || published.ImageDigest != "sha256:latest" {
				t.Fatalf("policy=%v confirm did not publish: %#v", policy, published)
			}
			if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
				t.Fatalf("policy=%v confirm calls=%v", policy, fake.calls)
			}
		}
	})

	t.Run("explicit-true-still-publishes", func(t *testing.T) {
		store, fake, rollout, app, old := updateHarness(t, "")
		view, err := rollout.AutoUpdate(context.Background(), app, boolPtr(true), dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
		got, _ := store.Get(app.ID)
		if err != nil || !view.AutoUpdate || !view.HasUpdate || !view.Published {
			t.Fatalf("explicit true view=%#v err=%v", view, err)
		}
		if got.InstanceID != "new" || got.Image != app.Image || got.RuleTarget != "new" || got.Phase != dockerapp.PhaseActive || got.ImageDigest != "sha256:latest" {
			t.Fatalf("explicit true cutover got=%#v", got)
		}
		if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
			t.Fatalf("explicit true calls=%v", fake.calls)
		}
		if err := rollout.Rollback(context.Background(), app); err != nil {
			t.Fatal(err)
		}
		restored, _ := store.Get(app.ID)
		if restored.InstanceID != old.InstanceID || restored.Image != old.Image || restored.RuleTarget != old.RuleTarget || restored.Generation != old.Generation || restored.Phase != dockerapp.PhaseActive {
			t.Fatalf("explicit true rollback got=%#v", restored)
		}
	})
}

func TestDockerManualUpdateConfirmAfterComposeDeployWithoutRolloutRecord(t *testing.T) {
	engine := dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	runtime := newLifecycleRuntime()
	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: testComposeYAML("nginx:latest")}
	apps, err := dockerapp.DeployComposeApp(context.Background(), nil, spec, engine, runtime, auditor)
	if err != nil || len(apps) != 1 || apps[0].Image != "nginx:latest" || !runtime.running["media"] {
		t.Fatalf("compose deploy apps=%#v err=%v", apps, err)
	}
	app := apps[0]

	store := dockerapp.NewDeploymentStore()
	if _, ok := store.Get(app.ID); ok {
		t.Fatal("compose deploy must not create a rollout record")
	}
	status := dockerapp.ProjectOpsStatus(true, false, dockerapp.Deployment{ImageDigest: "sha256:current"}, dockerapp.UpdatePolicy{}, "sha256:latest")
	if status != "有新版本" {
		t.Fatalf("compose app projected status = %q", status)
	}

	fake := &rolloutFake{}
	rollout := dockerapp.Rollout{Store: store, Executor: fake, Auditor: auditor}
	view, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
	got, ok := store.Get(app.ID)
	if err != nil || !view.HasUpdate || view.Published || view.AutoUpdate || len(fake.calls) != 0 {
		t.Fatalf("first observation view=%#v calls=%v err=%v", view, fake.calls, err)
	}
	if !ok || got.ImageDigest != "sha256:current" || got.AvailableDigest != "sha256:latest" || got.Phase != dockerapp.PhaseActive || got.Lease != "" {
		t.Fatalf("first observation did not persist digests: %#v ok=%v", got, ok)
	}
	if got.InstanceID != "" {
		t.Fatalf("first observation invented an instance: %#v", got)
	}

	if err := rollout.ConfirmUpdate(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	published, _ := store.Get(app.ID)
	if published.InstanceID != "new" || published.Image != app.Image || published.Phase != dockerapp.PhaseActive || published.ImageDigest != "sha256:latest" {
		t.Fatalf("compose confirm did not publish: %#v", published)
	}
	if published.RuleRef != "" {
		t.Fatalf("compose confirm invented rule_ref: %#v", published)
	}
	if strings.Join(fake.calls, ",") != "pull,start,ready,drain:" {
		t.Fatalf("compose confirm calls=%v", fake.calls)
	}
	if len(fake.cutoverRefs) != 0 {
		t.Fatalf("compose confirm cutovered empty http.rule: %v", fake.cutoverRefs)
	}
	if !runtime.running["media"] || !runtime.containerExists("media") {
		t.Fatalf("compose runtime was torn down: %#v", runtime)
	}
	if len(published.History) == 0 || published.History[0].ImageDigest != "sha256:current" {
		t.Fatalf("compose confirm did not keep rollback prior: %#v", published)
	}
}

func TestDockerRollbackAfterComposeConfirmRestoresPriorDigest(t *testing.T) {
	engine := dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	runtime := newLifecycleRuntime()
	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: testComposeYAML("nginx:latest")}
	apps, err := dockerapp.DeployComposeApp(context.Background(), nil, spec, engine, runtime, auditor)
	if err != nil || len(apps) != 1 {
		t.Fatalf("compose deploy apps=%#v err=%v", apps, err)
	}
	store := dockerapp.NewDeploymentStore()
	fake := &rolloutFake{}
	rollout := dockerapp.Rollout{Store: store, Executor: fake, Auditor: auditor}
	if _, err := rollout.AutoUpdate(context.Background(), apps[0], nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"}); err != nil {
		t.Fatal(err)
	}
	if err := rollout.ConfirmUpdate(context.Background(), apps[0]); err != nil {
		t.Fatal(err)
	}
	published, _ := store.Get(apps[0].ID)
	if published.ImageDigest != "sha256:latest" || len(published.History) == 0 || published.History[0].ImageDigest != "sha256:current" {
		t.Fatalf("confirm history=%#v", published)
	}
	composeBefore := apps[0].Compose
	if err := rollout.Rollback(context.Background(), apps[0]); err != nil {
		t.Fatal(err)
	}
	restored, _ := store.Get(apps[0].ID)
	if restored.ImageDigest != "sha256:current" || restored.Phase != dockerapp.PhaseActive {
		t.Fatalf("rollback digest=%#v", restored)
	}
	if apps[0].Compose != composeBefore || !runtime.running["media"] {
		t.Fatalf("rollback mutated compose/runtime: app=%#v running=%v", apps[0], runtime.running)
	}
	if len(fake.started) == 0 {
		t.Fatal("rollback republish did not start an instance")
	}
	republished := fake.started[len(fake.started)-1]
	if !strings.Contains(republished.Compose, "sha256:current") || !strings.Contains(republished.Image, "sha256:current") {
		t.Fatalf("rollback republish was not pinned: %#v", republished)
	}
	if !strings.Contains(republished.Compose, "nginx:latest") {
		t.Fatalf("rollback republish omitted current compose: %#v", republished)
	}
}

func TestDockerComposeOnlyConfirmUpdateRecoversDrainingIntent(t *testing.T) {
	engine := dockerapp.EngineObservation{Installed: true, Version: "27.1.1"}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	runtime := newLifecycleRuntime()
	spec := dockerapp.ComposeDeploySpec{AppID: "media", Generation: "generation-1", Compose: testComposeYAML("nginx:latest")}
	apps, err := dockerapp.DeployComposeApp(context.Background(), nil, spec, engine, runtime, auditor)
	if err != nil || len(apps) != 1 || apps[0].RuleRef != "" {
		t.Fatalf("compose deploy apps=%#v err=%v", apps, err)
	}
	app := apps[0]
	now := time.Unix(6000, 0)
	base := dockerapp.NewDeploymentStore()
	fake := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
	observed := dockerapp.Rollout{Store: base, Executor: fake, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
	if _, err := observed.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"}); err != nil {
		t.Fatal(err)
	}
	store := &faultStore{base: base, failPhase: dockerapp.PhaseActive, failRemaining: 1}
	rollout := dockerapp.Rollout{Store: store, Executor: fake, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
	if err := rollout.ConfirmUpdate(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
		t.Fatalf("compose confirm crash err=%v", err)
	}
	intent, ok := base.Get(app.ID)
	if !ok || intent.RuleRef != "" || intent.Phase != dockerapp.PhaseDraining || intent.PendingInstance != "new" {
		t.Fatalf("compose confirm did not persist draining intent: %#v ok=%v", intent, ok)
	}
	now = now.Add(2 * time.Second)
	if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
		t.Fatal(err)
	}
	published, _ := base.Get(app.ID)
	if published.InstanceID != "new" || published.Image != app.Image || published.Phase != dockerapp.PhaseActive || published.ImageDigest != "sha256:latest" || published.RuleRef != "" {
		t.Fatalf("compose confirm reconcile did not activate: %#v", published)
	}
	if contains(fake.calls, "remove:new") {
		t.Fatalf("compose confirm reconcile removed the ready instance: %v", fake.calls)
	}
	if len(fake.cutoverRefs) != 0 {
		t.Fatalf("compose confirm reconcile cutovered empty http.rule: %v", fake.cutoverRefs)
	}
}

func TestDockerComposeOnlyConfirmUpdateRestoresPriorWithoutHTTPRule(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	app := dockerapp.App{ID: "media", Image: "nginx:latest", Generation: "generation-1"}
	for _, fail := range []string{"ready", "drain"} {
		t.Run(fail, func(t *testing.T) {
			store := dockerapp.NewDeploymentStore()
			store.Put(dockerapp.Deployment{
				AppID: app.ID, InstanceID: "old", Image: "nginx:old", Generation: "generation-0",
				RuleTarget: "old", Phase: dockerapp.PhaseActive, ImageDigest: "sha256:current", AvailableDigest: "sha256:latest",
			})
			fake := &rolloutFake{fail: fail, state: dockerapp.RuntimeState{Instances: map[string]bool{"old": true}}}
			rollout := dockerapp.Rollout{Store: store, Executor: fake, Auditor: auditor}
			err := rollout.ConfirmUpdate(context.Background(), app)
			got, ok := store.Get(app.ID)
			if !ok || !errors.Is(err, dockerapp.ErrOperationFailed) {
				t.Fatalf("%s confirm err=%v ok=%v got=%#v", fail, err, ok, got)
			}
			if got.Phase != dockerapp.PhaseActive || got.InstanceID != "old" || got.Image != "nginx:old" || got.RuleRef != "" || got.RuleTarget != "old" || got.Lease != "" {
				t.Fatalf("%s confirm did not restore prior: %#v", fail, got)
			}
			if len(fake.cutoverRefs) != 0 || contains(fake.calls, "cutover:old") || fake.state.RuleTarget != "" {
				t.Fatalf("%s confirm cutovered empty http.rule: calls=%v refs=%v state=%#v", fail, fake.calls, fake.cutoverRefs, fake.state)
			}
			fake.fail = ""
			fake.calls = nil
			if err := rollout.Update(context.Background(), app); err != nil {
				t.Fatalf("%s retry after restore: %v", fail, err)
			}
			published, _ := store.Get(app.ID)
			if published.InstanceID != "new" || published.Phase != dockerapp.PhaseActive || published.RuleRef != "" {
				t.Fatalf("%s retry did not publish: %#v", fail, published)
			}
		})
	}
}

func TestDockerObserveUpdateWithoutExecutorDoesNotPublish(t *testing.T) {
	app := testApp("update-secret")
	store := dockerapp.NewDeploymentStore()
	rollout := dockerapp.Rollout{Store: store, Auditor: dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})}
	view, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"})
	got, ok := store.Get(app.ID)
	if err != nil || !view.HasUpdate || view.Published || view.AutoUpdate {
		t.Fatalf("observe without executor view=%#v err=%v", view, err)
	}
	if !ok || got.ImageDigest != "sha256:current" || got.AvailableDigest != "sha256:latest" || got.Phase != dockerapp.PhaseActive {
		t.Fatalf("observe without executor mutated publish state: %#v ok=%v", got, ok)
	}
	if err := rollout.ConfirmUpdate(context.Background(), app); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("confirm without executor err=%v", err)
	}
	unchanged, _ := store.Get(app.ID)
	if unchanged.ImageDigest != "sha256:current" || unchanged.AvailableDigest != "sha256:latest" {
		t.Fatalf("confirm without executor changed digest: %#v", unchanged)
	}
	if dockerapp.ProjectOpsStatus(true, false, unchanged, dockerapp.UpdatePolicy{}, "sha256:latest") != "有新版本" {
		t.Fatalf("missing executor hid update: %#v", unchanged)
	}
}

func TestDockerManualUpdateFailedConfirmAfterSeedRestoresActive(t *testing.T) {
	for _, fail := range []string{"pull", "start"} {
		t.Run(fail, func(t *testing.T) {
			app := testApp("update-secret")
			store := dockerapp.NewDeploymentStore()
			fake := &rolloutFake{fail: fail, secret: "update-secret", state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
			rollout := dockerapp.Rollout{Store: store, Executor: fake, Auditor: dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})}
			if _, err := rollout.AutoUpdate(context.Background(), app, nil, dockerapp.UpdateObservation{CurrentDigest: "sha256:current", LatestDigest: "sha256:latest"}); err != nil {
				t.Fatal(err)
			}
			err := rollout.ConfirmUpdate(context.Background(), app)
			got, _ := store.Get(app.ID)
			if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) {
				t.Fatalf("%s confirm err=%v", fail, err)
			}
			if got.Phase != dockerapp.PhaseActive || got.InstanceID != "" || got.ImageDigest != "sha256:current" || got.AvailableDigest != "sha256:latest" {
				t.Fatalf("%s confirm left seed unusable: %#v", fail, got)
			}
			if dockerapp.ProjectOpsStatus(true, false, got, dockerapp.UpdatePolicy{}, "sha256:latest") != "有新版本" {
				t.Fatalf("%s confirm hid update: %#v", fail, got)
			}
			fake.fail = ""
			fake.calls = nil
			if err := rollout.ConfirmUpdate(context.Background(), app); err != nil {
				t.Fatal(err)
			}
			published, _ := store.Get(app.ID)
			if published.InstanceID != "new" || published.Phase != dockerapp.PhaseActive || published.ImageDigest != "sha256:latest" {
				t.Fatalf("%s retry confirm got=%#v", fail, published)
			}
		})
	}
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
	if published.InstanceID != "new" || published.Image != app.Image || published.RuleTarget != "new" || published.Phase != dockerapp.PhaseActive || published.ImageDigest != "sha256:latest" {
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
		err := rollout.Rollback(context.Background(), app)
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
		if err := rollout.Rollback(context.Background(), app); err != nil {
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
		err := rollout.Rollback(context.Background(), app)
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
		if err := rollout.Rollback(context.Background(), app); err != nil {
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
	if err := rollout.Rollback(context.Background(), app); err != nil {
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

	if err := rollout.Rollback(context.Background(), app); err != nil {
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
	if err := rollout.ConfirmUpdate(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	published, ok := store.Get(app.ID)
	if !ok || published.InstanceID != "new" || published.Image == "" || published.RuleRef == "" || published.ImageDigest != "sha256:latest" {
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
		ImageDigest: "sha256:current",
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
