package dockerapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestDockerDiscoverLabelsAndExposedPortCandidates(t *testing.T) {
	result, err := dockerapp.Discover([]dockerapp.ContainerObservation{
		{ID: "labeled", Labels: map[string]string{dockerapp.AppLabel: "media"}, ExposedPorts: []uint16{8080}},
		{ID: "candidate", ExposedPorts: []uint16{9000, 8000}}, {ID: "hidden"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || !result[0].Candidate || result[1].AppID != "media" || result[1].Candidate {
		t.Fatalf("discoveries = %#v", result)
	}
	if _, err := dockerapp.Discover(make([]dockerapp.ContainerObservation, dockerapp.MaxDiscoveries+1)); !errors.Is(err, dockerapp.ErrBoundExceeded) {
		t.Fatalf("discovery bound = %v", err)
	}
}

func TestComposeRiskPreviewAuthorizationAuditAndSecretRedaction(t *testing.T) {
	plan := dockerapp.ComposePlan{AppID: "media", Generation: "generation-1", Project: "media", Services: []dockerapp.ComposeService{{
		Name: "web", Privileged: true, HostMounts: []string{"/host:/data"}, AddCapabilities: []string{"NET_ADMIN"}, Networks: []string{"front"}, Volumes: []string{"data"},
	}}, RuleImpacts: []string{"rule-media"}}
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil || len(preview.Items) != 6 {
		t.Fatalf("risk preview=%#v err=%v", preview, err)
	}
	if _, err := dockerapp.PreviewCompose(dockerapp.ComposePlan{AppID: "media", Generation: "generation-1", Project: "media", Services: make([]dockerapp.ComposeService, dockerapp.MaxComposeServices+1)}); !errors.Is(err, dockerapp.ErrBoundExceeded) {
		t.Fatalf("compose service bound = %v", err)
	}
	calls := 0
	var audits []dockerapp.AuditRecord
	auditor := dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })
	secret := "Registry/token-secret"
	inventory := dockerapp.ComposeInventoryFunc(func(context.Context, string, string) (dockerapp.ComposePlan, error) { return plan, nil })
	authorization := dockerapp.Authorization{Token: "approved", AppID: plan.AppID, Generation: plan.Generation, PreviewDigest: preview.Digest}
	verifier := dockerapp.AuthorizationVerifierFunc(func(_ context.Context, got dockerapp.Authorization, appID, generation, digest string) error {
		if got.Token != "approved" {
			return &secretCause{message: "bad token " + secret}
		}
		if got.AppID != appID || got.Generation != generation || got.PreviewDigest != digest {
			return errors.New("binding mismatch")
		}
		return nil
	})
	journal := dockerapp.NewOperationJournal()
	var operationKeys []string
	success := dockerapp.ComposeExecutorFunc(func(_ context.Context, operation string, _ dockerapp.ComposePlan) error {
		calls++
		operationKeys = append(operationKeys, operation)
		return nil
	})
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, nil); !errors.Is(err, dockerapp.ErrAuditRequired) || calls != 0 {
		t.Fatalf("missing auditor err=%v calls=%d", err, calls)
	}
	bad := authorization
	bad.Token = "forged"
	if err := dockerapp.ExecuteCompose(context.Background(), preview, bad, inventory, verifier, success, journal, auditor); !errors.Is(err, dockerapp.ErrUnauthorized) || calls != 0 || strings.Contains(err.Error(), secret) {
		t.Fatalf("unauthorized err=%v calls=%d", err, calls)
	}
	drift := preview
	drift.Items = append([]dockerapp.RiskItem(nil), preview.Items...)
	drift.Items[0].Target = "mutated"
	if err := dockerapp.ExecuteCompose(context.Background(), drift, authorization, inventory, verifier, success, journal, auditor); !errors.Is(err, dockerapp.ErrInvalidPreview) || calls != 0 {
		t.Fatalf("drift err=%v calls=%d", err, calls)
	}
	failing := dockerapp.ComposeExecutorFunc(func(context.Context, string, dockerapp.ComposePlan) error {
		calls++
		return &secretCause{message: "pull denied for " + secret}
	})
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, failing, journal, auditor)
	var raw *secretCause
	if err == nil || strings.Contains(err.Error(), secret) || errors.As(err, &raw) || errors.Unwrap(err) != dockerapp.ErrOperationFailed {
		t.Fatalf("unsafe error tree err=%v raw=%v unwrap=%v", err, raw, errors.Unwrap(err))
	}
	journal = dockerapp.NewOperationJournal()
	calls = 0
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, auditor); err != nil {
		t.Fatal(err)
	}
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, auditor); err != nil || calls != 1 {
		t.Fatalf("idempotent retry err=%v calls=%d", err, calls)
	}
	invalid := plan
	invalid.Services = append([]dockerapp.ComposeService(nil), plan.Services...)
	invalid.Services[0].Name = secret
	if _, err := dockerapp.PreviewCompose(invalid); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("validation leaked secret: %v", err)
	}
	calls = 0
	journalFailure := &failingJournal{failRead: true, secret: secret}
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journalFailure, auditor)
	var journalRaw *secretCause
	if !errors.Is(err, dockerapp.ErrOperationFailed) || errors.As(err, &journalRaw) || strings.Contains(err.Error(), secret) || calls != 0 {
		t.Fatalf("journal read boundary err=%v raw=%v calls=%d", err, journalRaw, calls)
	}
	journalFailure = &failingJournal{failWrite: true, secret: secret}
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journalFailure, auditor)
	journalRaw = nil
	if !errors.Is(err, dockerapp.ErrOperationFailed) || errors.As(err, &journalRaw) || strings.Contains(err.Error(), secret) || calls != 1 {
		t.Fatalf("journal write boundary err=%v raw=%v calls=%d", err, journalRaw, calls)
	}
	if len(operationKeys) < 2 || operationKeys[len(operationKeys)-1] != operationKeys[len(operationKeys)-2] {
		t.Fatalf("compose retry operation keys are not stable: %v", operationKeys)
	}
	encoded := fmt.Sprint(audits)
	if strings.Contains(encoded, secret) {
		t.Fatalf("unsafe audits = %s", encoded)
	}
}

func TestDockerCutoverDrainSuccessAndRollbackPreservesOld(t *testing.T) {
	secret := "deploy-secret"
	app := testApp(secret)
	for _, fail := range []string{"", "pull", "start", "ready", "cutover", "drain"} {
		t.Run(map[bool]string{true: "success", false: fail}[fail == ""], func(t *testing.T) {
			store := dockerapp.NewDeploymentStore()
			old := dockerapp.Deployment{AppID: app.ID, InstanceID: "old", Image: "old-image", RuleRef: app.RuleRef, RuleTarget: "old", Generation: "generation-0"}
			store.Put(old)
			fake := &rolloutFake{fail: fail, secret: secret}
			var audits []dockerapp.AuditRecord
			err := (dockerapp.Rollout{Store: store, Executor: fake, Auditor: dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })}).Update(context.Background(), app)
			got, _ := store.Get(app.ID)
			if fail == "" {
				if err != nil || got.InstanceID != "new" || strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
					t.Fatalf("success got=%#v calls=%v err=%v", got, fake.calls, err)
				}
			} else if err == nil || strings.Contains(err.Error(), secret) || got != old {
				t.Fatalf("rollback %s got=%#v err=%v", fail, got, err)
			}
			if strings.Contains(fmt.Sprint(audits), secret) {
				t.Fatalf("rollout audit leaked secret: %v", audits)
			}
			if fail == "drain" && !contains(fake.calls, "cutover:old") {
				t.Fatalf("drain failure did not restore old rule: %v", fake.calls)
			}
		})
	}
}

func TestDockerRollbackCleanupIsBoundedAndPersistsReconcile(t *testing.T) {
	app := testApp("cleanup-secret")
	old := dockerapp.Deployment{AppID: app.ID, InstanceID: "old", RuleRef: app.RuleRef, RuleTarget: "old", Generation: "generation-0", Phase: dockerapp.PhaseActive}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	for _, test := range []struct {
		name     string
		fake     *rolloutFake
		want     dockerapp.RolloutPhase
		noRemove bool
		wantText []string
	}{
		{name: "remove-failure", fake: &rolloutFake{fail: "ready", failRemove: true}, want: dockerapp.PhaseCleanupPending, wantText: []string{"readiness"}},
		{name: "restore-failure", fake: &rolloutFake{fail: "drain", failRestore: true}, want: dockerapp.PhaseRouteReconcile, noRemove: true, wantText: []string{"drain"}},
		{name: "blocked-remove", fake: &rolloutFake{fail: "ready", blockRemove: true}, want: dockerapp.PhaseCleanupPending},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := dockerapp.NewDeploymentStore()
			store.Put(old)
			err := (dockerapp.Rollout{Store: store, Executor: test.fake, Auditor: auditor, CleanupTimeout: 10 * time.Millisecond}).Update(context.Background(), app)
			got, _ := store.Get(app.ID)
			if !errors.Is(err, dockerapp.ErrOperationFailed) || got.Phase != test.want || strings.Contains(err.Error(), "cleanup-secret") {
				t.Fatalf("cleanup err=%v deployment=%#v", err, got)
			}
			var raw *secretCause
			if errors.As(err, &raw) {
				t.Fatalf("cleanup exposed raw cause: %v", raw)
			}
			for _, text := range test.wantText {
				if !strings.Contains(err.Error(), text) {
					t.Fatalf("joined cleanup error %q lacks %q", err, text)
				}
			}
			if test.noRemove && containsPrefix(test.fake.calls, "remove:") {
				t.Fatalf("new instance removed after restore failure: %v", test.fake.calls)
			}
		})
	}
	zero := &rolloutFake{}
	store := dockerapp.NewDeploymentStore()
	store.Put(old)
	if err := (dockerapp.Rollout{Store: store, Executor: zero}).Update(context.Background(), app); !errors.Is(err, dockerapp.ErrAuditRequired) || len(zero.calls) != 0 {
		t.Fatalf("missing auditor err=%v calls=%v", err, zero.calls)
	}
}

func TestDockerDeleteImpactPreviewSharedRefsAndCoreOwnership(t *testing.T) {
	impacts := []dockerapp.ResourceImpact{
		{Kind: "container", ID: "instance", Owner: dockerapp.OwnerPlugin}, {Kind: "volume", ID: "shared", Owner: dockerapp.OwnerPlugin, Shared: true}, {Kind: "rule", ID: "rule", Owner: dockerapp.OwnerCore},
		{Kind: "network", ID: "private", Owner: dockerapp.OwnerPlugin},
	}
	preview, err := dockerapp.PreviewDelete("media", "generation-1", impacts)
	if err != nil {
		t.Fatal(err)
	}
	authorization := dockerapp.Authorization{Token: "approved", AppID: "media", Generation: "generation-1", PreviewDigest: preview.Digest}
	inventory := dockerapp.DeleteInventoryFunc(func(context.Context, string, string) ([]dockerapp.ResourceImpact, error) { return impacts, nil })
	verifier := dockerapp.AuthorizationVerifierFunc(func(_ context.Context, got dockerapp.Authorization, appID, generation, digest string) error {
		if got.Token != "approved" || got.AppID != appID || got.Generation != generation || got.PreviewDigest != digest {
			return errors.New("authorization rejected")
		}
		return nil
	})
	var audits []dockerapp.AuditRecord
	auditor := dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })
	secret := "delete-secret"
	fake := &deleteFake{secret: secret}
	journal := dockerapp.NewOperationJournal()
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, nil); !errors.Is(err, dockerapp.ErrAuditRequired) || len(fake.calls) != 0 {
		t.Fatalf("missing audit err=%v calls=%v", err, fake.calls)
	}
	forged := preview
	forged.Impacts = append([]dockerapp.ResourceImpact(nil), preview.Impacts...)
	forged.Impacts[0].Owner = dockerapp.OwnerCore
	if err := dockerapp.ExecuteDelete(context.Background(), forged, authorization, inventory, verifier, fake, journal, auditor); !errors.Is(err, dockerapp.ErrInvalidPreview) || len(fake.calls) != 0 {
		t.Fatalf("forged preview err=%v calls=%v", err, fake.calls)
	}
	fake.failAt = 2
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, auditor); !errors.Is(err, dockerapp.ErrOperationFailed) {
		t.Fatalf("second effect failure=%v", err)
	} else {
		var raw *secretCause
		if strings.Contains(err.Error(), secret) || errors.As(err, &raw) {
			t.Fatalf("delete exposed raw cause: err=%v raw=%v", err, raw)
		}
	}
	fake.failAt = 0
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, auditor); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fake.calls, ",") != "delete:instance,delete:private,delete:private,release:rule" {
		t.Fatalf("idempotent cleanup calls = %v", fake.calls)
	}
	if len(fake.operationKeys) != 4 || fake.operationKeys[1] != fake.operationKeys[2] {
		t.Fatalf("delete retry operation keys are not stable: %v", fake.operationKeys)
	}
	if len(audits) == 0 {
		t.Fatal("delete outcomes/progress were not audited")
	}
}

func TestDockerControllerRPCGrantGenerationRevokeAndBounds(t *testing.T) {
	newController := func(admission dockerapp.TypedHandleAdmission) *dockerapp.Controller {
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: admission})
		if err != nil {
			t.Fatal(err)
		}
		return controller
	}
	request := handshake([]string{"docker-compose", "dynamic-ui", "http-rule"})
	if _, err := newController(nil).Handshake(context.Background(), handshake([]string{"docker-compose", "http-rule"})); err == nil {
		t.Fatal("missing dynamic-ui grant was accepted")
	}
	controller := newController(dockerapp.TypedHandleAdmissionFunc(func(_ context.Context, _ *rpcplugin.Generation, got pluginsdk.RPCHandshakeRequest, apps []dockerapp.App) error {
		if got.Generation != "generation-1" || len(apps) != 1 {
			t.Fatalf("admission request=%#v apps=%#v", got, apps)
		}
		return nil
	}))
	if _, err := controller.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "stale", Config: configWire(t, 1)}); response.Error == nil {
		t.Fatal("stale generation was accepted")
	}

	controller = newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
		return nil
	}))
	if _, err := controller.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil || len(controller.Apps()) != 0 {
		t.Fatalf("stop/revoke response=%#v apps=%v", response, controller.Apps())
	}

	for _, count := range []int{dockerapp.MaxApps, dockerapp.MaxApps + 1} {
		bounded := newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
			return nil
		}))
		if _, err := bounded.Handshake(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		response := bounded.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, count)})
		if (count == dockerapp.MaxApps) == (response.Error != nil) {
			t.Fatalf("count=%d response=%#v", count, response)
		}
	}
	huge := bytes.Repeat([]byte{'x'}, dockerapp.MaxConfigBytes+1)
	bounded := newController(nil)
	if _, err := bounded.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := bounded.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: huge}); response.Error == nil {
		t.Fatal("oversized config was accepted")
	}
	validation := newController(nil)
	if _, err := validation.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	validationSecret := "validation-secret"
	validationWire, err := json.Marshal(dockerapp.Configuration{Apps: []dockerapp.App{
		{ID: validationSecret, Image: "image:new", RuleRef: "rule-1", Generation: "generation-1"},
		{ID: validationSecret, Image: "image:new", RuleRef: "rule-2", Generation: "generation-1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if response := validation.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: validationWire}); response.Error == nil || strings.Contains(response.Error.Message, validationSecret) {
		t.Fatalf("validation response leaked caller data: %#v", response)
	}

	defaultGate := newController(nil)
	if _, err := defaultGate.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := defaultGate.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := defaultGate.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error == nil {
		t.Fatal("missing typed handles did not fail closed")
	}
	if len(defaultGate.Apps()) != 0 {
		t.Fatal("failed admission retained generation-owned apps")
	}
}

func TestDockerEntrypointCanonicalRPCAndDefaultFailClosed(t *testing.T) {
	var output bytes.Buffer
	if err := dockerapp.RunEntrypoint(context.Background(), []string{dockerapp.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint output=%q err=%v", output.String(), err)
	}
	if err := dockerapp.RunEntrypoint(context.Background(), nil, &output); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("default entrypoint err=%v", err)
	}
}

func TestDockerControllerDeadlineLateNilCannotCommitGenerationState(t *testing.T) {
	grants := []string{"docker-compose", "dynamic-ui", "http-rule"}
	t.Run("prepare", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact", PrepareTimeout: 20 * time.Millisecond,
			PrepareGate: func(context.Context) error { close(started); <-release; return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
			t.Fatal(err)
		}
		result := make(chan pluginsdk.LifecycleResponse, 1)
		go func() {
			result <- controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)})
		}()
		<-started
		if response := <-result; response.Error == nil || response.Error.Code != pluginsdk.ErrorDeadlineExceeded {
			t.Fatalf("prepare deadline response=%#v", response)
		}
		close(release)
		time.Sleep(30 * time.Millisecond)
		if len(controller.Apps()) != 0 {
			t.Fatal("late prepare committed generation apps/secrets")
		}
	})
	t.Run("activate", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond,
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
				close(started)
				<-release
				return nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
			t.Fatal(err)
		}
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)}); response.Error != nil {
			t.Fatal(response.Error)
		}
		result := make(chan pluginsdk.LifecycleResponse, 1)
		go func() {
			result <- controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
		}()
		<-started
		if response := <-result; response.Error == nil || response.Error.Code != pluginsdk.ErrorDeadlineExceeded {
			t.Fatalf("activate deadline response=%#v", response)
		}
		if len(controller.Apps()) != 0 {
			t.Fatal("activation timeout retained generation apps/secrets")
		}
		close(release)
		time.Sleep(30 * time.Millisecond)
		if len(controller.Apps()) != 0 {
			t.Fatal("late activation recommitted generation apps/secrets")
		}
	})
	t.Run("pre-canceled-prepare", func(t *testing.T) {
		var calls atomic.Int32
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact",
			PrepareGate: func(context.Context) error { calls.Add(1); return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		response := controller.Prepare(ctx, pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)})
		if response.Error == nil || calls.Load() != 0 || len(controller.Apps()) != 0 {
			t.Fatalf("pre-canceled prepare response=%#v calls=%d apps=%v", response, calls.Load(), controller.Apps())
		}
	})
	t.Run("pre-canceled-activate", func(t *testing.T) {
		var calls atomic.Int32
		controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
			PackageDigest: "package", ArtifactDigest: "artifact",
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, *rpcplugin.Generation, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
				calls.Add(1)
				return nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
			t.Fatal(err)
		}
		if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)}); response.Error != nil {
			t.Fatal(response.Error)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		response := controller.Activate(ctx, pluginsdk.LifecycleRequest{Generation: "generation-1"})
		if response.Error == nil || calls.Load() != 0 || len(controller.Apps()) != 0 {
			t.Fatalf("pre-canceled activate response=%#v calls=%d apps=%v", response, calls.Load(), controller.Apps())
		}
	})
}

func TestComposeCanonicalPlanOperationAndIdempotentMarkRetry(t *testing.T) {
	plan := dockerapp.ComposePlan{AppID: "media", Generation: "generation-1", Project: "media", Services: []dockerapp.ComposeService{{Name: "web"}}}
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Services = append(changed.Services, dockerapp.ComposeService{Name: "worker"})
	changedPreview, err := dockerapp.PreviewCompose(changed)
	if err != nil || changedPreview.Digest != preview.Digest {
		t.Fatalf("risk projection changed for risk-free service: %#v err=%v", changedPreview, err)
	}
	current := plan
	inventory := dockerapp.ComposeInventoryFunc(func(context.Context, string, string) (dockerapp.ComposePlan, error) { return current, nil })
	verifier := dockerapp.AuthorizationVerifierFunc(func(context.Context, dockerapp.Authorization, string, string, string) error { return nil })
	authorization := dockerapp.Authorization{AppID: plan.AppID, Generation: plan.Generation, PreviewDigest: preview.Digest}
	executor := &idempotentComposeFake{}
	journal := &failOnceJournal{OperationJournal: dockerapp.NewOperationJournal(), failMarkAt: 1}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, executor, journal, auditor); !errors.Is(err, dockerapp.ErrOperationFailed) {
		t.Fatalf("mark failure = %v", err)
	}
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, executor, journal, auditor); err != nil || executor.external != 1 || executor.attempts != 2 {
		t.Fatalf("idempotent retry err=%v attempts=%d external=%d", err, executor.attempts, executor.external)
	}
	current = changed
	if err := dockerapp.ExecuteCompose(context.Background(), changedPreview, authorization, inventory, verifier, executor, journal, auditor); err != nil || executor.external != 2 {
		t.Fatalf("risk-free plan change reused operation identity: err=%v external=%d keys=%v", err, executor.external, executor.keys)
	}
}

func TestDockerDeleteCanonicalIdentityAndIdempotentMarkRetry(t *testing.T) {
	if _, err := dockerapp.PreviewDelete("media", "generation-1", []dockerapp.ResourceImpact{{Kind: "volume", ID: "same", Owner: dockerapp.OwnerPlugin}, {Kind: "volume", ID: "same", Owner: dockerapp.OwnerCore}}); err == nil {
		t.Fatal("conflicting delete identity was accepted")
	}
	impacts := []dockerapp.ResourceImpact{{Kind: "a", ID: "b:c", Owner: dockerapp.OwnerPlugin}, {Kind: "a:b", ID: "c", Owner: dockerapp.OwnerPlugin}}
	preview, err := dockerapp.PreviewDelete("media", "generation-1", impacts)
	if err != nil {
		t.Fatal(err)
	}
	inventory := dockerapp.DeleteInventoryFunc(func(context.Context, string, string) ([]dockerapp.ResourceImpact, error) { return impacts, nil })
	verifier := dockerapp.AuthorizationVerifierFunc(func(context.Context, dockerapp.Authorization, string, string, string) error { return nil })
	authorization := dockerapp.Authorization{AppID: "media", Generation: "generation-1", PreviewDigest: preview.Digest}
	executor := &idempotentDeleteFake{seen: make(map[string]struct{})}
	journal := &failOnceJournal{OperationJournal: dockerapp.NewOperationJournal(), failMarkAt: 2}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, executor, journal, auditor); !errors.Is(err, dockerapp.ErrOperationFailed) {
		t.Fatalf("second mark failure = %v", err)
	}
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, executor, journal, auditor); err != nil || executor.external != 2 || executor.attempts != 3 || len(executor.seen) != 2 {
		t.Fatalf("delete retry err=%v attempts=%d external=%d keys=%v", err, executor.attempts, executor.external, executor.seen)
	}
}

func TestDockerDurableReconcileRestartCASAndPendingAdmission(t *testing.T) {
	app := testApp("")
	old := dockerapp.Deployment{AppID: app.ID, InstanceID: "old", RuleRef: app.RuleRef, RuleTarget: "old", Generation: "generation-0", Phase: dockerapp.PhaseActive}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	t.Run("cleanup-pending", func(t *testing.T) {
		store := dockerapp.NewDeploymentStore()
		store.Put(old)
		failed := &rolloutFake{fail: "ready", failRemove: true}
		if err := (dockerapp.Rollout{Store: store, Executor: failed, Auditor: auditor}).Update(context.Background(), app); !errors.Is(err, dockerapp.ErrOperationFailed) {
			t.Fatal(err)
		}
		pending, _ := store.Get(app.ID)
		pending.Lease, pending.LeaseUntil = "crashed-process", time.Now().Add(-time.Minute)
		store.Put(pending)
		blocked := &rolloutFake{}
		if err := (dockerapp.Rollout{Store: store, Executor: blocked, Auditor: auditor}).Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) || len(blocked.calls) != 0 {
			t.Fatalf("pending rollout err=%v calls=%v", err, blocked.calls)
		}
		restarted := &rolloutFake{state: dockerapp.RuntimeState{RuleTarget: "old", Instances: map[string]bool{"old": true, "new": true}}}
		if err := (dockerapp.Rollout{Store: store, Executor: restarted, Auditor: auditor}).Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(app.ID)
		if got.Phase != dockerapp.PhaseActive || got.PendingInstance != "" || !contains(restarted.calls, "remove:new") {
			t.Fatalf("recovered=%#v calls=%v", got, restarted.calls)
		}
	})
	t.Run("route-reconcile", func(t *testing.T) {
		store := dockerapp.NewDeploymentStore()
		store.Put(old)
		failed := &rolloutFake{fail: "drain", failRestore: true}
		if err := (dockerapp.Rollout{Store: store, Executor: failed, Auditor: auditor}).Update(context.Background(), app); !errors.Is(err, dockerapp.ErrOperationFailed) {
			t.Fatal(err)
		}
		restarted := &rolloutFake{state: dockerapp.RuntimeState{RuleTarget: "new", Instances: map[string]bool{"old": true, "new": true}}}
		if err := (dockerapp.Rollout{Store: store, Executor: restarted, Auditor: auditor}).Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get(app.ID)
		if got.RuleTarget != "old" || got.Phase != dockerapp.PhaseActive || !contains(restarted.calls, "cutover:old") || !contains(restarted.calls, "remove:new") {
			t.Fatalf("recovered=%#v calls=%v", got, restarted.calls)
		}
	})
	t.Run("stale-cas", func(t *testing.T) {
		store := dockerapp.NewDeploymentStore()
		store.Put(old)
		record, _, _ := store.Load(context.Background(), app.ID)
		if _, err := store.CompareAndSwap(context.Background(), app.ID, record.Version, old); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompareAndSwap(context.Background(), app.ID, record.Version, old); !errors.Is(err, dockerapp.ErrStateConflict) {
			t.Fatalf("stale CAS = %v", err)
		}
	})
}

func TestDockerSecretRefsAndGenerationBoundLateAdmission(t *testing.T) {
	grants := []string{"docker-compose", "dynamic-ui", "http-rule"}
	material := "plaintext-material-must-not-appear"
	legacy, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatal(err)
	}
	legacyWire := []byte(`{"apps":[{"id":"media","image":"image:new","rule_ref":"rule","generation":"generation-1","secrets":["` + material + `"]}]}`)
	if response := legacy.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: legacyWire}); response.Error == nil || strings.Contains(response.Error.Message, material) {
		t.Fatalf("plaintext secret config response=%#v", response)
	}
	var admitted []dockerapp.App
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: dockerapp.TypedHandleAdmissionFunc(func(_ context.Context, _ *rpcplugin.Generation, _ pluginsdk.RPCHandshakeRequest, apps []dockerapp.App) error {
		admitted = apps
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatal(err)
	}
	configuration := dockerapp.Configuration{Apps: []dockerapp.App{{ID: "media", Image: "image:new", RuleRef: "rule", Generation: "generation-1", SecretRefs: []string{"vault/registry"}}}}
	wire, _ := json.Marshal(configuration)
	if strings.Contains(string(wire), material) {
		t.Fatal("configuration contains secret material")
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	snapshot := controller.Apps()
	encoded, _ := json.Marshal([]any{snapshot, admitted})
	if strings.Contains(string(encoded), material) || len(snapshot) != 1 || len(snapshot[0].SecretRefs) != 1 {
		t.Fatalf("unsafe snapshots: %s", encoded)
	}
	snapshot[0].SecretRefs[0] = "mutated"
	if controller.Apps()[0].SecretRefs[0] != "vault/registry" {
		t.Fatal("snapshot alias mutated controller state")
	}
	if response := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil || len(controller.Apps()) != 0 {
		t.Fatalf("revoke response=%#v apps=%v", response, controller.Apps())
	}

	var acquired, closed, committed atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	late, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond, Admission: dockerapp.TypedHandleAdmissionFunc(func(ctx context.Context, generation *rpcplugin.Generation, _ pluginsdk.RPCHandshakeRequest, _ []dockerapp.App) error {
		resource := &struct{}{}
		handle, err := rpcplugin.BindHandle(generation, "docker-compose", resource, func(*struct{}) { closed.Add(1) })
		if err != nil {
			return err
		}
		acquired.Add(1)
		close(started)
		<-release
		return handle.Use(ctx, func(context.Context, *struct{}) error { committed.Add(1); return nil })
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := late.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatal(err)
	}
	if response := late.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	result := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		result <- late.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"})
	}()
	<-started
	response := <-result
	close(release)
	time.Sleep(30 * time.Millisecond)
	if response.Error == nil || acquired.Load() != 1 || closed.Load() != 1 || committed.Load() != 0 || len(late.Apps()) != 0 {
		t.Fatalf("late admission response=%#v acquired=%d closed=%d committed=%d apps=%v", response, acquired.Load(), closed.Load(), committed.Load(), late.Apps())
	}
}

func testApp(_ string) dockerapp.App {
	return dockerapp.App{ID: "media", Image: "registry/media:new", RuleRef: "rule-media", Generation: "generation-1", SecretRefs: []string{"registry-credential"}}
}

func configWire(t *testing.T, count int) []byte {
	t.Helper()
	apps := make([]dockerapp.App, count)
	for index := range apps {
		apps[index] = dockerapp.App{ID: fmt.Sprintf("app-%03d", index), Image: "image:new", RuleRef: fmt.Sprintf("rule-%03d", index), Generation: "generation-1"}
	}
	wire, err := json.Marshal(dockerapp.Configuration{Apps: apps})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func handshake(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: dockerapp.PluginID, PluginVersion: dockerapp.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1"}
}

type rolloutFake struct {
	fail, secret                         string
	calls                                []string
	failRestore, failRemove, blockRemove bool
	state                                dockerapp.RuntimeState
	inspectErr                           error
}

func (fake *rolloutFake) step(name string) error {
	fake.calls = append(fake.calls, name)
	phase := strings.Split(name, ":")[0]
	if fake.fail == phase {
		return &secretCause{message: fmt.Sprintf("%s %s", phase, fake.secret)}
	}
	return nil
}
func (fake *rolloutFake) Pull(context.Context, string) error { return fake.step("pull") }
func (fake *rolloutFake) Start(context.Context, dockerapp.App) (string, error) {
	if err := fake.step("start"); err != nil {
		return "", err
	}
	return "new", nil
}
func (fake *rolloutFake) Ready(context.Context, string) error { return fake.step("ready") }
func (fake *rolloutFake) Cutover(_ context.Context, _ string, target string) error {
	fake.calls = append(fake.calls, "cutover:"+target)
	if (target == "new" && fake.fail == "cutover") || (target == "old" && fake.failRestore) {
		return &secretCause{message: "cutover cleanup failed " + fake.secret}
	}
	return nil
}
func (fake *rolloutFake) Drain(_ context.Context, target string) error {
	return fake.step("drain:" + target)
}
func (fake *rolloutFake) Remove(ctx context.Context, target string) error {
	fake.calls = append(fake.calls, "remove:"+target)
	if fake.blockRemove {
		<-ctx.Done()
		return ctx.Err()
	}
	if fake.failRemove {
		return &secretCause{message: "remove cleanup failed " + fake.secret}
	}
	return nil
}
func (fake *rolloutFake) Inspect(context.Context, string, string) (dockerapp.RuntimeState, error) {
	fake.calls = append(fake.calls, "inspect")
	if fake.inspectErr != nil {
		return dockerapp.RuntimeState{}, fake.inspectErr
	}
	if fake.state.Instances != nil {
		return fake.state, nil
	}
	return dockerapp.RuntimeState{RuleTarget: "old", Instances: map[string]bool{"old": true, "new": true}}, nil
}

type deleteFake struct {
	calls         []string
	operationKeys []string
	failAt, count int
	secret        string
}

func (fake *deleteFake) DeleteOwned(_ context.Context, operation string, impact dockerapp.ResourceImpact) error {
	fake.calls = append(fake.calls, "delete:"+impact.ID)
	fake.operationKeys = append(fake.operationKeys, operation)
	fake.count++
	if fake.failAt == fake.count {
		return &secretCause{message: "delete failed " + fake.secret}
	}
	return nil
}
func (fake *deleteFake) ReleaseCoreRef(_ context.Context, operation string, impact dockerapp.ResourceImpact) error {
	fake.calls = append(fake.calls, "release:"+impact.ID)
	fake.operationKeys = append(fake.operationKeys, operation)
	fake.count++
	if fake.failAt == fake.count {
		return &secretCause{message: "release failed " + fake.secret}
	}
	return nil
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

type secretCause struct{ message string }

func (cause *secretCause) Error() string { return cause.message }

type failingJournal struct {
	failRead, failWrite bool
	secret              string
}

type failOnceJournal struct {
	*dockerapp.OperationJournal
	marks, failMarkAt int
}

func (journal *failOnceJournal) MarkCompleted(ctx context.Context, operation, effect string) error {
	journal.marks++
	if journal.marks == journal.failMarkAt {
		return errors.New("durable mark failed")
	}
	return journal.OperationJournal.MarkCompleted(ctx, operation, effect)
}

type idempotentComposeFake struct {
	attempts, external int
	keys               []string
	seen               sync.Map
}

func (fake *idempotentComposeFake) ApplyCompose(_ context.Context, operation string, _ dockerapp.ComposePlan) error {
	fake.attempts++
	fake.keys = append(fake.keys, operation)
	if _, loaded := fake.seen.LoadOrStore(operation, struct{}{}); !loaded {
		fake.external++
	}
	return nil
}

type idempotentDeleteFake struct {
	attempts, external int
	seen               map[string]struct{}
}

func (fake *idempotentDeleteFake) apply(operation string) error {
	fake.attempts++
	if _, ok := fake.seen[operation]; !ok {
		fake.seen[operation] = struct{}{}
		fake.external++
	}
	return nil
}
func (fake *idempotentDeleteFake) DeleteOwned(_ context.Context, operation string, _ dockerapp.ResourceImpact) error {
	return fake.apply(operation)
}
func (fake *idempotentDeleteFake) ReleaseCoreRef(_ context.Context, operation string, _ dockerapp.ResourceImpact) error {
	return fake.apply(operation)
}

func (journal *failingJournal) Completed(context.Context, string, string) (bool, error) {
	if journal.failRead {
		return false, &secretCause{message: "journal read failed " + journal.secret}
	}
	return false, nil
}

func (journal *failingJournal) MarkCompleted(context.Context, string, string) error {
	if journal.failWrite {
		return &secretCause{message: "journal write failed " + journal.secret}
	}
	return nil
}
