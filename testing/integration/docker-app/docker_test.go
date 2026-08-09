package dockerapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
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
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, nil, nil); !errors.Is(err, dockerapp.ErrAuditRequired) || calls != 0 {
		t.Fatalf("missing auditor err=%v calls=%d", err, calls)
	}
	bad := authorization
	bad.Token = "forged"
	if err := dockerapp.ExecuteCompose(context.Background(), preview, bad, inventory, verifier, success, journal, auditor, []string{secret}); !errors.Is(err, dockerapp.ErrUnauthorized) || calls != 0 || strings.Contains(err.Error(), secret) {
		t.Fatalf("unauthorized err=%v calls=%d", err, calls)
	}
	drift := preview
	drift.Items = append([]dockerapp.RiskItem(nil), preview.Items...)
	drift.Items[0].Target = "mutated"
	if err := dockerapp.ExecuteCompose(context.Background(), drift, authorization, inventory, verifier, success, journal, auditor, nil); !errors.Is(err, dockerapp.ErrInvalidPreview) || calls != 0 {
		t.Fatalf("drift err=%v calls=%d", err, calls)
	}
	failing := dockerapp.ComposeExecutorFunc(func(context.Context, string, dockerapp.ComposePlan) error {
		calls++
		return &secretCause{message: "pull denied for " + secret}
	})
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, failing, journal, auditor, []string{secret})
	var raw *secretCause
	if err == nil || strings.Contains(err.Error(), secret) || errors.As(err, &raw) || errors.Unwrap(err) != dockerapp.ErrOperationFailed {
		t.Fatalf("unsafe error tree err=%v raw=%v unwrap=%v", err, raw, errors.Unwrap(err))
	}
	journal = dockerapp.NewOperationJournal()
	calls = 0
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, auditor, nil); err != nil {
		t.Fatal(err)
	}
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journal, auditor, nil); err != nil || calls != 1 {
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
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journalFailure, auditor, []string{secret})
	var journalRaw *secretCause
	if !errors.Is(err, dockerapp.ErrOperationFailed) || errors.As(err, &journalRaw) || strings.Contains(err.Error(), secret) || calls != 0 {
		t.Fatalf("journal read boundary err=%v raw=%v calls=%d", err, journalRaw, calls)
	}
	journalFailure = &failingJournal{failWrite: true, secret: secret}
	err = dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, success, journalFailure, auditor, []string{secret})
	journalRaw = nil
	if !errors.Is(err, dockerapp.ErrOperationFailed) || errors.As(err, &journalRaw) || strings.Contains(err.Error(), secret) || calls != 1 {
		t.Fatalf("journal write boundary err=%v raw=%v calls=%d", err, journalRaw, calls)
	}
	if len(operationKeys) < 2 || operationKeys[len(operationKeys)-1] != operationKeys[len(operationKeys)-2] {
		t.Fatalf("compose retry operation keys are not stable: %v", operationKeys)
	}
	encoded := fmt.Sprint(audits)
	if strings.Contains(encoded, secret) || !strings.Contains(encoded, "[REDACTED]") {
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
		{name: "remove-failure", fake: &rolloutFake{fail: "ready", failRemove: true}, want: dockerapp.PhaseCleanupPending, wantText: []string{"ready", "remove cleanup failed"}},
		{name: "restore-failure", fake: &rolloutFake{fail: "drain", failRestore: true}, want: dockerapp.PhaseRouteReconcile, noRemove: true, wantText: []string{"drain", "cutover cleanup failed"}},
		{name: "blocked-remove", fake: &rolloutFake{fail: "ready", blockRemove: true}, want: dockerapp.PhaseCleanupPending},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := dockerapp.NewDeploymentStore()
			store.Put(old)
			err := (dockerapp.Rollout{Store: store, Executor: test.fake, Auditor: auditor, CleanupTimeout: 10 * time.Millisecond}).Update(context.Background(), app)
			got, _ := store.Get(app.ID)
			if !errors.Is(err, dockerapp.ErrOperationFailed) || got.Phase != test.want || strings.Contains(err.Error(), app.Secrets[0]) {
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
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, nil, nil); !errors.Is(err, dockerapp.ErrAuditRequired) || len(fake.calls) != 0 {
		t.Fatalf("missing audit err=%v calls=%v", err, fake.calls)
	}
	forged := preview
	forged.Impacts = append([]dockerapp.ResourceImpact(nil), preview.Impacts...)
	forged.Impacts[0].Owner = dockerapp.OwnerCore
	if err := dockerapp.ExecuteDelete(context.Background(), forged, authorization, inventory, verifier, fake, journal, auditor, nil); !errors.Is(err, dockerapp.ErrInvalidPreview) || len(fake.calls) != 0 {
		t.Fatalf("forged preview err=%v calls=%v", err, fake.calls)
	}
	fake.failAt = 2
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, auditor, []string{secret}); !errors.Is(err, dockerapp.ErrOperationFailed) {
		t.Fatalf("second effect failure=%v", err)
	} else {
		var raw *secretCause
		if strings.Contains(err.Error(), secret) || errors.As(err, &raw) {
			t.Fatalf("delete exposed raw cause: err=%v raw=%v", err, raw)
		}
	}
	fake.failAt = 0
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, journal, auditor, nil); err != nil {
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
	controller := newController(dockerapp.TypedHandleAdmissionFunc(func(_ context.Context, got pluginsdk.RPCHandshakeRequest, apps []dockerapp.App) error {
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

	controller = newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error { return nil }))
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
		bounded := newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error { return nil }))
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
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
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
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) error {
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

func testApp(secret string) dockerapp.App {
	return dockerapp.App{ID: "media", Image: "registry/media:new", RuleRef: "rule-media", Generation: "generation-1", Secrets: []string{secret}}
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
