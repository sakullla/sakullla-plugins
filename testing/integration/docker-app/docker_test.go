package dockerapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	if !dockerapp.RequiresRiskConfirmation(preview) {
		t.Fatal("privileged host-mount capability preview did not require confirmation")
	}
	if _, err := dockerapp.ConfirmComposeRisk(plan, ""); !errors.Is(err, dockerapp.ErrInvalidPreview) {
		t.Fatalf("missing confirm err=%v", err)
	}
	if _, err := dockerapp.ConfirmComposeRisk(plan, preview.Digest+"x"); !errors.Is(err, dockerapp.ErrInvalidPreview) {
		t.Fatalf("mismatched confirm err=%v", err)
	}
	if got, err := dockerapp.ConfirmComposeRisk(plan, preview.Digest); err != nil || got.Digest != preview.Digest {
		t.Fatalf("matching confirm preview=%#v err=%v", got, err)
	}
	safe := dockerapp.ComposePlan{AppID: "media", Generation: "generation-1", Project: "media", Services: []dockerapp.ComposeService{{Name: "web", Networks: []string{"front"}, Volumes: []string{"data"}}}}
	safePreview, err := dockerapp.PreviewCompose(safe)
	if err != nil || dockerapp.RequiresRiskConfirmation(safePreview) {
		t.Fatalf("non-blocking risks required confirm: %#v err=%v", safePreview, err)
	}
	if _, err := dockerapp.ConfirmComposeRisk(safe, ""); err != nil {
		t.Fatalf("non-blocking confirm err=%v", err)
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
			} else if err == nil || strings.Contains(err.Error(), secret) || got.InstanceID != old.InstanceID || got.RuleTarget != old.RuleTarget {
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
		{name: "remove-failure", fake: &rolloutFake{fail: "ready", failRemove: true}, want: dockerapp.PhaseCleanupPending},
		{name: "restore-failure", fake: &rolloutFake{fail: "drain", failRestore: true}, want: dockerapp.PhaseRouteReconcile, noRemove: true},
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
	request := handshake(requiredGrants())
	if _, err := newController(nil).Handshake(context.Background(), handshake(requiredGrants())); err != nil {
		t.Fatalf("handshake without container.compose: %v", err)
	}
	for _, grants := range [][]string{
		{"ui.dynamic"},
		{"http.rule"},
		{"container.compose"},
		{"container.compose", "ui.dynamic"},
		{"container.compose", "http.rule"},
	} {
		if _, err := newController(nil).Handshake(context.Background(), handshake(grants)); err == nil {
			t.Fatalf("incomplete grants %v were accepted", grants)
		}
	}
	controller := newController(dockerapp.TypedHandleAdmissionFunc(func(_ context.Context, got pluginsdk.RPCHandshakeRequest, apps []dockerapp.App) (dockerapp.PreparedAdmission, error) {
		if got.Generation != "generation-1" || len(apps) != 1 {
			t.Fatalf("admission request=%#v apps=%#v", got, apps)
		}
		return dockerapp.PreparedAdmissionFuncs{}, nil
	}))
	if _, err := controller.Handshake(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "stale", Config: configWire(t, 1)}); response.Error == nil {
		t.Fatal("stale generation was accepted")
	}

	controller = newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
		return dockerapp.PreparedAdmissionFuncs{}, nil
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
		bounded := newController(dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
			return dockerapp.PreparedAdmissionFuncs{}, nil
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
		{ID: validationSecret, Compose: testComposeYAML("image:new"), Generation: "generation-1"},
		{ID: validationSecret, Compose: testComposeYAML("image:new"), Generation: "generation-1"},
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

func TestDockerEntrypointCanonicalRPCAndSDKServers(t *testing.T) {
	var output bytes.Buffer
	if err := dockerapp.RunEntrypoint(context.Background(), []string{dockerapp.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint output=%q err=%v", output.String(), err)
	}
	t.Setenv("NRE_PLUGIN_ENDPOINT", "")
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", "")
	t.Setenv("NRE_PLUGIN_HTTP_ENDPOINT_CONFIG", "")
	if err := dockerapp.RunEntrypoint(context.Background(), nil, &output); err == nil || errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) || !strings.Contains(err.Error(), "NRE_PLUGIN_") {
		t.Fatalf("default entrypoint did not reach canonical SDK servers: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join("..", "..", "..", "plugins", "docker-app", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	for _, required := range []string{"http.rule", "ui.dynamic", "http.outbound", "host_scope: control-plane", "ui.route", "ui_route_id: docker-app", "resource.group", "resource_group_id: docker-app"} {
		if !strings.Contains(text, required) {
			t.Fatalf("plugin.yaml missing %q", required)
		}
	}
	for _, retired := range []string{"container.provider", "container.compose", "container.read", "container.manage", "ui.dynamic-actions", "dynamic-ui", "http-rule", "http.backend-provider", "http_backend_providers", "host_scope: agent"} {
		if strings.Contains(text, retired) {
			t.Fatalf("plugin.yaml still declares %q", retired)
		}
	}
	if !strings.Contains(text, "resource: docker-compose:managed") {
		t.Fatal("plugin.yaml must scope the revocable resource handle to managed Docker Compose")
	}
	if !strings.Contains(text, "host_scopes:") {
		t.Fatal("plugin.yaml missing host_scopes:")
	}
	if !strings.Contains(text, "- agent") && !strings.Contains(text, "[agent]") {
		t.Fatal("plugin.yaml host_scopes must include agent")
	}
	if regexp.MustCompile(`(?m)^[[:space:]]*host_scope:[[:space:]]*agent[[:space:]]*$`).MatchString(text) {
		t.Fatal("docker-app primary host_scope must not be agent")
	}
}

func TestDockerControllerDeadlineLateNilCannotCommitGenerationState(t *testing.T) {
	grants := requiredGrants()
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
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
				close(started)
				<-release
				return dockerapp.PreparedAdmissionFuncs{}, nil
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
			Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
				calls.Add(1)
				return dockerapp.PreparedAdmissionFuncs{}, nil
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
		leased, err := store.AcquireLease(context.Background(), app.ID, record.Version, old, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompareAndSwap(context.Background(), app.ID, leased.Version, leased.Value.FencingToken, old); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompareAndSwap(context.Background(), app.ID, leased.Version, leased.Value.FencingToken, old); !errors.Is(err, dockerapp.ErrStateConflict) {
			t.Fatalf("stale CAS = %v", err)
		}
	})
}

func TestDockerSecretRefsAndGenerationBoundLateAdmission(t *testing.T) {
	grants := requiredGrants()
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
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: dockerapp.TypedHandleAdmissionFunc(func(_ context.Context, _ pluginsdk.RPCHandshakeRequest, apps []dockerapp.App) (dockerapp.PreparedAdmission, error) {
		admitted = apps
		return dockerapp.PreparedAdmissionFuncs{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatal(err)
	}
	configuration := dockerapp.Configuration{Apps: []dockerapp.App{{ID: "media", Compose: testComposeYAML("image:new"), Generation: "generation-1", SecretRefs: []string{"vault/registry"}}}}
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

	var acquired, closed, committed, lasting atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	late, err := dockerapp.NewController(dockerapp.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", ActivateTimeout: 20 * time.Millisecond, DrainTimeout: 20 * time.Millisecond, Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
		acquired.Add(1)
		return dockerapp.PreparedAdmissionFuncs{CommitFunc: func(context.Context) error {
			committed.Add(1)
			lasting.Store(1)
			close(started)
			<-release
			return nil
		}, AbortFunc: func() { lasting.Store(0); closed.Add(1) }}, nil
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
	if response.Error == nil || acquired.Load() != 1 || closed.Load() != 1 || committed.Load() != 1 || lasting.Load() != 0 || len(late.Apps()) != 0 {
		t.Fatalf("late admission response=%#v acquired=%d closed=%d committed=%d lasting=%d apps=%v", response, acquired.Load(), closed.Load(), committed.Load(), lasting.Load(), late.Apps())
	}
}

func TestDockerFencingLeaseExpiryRejectsOldWriter(t *testing.T) {
	now := time.Unix(1000, 0)
	store := dockerapp.NewDeploymentStore()
	old := dockerapp.Deployment{AppID: "media", InstanceID: "old", RuleRef: "rule", RuleTarget: "old", Phase: dockerapp.PhaseActive}
	store.Put(old)
	record, _, _ := store.Load(context.Background(), "media")
	oldLease, err := store.AcquireLease(context.Background(), "media", record.Version, old, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	host := &rolloutFake{}
	if err := host.Pull(context.Background(), oldLease.Value.FencingToken, dockerapp.App{ID: "media", Image: "image:old"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	app := dockerapp.App{ID: "media", Image: "image:new", RuleRef: "rule", Generation: "generation-1"}
	if err := (dockerapp.Rollout{Store: store, Executor: host, Auditor: dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {}), Clock: func() time.Time { return now }, LeaseDuration: time.Second}).Update(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	current, _ := store.Get("media")
	if current.FencingToken <= oldLease.Value.FencingToken {
		t.Fatalf("fence did not advance: old=%d new=%d", oldLease.Value.FencingToken, current.FencingToken)
	}
	if err := host.Remove(context.Background(), oldLease.Value.FencingToken, dockerapp.App{ID: "media"}, "new"); !errors.Is(err, dockerapp.ErrStateConflict) {
		t.Fatalf("stale host effect=%v", err)
	}
}

func TestDockerCrashIntentsReconcileAfterStartCutoverAndFinalCAS(t *testing.T) {
	for _, phase := range []dockerapp.RolloutPhase{dockerapp.PhaseReadiness, dockerapp.PhaseDraining, dockerapp.PhaseActive} {
		t.Run(string(phase), func(t *testing.T) {
			now := time.Unix(2000, 0)
			base := dockerapp.NewDeploymentStore()
			old := dockerapp.Deployment{AppID: "media", InstanceID: "old", RuleRef: "rule-media", RuleTarget: "old", Phase: dockerapp.PhaseActive}
			base.Put(old)
			store := &faultStore{base: base, failPhase: phase, failRemaining: 1}
			host := &rolloutFake{}
			app := testApp("")
			rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {}), Clock: func() time.Time { return now }, LeaseDuration: time.Second}
			if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
				t.Fatalf("crash phase %s err=%v", phase, err)
			}
			incomplete, _ := base.Get(app.ID)
			if incomplete.Phase == dockerapp.PhaseActive {
				t.Fatalf("intent lost after phase %s: %#v", phase, incomplete)
			}
			now = now.Add(2 * time.Second)
			if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
				t.Fatalf("reconcile %s: %v state=%#v", phase, err, incomplete)
			}
			final, _ := base.Get(app.ID)
			if phase == dockerapp.PhaseReadiness {
				if final.InstanceID != "old" || final.RuleTarget != "old" {
					t.Fatalf("start crash truth=%#v", final)
				}
			} else if final.InstanceID != "new" || final.RuleTarget != "new" {
				t.Fatalf("post-cutover truth=%#v", final)
			}
		})
	}
}

func TestDockerReconcileAuthoritativeTruthAndFirstInstallTombstone(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	seed := func(value dockerapp.Deployment) (*dockerapp.DeploymentStore, *dockerapp.Rollout) {
		store := dockerapp.NewDeploymentStore()
		store.Put(value)
		r := &dockerapp.Rollout{Store: store, Auditor: auditor, CleanupTimeout: 20 * time.Millisecond}
		return store, r
	}
	t.Run("missing-old", func(t *testing.T) {
		store, r := seed(dockerapp.Deployment{AppID: "media", InstanceID: "old", RuleRef: "rule", PriorRuleTarget: "old", RuleTarget: "old", PendingInstance: "new", Phase: dockerapp.PhaseCleanupPending})
		r.Executor = &rolloutFake{state: dockerapp.RuntimeState{RuleTarget: "old", Instances: map[string]bool{"new": true}}}
		if err := r.Reconcile(context.Background(), "media"); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("missing old err=%v", err)
		}
		got, _ := store.Get("media")
		if got.Phase == dockerapp.PhaseActive {
			t.Fatalf("missing old finalized: %#v", got)
		}
	})
	t.Run("unrelated-target", func(t *testing.T) {
		store, r := seed(dockerapp.Deployment{AppID: "media", InstanceID: "old", RuleRef: "rule", PriorRuleTarget: "old", RuleTarget: "other", PendingInstance: "new", Phase: dockerapp.PhaseRouteReconcile})
		r.Executor = &rolloutFake{state: dockerapp.RuntimeState{RuleTarget: "other", Instances: map[string]bool{"old": true, "new": true}}}
		if err := r.Reconcile(context.Background(), "media"); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("unrelated err=%v", err)
		}
		got, _ := store.Get("media")
		if got.Phase == dockerapp.PhaseActive {
			t.Fatalf("unrelated finalized: %#v", got)
		}
	})
	t.Run("first-install-delete", func(t *testing.T) {
		store, r := seed(dockerapp.Deployment{AppID: "media", RuleRef: "rule", PendingInstance: "new", PriorAbsent: true, Phase: dockerapp.PhaseCleanupPending})
		r.Executor = &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{"new": true}}}
		if err := r.Reconcile(context.Background(), "media"); err != nil {
			t.Fatal(err)
		}
		if _, ok := store.Get("media"); ok {
			t.Fatal("first-install tombstone record retained")
		}
	})
	t.Run("post-effect-drift", func(t *testing.T) {
		store, r := seed(dockerapp.Deployment{AppID: "media", InstanceID: "old", RuleRef: "rule", PriorRuleRef: "rule", PriorRuleTarget: "old", RuleTarget: "old", PendingInstance: "new", Phase: dockerapp.PhaseCleanupPending})
		r.Executor = &rolloutFake{inspectStates: []dockerapp.RuntimeState{{RuleTarget: "old", Instances: map[string]bool{"old": true, "new": true}}, {RuleTarget: "other", Instances: map[string]bool{"old": true}}}}
		if err := r.Reconcile(context.Background(), "media"); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("drift err=%v", err)
		}
		got, _ := store.Get("media")
		if got.Phase == dockerapp.PhaseActive {
			t.Fatalf("post-effect drift finalized: %#v", got)
		}
	})
}

func TestDockerRollbackStoreCleanupContextsAndCASFailures(t *testing.T) {
	app := testApp("")
	old := dockerapp.Deployment{AppID: app.ID, InstanceID: "old", RuleRef: app.RuleRef, RuleTarget: "old", Phase: dockerapp.PhaseActive}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	t.Run("canceled-parent-independent", func(t *testing.T) {
		base := dockerapp.NewDeploymentStore()
		base.Put(old)
		store := &faultStore{base: base}
		host := &rolloutFake{fail: "pull"}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := (dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, CleanupTimeout: 20 * time.Millisecond}).Update(ctx, app)
		if !errors.Is(err, dockerapp.ErrOperationFailed) || !store.sawIndependentRecovery {
			t.Fatalf("err=%v independent=%v", err, store.sawIndependentRecovery)
		}
	})
	t.Run("blocking-recovery-store", func(t *testing.T) {
		base := dockerapp.NewDeploymentStore()
		base.Put(old)
		store := &faultStore{base: base, blockPhase: dockerapp.PhaseCleanupPending}
		host := &rolloutFake{fail: "pull"}
		started := time.Now()
		err := (dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, CleanupTimeout: 15 * time.Millisecond}).Update(context.Background(), app)
		if !errors.Is(err, dockerapp.ErrOperationFailed) || time.Since(started) > time.Second {
			t.Fatalf("bounded store err=%v elapsed=%v", err, time.Since(started))
		}
	})
	t.Run("release-cas-failure-joined", func(t *testing.T) {
		base := dockerapp.NewDeploymentStore()
		base.Put(old)
		store := &faultStore{base: base, failRelease: true}
		host := &rolloutFake{fail: "pull", inspectErr: errors.New("inspect failed")}
		err := (dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, CleanupTimeout: 20 * time.Millisecond}).Update(context.Background(), app)
		if !errors.Is(err, dockerapp.ErrOperationFailed) || store.releaseFailures != 1 || !contains(host.calls, "inspect") {
			t.Fatalf("combined err=%v releases=%d calls=%v", err, store.releaseFailures, host.calls)
		}
	})
}

func TestDockerDesiredMetadataSurvivesCrashAndFinalCAS(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	assertDesired := func(t *testing.T, got dockerapp.Deployment) {
		t.Helper()
		if got.AppID != "media" || got.InstanceID != "new" || got.Image != "image:new" || got.Generation != "generation-new" || got.RuleRef != "rule-new" || got.RuleTarget != "new" || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("incomplete desired deployment: %#v", got)
		}
		if got.PriorImage != "" || got.PriorGeneration != "" || got.PriorRuleRef != "" || got.PriorInstance != "" || got.PendingInstance != "" {
			t.Fatalf("active deployment retained recovery metadata: %#v", got)
		}
	}
	t.Run("first-install-final-cas", func(t *testing.T) {
		now := time.Unix(3000, 0)
		base := dockerapp.NewDeploymentStore()
		store := &faultStore{base: base, failPhase: dockerapp.PhaseActive, failRemaining: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
		app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new", RuleRef: "rule-new"}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("final CAS err=%v", err)
		}
		intent, ok := base.Get(app.ID)
		if !ok || intent.Image != app.Image || intent.Generation != app.Generation || intent.RuleRef != app.RuleRef || intent.Phase != dockerapp.PhaseDraining {
			t.Fatalf("desired intent not durable: %#v", intent)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		final, ok := base.Get(app.ID)
		if !ok {
			t.Fatal("first-install record was deleted")
		}
		assertDesired(t, final)
		if !contains(host.cutoverRefs, "rule-new") || !contains(host.inspectRefs, "rule-new") {
			t.Fatalf("wrong first-install refs: cutover=%v inspect=%v", host.cutoverRefs, host.inspectRefs)
		}
	})
	for _, failedPhase := range []dockerapp.RolloutPhase{dockerapp.PhaseDraining, dockerapp.PhaseActive} {
		t.Run("changed-metadata-"+string(failedPhase), func(t *testing.T) {
			now := time.Unix(4000, 0)
			base := dockerapp.NewDeploymentStore()
			base.Put(dockerapp.Deployment{AppID: "media", InstanceID: "old", Image: "image:old", Generation: "generation-old", RuleRef: "rule-old", RuleTarget: "old", Phase: dockerapp.PhaseActive})
			store := &faultStore{base: base, failPhase: failedPhase, failRemaining: 1}
			host := &rolloutFake{}
			app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new", RuleRef: "rule-new"}
			rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
			if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
				t.Fatalf("crash err=%v", err)
			}
			now = now.Add(2 * time.Second)
			if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
				t.Fatal(err)
			}
			final, _ := base.Get(app.ID)
			assertDesired(t, final)
			if !contains(host.cutoverRefs, "rule-new") || !contains(host.inspectRefs, "rule-new") {
				t.Fatalf("wrong changed refs: cutover=%v inspect=%v", host.cutoverRefs, host.inspectRefs)
			}
		})
	}
	t.Run("start-crash-restores-prior-metadata", func(t *testing.T) {
		now := time.Unix(5000, 0)
		base := dockerapp.NewDeploymentStore()
		base.Put(dockerapp.Deployment{AppID: "media", InstanceID: "old", Image: "image:old", Generation: "generation-old", RuleRef: "rule-old", RuleTarget: "old", Phase: dockerapp.PhaseActive})
		store := &faultStore{base: base, failPhase: dockerapp.PhaseReadiness, failRemaining: 1}
		host := &rolloutFake{}
		app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new", RuleRef: "rule-new"}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		final, _ := base.Get(app.ID)
		if final.InstanceID != "old" || final.Image != "image:old" || final.Generation != "generation-old" || final.RuleRef != "rule-old" || final.RuleTarget != "old" || final.Phase != dockerapp.PhaseActive {
			t.Fatalf("prior metadata not restored: %#v", final)
		}
		if !contains(host.inspectRefs, "rule-old") {
			t.Fatalf("start-crash inspected wrong rule: %v", host.inspectRefs)
		}
	})
}

func TestDockerPullingIntentAcquireFailureAndUnknownCommit(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	desired := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new", RuleRef: "rule-new"}
	prior := dockerapp.Deployment{AppID: "media", InstanceID: "old", Image: "image:old", Generation: "generation-old", RuleRef: "rule-old", RuleTarget: "old", Phase: dockerapp.PhaseActive}
	assertDesiredActive := func(t *testing.T, store *dockerapp.DeploymentStore) {
		t.Helper()
		got, ok := store.Get(desired.ID)
		if !ok || got.Phase != dockerapp.PhaseActive || got.InstanceID != "new" || got.Image != desired.Image || got.Generation != desired.Generation || got.RuleRef != desired.RuleRef || got.RuleTarget != "new" {
			t.Fatalf("desired deployment not active: %#v, exists=%v", got, ok)
		}
	}
	assertPriorActive := func(t *testing.T, store *dockerapp.DeploymentStore) {
		t.Helper()
		got, ok := store.Get(prior.AppID)
		if !ok || got.Phase != dockerapp.PhaseActive || got.InstanceID != prior.InstanceID || got.Image != prior.Image || got.Generation != prior.Generation || got.RuleRef != prior.RuleRef || got.RuleTarget != prior.RuleTarget {
			t.Fatalf("prior deployment not restored exactly: %#v, exists=%v", got, ok)
		}
		if got.PendingInstance != "" || got.DesiredRuleTarget != "" || got.PriorImage != "" || got.PriorGeneration != "" || got.PriorRuleRef != "" || got.PriorRuleTarget != "" || got.PriorInstance != "" || got.LastFailure != "" || got.Lease != "" || !got.LeaseUntil.IsZero() || got.PriorAbsent {
			t.Fatalf("restored deployment retained recovery fields: %#v", got)
		}
	}
	assertPulling := func(t *testing.T, got dockerapp.Deployment, firstInstall bool) {
		t.Helper()
		if got.Phase != dockerapp.PhasePulling || got.Image != desired.Image || got.Generation != desired.Generation || got.RuleRef != desired.RuleRef || got.PriorAbsent != firstInstall || got.PendingInstance != "" || got.DesiredRuleTarget != "" || got.LastFailure != "" {
			t.Fatalf("incomplete pulling intent: %#v", got)
		}
		if firstInstall {
			if got.InstanceID != "" || got.RuleTarget != "" || got.PriorImage != "" || got.PriorGeneration != "" || got.PriorRuleRef != "" || got.PriorRuleTarget != "" || got.PriorInstance != "" {
				t.Fatalf("first-install intent retained prior state: %#v", got)
			}
			return
		}
		if got.InstanceID != prior.InstanceID || got.RuleTarget != prior.RuleTarget || got.PriorImage != prior.Image || got.PriorGeneration != prior.Generation || got.PriorRuleRef != prior.RuleRef || got.PriorRuleTarget != prior.RuleTarget || got.PriorInstance != prior.InstanceID {
			t.Fatalf("update intent lost prior state: %#v", got)
		}
	}

	t.Run("first-install-failure-before-commit", func(t *testing.T) {
		base := dockerapp.NewDeploymentStore()
		store := &faultStore{base: base, failAcquireBefore: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor}
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("acquire failure=%v", err)
		}
		if len(host.calls) != 0 {
			t.Fatalf("host effects before durable intent: %v", host.calls)
		}
		if _, ok := base.Get(desired.ID); ok {
			t.Fatal("failed acquire created a deployment")
		}
		if err := rollout.Update(context.Background(), desired); err != nil {
			t.Fatalf("retry after pre-commit failure: %v", err)
		}
		assertDesiredActive(t, base)
	})

	t.Run("update-failure-before-commit", func(t *testing.T) {
		base := dockerapp.NewDeploymentStore()
		base.Put(prior)
		store := &faultStore{base: base, failAcquireBefore: 1}
		host := &rolloutFake{}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor}
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("acquire failure=%v", err)
		}
		if len(host.calls) != 0 {
			t.Fatalf("host effects before durable intent: %v", host.calls)
		}
		assertPriorActive(t, base)
		if err := rollout.Update(context.Background(), desired); err != nil {
			t.Fatalf("retry after pre-commit failure: %v", err)
		}
		assertDesiredActive(t, base)
	})

	t.Run("first-install-unknown-commit", func(t *testing.T) {
		now := time.Unix(6000, 0)
		base := dockerapp.NewDeploymentStore()
		store := &faultStore{base: base, failAcquireAfter: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("unknown acquire outcome=%v", err)
		}
		if len(host.calls) != 0 {
			t.Fatalf("host effects after unknown acquire outcome: %v", host.calls)
		}
		intent, ok := base.Get(desired.ID)
		if !ok {
			t.Fatal("committed pulling intent missing")
		}
		assertPulling(t, intent, true)
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) || len(host.calls) != 0 {
			t.Fatalf("live lease retry err=%v calls=%v", err, host.calls)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), desired.ID); err != nil {
			t.Fatalf("first-install reconcile: %v", err)
		}
		if _, ok := base.Get(desired.ID); ok {
			t.Fatal("first-install recovery did not write tombstone")
		}
		if err := rollout.Reconcile(context.Background(), desired.ID); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("repeated tombstone reconcile=%v", err)
		}
		if err := rollout.Update(context.Background(), desired); err != nil {
			t.Fatalf("retry after tombstone: %v", err)
		}
		assertDesiredActive(t, base)
	})

	t.Run("update-unknown-commit", func(t *testing.T) {
		now := time.Unix(7000, 0)
		base := dockerapp.NewDeploymentStore()
		base.Put(prior)
		store := &faultStore{base: base, failAcquireAfter: 1}
		host := &rolloutFake{}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("unknown acquire outcome=%v", err)
		}
		if len(host.calls) != 0 {
			t.Fatalf("host effects after unknown acquire outcome: %v", host.calls)
		}
		intent, ok := base.Get(desired.ID)
		if !ok {
			t.Fatal("committed pulling intent missing")
		}
		assertPulling(t, intent, false)
		if err := rollout.Update(context.Background(), desired); !errors.Is(err, dockerapp.ErrReconcilePending) || len(host.calls) != 0 {
			t.Fatalf("live lease retry err=%v calls=%v", err, host.calls)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), desired.ID); err != nil {
			t.Fatalf("update reconcile: %v", err)
		}
		assertPriorActive(t, base)
		if err := rollout.Reconcile(context.Background(), desired.ID); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("repeated active reconcile=%v", err)
		}
		assertPriorActive(t, base)
		if err := rollout.Update(context.Background(), desired); err != nil {
			t.Fatalf("retry after prior restore: %v", err)
		}
		assertDesiredActive(t, base)
	})
}

func TestDockerComposeOnlyDrainingIntentActivatesWithoutHTTPRule(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	assertActivated := func(t *testing.T, got dockerapp.Deployment, app dockerapp.App) {
		t.Helper()
		if got.InstanceID != "new" || got.Image != app.Image || got.Generation != app.Generation || got.RuleRef != "" || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("compose-only draining intent did not activate: %#v", got)
		}
	}
	t.Run("first-install-final-cas", func(t *testing.T) {
		now := time.Unix(3000, 0)
		base := dockerapp.NewDeploymentStore()
		store := &faultStore{base: base, failPhase: dockerapp.PhaseActive, failRemaining: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{}}}
		app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new"}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("final CAS err=%v", err)
		}
		intent, ok := base.Get(app.ID)
		if !ok || intent.Image != app.Image || intent.Generation != app.Generation || intent.RuleRef != "" || intent.Phase != dockerapp.PhaseDraining {
			t.Fatalf("desired intent not durable: %#v", intent)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		final, ok := base.Get(app.ID)
		if !ok {
			t.Fatal("first-install record was deleted")
		}
		assertActivated(t, final, app)
		if contains(host.calls, "remove:new") {
			t.Fatalf("compose-only reconcile removed the ready instance: %v", host.calls)
		}
		if len(host.cutoverRefs) != 0 {
			t.Fatalf("compose-only reconcile cutovered empty http.rule: %v", host.cutoverRefs)
		}
	})
	t.Run("changed-metadata-active", func(t *testing.T) {
		now := time.Unix(4000, 0)
		base := dockerapp.NewDeploymentStore()
		base.Put(dockerapp.Deployment{AppID: "media", InstanceID: "old", Image: "image:old", Generation: "generation-old", Phase: dockerapp.PhaseActive})
		store := &faultStore{base: base, failPhase: dockerapp.PhaseActive, failRemaining: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{"old": true}}}
		app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new"}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("crash err=%v", err)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
			t.Fatal(err)
		}
		final, _ := base.Get(app.ID)
		assertActivated(t, final, app)
		if contains(host.calls, "remove:new") {
			t.Fatalf("compose-only reconcile removed the ready instance: %v", host.calls)
		}
		if len(host.cutoverRefs) != 0 {
			t.Fatalf("compose-only reconcile cutovered empty http.rule: %v", host.cutoverRefs)
		}
		if !contains(host.calls, "drain:old") {
			t.Fatalf("compose-only reconcile skipped drain: %v", host.calls)
		}
	})
}

func TestDockerComposeOnlyFailureBeforeFinishNewRestoresPriorWithoutHTTPRule(t *testing.T) {
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	prior := dockerapp.Deployment{AppID: "media", InstanceID: "old", Image: "image:old", Generation: "generation-old", RuleTarget: "old", Phase: dockerapp.PhaseActive}
	app := dockerapp.App{ID: "media", Image: "image:new", Generation: "generation-new"}
	assertPrior := func(t *testing.T, got dockerapp.Deployment) {
		t.Helper()
		if got.InstanceID != prior.InstanceID || got.Image != prior.Image || got.Generation != prior.Generation || got.RuleRef != "" || got.RuleTarget != prior.RuleTarget || got.Phase != dockerapp.PhaseActive {
			t.Fatalf("compose-only prior was not restored: %#v", got)
		}
		if got.PendingInstance != "" || got.PriorInstance != "" || got.PriorRuleRef != "" || got.LastFailure != "" || got.Lease != "" || !got.LeaseUntil.IsZero() {
			t.Fatalf("restored compose-only deployment stayed rollout-busy: %#v", got)
		}
	}
	assertNoHTTPCutover := func(t *testing.T, host *rolloutFake) {
		t.Helper()
		if len(host.cutoverRefs) != 0 || contains(host.calls, "cutover:old") || contains(host.calls, "cutover:new") {
			t.Fatalf("compose-only restore cutovered empty http.rule: calls=%v refs=%v", host.calls, host.cutoverRefs)
		}
		if host.state.RuleTarget != "" {
			t.Fatalf("compose-only inspect invented http.rule target: %#v", host.state)
		}
	}

	for _, fail := range []string{"ready", "drain"} {
		t.Run(fail, func(t *testing.T) {
			store := dockerapp.NewDeploymentStore()
			store.Put(prior)
			host := &rolloutFake{fail: fail, state: dockerapp.RuntimeState{Instances: map[string]bool{"old": true}}}
			rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor}
			err := rollout.Update(context.Background(), app)
			got, _ := store.Get(app.ID)
			if !errors.Is(err, dockerapp.ErrOperationFailed) {
				t.Fatalf("%s err=%v got=%#v", fail, err, got)
			}
			assertPrior(t, got)
			assertNoHTTPCutover(t, host)
			host.fail = ""
			host.calls = nil
			if err := rollout.Update(context.Background(), app); err != nil {
				t.Fatalf("%s retry after restore: %v", fail, err)
			}
			published, _ := store.Get(app.ID)
			if published.InstanceID != "new" || published.Image != app.Image || published.Generation != app.Generation || published.Phase != dockerapp.PhaseActive || published.RuleRef != "" {
				t.Fatalf("%s retry did not publish: %#v", fail, published)
			}
		})
	}

	t.Run("readiness-crash-reconcile", func(t *testing.T) {
		now := time.Unix(8000, 0)
		base := dockerapp.NewDeploymentStore()
		base.Put(prior)
		store := &faultStore{base: base, failPhase: dockerapp.PhaseReadiness, failRemaining: 1}
		host := &rolloutFake{state: dockerapp.RuntimeState{Instances: map[string]bool{"old": true}}}
		rollout := dockerapp.Rollout{Store: store, Executor: host, Auditor: auditor, Clock: func() time.Time { return now }, LeaseDuration: time.Second}
		if err := rollout.Update(context.Background(), app); !errors.Is(err, dockerapp.ErrReconcilePending) {
			t.Fatalf("readiness crash err=%v", err)
		}
		now = now.Add(2 * time.Second)
		if err := rollout.Reconcile(context.Background(), app.ID); err != nil {
			t.Fatalf("readiness reconcile: %v", err)
		}
		final, _ := base.Get(app.ID)
		assertPrior(t, final)
		assertNoHTTPCutover(t, host)
		if err := rollout.Update(context.Background(), app); err != nil {
			t.Fatalf("retry after readiness restore: %v", err)
		}
		published, _ := base.Get(app.ID)
		if published.InstanceID != "new" || published.Phase != dockerapp.PhaseActive || published.RuleRef != "" {
			t.Fatalf("retry after readiness restore did not publish: %#v", published)
		}
	})
}

func testComposeYAML(image string) string {
	return "services:\n  web:\n    image: " + image + "\n"
}

func testApp(_ string) dockerapp.App {
	image := "registry/media:new"
	return dockerapp.App{ID: "media", Compose: testComposeYAML(image), Image: image, RuleRef: "rule-media", Generation: "generation-1", SecretRefs: []string{"registry-credential"}}
}

func configWire(t *testing.T, count int) []byte {
	t.Helper()
	apps := make([]dockerapp.App, count)
	for index := range apps {
		apps[index] = dockerapp.App{ID: fmt.Sprintf("app-%03d", index), Compose: testComposeYAML("image:new"), Generation: "generation-1"}
	}
	wire, err := json.Marshal(dockerapp.Configuration{Apps: apps})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func requiredGrants() []string {
	return []string{"http.rule", "ui.dynamic", "service.revocable-resource-handle", "storage.read", "storage.write"}
}

func handshake(grants []string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: dockerapp.PluginID, PluginVersion: dockerapp.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1"}
}

type rolloutFake struct {
	fail, secret                         string
	calls                                []string
	failRestore, failRemove, blockRemove bool
	state                                dockerapp.RuntimeState
	inspectStates                        []dockerapp.RuntimeState
	inspectErr                           error
	maxFence                             uint64
	mu                                   sync.Mutex
	inspectRefs, cutoverRefs             []string
}

func (fake *rolloutFake) acceptFence(fence uint64) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fence < fake.maxFence {
		return dockerapp.ErrStateConflict
	}
	if fence > fake.maxFence {
		fake.maxFence = fence
	}
	return nil
}
func (fake *rolloutFake) ensureState() {
	if fake.state.Instances == nil {
		fake.state = dockerapp.RuntimeState{RuleTarget: "old", Instances: map[string]bool{"old": true}}
	}
}

func (fake *rolloutFake) step(name string) error {
	fake.calls = append(fake.calls, name)
	phase := strings.Split(name, ":")[0]
	if fake.fail == phase {
		return &secretCause{message: fmt.Sprintf("%s %s", phase, fake.secret)}
	}
	return nil
}
func (fake *rolloutFake) Pull(_ context.Context, fence uint64, _ dockerapp.App) error {
	if err := fake.acceptFence(fence); err != nil {
		return err
	}
	return fake.step("pull")
}
func (fake *rolloutFake) Start(_ context.Context, fence uint64, _ dockerapp.App) (string, error) {
	if err := fake.acceptFence(fence); err != nil {
		return "", err
	}
	if err := fake.step("start"); err != nil {
		return "", err
	}
	fake.ensureState()
	fake.state.Instances["new"] = true
	fake.state.CandidateInstance = "new"
	return "new", nil
}
func (fake *rolloutFake) Ready(_ context.Context, fence uint64, _ dockerapp.App, _ string) error {
	if err := fake.acceptFence(fence); err != nil {
		return err
	}
	return fake.step("ready")
}
func (fake *rolloutFake) Cutover(_ context.Context, fence uint64, ruleRef string, target string) error {
	if err := fake.acceptFence(fence); err != nil {
		return err
	}
	if strings.TrimSpace(ruleRef) == "" {
		return nil
	}
	fake.calls = append(fake.calls, "cutover:"+target)
	fake.cutoverRefs = append(fake.cutoverRefs, ruleRef)
	if (target == "new" && fake.fail == "cutover") || (target == "old" && fake.failRestore) {
		return &secretCause{message: "cutover cleanup failed " + fake.secret}
	}
	fake.ensureState()
	fake.state.RuleTarget = target
	return nil
}
func (fake *rolloutFake) Drain(_ context.Context, fence uint64, _ dockerapp.App, target string) error {
	if err := fake.acceptFence(fence); err != nil {
		return err
	}
	return fake.step("drain:" + target)
}
func (fake *rolloutFake) Remove(ctx context.Context, fence uint64, _ dockerapp.App, target string) error {
	if err := fake.acceptFence(fence); err != nil {
		return err
	}
	fake.calls = append(fake.calls, "remove:"+target)
	if fake.blockRemove {
		<-ctx.Done()
		return ctx.Err()
	}
	if fake.failRemove {
		return &secretCause{message: "remove cleanup failed " + fake.secret}
	}
	fake.ensureState()
	delete(fake.state.Instances, target)
	if fake.state.CandidateInstance == target {
		fake.state.CandidateInstance = ""
	}
	return nil
}
func (fake *rolloutFake) Inspect(_ context.Context, fence uint64, _ dockerapp.App, ruleRef string) (dockerapp.RuntimeState, error) {
	if err := fake.acceptFence(fence); err != nil {
		return dockerapp.RuntimeState{}, err
	}
	fake.calls = append(fake.calls, "inspect")
	fake.inspectRefs = append(fake.inspectRefs, ruleRef)
	if fake.inspectErr != nil {
		return dockerapp.RuntimeState{}, fake.inspectErr
	}
	if len(fake.inspectStates) > 0 {
		state := fake.inspectStates[0]
		fake.inspectStates = fake.inspectStates[1:]
		fake.state = state
		return state, nil
	}
	fake.ensureState()
	return fake.state, nil
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

type faultStore struct {
	base                   *dockerapp.DeploymentStore
	failPhase, blockPhase  dockerapp.RolloutPhase
	failRemaining          int
	failAcquireBefore      int
	failAcquireAfter       int
	failRelease            bool
	releaseFailures        int
	sawIndependentRecovery bool
}

func (store *faultStore) Load(ctx context.Context, appID string) (dockerapp.DeploymentRecord, bool, error) {
	return store.base.Load(ctx, appID)
}
func (store *faultStore) AcquireLease(ctx context.Context, appID string, version uint64, value dockerapp.Deployment, until time.Time) (dockerapp.DeploymentRecord, error) {
	if store.failAcquireBefore > 0 {
		store.failAcquireBefore--
		return dockerapp.DeploymentRecord{}, dockerapp.ErrStateConflict
	}
	record, err := store.base.AcquireLease(ctx, appID, version, value, until)
	if err == nil && store.failAcquireAfter > 0 {
		store.failAcquireAfter--
		return dockerapp.DeploymentRecord{}, dockerapp.ErrStateConflict
	}
	return record, err
}
func (store *faultStore) CompareAndSwap(ctx context.Context, appID string, version, fence uint64, value dockerapp.Deployment) (dockerapp.DeploymentRecord, error) {
	recovery := value.Phase == dockerapp.PhaseCleanupPending || value.Phase == dockerapp.PhaseRouteReconcile
	if recovery && ctx.Err() == nil {
		store.sawIndependentRecovery = true
	}
	if store.blockPhase == value.Phase {
		<-ctx.Done()
		return dockerapp.DeploymentRecord{}, ctx.Err()
	}
	if store.failRelease && recovery && value.Lease == "" {
		store.releaseFailures++
		return dockerapp.DeploymentRecord{}, dockerapp.ErrStateConflict
	}
	if store.failPhase == value.Phase && store.failRemaining > 0 {
		store.failRemaining--
		return dockerapp.DeploymentRecord{}, dockerapp.ErrStateConflict
	}
	return store.base.CompareAndSwap(ctx, appID, version, fence, value)
}
func (store *faultStore) DeleteCAS(ctx context.Context, appID string, version, fence uint64) error {
	return store.base.DeleteCAS(ctx, appID, version, fence)
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
