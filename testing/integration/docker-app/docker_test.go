package dockerapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

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
	plan := dockerapp.ComposePlan{Project: "media", Services: []dockerapp.ComposeService{{
		Name: "web", Privileged: true, HostMounts: []string{"/host:/data"}, AddCapabilities: []string{"NET_ADMIN"}, Networks: []string{"front"}, Volumes: []string{"data"},
	}}, RuleImpacts: []string{"rule-media"}}
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil || len(preview.Items) != 6 {
		t.Fatalf("risk preview=%#v err=%v", preview, err)
	}
	if _, err := dockerapp.PreviewCompose(dockerapp.ComposePlan{Project: "media", Services: make([]dockerapp.ComposeService, dockerapp.MaxComposeServices+1)}); !errors.Is(err, dockerapp.ErrBoundExceeded) {
		t.Fatalf("compose service bound = %v", err)
	}
	calls := 0
	var audits []dockerapp.AuditRecord
	auditor := dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })
	executor := dockerapp.ComposeExecutorFunc(func(context.Context, dockerapp.ComposePlan) error { calls++; return nil })
	if err := dockerapp.ExecuteCompose(context.Background(), plan, dockerapp.Authorization{}, executor, auditor, nil); !errors.Is(err, dockerapp.ErrUnauthorized) || calls != 0 {
		t.Fatalf("unauthorized err=%v calls=%d", err, calls)
	}
	approved := map[dockerapp.RiskKind]bool{}
	for _, item := range preview.Items {
		approved[item.Kind] = true
	}
	secret := "registry-token-secret"
	failing := dockerapp.ComposeExecutorFunc(func(context.Context, dockerapp.ComposePlan) error {
		calls++
		return fmt.Errorf("pull denied for %s", secret)
	})
	if err := dockerapp.ExecuteCompose(context.Background(), plan, dockerapp.Authorization{Approved: approved}, failing, auditor, []string{secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("executor failure was ignored")
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

func TestDockerDeleteImpactPreviewSharedRefsAndCoreOwnership(t *testing.T) {
	preview, err := dockerapp.PreviewDelete("media", []dockerapp.ResourceImpact{
		{Kind: "container", ID: "instance", Owner: dockerapp.OwnerPlugin}, {Kind: "volume", ID: "shared", Owner: dockerapp.OwnerPlugin, Shared: true}, {Kind: "rule", ID: "rule", Owner: dockerapp.OwnerCore},
		{Kind: "network", ID: "private", Owner: dockerapp.OwnerPlugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := &deleteFake{}
	if err := dockerapp.ExecuteDelete(context.Background(), preview, false, fake, nil, nil); !errors.Is(err, dockerapp.ErrUnauthorized) || len(fake.calls) != 0 {
		t.Fatalf("unauthorized delete err=%v calls=%v", err, fake.calls)
	}
	if err := dockerapp.ExecuteDelete(context.Background(), preview, true, fake, nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fake.calls, ",") != "delete:instance,release:rule,delete:private" {
		t.Fatalf("cleanup ownership calls = %v", fake.calls)
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
	request := handshake([]string{"docker-compose", "http-rule"})
	if _, err := newController(nil).Handshake(context.Background(), handshake([]string{"docker-compose"})); err == nil {
		t.Fatal("missing grant was accepted")
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
	fail, secret string
	calls        []string
}

func (fake *rolloutFake) step(name string) error {
	fake.calls = append(fake.calls, name)
	phase := strings.Split(name, ":")[0]
	if fake.fail == phase {
		return fmt.Errorf("%s %s", phase, fake.secret)
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
	return fake.step("cutover:" + target)
}
func (fake *rolloutFake) Drain(_ context.Context, target string) error {
	return fake.step("drain:" + target)
}
func (fake *rolloutFake) Remove(_ context.Context, target string) error {
	fake.calls = append(fake.calls, "remove:"+target)
	return nil
}

type deleteFake struct{ calls []string }

func (fake *deleteFake) DeleteOwned(_ context.Context, impact dockerapp.ResourceImpact) error {
	fake.calls = append(fake.calls, "delete:"+impact.ID)
	return nil
}
func (fake *deleteFake) ReleaseCoreRef(_ context.Context, impact dockerapp.ResourceImpact) error {
	fake.calls = append(fake.calls, "release:"+impact.ID)
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
