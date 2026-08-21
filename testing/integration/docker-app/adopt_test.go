package dockerapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

const adoptSecret = "Registry/token-secret"

func TestComposeAdoptPreviewAuthorizationBecomesManagedWithRuntimeStatus(t *testing.T) {
	document := `name: media
services:
  web:
    image: nginx:latest
    privileged: true
    cap_add:
      - NET_ADMIN
    volumes:
      - /host:/data
      - data:/var/lib/data
    networks:
      - front
    environment:
      REGISTRY_TOKEN: ` + adoptSecret + `
`
	plan, app, err := dockerapp.ParseComposeDocument(document, "media", "generation-1", "rule-media")
	if err != nil {
		t.Fatal(err)
	}
	assertAdoptedApp(t, app, "media", "nginx:latest", "REGISTRY_TOKEN")
	assertAdoptPlan(t, plan, "media", dockerapp.ComposeService{
		Name: "web", Privileged: true, HostMounts: []string{"/host:/data"}, AddCapabilities: []string{"NET_ADMIN"}, Networks: []string{"front"}, Volumes: []string{"data"},
	})
	assertNoSecretMaterial(t, adoptSecret, plan, app)

	if view := projectCatalog(t, nil, nil, nil); len(view.Managed) != 0 {
		t.Fatalf("unapplied compose already managed: %#v", view)
	}
	if _, apps := applyUnauthorizedCompose(t, plan); len(apps) != 0 {
		t.Fatalf("unauthorized compose registered apps=%#v", apps)
	}

	apps := applyAuthorizedCompose(t, plan, app)
	observations, runtimes := labeledRunning("ctr-media", app.ID, 8080)
	view := projectCatalog(t, observations, runtimes, apps)
	assertRunningManaged(t, view, app)
	assertNoSecretMaterial(t, adoptSecret, view)
}

func TestDockerRunPreviewAuthorizationBecomesManagedWithRuntimeStatus(t *testing.T) {
	command := "docker run -d --name media --privileged --cap-add NET_ADMIN -v /host:/data -v data:/var/lib/data --network front -e REGISTRY_TOKEN=" + adoptSecret + " nginx:latest"
	plan, app, err := dockerapp.ParseDockerRun(command, "generation-1", "rule-media")
	if err != nil {
		t.Fatal(err)
	}
	assertAdoptedApp(t, app, "media", "nginx:latest", "REGISTRY_TOKEN")
	assertAdoptPlan(t, plan, "media", dockerapp.ComposeService{
		Name: "media", Privileged: true, HostMounts: []string{"/host:/data"}, AddCapabilities: []string{"NET_ADMIN"}, Networks: []string{"front"}, Volumes: []string{"data"},
	})
	assertNoSecretMaterial(t, adoptSecret, plan, app)

	if view := projectCatalog(t, nil, nil, nil); len(view.Managed) != 0 {
		t.Fatalf("unapplied docker run already managed: %#v", view)
	}
	if _, apps := applyUnauthorizedCompose(t, plan); len(apps) != 0 {
		t.Fatalf("unauthorized docker run registered apps=%#v", apps)
	}
	apps := applyAuthorizedCompose(t, plan, app)
	observations, runtimes := labeledRunning("ctr-media", app.ID, 8080)
	view := projectCatalog(t, observations, runtimes, apps)
	assertRunningManaged(t, view, app)
	assertNoSecretMaterial(t, adoptSecret, view)
}

func TestDockerAdoptCandidateStaysOutOfManagedUntilExplicitAdoptThenStopDelete(t *testing.T) {
	observation := dockerapp.ContainerObservation{ID: "ctr-open", ExposedPorts: []uint16{9000}}
	discoveries, err := dockerapp.Discover([]dockerapp.ContainerObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if len(discoveries) != 1 || !discoveries[0].Candidate || discoveries[0].AppID != "" {
		t.Fatalf("discoveries = %#v", discoveries)
	}
	view := projectCatalog(t, []dockerapp.ContainerObservation{observation}, []dockerapp.RuntimeObservation{{ContainerID: observation.ID, Running: true}}, nil)
	if len(view.Managed) != 0 || len(view.Candidates) != 1 || !view.Candidates[0].Candidate || view.Candidates[0].ContainerID != observation.ID {
		t.Fatalf("implicit candidate catalog = %#v", view)
	}

	app := dockerapp.App{ID: "imported", Image: "nginx:latest", RuleRef: "rule-imported", Generation: "generation-1"}
	if _, err := dockerapp.AdoptCandidate([]dockerapp.ContainerObservation{{ID: "hidden"}}, nil, observation.ID, app); !errors.Is(err, dockerapp.ErrNotCandidate) {
		t.Fatalf("adopted a container that is not a candidate: %v", err)
	}
	if _, err := dockerapp.AdoptCandidate([]dockerapp.ContainerObservation{observation}, nil, "missing", app); !errors.Is(err, dockerapp.ErrNotCandidate) {
		t.Fatalf("adopted a missing container: %v", err)
	}
	already := dockerapp.LabelObservation(observation, "already")
	if _, err := dockerapp.AdoptCandidate([]dockerapp.ContainerObservation{already}, nil, observation.ID, app); !errors.Is(err, dockerapp.ErrNotCandidate) {
		t.Fatalf("adopted an already labeled container: %v", err)
	}

	apps, err := dockerapp.AdoptCandidate([]dockerapp.ContainerObservation{observation}, nil, observation.ID, app)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].ID != app.ID {
		t.Fatalf("adopted apps = %#v", apps)
	}
	labeled := dockerapp.LabelObservation(observation, app.ID)
	view = projectCatalog(t, []dockerapp.ContainerObservation{labeled}, []dockerapp.RuntimeObservation{{ContainerID: labeled.ID, Running: true}}, apps)
	assertRunningManaged(t, view, app)
	if len(view.Candidates) != 0 {
		t.Fatalf("adopted candidate remained in candidate list: %#v", view.Candidates)
	}

	var audits []dockerapp.AuditRecord
	auditor := dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })
	var stopped []string
	if err := dockerapp.StopManaged(context.Background(), app, nil, auditor); !errors.Is(err, dockerapp.ErrTypedHandlesUnavailable) {
		t.Fatalf("missing stop executor err=%v", err)
	}
	if err := dockerapp.StopManaged(context.Background(), app, dockerapp.StopExecutorFunc(func(_ context.Context, appID string) error {
		stopped = append(stopped, appID)
		return nil
	}), nil); !errors.Is(err, dockerapp.ErrAuditRequired) || len(stopped) != 0 {
		t.Fatalf("missing stop auditor err=%v calls=%v", err, stopped)
	}
	if err := dockerapp.StopManaged(context.Background(), app, dockerapp.StopExecutorFunc(func(_ context.Context, appID string) error {
		stopped = append(stopped, appID)
		return nil
	}), auditor); err != nil || len(stopped) != 1 || stopped[0] != app.ID {
		t.Fatalf("stop err=%v calls=%v", err, stopped)
	}
	view = projectCatalog(t, []dockerapp.ContainerObservation{labeled}, []dockerapp.RuntimeObservation{{ContainerID: labeled.ID, Running: false}}, apps)
	if len(view.Managed) != 1 || view.Managed[0].Running || view.Managed[0].Status != dockerapp.AppStatusStopped {
		t.Fatalf("stopped catalog = %#v", view)
	}

	impacts := []dockerapp.ResourceImpact{{Kind: "container", ID: labeled.ID, Owner: dockerapp.OwnerPlugin}}
	preview, err := dockerapp.PreviewDelete(app.ID, app.Generation, impacts)
	if err != nil {
		t.Fatal(err)
	}
	authorization := dockerapp.Authorization{Token: "approved", AppID: app.ID, Generation: app.Generation, PreviewDigest: preview.Digest}
	inventory := dockerapp.DeleteInventoryFunc(func(context.Context, string, string) ([]dockerapp.ResourceImpact, error) { return impacts, nil })
	verifier := dockerapp.AuthorizationVerifierFunc(func(_ context.Context, got dockerapp.Authorization, appID, generation, digest string) error {
		if got.Token != "approved" || got.AppID != appID || got.Generation != generation || got.PreviewDigest != digest {
			return errors.New("authorization rejected")
		}
		return nil
	})
	fake := &deleteFake{}
	if err := dockerapp.ExecuteDelete(context.Background(), preview, authorization, inventory, verifier, fake, dockerapp.NewOperationJournal(), auditor); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fake.calls, ",") != "delete:"+labeled.ID {
		t.Fatalf("delete calls = %v", fake.calls)
	}
	apps = dockerapp.RemoveManaged(apps, app.ID)
	view = projectCatalog(t, []dockerapp.ContainerObservation{observation}, nil, apps)
	if len(view.Managed) != 0 || len(apps) != 0 {
		t.Fatalf("deleted app remained managed: apps=%#v catalog=%#v", apps, view)
	}
}

func TestDockerAdoptAndDockerRunKeepSecretRefsAndRedactUnsafeErrors(t *testing.T) {
	material := []byte(adoptSecret)
	refs, err := dockerapp.BindSecretRefs([]dockerapp.TransientCredential{{Name: "REGISTRY_TOKEN", Material: material}})
	if err != nil || len(refs) != 1 || refs[0] != "REGISTRY_TOKEN" {
		t.Fatalf("bound refs=%v err=%v", refs, err)
	}
	if string(material) == adoptSecret {
		t.Fatal("BindSecretRefs left credential material intact")
	}

	bound, err := dockerapp.AppWithBoundSecrets(dockerapp.App{ID: "media", Image: "nginx:latest", RuleRef: "rule-media", Generation: "generation-1"}, []dockerapp.TransientCredential{{Name: "REGISTRY_TOKEN", Material: []byte(adoptSecret)}})
	if err != nil {
		t.Fatal(err)
	}
	assertAdoptedApp(t, bound, "media", "nginx:latest", "REGISTRY_TOKEN")
	assertNoSecretMaterial(t, adoptSecret, bound)

	invalid, err := dockerapp.AppWithBoundSecrets(dockerapp.App{ID: "Bad_Name", Image: "nginx:latest", RuleRef: "rule-media", Generation: "generation-1"}, []dockerapp.TransientCredential{{Name: "REGISTRY_TOKEN", Material: []byte(adoptSecret)}})
	var raw *secretCause
	if err == nil || !errors.Is(err, dockerapp.ErrInvalidPreview) || strings.Contains(err.Error(), adoptSecret) || errors.As(err, &raw) || strings.Contains(fmt.Sprint(invalid), adoptSecret) {
		t.Fatalf("invalid app leaked secret: app=%#v err=%v", invalid, err)
	}

	command := "docker run --name media --env REGISTRY_TOKEN=" + adoptSecret + " nginx:latest"
	plan, app, err := dockerapp.ParseDockerRun(command, "generation-1", "rule-media")
	if err != nil {
		t.Fatal(err)
	}
	assertAdoptedApp(t, app, "media", "nginx:latest", "REGISTRY_TOKEN")
	assertNoSecretMaterial(t, adoptSecret, plan, app)

	document := "name: media\nservices:\n  web:\n    image: nginx:latest\n    environment:\n      REGISTRY_TOKEN: " + adoptSecret + "\n"
	composePlan, composeApp, err := dockerapp.ParseComposeDocument(document, "media", "generation-1", "rule-media")
	if err != nil {
		t.Fatal(err)
	}
	assertAdoptedApp(t, composeApp, "media", "nginx:latest", "REGISTRY_TOKEN")
	assertNoSecretMaterial(t, adoptSecret, composePlan, composeApp)

	if _, _, err := dockerapp.ParseDockerRun("docker run --name Bad_Name -e REGISTRY_TOKEN="+adoptSecret+" nginx:latest", "generation-1", "rule-media"); err == nil || strings.Contains(err.Error(), adoptSecret) {
		t.Fatalf("invalid docker run leaked or accepted: %v", err)
	}
	if _, _, err := dockerapp.ParseComposeDocument("name: media\nservices:\n  web:\n    image: nginx:latest\n    environment:\n      REGISTRY_TOKEN: "+adoptSecret+"\n", "Bad_Name", "generation-1", "rule-media"); err == nil || strings.Contains(err.Error(), adoptSecret) {
		t.Fatalf("invalid compose leaked or accepted: %v", err)
	}

	var audits []dockerapp.AuditRecord
	auditor := dockerapp.AuditorFunc(func(record dockerapp.AuditRecord) { audits = append(audits, record) })
	err = dockerapp.StopManaged(context.Background(), app, dockerapp.StopExecutorFunc(func(context.Context, string) error {
		return &secretCause{message: "stop denied for " + adoptSecret}
	}), auditor)
	raw = nil
	if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) || errors.As(err, &raw) || errors.Unwrap(err) != dockerapp.ErrOperationFailed || strings.Contains(err.Error(), adoptSecret) {
		t.Fatalf("unsafe stop error err=%v raw=%v unwrap=%v", err, raw, errors.Unwrap(err))
	}
	if strings.Contains(fmt.Sprint(audits), adoptSecret) {
		t.Fatalf("stop audit leaked secret: %v", audits)
	}

	wire, err := json.Marshal(dockerapp.Configuration{Apps: []dockerapp.App{composeApp}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), adoptSecret) || !strings.Contains(string(wire), "secret_refs") || !strings.Contains(string(wire), "REGISTRY_TOKEN") {
		t.Fatalf("configuration wire = %s", wire)
	}
	if _, err := dockerapp.ParseConfiguration(wire); err != nil {
		t.Fatal(err)
	}
}

func assertAdoptedApp(t *testing.T, app dockerapp.App, id, image, secretRef string) {
	t.Helper()
	if app.ID != id || app.Image != image || app.Generation != "generation-1" || (app.RuleRef != "rule-media" && app.RuleRef != "rule-imported") {
		t.Fatalf("app = %#v", app)
	}
	if len(app.SecretRefs) != 1 || app.SecretRefs[0] != secretRef {
		t.Fatalf("secret refs = %#v want %q", app.SecretRefs, secretRef)
	}
}

func assertAdoptPlan(t *testing.T, plan dockerapp.ComposePlan, appID string, want dockerapp.ComposeService) {
	t.Helper()
	if plan.AppID != appID || plan.Generation != "generation-1" || plan.Project != appID || len(plan.Services) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	got := plan.Services[0]
	if got.Name != want.Name || got.Privileged != want.Privileged || !stringSetEqual(got.HostMounts, want.HostMounts) || !stringSetEqual(got.AddCapabilities, want.AddCapabilities) || !stringSetEqual(got.Networks, want.Networks) || !stringSetEqual(got.Volumes, want.Volumes) {
		t.Fatalf("service = %#v want %#v", got, want)
	}
}

func assertRunningManaged(t *testing.T, view dockerapp.CatalogView, app dockerapp.App) {
	t.Helper()
	if len(view.Managed) != 1 || view.Managed[0].App.ID != app.ID || !view.Managed[0].Running || view.Managed[0].Status != dockerapp.AppStatusRunning {
		t.Fatalf("managed catalog = %#v", view)
	}
	if len(view.Managed[0].App.SecretRefs) != len(app.SecretRefs) {
		t.Fatalf("managed secret refs = %#v", view.Managed[0].App.SecretRefs)
	}
}

func assertNoSecretMaterial(t *testing.T, secret string, values ...any) {
	t.Helper()
	encoded := fmt.Sprint(values...)
	wire, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, secret) || strings.Contains(string(wire), secret) {
		t.Fatalf("secret material retained: %s", wire)
	}
}

func applyUnauthorizedCompose(t *testing.T, plan dockerapp.ComposePlan) (dockerapp.RiskPreview, []dockerapp.App) {
	t.Helper()
	preview, verifier, inventory := composeGate(t, plan)
	bad := dockerapp.Authorization{Token: "forged", AppID: plan.AppID, Generation: plan.Generation, PreviewDigest: preview.Digest}
	if err := dockerapp.ExecuteCompose(context.Background(), preview, bad, inventory, verifier, dockerapp.ComposeExecutorFunc(func(context.Context, string, dockerapp.ComposePlan) error {
		t.Fatal("unauthorized compose executed")
		return nil
	}), dockerapp.NewOperationJournal(), dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); !errors.Is(err, dockerapp.ErrUnauthorized) {
		t.Fatalf("unauthorized compose err=%v", err)
	}
	return preview, nil
}

func applyAuthorizedCompose(t *testing.T, plan dockerapp.ComposePlan, app dockerapp.App) []dockerapp.App {
	t.Helper()
	preview, verifier, inventory := composeGate(t, plan)
	authorization := dockerapp.Authorization{Token: "approved", AppID: plan.AppID, Generation: plan.Generation, PreviewDigest: preview.Digest}
	if err := dockerapp.ExecuteCompose(context.Background(), preview, authorization, inventory, verifier, dockerapp.ComposeExecutorFunc(func(context.Context, string, dockerapp.ComposePlan) error {
		return nil
	}), dockerapp.NewOperationJournal(), dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})); err != nil {
		t.Fatal(err)
	}
	apps, err := dockerapp.RegisterManaged(nil, app)
	if err != nil {
		t.Fatal(err)
	}
	return apps
}

func composeGate(t *testing.T, plan dockerapp.ComposePlan) (dockerapp.RiskPreview, dockerapp.AuthorizationVerifier, dockerapp.ComposeInventory) {
	t.Helper()
	preview, err := dockerapp.PreviewCompose(plan)
	if err != nil {
		t.Fatal(err)
	}
	inventory := dockerapp.ComposeInventoryFunc(func(context.Context, string, string) (dockerapp.ComposePlan, error) { return plan, nil })
	verifier := dockerapp.AuthorizationVerifierFunc(func(_ context.Context, got dockerapp.Authorization, appID, generation, digest string) error {
		if got.Token != "approved" {
			return &secretCause{message: "bad token " + adoptSecret}
		}
		if got.AppID != appID || got.Generation != generation || got.PreviewDigest != digest {
			return errors.New("binding mismatch")
		}
		return nil
	})
	return preview, verifier, inventory
}

func projectCatalog(t *testing.T, observations []dockerapp.ContainerObservation, runtimes []dockerapp.RuntimeObservation, apps []dockerapp.App) dockerapp.CatalogView {
	t.Helper()
	view, err := dockerapp.ProjectCatalog(observations, runtimes, apps)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range view.Managed {
		if item.App.ID == "" || item.Status == "" {
			t.Fatalf("managed item missing identity or status: %#v", item)
		}
	}
	return view
}

func labeledRunning(containerID, appID string, port uint16) ([]dockerapp.ContainerObservation, []dockerapp.RuntimeObservation) {
	observation := dockerapp.ContainerObservation{ID: containerID, Labels: map[string]string{dockerapp.AppLabel: appID}, ExposedPorts: []uint16{port}}
	return []dockerapp.ContainerObservation{observation}, []dockerapp.RuntimeObservation{{ContainerID: containerID, Running: true}}
}

func stringSetEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, value := range want {
		seen[value]++
	}
	for _, value := range got {
		seen[value]--
		if seen[value] < 0 {
			return false
		}
	}
	return true
}
