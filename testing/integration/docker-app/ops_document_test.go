package dockerapp_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestOpsDocumentContainsOnlyZeroFoundationFields(t *testing.T) {
	app := testApp("ops-secret")
	app.Image = "registry/media:new@sha256:0123456789abcdef0123456789abcdef"
	documents := []dockerapp.OpsDocument{
		projectOpsDocument(t, app, true, false, dockerapp.Deployment{Phase: dockerapp.PhaseActive}, dockerapp.UpdatePolicy{}, ""),
		dockerapp.ProjectPluginOpsDocument(true),
	}
	for _, document := range documents {
		assertOpsDocumentShape(t, document)
	}
	if documents[0].Name != app.ID || documents[0].Version != "registry/media:new sha256:0123456789ab" {
		t.Fatalf("app document = %#v", documents[0])
	}
	if documents[1].Name != "Docker 应用" || documents[1].Version != dockerapp.PluginVersion {
		t.Fatalf("plugin document = %#v", documents[1])
	}
}

func TestOpsDocumentShowsFixedTagAndLatestWithDigest(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef"
	short := "sha256:0123456789ab"
	newer := "sha256:fedcba9876543210fedcba9876543210"
	for _, test := range []struct {
		name  string
		image string
		tag   string
	}{
		{name: "fixed-tag", image: "nginx:1.27", tag: "nginx:1.27"},
		{name: "latest", image: "nginx:latest", tag: "nginx:latest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := testApp("ops-secret")
			app.Image = test.image
			app.Compose = testComposeYAML(test.image)
			current := projectOpsDocument(t, app, true, false, dockerapp.Deployment{
				Phase: dockerapp.PhaseActive, ImageDigest: digest,
			}, dockerapp.UpdatePolicy{}, digest)
			if current.Version != test.tag+" "+short {
				t.Fatalf("current version = %q want %q", current.Version, test.tag+" "+short)
			}
			if current.Status != "运行中" || hasAction(current, dockerapp.OpsActionUpdate) {
				t.Fatalf("same digest should not offer update: %#v", current)
			}

			available := projectOpsDocument(t, app, true, false, dockerapp.Deployment{
				Phase: dockerapp.PhaseActive, ImageDigest: digest,
			}, dockerapp.UpdatePolicy{}, newer)
			if available.Version != test.tag+" "+short {
				t.Fatalf("available version = %q want current digest display", available.Version)
			}
			if available.Status != "有新版本" || !hasAction(available, dockerapp.OpsActionUpdate) {
				t.Fatalf("digest change should keep tag %q and offer update: %#v", test.tag, available)
			}
			if !strings.Contains(available.Version, "latest") && test.tag == "nginx:latest" {
				t.Fatalf("latest tag was hidden: %#v", available)
			}
		})
	}
}

func TestOpsDocumentProjectsPlainChineseStatusesWithoutInternalPhaseOrErrorCodes(t *testing.T) {
	app := testApp("ops-secret")
	for _, test := range []struct {
		name       string
		running    bool
		unhealthy  bool
		deployment dockerapp.Deployment
		policy     dockerapp.UpdatePolicy
		latest     string
		want       string
	}{
		{name: "running", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive}, want: "运行中"},
		{name: "stopped", deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive}, want: "已停止"},
		{name: "update-available", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive, ImageDigest: "sha256:current"}, policy: dockerapp.AutoUpdatePolicy(false), latest: "sha256:latest", want: "有新版本"},
		{name: "update-available-default", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive, ImageDigest: "sha256:current"}, latest: "sha256:latest", want: "有新版本"},
		{name: "same-digest", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive, ImageDigest: "sha256:current"}, latest: "sha256:current", want: "运行中"},
		{name: "publishing", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseCutover, LastFailure: "E_CUTOVER_FAILED"}, want: "发布中"},
		{name: "unhealthy", running: true, unhealthy: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseActive, LastFailure: dockerapp.ErrOperationFailed.Error()}, want: "异常"},
		{name: "cleanup-pending", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseCleanupPending, LastFailure: "E_CLEANUP_PENDING"}, want: "发布中"},
		{name: "route-reconcile", running: true, deployment: dockerapp.Deployment{Phase: dockerapp.PhaseRouteReconcile, LastFailure: "E_ROUTE_RECONCILE"}, want: "发布中"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := dockerapp.ProjectOpsStatus(test.running, test.unhealthy, test.deployment, test.policy, test.latest); got != test.want {
				t.Fatalf("projected status = %q want %q", got, test.want)
			}
			document := projectOpsDocument(t, app, test.running, test.unhealthy, test.deployment, test.policy, test.latest)
			if document.Status != test.want {
				t.Fatalf("status = %q want %q document=%#v", document.Status, test.want, document)
			}
			assertOpsDocumentHasNoInternalTerms(t, document, test.deployment.LastFailure, string(test.deployment.Phase))
		})
	}
}

func TestOpsDocumentOmitsEventsAndAuditFromDefaultView(t *testing.T) {
	app := testApp("ops-secret")
	audits := []dockerapp.AuditRecord{
		{Action: "app.stop", Outcome: "succeeded", Detail: "lifecycle audit trail"},
		{Action: "event.emit", Outcome: "recorded", Detail: "事件时间线"},
	}
	documents := []dockerapp.OpsDocument{
		dockerapp.ProjectOpsDocument(app, dockerapp.AppStatusRunning),
		dockerapp.ProjectPluginOpsDocument(true),
		dockerapp.ProjectOpsDocumentFromRuntime(app, true, false, dockerapp.Deployment{
			Phase: dockerapp.PhaseCleanupPending, LastFailure: audits[0].Detail,
			History: []dockerapp.DeploymentRevision{{InstanceID: "old", Image: "old-image"}},
		}, dockerapp.UpdatePolicy{}, ""),
	}
	for _, document := range documents {
		assertOpsDocumentShape(t, document)
		encoded := fmt.Sprint(document)
		payload, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		blob := encoded + string(payload)
		for _, forbidden := range []string{
			"事件", "审计", "audit", "Audit", "event.emit", "lifecycle audit trail", "事件时间线",
			audits[0].Action, audits[0].Detail, audits[1].Action, audits[1].Detail,
		} {
			if strings.Contains(blob, forbidden) {
				t.Fatalf("default document leaked %q: %s", forbidden, payload)
			}
		}
		decoded := jsonObject(t, payload)
		for _, key := range []string{"events", "event", "audit", "audits"} {
			if _, ok := decoded[key]; ok {
				t.Fatalf("default document included %q: %s", key, payload)
			}
		}
	}
}

func projectOpsDocument(t *testing.T, app dockerapp.App, running, unhealthy bool, deployment dockerapp.Deployment, policy dockerapp.UpdatePolicy, latest string) dockerapp.OpsDocument {
	t.Helper()
	document := dockerapp.ProjectOpsDocumentFromRuntime(app, running, unhealthy, deployment, policy, latest)
	assertOpsDocumentShape(t, document)
	return document
}

func assertOpsDocumentShape(t *testing.T, document dockerapp.OpsDocument) {
	t.Helper()
	if document.Name == "" || document.Status == "" || document.Version == "" || document.ConfigEntry == "" || document.Usage == "" || len(document.Actions) == 0 {
		t.Fatalf("document = %#v", document)
	}
	if !hasHan(document.ConfigEntry) || !hasHan(document.Usage) || !hasHan(fmt.Sprint(document.Actions)) {
		t.Fatalf("document is not popular Chinese: %#v", document)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded := jsonObject(t, payload)
	allowed := map[string]struct{}{}
	for _, key := range dockerapp.DefaultOpsFields() {
		allowed[key] = struct{}{}
	}
	for _, key := range []string{"name", "status", "version", "config_entry", "usage", "actions"} {
		allowed[key] = struct{}{}
		if !hasJSONKey(decoded, key) {
			t.Fatalf("missing %s in %s", key, payload)
		}
	}
	for key := range decoded {
		if _, ok := allowed[key]; !ok {
			t.Fatalf("unexpected field %q in %s", key, payload)
		}
	}
}

func assertOpsDocumentHasNoInternalTerms(t *testing.T, document dockerapp.OpsDocument, extras ...string) {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	blob := fmt.Sprint(document) + string(payload)
	forbidden := []string{
		string(dockerapp.AppStatusRunning),
		string(dockerapp.AppStatusStopped),
		string(dockerapp.AppStatusUpdateAvailable),
		string(dockerapp.AppStatusPublishing),
		string(dockerapp.AppStatusUnhealthy),
		string(dockerapp.PhasePulling),
		string(dockerapp.PhaseStarting),
		string(dockerapp.PhaseReadiness),
		string(dockerapp.PhaseCutover),
		string(dockerapp.PhaseDraining),
		string(dockerapp.PhaseCleanupPending),
		string(dockerapp.PhaseRouteReconcile),
		dockerapp.ErrOperationFailed.Error(),
		dockerapp.ErrUnauthorized.Error(),
		dockerapp.ErrBoundExceeded.Error(),
		"E_CUTOVER_FAILED",
		"LastFailure",
		"sha256:0123456789abcdef0123456789abcdef",
	}
	forbidden = append(forbidden, extras...)
	for _, term := range forbidden {
		if term == "" || term == string(dockerapp.PhaseActive) {
			continue
		}
		if strings.Contains(blob, term) {
			t.Fatalf("document leaked internal term %q: %s", term, payload)
		}
	}
}

func hasJSONKey(values map[string]any, want string) bool {
	normalizedWant := strings.ReplaceAll(strings.ToLower(want), "_", "")
	for key := range values {
		if strings.ReplaceAll(strings.ToLower(key), "_", "") == normalizedWant {
			return true
		}
	}
	return false
}

func jsonObject(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func hasHan(value string) bool {
	for _, current := range value {
		if unicode.Is(unicode.Han, current) {
			return true
		}
	}
	return false
}

func hasAction(document dockerapp.OpsDocument, id string) bool {
	for _, action := range document.Actions {
		if action.ID == id {
			return true
		}
	}
	return false
}
