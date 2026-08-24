package dockerapp_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestHTTPOfferHTTPManagedAppsAppearInBackendProviderList(t *testing.T) {
	httpApp := dockerapp.App{ID: "media", Image: "nginx:latest", RuleRef: "rule-media", Generation: "generation-1"}
	worker := dockerapp.App{ID: "worker", Image: "batch:latest", RuleRef: "rule-worker", Generation: "generation-1"}
	observations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: httpApp.ID}, ExposedPorts: []uint16{8080}},
		{ID: "ctr-worker", Labels: map[string]string{dockerapp.AppLabel: worker.ID}},
		{ID: "ctr-candidate", ExposedPorts: []uint16{9000}},
	}

	offers, err := dockerapp.ProjectHTTPOffers([]dockerapp.App{httpApp, worker}, observations, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 || offers[0].AppID != httpApp.ID || offers[0].ProviderID != httpApp.ID || offers[0].RuleRef != httpApp.RuleRef {
		t.Fatalf("offers = %#v", offers)
	}
	if len(offers[0].Ports) != 1 || offers[0].Ports[0] != 8080 {
		t.Fatalf("offer ports = %#v", offers[0].Ports)
	}
}

func TestHTTPOfferNonHTTPAppsAndMissingGrantStayOffProviderList(t *testing.T) {
	httpApp := dockerapp.App{ID: "media", Image: "nginx:latest", RuleRef: "rule-media", Generation: "generation-1"}
	worker := dockerapp.App{ID: "worker", Image: "batch:latest", RuleRef: "rule-worker", Generation: "generation-1"}
	observations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: httpApp.ID}, ExposedPorts: []uint16{8080}},
		{ID: "ctr-worker", Labels: map[string]string{dockerapp.AppLabel: worker.ID}},
	}

	ungranted, err := dockerapp.ProjectHTTPOffers([]dockerapp.App{httpApp, worker}, observations, false)
	if err != nil || len(ungranted) != 0 {
		t.Fatalf("ungranted offers = %#v err=%v", ungranted, err)
	}

	onlyWorker, err := dockerapp.ProjectHTTPOffers([]dockerapp.App{worker}, observations, true)
	if err != nil || len(onlyWorker) != 0 {
		t.Fatalf("non-HTTP offers = %#v err=%v", onlyWorker, err)
	}
}

func TestHTTPOfferCutoverSwitchesRuleTargetAfterReady(t *testing.T) {
	store, fake, rollout, app, old := updateHarness(t, "")
	if err := rollout.Update(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(app.ID)
	if got.InstanceID != "new" || got.RuleTarget != "new" || got.RuleRef != app.RuleRef || got.Phase != dockerapp.PhaseActive {
		t.Fatalf("cutover got=%#v", got)
	}
	if strings.Join(fake.calls, ",") != "pull,start,ready,cutover:new,drain:old" {
		t.Fatalf("cutover calls=%v", fake.calls)
	}
	if !contains(fake.cutoverRefs, app.RuleRef) {
		t.Fatalf("cutover skipped http.rule ref %q: %v", app.RuleRef, fake.cutoverRefs)
	}

	observations := []dockerapp.ContainerObservation{
		{ID: got.InstanceID, Labels: map[string]string{dockerapp.AppLabel: app.ID}, ExposedPorts: []uint16{8080}},
	}
	offers, err := dockerapp.ProjectHTTPOffers([]dockerapp.App{app}, observations, true)
	if err != nil || len(offers) != 1 || offers[0].ProviderID != app.ID || offers[0].RuleRef != app.RuleRef {
		t.Fatalf("post-cutover offers=%#v err=%v", offers, err)
	}
	if got.RuleTarget == old.RuleTarget {
		t.Fatalf("rule target did not switch: %#v", got)
	}
}

func TestHTTPOfferCutoverFailureKeepsOldRuleTarget(t *testing.T) {
	for _, fail := range []string{"ready", "cutover"} {
		t.Run(fail, func(t *testing.T) {
			store, fake, rollout, app, old := updateHarness(t, fail)
			err := rollout.Update(context.Background(), app)
			got, _ := store.Get(app.ID)
			if err == nil || !errors.Is(err, dockerapp.ErrOperationFailed) {
				t.Fatalf("%s err=%v", fail, err)
			}
			if got.InstanceID != old.InstanceID || got.RuleTarget != old.RuleTarget || got.RuleRef != old.RuleRef {
				t.Fatalf("%s dropped old target: %#v", fail, got)
			}
			if fail == "ready" && contains(fake.calls, "cutover:new") {
				t.Fatalf("ready failure still cut over: %v", fake.calls)
			}
			if fail == "cutover" && got.RuleTarget != old.RuleTarget {
				t.Fatalf("cutover failure switched target: %#v", got)
			}

			observations := []dockerapp.ContainerObservation{
				{ID: old.InstanceID, Labels: map[string]string{dockerapp.AppLabel: app.ID}, ExposedPorts: []uint16{8080}},
			}
			offers, offerErr := dockerapp.ProjectHTTPOffers([]dockerapp.App{app}, observations, true)
			if offerErr != nil || len(offers) != 1 || offers[0].ProviderID != app.ID {
				t.Fatalf("%s offers=%#v err=%v", fail, offers, offerErr)
			}
		})
	}
}

func TestHTTPRuleCreatedFromPublishedPortAndDomain(t *testing.T) {
	app := dockerapp.App{
		ID: "media", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n      - \"127.0.0.1:9090:90\"\n      - target: 443\n        published: 8443\n",
	}
	observations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: app.ID}, ExposedPorts: []uint16{8080, 8443, 9090}},
	}
	view := projectCatalog(t, observations, []dockerapp.RuntimeObservation{{ContainerID: "ctr-media", Running: true}}, []dockerapp.App{app})
	if len(view.Managed) != 1 || !portsEqual(view.Managed[0].PublishedPorts, []uint16{8080, 8443, 9090}) {
		t.Fatalf("catalog published ports = %#v", view.Managed[0].PublishedPorts)
	}

	ingress, err := dockerapp.ProjectAppHTTPIngress(app, observations)
	if err != nil || ingress.AppID != app.ID || !ingress.CanCreate || !portsEqual(ingress.PublishedPorts, []uint16{8080, 8443, 9090}) {
		t.Fatalf("ingress = %#v err=%v", ingress, err)
	}
	composeOnly, err := dockerapp.ProjectAppHTTPIngress(app, nil)
	if err != nil || !composeOnly.CanCreate || !portsEqual(composeOnly.PublishedPorts, []uint16{8080, 8443, 9090}) {
		t.Fatalf("compose-declared ports = %#v err=%v", composeOnly, err)
	}

	store := &recordingHostHTTPRules{}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})

	rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), store, store, app, observations, "https://app.example.com", 8080, auditor)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.specs) != 1 || store.specs[0].AppID != app.ID || store.specs[0].AgentID != app.AgentID || store.specs[0].Domain != "https://app.example.com" || store.specs[0].Port != 8080 {
		t.Fatalf("create spec = %#v", store.specs)
	}
	if len(rules) != 1 {
		t.Fatalf("host rules = %#v", rules)
	}
	created := rules[0]
	if created.Ref != "rule-media-8080" || created.Domain != "https://app.example.com" || created.Port != 8080 || created.AppID != app.ID || created.AgentID != app.AgentID {
		t.Fatalf("created rule = %#v", created)
	}
	if created.Backend != "http://127.0.0.1:8080" || !strings.Contains(created.Backend, "8080") {
		t.Fatalf("backend does not point at Agent published port: %#v", created)
	}

	containerOnly := dockerapp.App{
		ID: "sidecar", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"80\"\n",
	}
	runtimeHost := []dockerapp.ContainerObservation{
		{ID: "ctr-sidecar", Labels: map[string]string{dockerapp.AppLabel: containerOnly.ID}, ExposedPorts: []uint16{32768}},
	}
	store.specs = nil
	rules, err = dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), store, store, containerOnly, runtimeHost, "sidecar.example.com", 32768, auditor)
	if err != nil || len(store.specs) != 1 || store.specs[0].Port != 32768 || store.specs[0].Domain != "http://sidecar.example.com" {
		t.Fatalf("runtime host create spec=%#v rules=%#v err=%v", store.specs, rules, err)
	}
	sidecar := rules[len(rules)-1]
	if sidecar.Backend != "http://127.0.0.1:32768" || sidecar.AgentID != containerOnly.AgentID || sidecar.Port != 32768 {
		t.Fatalf("runtime backend = %#v", sidecar)
	}
}

func TestHTTPRuleDeletedFromPublishedPortAndDomain(t *testing.T) {
	app := dockerapp.App{
		ID: "media", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n",
	}
	observations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: app.ID}, ExposedPorts: []uint16{8080}},
	}
	store := &recordingHostHTTPRules{}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), store, store, app, observations, "https://app.example.com", 8080, auditor)
	if err != nil || len(rules) != 1 || rules[0].Ref == "" {
		t.Fatalf("create rules=%#v err=%v", rules, err)
	}
	ref := rules[0].Ref

	deleted, err := dockerapp.DeleteHTTPRule(context.Background(), store, store, app, observations, ref, auditor)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.deletes) != 1 || store.deletes[0] != (recordedHTTPRuleDelete{AgentID: app.AgentID, RuleRef: ref}) {
		t.Fatalf("host deletes=%#v", store.deletes)
	}
	if len(deleted) != 0 || len(store.rules) != 0 {
		t.Fatalf("host list still has rule deleted=%#v store=%#v", deleted, store.rules)
	}

	snapshot := append([]dockerapp.HostHTTPRule(nil), store.rules...)
	again, err := dockerapp.DeleteHTTPRule(context.Background(), store, store, app, observations, ref, auditor)
	if !errors.Is(err, dockerapp.ErrUnknownHTTPRule) || len(store.deletes) != 1 || len(again) != 0 {
		t.Fatalf("second delete err=%v deletes=%#v rules=%#v", err, store.deletes, again)
	}
	if len(store.rules) != len(snapshot) {
		t.Fatalf("unknown delete mutated rules: %#v", store.rules)
	}
}

func TestHTTPRuleNotCreatedWithoutPublishedPortOrDomain(t *testing.T) {
	httpApp := dockerapp.App{
		ID: "media", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n",
	}
	worker := dockerapp.App{
		ID: "worker", AgentID: "agent-1", Image: "batch:latest", Generation: "generation-1",
		Compose: "services:\n  job:\n    image: batch:latest\n",
	}
	containerOnly := dockerapp.App{
		ID: "sidecar", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"80\"\n      - 443\n      - \":8080\"\n      - \"80/tcp\"\n      - target: 9000\n",
	}
	httpObservations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: httpApp.ID}, ExposedPorts: []uint16{8080}},
	}
	workerObservations := []dockerapp.ContainerObservation{
		{ID: "ctr-worker", Labels: map[string]string{dockerapp.AppLabel: worker.ID}},
	}
	store := &recordingHostHTTPRules{rules: []dockerapp.HostHTTPRule{{
		Ref: "rule-kept", Domain: "http://kept.example.com", Port: 9000, Backend: "http://127.0.0.1:9000", AgentID: "agent-1", Enabled: true,
	}}}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})

	workerIngress, err := dockerapp.ProjectAppHTTPIngress(worker, workerObservations)
	if err != nil || workerIngress.CanCreate || len(workerIngress.PublishedPorts) != 0 {
		t.Fatalf("worker ingress = %#v err=%v", workerIngress, err)
	}
	containerOnlyIngress, err := dockerapp.ProjectAppHTTPIngress(containerOnly, nil)
	if err != nil || containerOnlyIngress.CanCreate || len(containerOnlyIngress.PublishedPorts) != 0 {
		t.Fatalf("container-only compose ports = %#v err=%v", containerOnlyIngress, err)
	}
	observedHost := []dockerapp.ContainerObservation{
		{ID: "ctr-sidecar", Labels: map[string]string{dockerapp.AppLabel: containerOnly.ID}, ExposedPorts: []uint16{32768}},
	}
	observedIngress, err := dockerapp.ProjectAppHTTPIngress(containerOnly, observedHost)
	if err != nil || !observedIngress.CanCreate || !portsEqual(observedIngress.PublishedPorts, []uint16{32768}) {
		t.Fatalf("runtime host port = %#v err=%v", observedIngress, err)
	}

	for _, test := range []struct {
		name         string
		app          dockerapp.App
		observations []dockerapp.ContainerObservation
		domain       string
		port         uint16
		want         error
		nilHandle    bool
		nilAuditor   bool
	}{
		{name: "empty-domain", app: httpApp, observations: httpObservations, domain: "", port: 8080, want: dockerapp.ErrEmptyIngressDomain},
		{name: "whitespace-domain", app: httpApp, observations: httpObservations, domain: "   ", port: 8080, want: dockerapp.ErrEmptyIngressDomain},
		{name: "no-published-port", app: worker, observations: workerObservations, domain: "app.example.com", port: 8080, want: dockerapp.ErrNoPublishedPort},
		{name: "container-only-short-syntax", app: containerOnly, observations: nil, domain: "app.example.com", port: 80, want: dockerapp.ErrNoPublishedPort},
		{name: "container-only-target", app: containerOnly, observations: nil, domain: "app.example.com", port: 9000, want: dockerapp.ErrNoPublishedPort},
		{name: "unknown-port", app: httpApp, observations: httpObservations, domain: "app.example.com", port: 9000, want: dockerapp.ErrNoPublishedPort},
		{name: "missing-handle", app: httpApp, observations: httpObservations, domain: "app.example.com", port: 8080, want: dockerapp.ErrTypedHandlesUnavailable, nilHandle: true},
		{name: "missing-auditor", app: httpApp, observations: httpObservations, domain: "app.example.com", port: 8080, want: dockerapp.ErrAuditRequired, nilAuditor: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(store.specs)
			snapshot := append([]dockerapp.HostHTTPRule(nil), store.rules...)
			var create dockerapp.HTTPRuleCreateHandle
			if !test.nilHandle {
				create = store
			}
			var audit dockerapp.Auditor
			if !test.nilAuditor {
				audit = auditor
			}
			rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), create, store, test.app, test.observations, test.domain, test.port, audit)
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v want %v", err, test.want)
			}
			if len(store.specs) != before {
				t.Fatal("host create was invoked")
			}
			if len(rules) != 0 {
				t.Fatalf("denied create returned local rules: %#v", rules)
			}
			if len(store.rules) != len(snapshot) || store.rules[0] != snapshot[0] {
				t.Fatalf("existing rules changed: %#v", store.rules)
			}
		})
	}

	t.Run("create-failure", func(t *testing.T) {
		failing := &recordingHostHTTPRules{createErr: errors.New("host rejected fixture-value")}
		rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), failing, failing, httpApp, httpObservations, "app.example.com", 8080, auditor)
		if !errors.Is(err, dockerapp.ErrOperationFailed) {
			t.Fatalf("create failure err=%v", err)
		}
		if len(rules) != 0 || len(failing.rules) != 0 {
			t.Fatalf("failed create recorded local success: rules=%#v store=%#v", rules, failing.rules)
		}
		if strings.Contains(err.Error(), "fixture-value") {
			t.Fatalf("create failure leaked cause: %v", err)
		}
	})

	t.Run("list-failure", func(t *testing.T) {
		failing := &recordingHostHTTPRules{listErr: errors.New("host list rejected fixture-value")}
		rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), failing, failing, httpApp, httpObservations, "app.example.com", 8080, auditor)
		if !errors.Is(err, dockerapp.ErrHTTPRuleListFailed) {
			t.Fatalf("list failure err=%v", err)
		}
		if len(failing.specs) != 1 {
			t.Fatalf("list failure skipped create: %#v", failing.specs)
		}
		if len(rules) != 0 {
			t.Fatalf("list failure returned local success: %#v", rules)
		}
		if strings.Contains(err.Error(), "fixture-value") {
			t.Fatalf("list failure leaked cause: %v", err)
		}
	})
}

func TestHTTPRuleNotDeletedWithoutRefOrOnFailure(t *testing.T) {
	httpApp := dockerapp.App{
		ID: "media", AgentID: "agent-1", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n",
	}
	httpObservations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: httpApp.ID}, ExposedPorts: []uint16{8080}},
	}
	store := &recordingHostHTTPRules{}
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})
	created, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), store, store, httpApp, httpObservations, "https://app.example.com", 8080, auditor)
	if err != nil || len(created) != 1 {
		t.Fatalf("seed create rules=%#v err=%v", created, err)
	}
	ref := created[0].Ref

	for _, test := range []struct {
		name       string
		ref        string
		want       error
		nilHandle  bool
		nilAuditor bool
	}{
		{name: "empty-ref", ref: "", want: dockerapp.ErrEmptyHTTPRuleRef},
		{name: "whitespace-ref", ref: "   ", want: dockerapp.ErrEmptyHTTPRuleRef},
		{name: "unknown-ref", ref: "rule-other", want: dockerapp.ErrUnknownHTTPRule},
		{name: "missing-handle", ref: ref, want: dockerapp.ErrTypedHandlesUnavailable, nilHandle: true},
		{name: "missing-auditor", ref: ref, want: dockerapp.ErrAuditRequired, nilAuditor: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(store.deletes)
			snapshot := append([]dockerapp.HostHTTPRule(nil), store.rules...)
			var handle dockerapp.HTTPRuleDeleteHandle
			if !test.nilHandle {
				handle = store
			}
			var audit dockerapp.Auditor
			if !test.nilAuditor {
				audit = auditor
			}
			rules, err := dockerapp.DeleteHTTPRule(context.Background(), handle, store, httpApp, httpObservations, test.ref, audit)
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v want %v", err, test.want)
			}
			if len(store.deletes) != before {
				t.Fatal("host delete was invoked")
			}
			if len(rules) != 0 {
				t.Fatalf("denied delete returned local rules: %#v", rules)
			}
			if len(store.rules) != len(snapshot) || store.rules[0] != snapshot[0] {
				t.Fatalf("existing rules changed: %#v", store.rules)
			}
		})
	}

	t.Run("delete-failure", func(t *testing.T) {
		failing := &recordingHostHTTPRules{rules: append([]dockerapp.HostHTTPRule(nil), store.rules...), deleteErr: errors.New("host rejected fixture-value")}
		rules, err := dockerapp.DeleteHTTPRule(context.Background(), failing, failing, httpApp, httpObservations, ref, auditor)
		if !errors.Is(err, dockerapp.ErrOperationFailed) {
			t.Fatalf("delete failure err=%v", err)
		}
		if len(rules) != 0 || len(failing.rules) != 1 {
			t.Fatalf("failed delete recorded local success: rules=%#v store=%#v", rules, failing.rules)
		}
		if strings.Contains(err.Error(), "fixture-value") {
			t.Fatalf("delete failure leaked cause: %v", err)
		}
	})
}

func TestProjectHTTPBackendCatalogUsesComposePortsAndAvailability(t *testing.T) {
	hub := dockerapp.App{
		ID: "hubproxy", AgentID: "edge-a", Image: "hubproxy:latest", Generation: "generation-1",
		Compose: "services:\n  hubproxy:\n    image: hubproxy:latest\n    ports:\n      - \"5000:5000\"\n",
	}
	worker := dockerapp.App{
		ID: "worker", AgentID: "edge-a", Image: "batch:latest", Generation: "generation-1",
		Compose: "services:\n  job:\n    image: batch:latest\n",
	}
	catalog, err := dockerapp.ProjectHTTPBackendCatalog([]dockerapp.App{hub, worker}, nil, map[string]bool{"hubproxy": true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 1 || catalog[0].ResourceID != "hubproxy" || catalog[0].AgentID != "edge-a" || catalog[0].Port != 5000 || catalog[0].DisplayName != "hubproxy" || !catalog[0].Available {
		t.Fatalf("catalog = %#v", catalog)
	}

	stopped, err := dockerapp.ProjectHTTPBackendCatalog([]dockerapp.App{hub}, nil, map[string]bool{"hubproxy": false}, true)
	if err != nil || len(stopped) != 1 || stopped[0].Available {
		t.Fatalf("stopped catalog = %#v err=%v", stopped, err)
	}
	missingOverlay, err := dockerapp.ProjectHTTPBackendCatalog([]dockerapp.App{hub}, nil, map[string]bool{}, true)
	if err != nil || len(missingOverlay) != 1 || !missingOverlay[0].Available {
		t.Fatalf("missing runtime overlay catalog = %#v err=%v", missingOverlay, err)
	}
	otherAppOnly, err := dockerapp.ProjectHTTPBackendCatalog([]dockerapp.App{hub}, nil, map[string]bool{"worker": false}, true)
	if err != nil || len(otherAppOnly) != 1 || !otherAppOnly[0].Available {
		t.Fatalf("unrelated runtime overlay catalog = %#v err=%v", otherAppOnly, err)
	}
	ungranted, err := dockerapp.ProjectHTTPBackendCatalog([]dockerapp.App{hub}, nil, map[string]bool{"hubproxy": true}, false)
	if err != nil || len(ungranted) != 0 {
		t.Fatalf("ungranted catalog = %#v err=%v", ungranted, err)
	}
}

type recordedHTTPRuleDelete struct {
	AgentID string
	RuleRef string
}

type recordingHostHTTPRules struct {
	specs     []dockerapp.HTTPRuleSpec
	rules     []dockerapp.HostHTTPRule
	deletes   []recordedHTTPRuleDelete
	createErr error
	listErr   error
	deleteErr error
}

func (store *recordingHostHTTPRules) Create(_ context.Context, spec dockerapp.HTTPRuleSpec) (dockerapp.HostHTTPRule, error) {
	store.specs = append(store.specs, spec)
	if store.createErr != nil {
		return dockerapp.HostHTTPRule{}, store.createErr
	}
	rule := dockerapp.HostHTTPRule{
		Ref:     fmt.Sprintf("rule-%s-%d", spec.AppID, spec.Port),
		Domain:  spec.Domain,
		Port:    spec.Port,
		Backend: fmt.Sprintf("http://127.0.0.1:%d", spec.Port),
		AppID:   spec.AppID,
		AgentID: spec.AgentID,
		Enabled: true,
	}
	store.rules = append(store.rules, rule)
	return rule, nil
}

func (store *recordingHostHTTPRules) List(_ context.Context, agentID string) ([]dockerapp.HostHTTPRule, error) {
	if store.listErr != nil {
		return nil, store.listErr
	}
	listed := make([]dockerapp.HostHTTPRule, 0, len(store.rules))
	for _, rule := range store.rules {
		if rule.AgentID == "" || rule.AgentID == agentID {
			listed = append(listed, rule)
		}
	}
	return listed, nil
}

func (store *recordingHostHTTPRules) Delete(_ context.Context, agentID, ruleRef string) error {
	store.deletes = append(store.deletes, recordedHTTPRuleDelete{AgentID: agentID, RuleRef: ruleRef})
	if store.deleteErr != nil {
		return store.deleteErr
	}
	kept := make([]dockerapp.HostHTTPRule, 0, len(store.rules))
	for _, rule := range store.rules {
		if rule.Ref != ruleRef {
			kept = append(kept, rule)
		}
	}
	store.rules = kept
	return nil
}

func portsEqual(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
