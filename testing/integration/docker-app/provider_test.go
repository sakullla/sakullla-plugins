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
		ID: "media", Image: "nginx:1.27", Generation: "generation-1",
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

	existing := []dockerapp.HostHTTPRule{{Ref: "rule-kept", Domain: "kept.example.com", Port: 9000, Backend: "127.0.0.1:9000", AppID: "other"}}
	var calls []dockerapp.HTTPRuleSpec
	handle := dockerapp.HTTPRuleCreateHandleFunc(func(_ context.Context, spec dockerapp.HTTPRuleSpec) (dockerapp.HostHTTPRule, error) {
		calls = append(calls, spec)
		return dockerapp.HostHTTPRule{
			Ref:     "rule-media-8080",
			Domain:  spec.Domain,
			Port:    spec.Port,
			Backend: fmt.Sprintf("127.0.0.1:%d", spec.Port),
			AppID:   spec.AppID,
		}, nil
	})
	auditor := dockerapp.AuditorFunc(func(dockerapp.AuditRecord) {})

	rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), handle, existing, app, observations, "https://app.example.com", 8080, auditor)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].AppID != app.ID || calls[0].Domain != "app.example.com" || calls[0].Port != 8080 {
		t.Fatalf("create spec = %#v", calls)
	}
	if len(rules) != 2 || rules[0] != existing[0] {
		t.Fatalf("host rules = %#v", rules)
	}
	created := rules[1]
	if created.Ref != "rule-media-8080" || created.Domain != "app.example.com" || created.Port != 8080 || created.AppID != app.ID {
		t.Fatalf("created rule = %#v", created)
	}
	if created.Backend != "127.0.0.1:8080" || !strings.Contains(created.Backend, "8080") {
		t.Fatalf("backend does not point at published port: %#v", created)
	}

	containerOnly := dockerapp.App{
		ID: "sidecar", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"80\"\n",
	}
	runtimeHost := []dockerapp.ContainerObservation{
		{ID: "ctr-sidecar", Labels: map[string]string{dockerapp.AppLabel: containerOnly.ID}, ExposedPorts: []uint16{32768}},
	}
	calls = nil
	rules, err = dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), handle, existing, containerOnly, runtimeHost, "sidecar.example.com", 32768, auditor)
	if err != nil || len(calls) != 1 || calls[0].Port != 32768 {
		t.Fatalf("runtime host create spec=%#v rules=%#v err=%v", calls, rules, err)
	}
	if rules[len(rules)-1].Backend != "127.0.0.1:32768" {
		t.Fatalf("runtime backend = %#v", rules[len(rules)-1])
	}
}

func TestHTTPRuleNotCreatedWithoutPublishedPortOrDomain(t *testing.T) {
	httpApp := dockerapp.App{
		ID: "media", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n",
	}
	worker := dockerapp.App{
		ID: "worker", Image: "batch:latest", Generation: "generation-1",
		Compose: "services:\n  job:\n    image: batch:latest\n",
	}
	containerOnly := dockerapp.App{
		ID: "sidecar", Image: "nginx:1.27", Generation: "generation-1",
		Compose: "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"80\"\n      - 443\n      - \":8080\"\n      - \"80/tcp\"\n      - target: 9000\n",
	}
	httpObservations := []dockerapp.ContainerObservation{
		{ID: "ctr-media", Labels: map[string]string{dockerapp.AppLabel: httpApp.ID}, ExposedPorts: []uint16{8080}},
	}
	workerObservations := []dockerapp.ContainerObservation{
		{ID: "ctr-worker", Labels: map[string]string{dockerapp.AppLabel: worker.ID}},
	}
	existing := []dockerapp.HostHTTPRule{{Ref: "rule-kept", Domain: "kept.example.com", Port: 9000, Backend: "127.0.0.1:9000"}}
	called := false
	handle := dockerapp.HTTPRuleCreateHandleFunc(func(context.Context, dockerapp.HTTPRuleSpec) (dockerapp.HostHTTPRule, error) {
		called = true
		return dockerapp.HostHTTPRule{Ref: "rule-new"}, nil
	})
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
			called = false
			var create dockerapp.HTTPRuleCreateHandle
			if !test.nilHandle {
				create = handle
			}
			var audit dockerapp.Auditor
			if !test.nilAuditor {
				audit = auditor
			}
			snapshot := append([]dockerapp.HostHTTPRule(nil), existing...)
			rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), create, existing, test.app, test.observations, test.domain, test.port, audit)
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v want %v", err, test.want)
			}
			if called {
				t.Fatal("host create was invoked")
			}
			if len(rules) != len(snapshot) || rules[0] != snapshot[0] {
				t.Fatalf("existing rules changed: %#v", rules)
			}
			if existing[0] != snapshot[0] {
				t.Fatalf("input rules mutated: %#v", existing)
			}
		})
	}

	t.Run("create-failure", func(t *testing.T) {
		failing := dockerapp.HTTPRuleCreateHandleFunc(func(context.Context, dockerapp.HTTPRuleSpec) (dockerapp.HostHTTPRule, error) {
			return dockerapp.HostHTTPRule{Ref: "rule-new", Domain: "app.example.com", Port: 8080, Backend: "127.0.0.1:8080"}, errors.New("host rejected")
		})
		snapshot := append([]dockerapp.HostHTTPRule(nil), existing...)
		rules, err := dockerapp.CreateHTTPRuleFromPublishedPort(context.Background(), failing, existing, httpApp, httpObservations, "app.example.com", 8080, auditor)
		if !errors.Is(err, dockerapp.ErrOperationFailed) {
			t.Fatalf("create failure err=%v", err)
		}
		if len(rules) != len(snapshot) || rules[0] != snapshot[0] {
			t.Fatalf("failed create changed rules: %#v", rules)
		}
	})
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
