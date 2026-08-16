package dockerapp_test

import (
	"context"
	"errors"
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
