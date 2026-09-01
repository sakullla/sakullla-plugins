package dockerapp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestComposeImagePairsServices(t *testing.T) {
	t.Parallel()
	document := "services:\n  web:\n    image: nginx:1.27.1\n  db:\n    image: postgres:16.3\n"
	want := []ServiceImage{
		{Name: "db", Image: "postgres:16.3"},
		{Name: "web", Image: "nginx:1.27.1"},
	}
	if got := ComposeServiceImages(document); !slices.Equal(got, want) {
		t.Fatalf("ComposeServiceImages()=%v want %v", got, want)
	}
	_, app, err := ParseComposeDocument(document, "media", "generation-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(app.ServiceImages, want) {
		t.Fatalf("ParseComposeDocument ServiceImages=%v want %v", app.ServiceImages, want)
	}
	if app.Image != "postgres:16.3" && app.Image != "nginx:1.27.1" {
		t.Fatalf("derived Image=%q", app.Image)
	}
	if len(app.ServiceImages) != 2 {
		t.Fatalf("paired images=%v", app.ServiceImages)
	}
}

func TestBindComposePairsServiceImagesAndKeepsPolicies(t *testing.T) {
	t.Parallel()
	app := App{
		ID:         "media",
		Generation: "generation-1",
		Compose:    "services:\n  web:\n    image: nginx:1.27.1\n  db:\n    image: postgres:16.3\n",
		ImageLocks: map[string]string{"web": " ^1.27.1 "},
		IgnoredUpdates: map[string][]string{
			"web": {"1.27.2"},
			"db":  {"16.4.0"},
		},
	}
	if err := app.bindCompose(); err != nil {
		t.Fatal(err)
	}
	want := []ServiceImage{
		{Name: "db", Image: "postgres:16.3"},
		{Name: "web", Image: "nginx:1.27.1"},
	}
	if !slices.Equal(app.ServiceImages, want) {
		t.Fatalf("ServiceImages=%v want %v", app.ServiceImages, want)
	}
	if app.ImageLocks["web"] != "^1.27.1" {
		t.Fatalf("trimmed lock=%q", app.ImageLocks["web"])
	}
	if !slices.Equal(app.IgnoredUpdates["web"], []string{"1.27.2"}) || !slices.Equal(app.IgnoredUpdates["db"], []string{"16.4.0"}) {
		t.Fatalf("ignored=%v", app.IgnoredUpdates)
	}
}

func TestParseConfigurationPersistsImageLocksAndIgnoredUpdates(t *testing.T) {
	t.Parallel()
	document := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n  db:\n    image: postgres:16.3\n","generation":"generation-1","image_locks":{"web":"^1.27.1","db":"~16.3.0"},"ignored_updates":{"web":["1.27.2"]}}]}`)
	got, err := ParseConfiguration(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 {
		t.Fatalf("apps=%#v", got.Apps)
	}
	app := got.Apps[0]
	wantImages := []ServiceImage{
		{Name: "db", Image: "postgres:16.3"},
		{Name: "web", Image: "nginx:1.27.1"},
	}
	if !slices.Equal(app.ServiceImages, wantImages) {
		t.Fatalf("ServiceImages=%v want %v", app.ServiceImages, wantImages)
	}
	if app.ImageLocks["web"] != "^1.27.1" || app.ImageLocks["db"] != "~16.3.0" {
		t.Fatalf("locks=%v", app.ImageLocks)
	}
	if !slices.Equal(app.IgnoredUpdates["web"], []string{"1.27.2"}) {
		t.Fatalf("ignored=%v", app.IgnoredUpdates)
	}
	wire, err := json.Marshal(cloneApps([]App{app}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"image_locks"`) || !strings.Contains(string(wire), `"ignored_updates"`) {
		t.Fatalf("StoreApps payload omitted policies: %s", wire)
	}
	var stored []App
	if err := json.Unmarshal(wire, &stored); err != nil || len(stored) != 1 {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	if stored[0].ImageLocks["web"] != "^1.27.1" || stored[0].ImageLocks["db"] != "~16.3.0" {
		t.Fatalf("round-trip locks=%v", stored[0].ImageLocks)
	}
	if !slices.Equal(stored[0].IgnoredUpdates["web"], []string{"1.27.2"}) {
		t.Fatalf("round-trip ignored=%v", stored[0].IgnoredUpdates)
	}
	if err := stored[0].bindCompose(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored[0].ServiceImages, wantImages) {
		t.Fatalf("rebound ServiceImages=%v", stored[0].ServiceImages)
	}
}

func TestParseConfigurationRejectsUnknownOverlayKeysAndInvalidLocks(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","image_lock":{"web":"^1.27.1"}}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","locks":{"web":"^1.27.1"}}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","ignored_update":["1.27.2"]}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","image_locks":{"web":"not-a-constraint"}}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","image_locks":{"Web":"^1.27.1"}}]}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27.1\n","generation":"generation-1","ignored_updates":{"web":[""]}}]}`,
	} {
		if _, err := ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("document %s was accepted", document)
		}
	}
}
