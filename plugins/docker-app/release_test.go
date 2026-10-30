package dockerapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func frpcTagEntries() []ImageTagEntry {
	return []ImageTagEntry{
		{Tag: "v0.71.1", Digest: "sha256:7a0a18bc9c83dc106a7e5213a890f521affdf90d595829c56b0ed8481377d50e"},
		{Tag: "test"},
		{Tag: "v0.71.0", Digest: "sha256:99ece6a2b62cfc68731e0df289af804ff1c699911cfc47871856434f1d6d53ee"},
		{Tag: "v0.70.1"},
	}
}

func subStoreTagEntries() []ImageTagEntry {
	return []ImageTagEntry{
		{Tag: "latest", Digest: "sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc"},
		{Tag: "2.42.6", Digest: "sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc"},
		{Tag: "2.42.6-http-meta", Digest: "sha256:1d3f0b4c2a5e68790b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778"},
		{Tag: "http-meta"},
		{Tag: "2.42.5", Digest: "sha256:bb"},
	}
}

func TestProjectServiceReleaseReportsPinnedVersionAsCurrent(t *testing.T) {
	listing := serviceTagListing{Tags: imageTagNames(frpcTagEntries()), Entries: frpcTagEntries(), Known: true}
	view := projectServiceView(App{ID: "media"}, ServiceImage{Name: "frpc", Image: "fatedier/frpc:v0.71.1"}, listing, serviceDigestState{})
	if view.VersionState != VersionStateCurrent {
		t.Fatalf("version state=%q want %q", view.VersionState, VersionStateCurrent)
	}
	if view.Version != "v0.71.1" || view.Latest != "v0.71.1" {
		t.Fatalf("version=%q latest=%q", view.Version, view.Latest)
	}
	if view.Update {
		t.Fatal("a pinned newest release must not be reported as an update")
	}
	if view.Message != "已是最新版本 v0.71.1" {
		t.Fatalf("message=%q", view.Message)
	}
	if view.Floating {
		t.Fatal("a pinned release must not be reported as floating")
	}
}

func TestProjectServiceReleaseOffersNewerPinnedVersion(t *testing.T) {
	listing := serviceTagListing{Tags: imageTagNames(frpcTagEntries()), Entries: frpcTagEntries(), Known: true}
	view := projectServiceView(App{ID: "media"}, ServiceImage{Name: "frpc", Image: "fatedier/frpc:v0.71.0"}, listing, serviceDigestState{})
	if view.VersionState != VersionStateOutdated {
		t.Fatalf("version state=%q want %q", view.VersionState, VersionStateOutdated)
	}
	if !view.Update || view.DefaultTag != "v0.71.1" {
		t.Fatalf("update=%v default=%q", view.Update, view.DefaultTag)
	}
	if len(view.Candidates) != 1 || view.Candidates[0].Tag != "v0.71.1" {
		t.Fatalf("candidates=%+v", view.Candidates)
	}
}

func TestProjectServiceReleasePlacesMovingTagOnItsRelease(t *testing.T) {
	entries := subStoreTagEntries()
	listing := serviceTagListing{Tags: imageTagNames(entries), Entries: entries, Known: true}
	digest := serviceDigestState{Current: true, Latest: "sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc"}
	view := projectServiceView(App{ID: "store"}, ServiceImage{Name: "sub-store", Image: "xream/sub-store:latest"}, listing, digest)
	if view.VersionState != VersionStateCurrent {
		t.Fatalf("version state=%q want %q", view.VersionState, VersionStateCurrent)
	}
	if view.Version != "2.42.6" || view.Latest != "2.42.6" {
		t.Fatalf("version=%q latest=%q", view.Version, view.Latest)
	}
	if !view.Floating {
		t.Fatal("a moving tag must stay marked as floating")
	}
	if view.Update {
		t.Fatal("a moving tag on the newest release must not be reported as an update")
	}
	if len(view.Candidates) != 0 {
		t.Fatalf("candidates=%+v", view.Candidates)
	}
}

func TestProjectServiceReleaseOffersReleaseForMovingTag(t *testing.T) {
	entries := subStoreTagEntries()
	listing := serviceTagListing{Tags: imageTagNames(entries), Entries: entries, Known: true}
	digest := serviceDigestState{Available: true, Latest: "sha256:cc"}
	view := projectServiceView(App{ID: "store"}, ServiceImage{Name: "sub-store", Image: "xream/sub-store:latest"}, listing, digest)
	if !view.Update {
		t.Fatal("a moved digest must be reported as an update")
	}
	var release bool
	for _, candidate := range view.Candidates {
		if candidate.Release && candidate.Tag == "2.42.6" {
			release = true
		}
	}
	if !release {
		t.Fatalf("candidates=%+v", view.Candidates)
	}
}

func TestPinnedReleaseIgnoresOlderAlphabeticalMaximum(t *testing.T) {
	listing := serviceTagListing{Tags: []string{"1.10.0", "1.11.0"}, Known: true}
	view := projectServiceView(App{ID: "git"}, ServiceImage{Name: "server", Image: "docker.gitea.com/gitea:1.27.3"}, listing, serviceDigestState{})
	if view.VersionState != VersionStateCurrent {
		t.Fatalf("version state=%q", view.VersionState)
	}
	if view.Latest != "1.27.3" || view.Version != "1.27.3" {
		t.Fatalf("version=%q latest=%q", view.Version, view.Latest)
	}
	if view.Update || len(view.Candidates) != 0 {
		t.Fatalf("older tag was offered as an upgrade: %#v", view)
	}
	if view.Message != "已是最新版本 1.27.3" {
		t.Fatalf("message=%q", view.Message)
	}
	if view.Listing == serviceListingFailed {
		t.Fatal("a short alphabetical page was reported as unlistable")
	}
}

func TestFloatingTagKeepsKnownReleaseWhenDigestFails(t *testing.T) {
	entries := subStoreTagEntries()
	listing := serviceTagListing{Tags: imageTagNames(entries), Entries: entries, Known: true}
	view := projectServiceView(App{ID: "store"}, ServiceImage{Name: "substore", Image: "xream/sub-store:latest"}, listing, serviceDigestState{Failed: true})
	if view.Listing == serviceListingFailed || view.Message == serviceListingFailedMessage {
		t.Fatalf("known tags were hidden behind a listing failure: %#v", view)
	}
	if !view.Floating || view.Latest != "2.42.6" {
		t.Fatalf("view=%#v", view)
	}
	if view.VersionState != VersionStateFloating {
		t.Fatalf("version state=%q", view.VersionState)
	}
}

func TestProjectServiceReleaseReadsReleaseLineFromTagNames(t *testing.T) {
	listing := serviceTagListing{Tags: []string{"latest", "2.42.6", "2.42.6-http-meta", "2.42.5"}, Known: true}
	view := projectServiceView(App{ID: "store"}, ServiceImage{Name: "sub-store", Image: "xream/sub-store:latest"}, listing, serviceDigestState{Current: true})
	if view.Latest != "2.42.6" {
		t.Fatalf("latest=%q", view.Latest)
	}
	if view.VersionState != VersionStateFloating {
		t.Fatalf("version state=%q want %q", view.VersionState, VersionStateFloating)
	}
	if view.Update {
		t.Fatal("an unresolved moving tag must not be reported as an update")
	}
	if len(view.Candidates) != 1 || view.Candidates[0].Tag != "2.42.6" || !view.Candidates[0].Release {
		t.Fatalf("candidates=%+v", view.Candidates)
	}
}

func TestImageRepositoryKeepsRegistryHost(t *testing.T) {
	cases := map[string]string{
		"fatedier/frpc:v0.71.1":  "fatedier/frpc",
		"xream/sub-store:latest": "xream/sub-store",
		"nginx:1.27":             "nginx",
		"ghcr.io/owner/img:tag":  "ghcr.io/owner/img",
		"repo/img@sha256:" + "a": "repo/img",
	}
	for image, want := range cases {
		if got := imageRepository(image); got != want {
			t.Fatalf("imageRepository(%q)=%q want %q", image, got, want)
		}
	}
}

func TestReleaseKeepsVariantLinesApart(t *testing.T) {
	releases := imageReleases(subStoreTagEntries())
	plain := releaseFamily(releases, "")
	if len(plain) != 2 {
		t.Fatalf("plain family=%+v", plain)
	}
	variant := releaseFamily(releases, "http-meta")
	if len(variant) != 1 || variant[0].Tag != "2.42.6-http-meta" {
		t.Fatalf("variant family=%+v", variant)
	}
	latest, ok := newestRelease(plain)
	if !ok || latest.Tag != "2.42.6" {
		t.Fatalf("latest=%+v ok=%v", latest, ok)
	}
	primary := primaryReleaseLine(releases)
	newest, ok := newestRelease(primary)
	if !ok || newest.Tag != "2.42.6" {
		t.Fatalf("primary newest=%+v ok=%v", newest, ok)
	}
}

func TestAppViewProjectsVersionStateForPinnedAndMovingTags(t *testing.T) {
	app := App{ID: "store", Generation: "generation-1", Compose: "services:\n  frpc:\n    image: fatedier/frpc:v0.71.1\n  sub:\n    image: xream/sub-store:latest\n"}
	if err := app.bindCompose(); err != nil {
		t.Fatal(err)
	}
	frpc := frpcTagEntries()
	sub := subStoreTagEntries()
	view := projectAppView(app, true, Deployment{}, "", map[string]serviceTagListing{
		"frpc": {Tags: imageTagNames(frpc), Entries: frpc, Known: true},
		"sub":  {Tags: imageTagNames(sub), Entries: sub, Known: true},
	}, map[string]serviceDigestState{
		"sub": {Current: true, Latest: "sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc"},
	})
	if len(view.ServiceImages) != 2 {
		t.Fatalf("service images=%v", view.ServiceImages)
	}
	pinned := view.ServiceImages[0]
	if pinned.VersionState != VersionStateCurrent || pinned.Version != "v0.71.1" || pinned.Latest != "v0.71.1" {
		t.Fatalf("pinned view=%#v", pinned)
	}
	moving := view.ServiceImages[1]
	if moving.VersionState != VersionStateCurrent || moving.Version != "2.42.6" || !moving.Floating {
		t.Fatalf("moving view=%#v", moving)
	}
	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"version_state"`, `"version"`, `"latest"`, `"floating"`} {
		if !strings.Contains(string(payload), key) {
			t.Fatalf("app view payload misses %s: %s", key, payload)
		}
	}
}

func TestMirrorCatalogKeepsTagDigests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/xream/sub-store/tags/list" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/api/tags" {
			t.Errorf("unexpected mirror request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"name":"latest","digest":"sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc","last_updated":"2026-01-02T03:04:05Z"},{"name":"2.42.6","digest":"sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc","last_updated":"2026-01-02T03:04:05Z"}],"next":null}`))
	}))
	defer server.Close()
	controller := daemonMirrorController(t, server.URL, "")
	controller.registryMirror = "https://unused-install-hint.invalid"
	entries, err := controller.dockerImageTagEntries(context.Background(), "xream/sub-store:latest")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%v", entries)
	}
	if entries[0].Digest != "sha256:025a987a43cfb92a36db1813d305bbafd86164a1c4616af5d8272b287c4607bc" {
		t.Fatalf("digest=%q", entries[0].Digest)
	}
	if entries[0].UpdatedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("updated_at=%q", entries[0].UpdatedAt)
	}
}

func TestCallImageListTagsPublishesTagEntries(t *testing.T) {
	controller := newCallController(t, t.TempDir(), nil, nil)
	controller.callImages = imageTagEntryObserver{entries: []ImageTagEntry{{Tag: "v0.71.1", Digest: "sha256:aa"}}}
	payload, err := controller.callImageListTags(context.Background(), imageCallRequest{Image: "fatedier/frpc:v0.71.1"})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tags    []string        `json:"tags"`
		Entries []ImageTagEntry `json:"entries"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tags) != 1 || result.Tags[0] != "v0.71.1" {
		t.Fatalf("tags=%v", result.Tags)
	}
	if len(result.Entries) != 1 || result.Entries[0].Digest != "sha256:aa" {
		t.Fatalf("entries=%v", result.Entries)
	}
}

// imageTagEntryObserver publishes rich tag entries like a registry-aware Agent.
type imageTagEntryObserver struct {
	entries []ImageTagEntry
}

func (observer imageTagEntryObserver) ObserveImage(context.Context, App) (UpdateObservation, error) {
	return UpdateObservation{}, nil
}

func (observer imageTagEntryObserver) ListImageTags(context.Context, App) ([]string, error) {
	return imageTagNames(observer.entries), nil
}

func (observer imageTagEntryObserver) ListImageTagEntries(context.Context, App) ([]ImageTagEntry, error) {
	return observer.entries, nil
}
