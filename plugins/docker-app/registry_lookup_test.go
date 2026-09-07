package dockerapp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func daemonMirrorController(t *testing.T, mirror, current string) *Controller {
	t.Helper()
	controller := newCallController(t, t.TempDir(), nil, nil)
	controller.commandRunner = CommandRunnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
		if name == "docker" && len(args) == 3 && args[0] == "info" && args[2] == registryMirrorInfoFormat {
			return json.Marshal([]string{mirror})
		}
		if name == "docker" && len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[3] == localImageDigestFormat {
			return []byte("amd64\n" + current), nil
		}
		t.Errorf("unexpected command during mirror metadata lookup: %s %q", name, args)
		return nil, errors.New("unexpected Docker command")
	})
	return controller
}

func TestImageTagsUseDaemonMirrorCatalogAndKeepPaginationOnMirror(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/example/gateway/tags/list" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/api/tags" || r.URL.Query().Get("image") != "example/gateway" {
			t.Errorf("unexpected mirror request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		pages = append(pages, r.URL.Query().Get("page"))
		if r.URL.Query().Get("page") == "1" {
			_, _ = w.Write([]byte(`{"results":[{"name":"v1.2.3"}],"next":"https://hub.docker.com/v2/namespaces/example/repositories/gateway/tags?page=2&page_size=100"}`))
		} else {
			_, _ = w.Write([]byte(`{"results":[{"name":"v1.2.4"},{"name":"v1.2.3"}],"next":null}`))
		}
	}))
	defer server.Close()
	controller := daemonMirrorController(t, server.URL, "")
	controller.registryMirror = "https://unused-install-hint.invalid"
	tags, err := controller.dockerImageTags(context.Background(), "example/gateway:v1.2.3")
	if err != nil || strings.Join(tags, ",") != "v1.2.3,v1.2.4" || strings.Join(pages, ",") != "1,2" {
		t.Fatalf("mirror tags=%v pages=%v error=%v", tags, pages, err)
	}
	app := App{ID: "sample", Generation: "generation-1", Compose: "services:\n  gateway:\n    image: example/gateway:v1.2.3\n"}
	if err := app.bindCompose(); err != nil {
		t.Fatal(err)
	}
	view := projectAppView(app, true, Deployment{}, "", map[string]serviceTagListing{"gateway": {Tags: tags, Known: true}}, nil)
	if view.Notice != OpsStatusUpdateAvailable || !view.ServiceImages[0].Update {
		t.Fatalf("mirror candidate did not produce an update notice: %#v", view.ServiceImages)
	}
}

func TestConfiguredMirrorFailureDoesNotFallBackToDockerHub(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer server.Close()
	previous := dockerHubTagListURL
	dockerHubTagListURL = func(string) string { t.Error("configured mirror failure fell back to Hub"); return server.URL }
	defer func() { dockerHubTagListURL = previous }()
	controller := daemonMirrorController(t, server.URL, "example/worker@sha256:"+strings.Repeat("a", 64))
	if _, err := controller.dockerImageTags(context.Background(), "example/worker:latest"); err == nil {
		t.Fatal("failed mirror listing looked like an empty repository")
	}
	if _, err := controller.callImageObserve(context.Background(), imageCallRequest{Image: "example/worker:latest"}); err == nil {
		t.Fatal("failed mirror digest looked up to date")
	}
}

func TestImageObserveUsesMirrorManifestWithoutRewritingImageIdentity(t *testing.T) {
	body := []byte(`{"schemaVersion":2,"manifests":[{"digest":"sha256:` + strings.Repeat("b", 64) + `","platform":{"architecture":"amd64","os":"linux"}}]}`)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/example/worker/manifests/latest" || !strings.Contains(r.Header.Get("Accept"), "image.index") {
			t.Errorf("unexpected manifest request %s", r.URL)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	current := "example/worker@sha256:" + strings.Repeat("a", 64)
	controller := daemonMirrorController(t, server.URL, current)
	raw, err := controller.callImageObserve(context.Background(), imageCallRequest{Image: "example/worker:latest"})
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		Current string `json:"current_digest"`
		Latest  string `json:"latest_digest"`
	}
	if err := json.Unmarshal(raw, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.Current != current || observed.Latest != "example/worker@"+digest {
		t.Fatalf("mirror comparison changed image identity or hid an update: %#v", observed)
	}
}

func TestRegistryTagPaginationRejectsOtherOrigins(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://unrelated.invalid/v2/example/worker/tags/list?n=100>; rel="next"`)
		_, _ = w.Write([]byte(`{"tags":["latest"]}`))
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/v2/example/worker/tags/list")
	if _, err := listMirrorTagPages(context.Background(), endpoint, false); err == nil {
		t.Fatal("pagination left the configured mirror")
	}
}

// Explicit, read-only field diagnostic. Real image names are supplied by the
// operator, never embedded in fixtures; ordinary test runs stay offline.
func TestLiveDockerImageMetadata(t *testing.T) {
	images := strings.Fields(os.Getenv("NRE_DOCKER_APP_LIVE_IMAGES"))
	if len(images) == 0 {
		t.Skip("set NRE_DOCKER_APP_LIVE_IMAGES for the read-only Agent diagnostic")
	}
	controller, err := NewController(ControllerConfig{PackageDigest: "diagnostic", ArtifactDigest: "diagnostic"})
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			tags, err := controller.dockerImageTags(ctx, image)
			if err != nil || len(tags) == 0 {
				t.Fatalf("tag enumeration failed: %v", err)
			}
			raw, err := controller.callImageObserve(ctx, imageCallRequest{Image: image})
			if err != nil {
				t.Fatal(err)
			}
			var observed struct {
				Current string `json:"current_digest"`
				Latest  string `json:"latest_digest"`
			}
			if err := json.Unmarshal(raw, &observed); err != nil {
				t.Fatal(err)
			}
			app := App{ID: "diagnostic", Generation: "generation-1", Compose: "services:\n  service:\n    image: " + image + "\n"}
			if err := app.bindCompose(); err != nil {
				t.Fatal(err)
			}
			view := projectAppView(app, true, Deployment{}, "", map[string]serviceTagListing{"service": {Tags: tags, Known: true}}, map[string]serviceDigestState{"service": {Available: observed.Current != observed.Latest, Current: observed.Current == observed.Latest}})
			t.Logf("tags=%d current=%s latest=%s update=%t default_tag=%s", len(tags), observed.Current, observed.Latest, view.Notice == OpsStatusUpdateAvailable, view.ServiceImages[0].DefaultTag)
			if view.ServiceImages[0].Listing == serviceListingFailed {
				t.Fatal("successful metadata still displayed as unavailable")
			}
		})
	}
}
