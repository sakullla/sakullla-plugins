package webdav_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/webdav"
)

func TestFileSharePasswordWebDAVAndEscape(t *testing.T) {
	owned := t.TempDir()
	outside := filepath.Join(filepath.Dir(owned), "nre-webdav-outside-secret.txt")
	if err := os.WriteFile(filepath.Join(owned, "visible-inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("LEAKME-OUTSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadyController, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	unreadyRequest := handshakeRequest("missing-password")
	if _, err := unreadyController.Handshake(t.Context(), unreadyRequest); err != nil {
		t.Fatal(err)
	}
	if result := unreadyController.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: unreadyRequest.Generation, Config: []byte(`{}`)}); result.Error == nil {
		t.Fatal("missing password was accepted")
	}
	unready := httptest.NewRecorder()
	unreadyController.ServeHTTP(unready, httptest.NewRequest(http.MethodGet, "http://share.test/", nil))
	if unready.Code != http.StatusServiceUnavailable || strings.Contains(unready.Body.String(), "visible-inside.txt") {
		t.Fatalf("unready response = %d %q", unready.Code, unready.Body.String())
	}
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "file-share")

	wrong := httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil)
	wrong.SetBasicAuth(webdav.DavMountUsername, "wrong-pass")
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, wrong)
	if denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "visible-inside.txt") {
		t.Fatalf("wrong password = %d %q", denied.Code, denied.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, "http://share.test/dav/from-webdav.txt", strings.NewReader("shared-root"))
	put.SetBasicAuth(webdav.DavMountUsername, testSharePassword)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, put)
	if created.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", created.Code, created.Body.String())
	}
	listed := httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil)
	listed.SetBasicAuth(webdav.DavMountUsername, testSharePassword)
	listing := httptest.NewRecorder()
	controller.ServeHTTP(listing, listed)
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), "from-webdav.txt") {
		t.Fatalf("list = %d %q", listing.Code, listing.Body.String())
	}

	escape := httptest.NewRequest(http.MethodGet, "http://share.test/api/download?path=../nre-webdav-outside-secret.txt", nil)
	escape.SetBasicAuth(webdav.DavMountUsername, testSharePassword)
	blocked := httptest.NewRecorder()
	controller.ServeHTTP(blocked, escape)
	if blocked.Code < 400 || strings.Contains(blocked.Body.String(), "LEAKME-OUTSIDE") {
		t.Fatalf("escape = %d %q", blocked.Code, blocked.Body.String())
	}
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "file-share"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(owned, "from-webdav.txt")); err != nil {
		t.Fatalf("stop deleted owned file: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("stop deleted outside file: %v", err)
	}
}

func TestConfiguredRootPathThenDefaultNoLongerTouchesIt(t *testing.T) {
	owned := t.TempDir()
	external := t.TempDir()
	externalController, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"password": testSharePassword, "root_path": external})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, externalController, "root-path", payload)
	put := httptest.NewRequest(http.MethodPut, "http://share.test/dav/external.txt", strings.NewReader("on-disk"))
	put.SetBasicAuth(webdav.DavMountUsername, testSharePassword)
	created := httptest.NewRecorder()
	externalController.ServeHTTP(created, put)
	if created.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", created.Code, created.Body.String())
	}
	if result := externalController.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "root-path"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "owned-again")
	listed := httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil)
	listed.SetBasicAuth(webdav.DavMountUsername, testSharePassword)
	listing := httptest.NewRecorder()
	controller.ServeHTTP(listing, listed)
	if strings.Contains(listing.Body.String(), "external.txt") {
		t.Fatalf("owned share listed previous root_path file: %q", listing.Body.String())
	}
	body, err := os.ReadFile(filepath.Join(external, "external.txt"))
	if err != nil || string(body) != "on-disk" {
		t.Fatalf("root_path file = %q err=%v", body, err)
	}
}

func activateControllerWithConfig(t *testing.T, controller *webdav.Controller, generation string, config []byte) {
	t.Helper()
	request := handshakeRequest(generation)
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: generation, Config: config}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: generation}); result.Error != nil {
		t.Fatal(result.Error)
	}
}
