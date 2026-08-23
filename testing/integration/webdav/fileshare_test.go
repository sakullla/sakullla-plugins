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
	wrong.Header.Set("Authorization", "Bearer wrong-pass")
	denied := httptest.NewRecorder()
	controller.ServeHTTP(denied, wrong)
	if denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "visible-inside.txt") {
		t.Fatalf("wrong password = %d %q", denied.Code, denied.Body.String())
	}

	put := httptest.NewRequest(http.MethodPut, "http://share.test/dav/from-webdav.txt", strings.NewReader("shared-root"))
	put.Header.Set("Authorization", "Bearer "+testSharePassword)
	created := httptest.NewRecorder()
	controller.ServeHTTP(created, put)
	if created.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", created.Code, created.Body.String())
	}
	listed := httptest.NewRequest(http.MethodGet, "http://share.test/api/list?path=/", nil)
	listed.Header.Set("Authorization", "Bearer "+testSharePassword)
	listing := httptest.NewRecorder()
	controller.ServeHTTP(listing, listed)
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), "from-webdav.txt") {
		t.Fatalf("list = %d %q", listing.Code, listing.Body.String())
	}

	escape := httptest.NewRequest(http.MethodGet, "http://share.test/api/download?path=../nre-webdav-outside-secret.txt", nil)
	escape.Header.Set("Authorization", "Bearer "+testSharePassword)
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
	put.Header.Set("Authorization", "Bearer "+testSharePassword)
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
	listed.Header.Set("Authorization", "Bearer "+testSharePassword)
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

func TestAuthenticationAndUserIsolation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "shared.txt"), []byte("bearer-root"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "auth-isolation")

	doBasic := func(username, method, target, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		request.SetBasicAuth(username, testSharePassword)
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, request)
		return recorder
	}
	if got := doBasic("alice", http.MethodPut, "http://share.test/dav/only-alice.txt", "alice"); got.Code != http.StatusCreated {
		t.Fatalf("alice PUT = %d %q", got.Code, got.Body.String())
	}
	if got := doBasic("bob", http.MethodGet, "http://share.test/api/list?path=/", ""); got.Code != http.StatusOK || strings.Contains(got.Body.String(), "only-alice.txt") || strings.Contains(got.Body.String(), "shared.txt") {
		t.Fatalf("bob listing = %d %q", got.Code, got.Body.String())
	}
	if got := doBasic("bob", http.MethodPut, "http://share.test/dav/only-alice.txt", "bob"); got.Code != http.StatusCreated {
		t.Fatalf("bob same-path PUT = %d %q", got.Code, got.Body.String())
	}
	if got := doBasic("alice", http.MethodGet, "http://share.test/dav/only-alice.txt", ""); got.Code != http.StatusOK || got.Body.String() != "alice" {
		t.Fatalf("alice file after bob PUT = %d %q", got.Code, got.Body.String())
	}
	bearer := httptest.NewRequest(http.MethodGet, "http://share.test/api/download?path=/shared.txt", nil)
	bearer.Header.Set("Authorization", "Bearer "+testSharePassword)
	shared := httptest.NewRecorder()
	controller.ServeHTTP(shared, bearer)
	if shared.Code != http.StatusOK || shared.Body.String() != "bearer-root" {
		t.Fatalf("bearer shared root = %d %q", shared.Code, shared.Body.String())
	}
	invalid := doBasic("../alice", http.MethodPut, "http://share.test/dav/escape.txt", "escape")
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("invalid username = %d %q", invalid.Code, invalid.Body.String())
	}
	if challenges := invalid.Header().Values("WWW-Authenticate"); len(challenges) != 2 {
		t.Fatalf("invalid username challenges = %q", challenges)
	}
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("invalid username changed root: %v", err)
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
