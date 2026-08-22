package webdav

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	testSharePassword = "share-pass"
	testInsideName    = "visible-inside.txt"
	testOutsideName   = "nre-webdav-outside-secret.txt"
	testOutsideBody   = "LEAKME-OUTSIDE"
)

func TestMissingPasswordFailsPrepareWithoutListingFiles(t *testing.T) {
	owned := t.TempDir()
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact",
		GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: "no-password",
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{[]byte(`{}`), []byte(`{"password":""}`), nil} {
		result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "no-password", Config: config})
		if result.Error == nil {
			t.Fatalf("prepare accepted %#q", config)
		}
	}
	recorder := doShareRequest(t, controller, http.MethodGet, "http://provider.test/", "", nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), testInsideName) {
		t.Fatalf("unprepared response leaked file name: %q", recorder.Body.String())
	}
}

func TestWrongPasswordIs401WithoutFileNamesOrMutations(t *testing.T) {
	controller, owned := startShare(t, "")
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"http://provider.test/",
		"http://provider.test/api/list?path=/",
		"http://provider.test/dav/",
	} {
		recorder := doShareRequest(t, controller, http.MethodGet, target, "wrong-pass", nil)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401 body=%q", target, recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s missing WWW-Authenticate", target)
		}
		if strings.Contains(recorder.Body.String(), testInsideName) {
			t.Fatalf("%s leaked file name: %q", target, recorder.Body.String())
		}
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://provider.test/dav/evil.txt", "wrong-pass", strings.NewReader("nope"))
	if put.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized put status = %d", put.Code)
	}
	if _, err := os.Stat(filepath.Join(owned, "evil.txt")); !os.IsNotExist(err) {
		t.Fatalf("unauthorized put wrote a file: %v", err)
	}
}

func TestPageServesManagerAndDavMountInstructions(t *testing.T) {
	controller, owned := startShare(t, "")
	if err := os.WriteFile(filepath.Join(owned, testInsideName), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	page := doShareRequest(t, controller, http.MethodGet, "http://share.test/", testSharePassword, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("page status = %d body=%q", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("page CSP = %q", page.Header().Get("Content-Security-Policy"))
	}
	body := page.Body.String()
	for _, fragment := range []string{"文件共享", "/dav/", "HTTP Basic", `id="dav-url"`, `id="upload-input"`, `id="mkdir-button"`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page missing %q", fragment)
		}
	}
	if strings.Contains(body, testInsideName) || strings.Contains(body, testSharePassword) {
		t.Fatal("page leaked share contents or password")
	}
	script := doShareRequest(t, controller, http.MethodGet, "http://share.test/static/app.js", testSharePassword, nil)
	if script.Code != http.StatusOK || !strings.Contains(script.Body.String(), "window.location.origin") || !strings.Contains(script.Body.String(), "/dav/") {
		t.Fatalf("script = %d %q", script.Code, script.Body.String())
	}
}

func TestWebpageAPIsBrowseDownloadUploadMkdirRenameDelete(t *testing.T) {
	controller, owned := startShare(t, "")
	listed := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/list?path=/", testSharePassword, nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%q", listed.Code, listed.Body.String())
	}
	mkdir := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/mkdir", testSharePassword, strings.NewReader(`{"path":"docs"}`))
	if mkdir.Code != http.StatusCreated {
		t.Fatalf("mkdir status = %d body=%q", mkdir.Code, mkdir.Body.String())
	}
	upload := uploadShareFile(t, controller, "/docs", "notes.txt", "hello-web")
	if upload.Code != http.StatusCreated {
		t.Fatalf("upload status = %d body=%q", upload.Code, upload.Body.String())
	}
	download := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path="+url.QueryEscape("/docs/notes.txt"), testSharePassword, nil)
	if download.Code != http.StatusOK || download.Body.String() != "hello-web" {
		t.Fatalf("download = %d %q", download.Code, download.Body.String())
	}
	rename := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/rename", testSharePassword, strings.NewReader(`{"from":"/docs/notes.txt","to":"/docs/renamed.txt"}`))
	if rename.Code != http.StatusOK {
		t.Fatalf("rename status = %d body=%q", rename.Code, rename.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "docs", "renamed.txt")); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
	remove := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/delete", testSharePassword, strings.NewReader(`{"path":"/docs/renamed.txt"}`))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%q", remove.Code, remove.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "docs", "renamed.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file still present: %v", err)
	}
}

func TestWebDAVMethodsShareTheSameRoot(t *testing.T) {
	controller, owned := startShare(t, "")
	mkcol := doShareRequest(t, controller, "MKCOL", "http://share.test/dav/folder", testSharePassword, nil)
	if mkcol.Code != http.StatusCreated {
		t.Fatalf("mkcol status = %d body=%q", mkcol.Code, mkcol.Body.String())
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/folder/from-dav.txt", testSharePassword, strings.NewReader("via-dav"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	got := doShareRequest(t, controller, http.MethodGet, "http://share.test/dav/folder/from-dav.txt", testSharePassword, nil)
	if got.Code != http.StatusOK || got.Body.String() != "via-dav" {
		t.Fatalf("dav get = %d %q", got.Code, got.Body.String())
	}
	listed := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/list?path="+url.QueryEscape("/folder"), testSharePassword, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "from-dav.txt") {
		t.Fatalf("web list missing dav file: %d %q", listed.Code, listed.Body.String())
	}
	move := httptest.NewRequest("MOVE", "http://share.test/dav/folder/from-dav.txt", nil)
	move.SetBasicAuth(DavMountUsername, testSharePassword)
	move.Header.Set("Destination", "http://share.test/dav/folder/moved.txt")
	move.Header.Set("Overwrite", "T")
	moved := httptest.NewRecorder()
	controller.ServeHTTP(moved, move)
	if moved.Code != http.StatusCreated && moved.Code != http.StatusNoContent {
		t.Fatalf("move status = %d body=%q", moved.Code, moved.Body.String())
	}
	propfind := httptest.NewRequest("PROPFIND", "http://share.test/dav/folder", http.NoBody)
	propfind.SetBasicAuth(DavMountUsername, testSharePassword)
	propfind.Header.Set("Depth", "1")
	found := httptest.NewRecorder()
	controller.ServeHTTP(found, propfind)
	if found.Code != http.StatusMultiStatus || !strings.Contains(found.Body.String(), "moved.txt") {
		t.Fatalf("propfind = %d %q", found.Code, found.Body.String())
	}
	del := doShareRequest(t, controller, http.MethodDelete, "http://share.test/dav/folder/moved.txt", testSharePassword, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%q", del.Code, del.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "folder", "moved.txt")); !os.IsNotExist(err) {
		t.Fatalf("dav delete left file: %v", err)
	}
}

func TestRootPathSwitchAndCloseKeepExternalFiles(t *testing.T) {
	owned := t.TempDir()
	external := t.TempDir()
	externalController, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, externalController, "external-root", testShareConfig(testSharePassword, external))
	if externalController.Status().Root != external {
		t.Fatalf("root = %q, want %q", externalController.Status().Root, external)
	}
	put := doShareRequest(t, externalController, http.MethodPut, "http://share.test/dav/placed.txt", testSharePassword, strings.NewReader("external-bytes"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	if _, err := os.Stat(filepath.Join(owned, "placed.txt")); !os.IsNotExist(err) {
		t.Fatal("default owned root was written while root_path was set")
	}
	if result := externalController.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "external-root"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(external, "placed.txt")); err != nil {
		t.Fatalf("stop deleted root_path file: %v", err)
	}
	ownedController, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, ownedController, "owned-root", testShareConfig(testSharePassword, ""))
	if ownedController.Status().Root != owned {
		t.Fatalf("owned root = %q, want %q", ownedController.Status().Root, owned)
	}
	listed := doShareRequest(t, ownedController, http.MethodGet, "http://share.test/api/list?path=/", testSharePassword, nil)
	if strings.Contains(listed.Body.String(), "placed.txt") {
		t.Fatalf("default share still listed root_path file: %q", listed.Body.String())
	}
	rewrite := doShareRequest(t, ownedController, http.MethodPut, "http://share.test/dav/placed.txt", testSharePassword, strings.NewReader("owned-bytes"))
	if rewrite.Code != http.StatusCreated {
		t.Fatalf("owned put status = %d body=%q", rewrite.Code, rewrite.Body.String())
	}
	body, err := os.ReadFile(filepath.Join(external, "placed.txt"))
	if err != nil || string(body) != "external-bytes" {
		t.Fatalf("root_path file changed after switching back: %q err=%v", body, err)
	}
	if result := ownedController.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "owned-root"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(external, "placed.txt")); err != nil {
		t.Fatalf("later stop deleted root_path file: %v", err)
	}
}

func TestPathEscapeIsRejected(t *testing.T) {
	controller, owned := startShare(t, "")
	outside := filepath.Join(filepath.Dir(owned), testOutsideName)
	if err := os.WriteFile(outside, []byte(testOutsideBody), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(owned, "safe.txt")
	if err := os.WriteFile(inside, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	escapes := []string{
		"../" + testOutsideName,
		"..\\" + testOutsideName,
		filepath.ToSlash(outside),
	}
	if volume := filepath.VolumeName(outside); volume != "" {
		escapes = append(escapes, outside)
	}
	for _, path := range escapes {
		download := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path="+url.QueryEscape(path), testSharePassword, nil)
		if download.Code < 400 {
			t.Fatalf("escape download %q status = %d", path, download.Code)
		}
		if strings.Contains(download.Body.String(), testOutsideBody) || strings.Contains(download.Body.String(), testOutsideName) {
			t.Fatalf("escape download leaked outside file: %q", download.Body.String())
		}
		mkdir := doShareRequest(t, controller, http.MethodPost, "http://share.test/api/mkdir", testSharePassword, strings.NewReader(`{"path":`+jsonString(path+"/escaped-dir")+`}`))
		if mkdir.Code < 400 {
			t.Fatalf("escape mkdir %q status = %d body=%q", path, mkdir.Code, mkdir.Body.String())
		}
	}
	dav := doShareRequest(t, controller, http.MethodGet, "http://share.test/dav/../"+testOutsideName, testSharePassword, nil)
	if strings.Contains(dav.Body.String(), testOutsideBody) {
		t.Fatalf("dav escape leaked outside file: %q", dav.Body.String())
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/../escaped-put.txt", testSharePassword, strings.NewReader("nope"))
	if _, err := os.Stat(filepath.Join(filepath.Dir(owned), "escaped-put.txt")); !os.IsNotExist(err) {
		t.Fatalf("dav escape created outside file: %v", err)
	}
	_ = put
	body, err := os.ReadFile(outside)
	if err != nil || string(body) != testOutsideBody {
		t.Fatalf("outside file changed: %q err=%v", body, err)
	}
	safe := doShareRequest(t, controller, http.MethodGet, "http://share.test/api/download?path=safe.txt", testSharePassword, nil)
	if safe.Code != http.StatusOK || safe.Body.String() != "safe" {
		t.Fatalf("in-root download = %d %q", safe.Code, safe.Body.String())
	}
}

func TestDefaultRootIsNotFilesystemRootAndStopKeepsFiles(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	activateController(t, controller, "cwd-share")
	root := controller.Status().Root
	if root != filepath.Join(cwd, OwnedShareName) || isVolumeRoot(root) {
		t.Fatalf("share root = %q", root)
	}
	put := doShareRequest(t, controller, http.MethodPut, "http://share.test/dav/kept.txt", testSharePassword, strings.NewReader("keep"))
	if put.Code != http.StatusCreated {
		t.Fatalf("put status = %d body=%q", put.Code, put.Body.String())
	}
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "cwd-share"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := os.Stat(filepath.Join(root, "kept.txt")); err != nil {
		t.Fatalf("stop deleted owned share file: %v", err)
	}
}

func startShare(t *testing.T, rootPath string) (*Controller, string) {
	t.Helper()
	owned := t.TempDir()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	activateControllerWithConfig(t, controller, "share", testShareConfig(testSharePassword, rootPath))
	return controller, owned
}

func testShareConfig(password, rootPath string) []byte {
	payload := map[string]string{"password": password}
	if rootPath != "" {
		payload["root_path"] = rootPath
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func doShareRequest(t *testing.T, handler http.Handler, method, target, password string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, body)
	if password != "" {
		request.SetBasicAuth(DavMountUsername, password)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func uploadShareFile(t *testing.T, handler http.Handler, dir, name, contents string) *httptest.ResponseRecorder {
	t.Helper()
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writer.WriteField("path", dir); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://share.test/api/upload", &buffer)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.SetBasicAuth(DavMountUsername, testSharePassword)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func jsonString(value string) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(payload)
}
