package cloudflaredns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestMappingUIAuthorizedCRUDPersistsAcrossRefresh(t *testing.T) {
	t.Parallel()
	service, trace, runtime := newUIHarness(t, nil)
	create := uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"Example.COM.","token":"super-secret-cf-token-ui"}`, "operation/ui-create")
	created := httptest.NewRecorder()
	service.ServeHTTP(created, create)
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "super-secret-cf-token-ui") || strings.Contains(created.Body.String(), `"token"`) {
		t.Fatalf("create echoed token: %s", created.Body.String())
	}

	page := httptest.NewRecorder()
	service.ServeHTTP(page, uiRequest(http.MethodGet, "/", "", "operation/ui-page"))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="mapping-workspace"`) || strings.Contains(page.Body.String(), "{{") {
		t.Fatalf("refresh page status=%d body=%s", page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), "super-secret-cf-token-ui") || strings.Contains(page.Body.String(), `value="super-secret`) {
		t.Fatalf("page prefilled token: %s", page.Body.String())
	}
	if !strings.Contains(page.Body.String(), `id="mapping-create"`) || !strings.Contains(page.Body.String(), `name="token"`) {
		t.Fatal("authorized page missing write entry")
	}
	if strings.Contains(page.Body.String(), `name="zone_token"`) || strings.Contains(page.Body.String(), `id="dns-record"`) || strings.Contains(page.Body.String(), `data-action="dns-`) {
		t.Fatal("page includes excluded fields")
	}

	detail := httptest.NewRecorder()
	service.ServeHTTP(detail, uiRequest(http.MethodGet, "/api/mappings/example.com", "", "operation/ui-get"))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"suffix":"example.com"`) || strings.Contains(detail.Body.String(), "super-secret-cf-token-ui") || strings.Contains(detail.Body.String(), `"token"`) {
		t.Fatalf("detail=%s status=%d", detail.Body.String(), detail.Code)
	}

	rename := uiJSONRequest(http.MethodPost, "/api/mappings/example.com/rename", `{"suffix":"other.test","confirm":"example.com"}`, "operation/ui-rename")
	renamed := httptest.NewRecorder()
	service.ServeHTTP(renamed, rename)
	if renamed.Code != http.StatusOK || !strings.Contains(renamed.Body.String(), `"suffix":"other.test"`) {
		t.Fatalf("rename status=%d body=%s", renamed.Code, renamed.Body.String())
	}

	rotate := uiJSONRequest(http.MethodPost, "/api/mappings/other.test/rotate", `{"token":"rotated-secret-cf-token-ui","confirm":"other.test"}`, "operation/ui-rotate")
	rotated := httptest.NewRecorder()
	service.ServeHTTP(rotated, rotate)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), "rotated-secret-cf-token-ui") {
		t.Fatalf("rotate status=%d body=%s", rotated.Code, rotated.Body.String())
	}

	if err := service.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(uiConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := httptest.NewRecorder()
	restarted.ServeHTTP(refreshed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-list"))
	if refreshed.Code != http.StatusOK || !strings.Contains(refreshed.Body.String(), `"suffix":"other.test"`) || strings.Contains(refreshed.Body.String(), "rotated-secret-cf-token-ui") {
		t.Fatalf("restarted list=%s status=%d", refreshed.Body.String(), refreshed.Code)
	}
	resolved, err := restarted.ResolveToken(context.Background(), uiAction("operation/ui-resolve"), "www.other.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resolved.Token(), []byte("rotated-secret-cf-token-ui")) || resolved.Fallback {
		t.Fatalf("restarted token=%q fallback=%v", resolved.Token(), resolved.Fallback)
	}
	resolved.Clear()

	deleted := httptest.NewRecorder()
	restarted.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/mappings/other.test/delete", `{"confirm":"other.test"}`, "operation/ui-delete"))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	empty := httptest.NewRecorder()
	restarted.ServeHTTP(empty, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-list-empty"))
	if empty.Code != http.StatusOK || strings.Contains(empty.Body.String(), `"suffix"`) {
		t.Fatalf("after delete list=%s", empty.Body.String())
	}
	assertUITraceRedacted(t, trace, []string{"super-secret-cf-token-ui", "rotated-secret-cf-token-ui"})
}

func TestInternalDNSResolveReturnsMappedTokenOnlyOnPrivateProviderPath(t *testing.T) {
	t.Parallel()
	service, _, _ := newUIHarness(t, nil)
	created := httptest.NewRecorder()
	service.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"private-provider-token"}`, "operation/ui-create-private-provider"))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}

	request := uiJSONRequest(http.MethodPost, internalDNSResolvePath, `{"domain":"edge.example.com"}`, "operation/internal-resolve")
	resolved := httptest.NewRecorder()
	service.ServeHTTP(resolved, request)
	if resolved.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", resolved.Code, resolved.Body.String())
	}
	if resolved.Header().Get(internalDNSVersionHeader) != "1" {
		t.Fatal("private provider contract version header is missing")
	}
	var response internalDNSResolveResponse
	if err := json.Unmarshal(resolved.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if string(response.Token) != "private-provider-token" || response.Error != "" || response.Provider != ProviderCloudflare {
		t.Fatalf("resolve response token=%q provider=%q error=%q", response.Token, response.Provider, response.Error)
	}
	clear(response.Token)

	missing := httptest.NewRecorder()
	service.ServeHTTP(missing, uiJSONRequest(http.MethodPost, internalDNSResolvePath, `{"domain":"unmapped.test"}`, "operation/internal-resolve-missing"))
	if missing.Code != http.StatusNotFound || strings.Contains(missing.Body.String(), "private-provider-token") {
		t.Fatalf("missing status=%d body=%s", missing.Code, missing.Body.String())
	}
}

func TestRotateMappingReplacesInvalidCurrentToken(t *testing.T) {
	t.Parallel()
	service, _, runtime := newUIHarness(t, nil)
	created, err := service.CreateMapping(context.Background(), uiAction("operation/create-revoked"), "example.com", []byte("revoked-token"))
	if err != nil {
		t.Fatal(err)
	}
	vault := runtime.Vault.(*uiFakeVault)
	vault.mu.Lock()
	vault.verifyErrors[created.SecretRef] = ErrTokenInvalid
	vault.mu.Unlock()

	rotated, err := service.RotateMappingToken(context.Background(), uiAction("operation/replace-revoked"), "example.com", []byte("replacement-token"))
	if err != nil {
		t.Fatalf("rotate invalid current token: %v", err)
	}
	if rotated.SecretRef != created.SecretRef || rotated.Version == created.Version {
		t.Fatalf("rotated mapping=%#v created=%#v", rotated, created)
	}
	vault.mu.Lock()
	delete(vault.verifyErrors, created.SecretRef)
	vault.mu.Unlock()
	resolved, err := service.ResolveToken(context.Background(), uiAction("operation/resolve-replacement"), "edge.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if !bytes.Equal(resolved.Token(), []byte("replacement-token")) {
		t.Fatalf("replacement token=%q", resolved.Token())
	}
}

func TestMappingUISecondRotateWithoutOperationKeyStoresNewToken(t *testing.T) {
	t.Parallel()
	service, _, runtime := newUIHarness(t, nil)
	created := httptest.NewRecorder()
	service.ServeHTTP(created, uiAnonymousJSON(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"first-secret-cf-token"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	first := httptest.NewRecorder()
	service.ServeHTTP(first, uiAnonymousJSON(http.MethodPost, "/api/mappings/example.com/rotate", `{"token":"second-secret-cf-token","confirm":"example.com"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("first rotate status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	service.ServeHTTP(second, uiAnonymousJSON(http.MethodPost, "/api/mappings/example.com/rotate", `{"token":"third-secret-cf-token","confirm":"example.com"}`))
	if second.Code != http.StatusOK || strings.Contains(second.Body.String(), "third-secret-cf-token") {
		t.Fatalf("second rotate status=%d body=%s", second.Code, second.Body.String())
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(uiConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := restarted.ResolveToken(context.Background(), uiAction("operation/ui-resolve"), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if !bytes.Equal(resolved.Token(), []byte("third-secret-cf-token")) {
		t.Fatalf("second rotate token=%q", resolved.Token())
	}
}

func TestMappingUILongSuffixWriteWithoutOperationKey(t *testing.T) {
	t.Parallel()
	service, _, _ := newUIHarness(t, nil)
	suffix := strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + ".example.com"
	create := httptest.NewRecorder()
	service.ServeHTTP(create, uiAnonymousJSON(http.MethodPost, "/api/mappings", `{"suffix":"`+suffix+`","token":"long-secret-cf-token"}`))
	if create.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	path := "/api/mappings/" + url.PathEscape(suffix)
	detail := httptest.NewRecorder()
	service.ServeHTTP(detail, uiAnonymousRequest(http.MethodGet, path, ""))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), suffix) {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}
	rotate := httptest.NewRecorder()
	service.ServeHTTP(rotate, uiAnonymousJSON(http.MethodPost, path+"/rotate", `{"token":"long-rotated-secret","confirm":"`+suffix+`"}`))
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotate.Code, rotate.Body.String())
	}
	deleted := httptest.NewRecorder()
	service.ServeHTTP(deleted, uiAnonymousJSON(http.MethodPost, path+"/delete", `{"confirm":"`+suffix+`"}`))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestMappingUIUnauthorizedIsExplicitRejection(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, func(action ActionContext) error { return errors.New("raw denied") })
	page := httptest.NewRecorder()
	service.ServeHTTP(page, uiRequest(http.MethodGet, "/", "", "operation/ui-denied"))
	if page.Code != http.StatusOK {
		t.Fatalf("denied page status=%d", page.Code)
	}
	body := page.Body.String()
	if body == "" || !strings.Contains(body, "明确拒绝") || !strings.Contains(body, `id="mapping-denied"`) || strings.Contains(body, "{{") {
		t.Fatalf("denied page was blank or unclear: %q", body)
	}
	deniedAPI := httptest.NewRecorder()
	service.ServeHTTP(deniedAPI, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-denied-api"))
	if deniedAPI.Code != http.StatusForbidden || !strings.Contains(deniedAPI.Body.String(), ErrAuthorizationDenied.Error()) {
		t.Fatalf("denied API status=%d body=%s", deniedAPI.Code, deniedAPI.Body.String())
	}

	anonymous := httptest.NewRecorder()
	service.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code != http.StatusOK || !strings.Contains(anonymous.Body.String(), `id="mapping-denied"`) {
		t.Fatalf("anonymous page status=%d body=%s", anonymous.Code, anonymous.Body.String())
	}

	write := httptest.NewRecorder()
	service.ServeHTTP(write, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"denied-secret-token"}`, "operation/ui-denied-write"))
	if write.Code != http.StatusForbidden || strings.Contains(write.Body.String(), "denied-secret-token") || write.Body.Len() == 0 {
		t.Fatalf("denied write=%s status=%d", write.Body.String(), write.Code)
	}
}

func TestMappingUIReadOnlyHidesWriteEntry(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, nil)
	if _, err := service.CreateMapping(context.Background(), uiAction("operation/seed"), "example.com", []byte("seed-secret-token")); err != nil {
		t.Fatal(err)
	}
	service.runtime.Authorizer = AuthorizerFunc(func(_ context.Context, action ActionContext) error {
		if action.Permission == PermissionVaultEnroll || action.Permission == PermissionVaultRotate {
			return errors.New("raw write denied")
		}
		return nil
	})
	page := httptest.NewRecorder()
	service.ServeHTTP(page, uiRequest(http.MethodGet, "/", "", "operation/ui-readonly"))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="mapping-create"`) || !strings.Contains(page.Body.String(), "hidden") {
		t.Fatalf("readonly page status=%d body=%s", page.Code, page.Body.String())
	}
	script, err := mappingUIAssets.ReadFile("ui/app.js")
	if err != nil || !bytes.Contains(script, []byte("addButton.hidden = !canWrite")) || !bytes.Contains(script, []byte("emptyAdd.hidden = !canWrite")) {
		t.Fatalf("readonly page does not hide the write entry: %s", script)
	}
	listed := httptest.NewRecorder()
	service.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-readonly-list"))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "example.com") || strings.Contains(listed.Body.String(), `"can_write":true`) || strings.Contains(listed.Body.String(), `"can_rotate":true`) {
		t.Fatalf("read-only list status=%d body=%s", listed.Code, listed.Body.String())
	}
	denied := httptest.NewRecorder()
	service.ServeHTTP(denied, uiJSONRequest(http.MethodPost, "/api/mappings/example.com/delete", `{"confirm":"example.com"}`, "operation/ui-readonly-delete"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("readonly delete status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestMappingUIConfirmCancelDoesNotChangeState(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, nil)
	if _, err := service.CreateMapping(context.Background(), uiAction("operation/seed"), "example.com", []byte("keep-secret-token")); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		path string
		body string
	}{
		{path: "/api/mappings/example.com/delete", body: `{}`},
		{path: "/api/mappings/example.com/rotate", body: `{"token":"other-secret-token"}`},
		{path: "/api/mappings/example.com/rename", body: `{"suffix":"other.test"}`},
		{path: "/api/mappings/example.com/delete", body: `{"confirm":"other.test"}`},
	} {
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, uiJSONRequest(http.MethodPost, fixture.path, fixture.body, "operation/ui-cancel"))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "confirmation required") {
			t.Fatalf("path %s status=%d body=%s", fixture.path, recorder.Code, recorder.Body.String())
		}
	}
	listed, err := service.ListMappings(context.Background(), uiAction("operation/list"))
	if err != nil || len(listed) != 1 || listed[0].Suffix != "example.com" {
		t.Fatalf("list after cancel=%#v err=%v", listed, err)
	}
	script, err := mappingUIAssets.ReadFile("ui/app.js")
	if err != nil || !bytes.Contains(script, []byte("取消不会更改映射")) || !bytes.Contains(script, []byte("NREUI.confirm")) || !bytes.Contains(script, []byte("window.confirm")) {
		t.Fatalf("script missing cancel confirmation: %s", script)
	}
}

func TestMappingUIDuplicateSuffixRejected(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, nil)
	first := httptest.NewRecorder()
	service.ServeHTTP(first, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"first-secret-token"}`, "operation/ui-first"))
	if first.Code != http.StatusOK {
		t.Fatalf("first create status=%d", first.Code)
	}
	duplicate := httptest.NewRecorder()
	service.ServeHTTP(duplicate, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"Example.COM.","token":"second-secret-token"}`, "operation/ui-dup"))
	if duplicate.Code != http.StatusConflict || !strings.Contains(duplicate.Body.String(), ErrMappingConflict.Error()) || strings.Contains(duplicate.Body.String(), "second-secret-token") {
		t.Fatalf("duplicate=%s status=%d", duplicate.Body.String(), duplicate.Code)
	}
}

func TestMappingUIAssetsAndInactiveController(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, nil)
	for _, route := range []string{"/app.js", "/style.css", "/ui-kit.js", "/ui-kit.css"} {
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("asset %s status=%d", route, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "http://") || strings.Contains(recorder.Body.String(), "https://") {
			t.Fatalf("asset %s has external dependency", route)
		}
	}
	script, err := mappingUIAssets.ReadFile("ui/app.js")
	if err != nil || !bytes.Contains(script, []byte("X-NRE-Operation-Key")) || !bytes.Contains(script, []byte("getRandomValues")) {
		t.Fatalf("script missing unique operation key: %s", script)
	}
	page, err := mappingUIAssets.ReadFile("ui/index.html")
	if err != nil || !bytes.Contains(page, []byte(`id="create-form" method="post"`)) || bytes.Contains(page, []byte("{{")) || !bytes.Contains(page, []byte(`method="post"`)) {
		t.Fatalf("token forms missing post method: %s", page)
	}
	if !bytes.Contains(page, []byte("Zone → DNS → Edit")) || !bytes.Contains(page, []byte("guides/certificates")) || !bytes.Contains(page, []byte("最长匹配")) {
		t.Fatal("page missing Cloudflare token setup guide")
	}
	if !bytes.Contains(script, []byte(`setAttribute("data-row-action", action)`)) || !bytes.Contains(script, []byte(`"rotate"`)) || !bytes.Contains(script, []byte(`"delete"`)) {
		t.Fatalf("native UI script is missing dynamic row actions: %s", script)
	}
	if !bytes.Contains(script, []byte("NREUI.openDialog")) || !bytes.Contains(script, []byte("NREUI.confirm")) {
		t.Fatalf("native UI script does not use the shared dialogs: %s", script)
	}
	if !bytes.Contains(page, []byte(`id="mapping-create" data-ui-dialog`)) || !bytes.Contains(page, []byte(`id="mapping-rename"`)) || !bytes.Contains(page, []byte(`id="mapping-rotate"`)) {
		t.Fatalf("page is missing the create/rename/rotate dialogs: %s", page)
	}
	css, err := mappingUIAssets.ReadFile("ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	assertDesignSystemPage(t, string(page), string(script), string(css))
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	inactive := httptest.NewRecorder()
	controller.ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "/", nil))
	if inactive.Code != http.StatusOK || !strings.Contains(inactive.Body.String(), "mapping-unavailable") || inactive.Body.Len() == 0 {
		t.Fatalf("inactive controller status=%d body=%s", inactive.Code, inactive.Body.String())
	}
	unavailableResolve := httptest.NewRecorder()
	controller.ServeHTTP(unavailableResolve, httptest.NewRequest(http.MethodPost, internalDNSResolvePath, strings.NewReader(`{"domain":"unmapped.test"}`)))
	if unavailableResolve.Code != http.StatusNotFound || unavailableResolve.Header().Get(internalDNSVersionHeader) != "1" || !strings.Contains(unavailableResolve.Body.String(), ErrTokenUnavailable.Error()) {
		t.Fatalf("inactive resolver status=%d headers=%v body=%s", unavailableResolve.Code, unavailableResolve.Header(), unavailableResolve.Body.String())
	}
}

func TestMappingUIViewportLayout(t *testing.T) {
	t.Parallel()
	css, err := mappingUIAssets.ReadFile("ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	for _, want := range []string{
		"@media (max-width: 768px)",
		"#mapping-list .ui-table thead",
		"grid-template-columns: minmax(0, 1fr) auto",
		"overflow-wrap: anywhere",
		"min-width: 0",
		"var(--ui-space-",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("stylesheet missing viewport rule %q", want)
		}
	}
	if strings.Contains(text, "max-width: 52rem") || strings.Contains(text, "max-width: 64rem") || strings.Contains(text, "max-width: 880px") {
		t.Fatal("stylesheet still caps the page width")
	}
	if strings.Contains(text, "width: 100vw") || strings.Contains(text, "min-width: 60rem") {
		t.Fatal("stylesheet forces a wider-than-viewport layout")
	}
	if !strings.Contains(text, "grid-column: 1 / -1") {
		t.Fatal("mobile mapping cards do not span the full row")
	}
}

func TestMappingUITouchTargetsAndUnsavedGuard(t *testing.T) {
	t.Parallel()
	css, err := mappingUIAssets.ReadFile("ui/style.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	if !strings.Contains(text, "@media (max-width: 480px)") || !strings.Contains(text, ".mapping-help > summary") || !strings.Contains(text, "min-height: var(--ui-touch)") {
		t.Fatal("mobile help summary is not a 44px touch target")
	}
	if strings.Contains(text, "#mapping-search") && strings.Contains(text, "min-height: var(--ui-control-height)") {
		t.Fatal("page CSS still pins the search field to the desktop control height")
	}
	script, err := mappingUIAssets.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(script)
	for _, want := range []string{
		"改动尚未保存",
		"丢弃修改",
		"beforeunload",
		"requestDialogClose",
		"正在删除",
		"删除后不可恢复",
		"NREUI.fieldError",
		"NREUI.clearFieldError",
		"aria-describedby",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app script missing %q", want)
		}
	}
}

func assertDesignSystemPage(t *testing.T, page, script, style string) {
	t.Helper()
	if !strings.Contains(page, `data-theme-mode="host"`) {
		t.Fatal("page does not declare the host theme authority")
	}
	if !strings.Contains(page, `data-theme="light"`) {
		t.Fatal("page default theme is not light")
	}
	kitScript := strings.Index(page, `<script src="ui-kit.js"></script>`)
	kitStyle := strings.Index(page, `<link rel="stylesheet" href="ui-kit.css">`)
	pageStyle := strings.Index(page, `<link rel="stylesheet" href="style.css">`)
	if kitScript < 0 || kitStyle < 0 || pageStyle < 0 || !(kitScript < kitStyle && kitStyle < pageStyle) {
		t.Fatal("page does not load ui-kit.js before ui-kit.css and style.css")
	}
	for _, class := range []string{"ui-page", "ui-page-head", "ui-toolbar", "ui-dialog", "ui-empty", "ui-error-state", "ui-denied", "ui-help"} {
		if !strings.Contains(page, class) {
			t.Fatalf("page is missing kit class %q", class)
		}
	}
	for _, class := range []string{"ui-table", "ui-table-wrap", "ui-badge"} {
		if !strings.Contains(script, class) {
			t.Fatalf("rendered list is missing kit class %q", class)
		}
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, " onclick=") {
		t.Fatal("page must not depend on inline script or handlers under self-only CSP")
	}
	if strings.Contains(style, `[data-theme="dark"]`) || strings.Contains(style, `[data-theme="sakura-day"]`) || strings.Contains(style, "#818cf8") {
		t.Fatal("page CSS must not define its own theme palettes")
	}
	for _, token := range []string{"var(--ui-space-", "var(--ui-text-", "var(--ui-border", "var(--ui-primary)"} {
		if !strings.Contains(style, token) {
			t.Fatalf("page CSS is not using kit token %q", token)
		}
	}
	if strings.Contains(script, "window.parent") || strings.Contains(script, "applyHostTheme") || strings.Contains(script, "aliases") {
		t.Fatal("page script still resolves themes itself instead of ui-kit.js")
	}
	if !strings.Contains(script, "data-open-create") || !strings.Contains(script, "data-row-action") {
		t.Fatal("page script is missing dialog and row action wiring")
	}
}

func TestMappingUIStatesAreDistinct(t *testing.T) {
	t.Parallel()
	page, err := mappingUIAssets.ReadFile("ui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []struct {
		fragment string
		state    string
	}{
		{fragment: `<section class="ui-loading" id="mapping-loading" role="status"`, state: "loading"},
		{fragment: `id="mapping-error" role="alert" hidden`, state: "error"},
		{fragment: `id="mapping-unavailable" role="status" hidden`, state: "unavailable"},
		{fragment: `id="mapping-denied" role="alert" hidden`, state: "denied"},
		{fragment: `id="mapping-empty" hidden`, state: "empty"},
		{fragment: `id="mapping-filter-empty" hidden`, state: "filter-empty"},
	} {
		if !strings.Contains(text, want.fragment) {
			t.Fatalf("page is missing the %s state", want.state)
		}
	}
	if !strings.Contains(text, `id="mapping-workspace" hidden`) {
		t.Fatal("workspace must stay hidden until the mapping list is loaded")
	}
}

func TestPluginYAMLDeclaresUIRouteNotPanelPage(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: cloudflare-dns") {
		t.Fatalf("plugin.yaml must declare ui.route support: %s", text)
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: cloudflare-dns") {
		t.Fatalf("plugin.yaml must declare resource.group support: %s", text)
	}
	if strings.Contains(text, "ui_schema:") {
		t.Fatal("mapping UI must not use host config ui_schema")
	}
}

func TestPluginYAMLDeclaresResourceGroupForHostCatalog(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"resource.group.ref: resource-group/cloudflare-dns",
		"resource.group.label: Cloudflare DNS",
		"resource.group.description: 按域名后缀隔离 Token 映射",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin.yaml must declare %q: %s", want, text)
		}
	}
	if !strings.Contains(text, "- resource.group") || !strings.Contains(text, "resource_group_id: cloudflare-dns") {
		t.Fatal("plugin.yaml must declare resource.group as an SDK extension point")
	}
}

func TestMappingUIUsesConfiguredResourceGroupWhenHeaderMissing(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	request.Header.Set(mappingActorHeader, "actor/admin")
	request.Header.Set(mappingOperationHeader, "operation/ui-list-declared")
	listed := httptest.NewRecorder()
	service.ServeHTTP(listed, request)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"access"`) {
		t.Fatalf("list without group header status=%d body=%s", listed.Code, listed.Body.String())
	}
}

func TestMappingUIPersistsAcrossControllerStopActivate(t *testing.T) {
	t.Parallel()
	_, _, runtime := newUIHarness(t, nil)
	runtime.Catalog = nil
	first := newUIController(t, runtime)
	created := httptest.NewRecorder()
	first.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"controller-secret-token"}`, "operation/ui-create"))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if response := first.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	second := newUIController(t, runtime)
	listed := httptest.NewRecorder()
	second.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-list"))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"suffix":"example.com"`) || strings.Contains(listed.Body.String(), "controller-secret-token") {
		t.Fatalf("reactivated list=%s status=%d", listed.Body.String(), listed.Code)
	}
	if err := second.Use(context.Background(), func(ctx context.Context, service *Service) error {
		resolved, err := service.ResolveToken(ctx, uiAction("operation/ui-resolve"), "www.example.com", nil)
		if err != nil {
			return err
		}
		defer resolved.Clear()
		if !bytes.Equal(resolved.Token(), []byte("controller-secret-token")) || resolved.Fallback {
			t.Fatalf("reactivated token=%q fallback=%v", resolved.Token(), resolved.Fallback)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMappingUIRemainsAvailableAfterActivateRequestContextEnds(t *testing.T) {
	t.Parallel()
	_, _, runtime := newUIHarness(t, nil)
	controller, err := NewController(ControllerConfig{
		PackageDigest:  "package",
		ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) { return runtime, nil }}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(),
		Generation: "generation-request-context", RequiredFeatures: []string{pluginsdk.RPCFeatureDurableActionsV1},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration := uiConfiguration()
	configuration.Generation = "generation-request-context"
	config, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	prepareCtx, cancelPrepare := context.WithCancel(context.Background())
	if response := controller.Prepare(prepareCtx, pluginsdk.LifecycleRequest{Generation: "generation-request-context", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	cancelPrepare()
	activateCtx, cancelActivate := context.WithCancel(context.Background())
	if response := controller.Activate(activateCtx, pluginsdk.LifecycleRequest{Generation: "generation-request-context"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	cancelActivate()

	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-after-activate-context"))
	if listed.Code != http.StatusOK {
		t.Fatalf("list after activate request ended status=%d body=%s", listed.Code, listed.Body.String())
	}
}

func assertUITraceRedacted(t *testing.T, trace *uiTrace, secrets []string) {
	t.Helper()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	wire, err := json.Marshal(struct {
		UI    []UIProjection
		Audit []AuditRecord
		Log   []EventRecord
	}{trace.ui, trace.audit, trace.logs})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("secret %q leaked in UI/audit/log: %s", secret, wire)
		}
	}
}

func uiRequest(method, path, body, operation string) *http.Request {
	request := uiAnonymousRequest(method, path, body)
	request.Header.Set(mappingOperationHeader, operation)
	return request
}

func uiAnonymousRequest(method, path, body string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set(mappingActorHeader, "actor/admin")
	request.Header.Set(mappingGroupHeader, "group/main")
	return request
}

func uiJSONRequest(method, path, body, operation string) *http.Request {
	request := uiRequest(method, path, body, operation)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func uiAnonymousJSON(method, path, body string) *http.Request {
	request := uiAnonymousRequest(method, path, body)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func uiAction(operation string) ActionRequest {
	return ActionRequest{Actor: "actor/admin", ResourceGroupRef: "group/main", OperationKey: operation}
}

func uiConfiguration() Configuration {
	return Configuration{Generation: "generation-1", SecretRef: "vault/cloudflare", ResourceGroupRef: "group/main"}
}

func newUIService(t *testing.T, authorize func(ActionContext) error) (*Service, *uiTrace) {
	t.Helper()
	service, trace, _ := newUIHarness(t, authorize)
	return service, trace
}

func newUIHarness(t *testing.T, authorize func(ActionContext) error) (*Service, *uiTrace, RuntimeAdapters) {
	t.Helper()
	if authorize == nil {
		authorize = func(ActionContext) error { return nil }
	}
	vault := newUIVault()
	trace := &uiTrace{}
	runtime := RuntimeAdapters{
		Vault:      vault,
		DNS:        uiFakeDNS{},
		Operations: uiInspector{vault: vault},
		Lease:      GenerationLeaseFunc(func() {}),
		Authorizer: AuthorizerFunc(func(_ context.Context, action ActionContext) error { return authorize(action) }),
		UI:         DynamicUIFunc(func(_ context.Context, projection UIProjection) error { trace.addUI(projection); return nil }),
		Auditor:    AuditorFunc(func(_ context.Context, record AuditRecord) error { trace.addAudit(record); return nil }),
		Logger:     EventLoggerFunc(func(_ context.Context, record EventRecord) error { trace.addLog(record); return nil }),
		Catalog:    newMemoryMappingCatalog(),
	}
	service, err := NewService(uiConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	return service, trace, runtime
}

func newUIController(t *testing.T, runtime RuntimeAdapters) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
		return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) { return runtime, nil }}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI:            pluginsdk.RPCABIV1,
		PluginID:       PluginID,
		PluginVersion:  PluginVersion,
		PackageDigest:  "package",
		ArtifactDigest: "artifact",
		GrantedScopes:  requiredGrants(),
		Generation:     "generation-1",
		RequiredFeatures: []string{
			pluginsdk.RPCFeatureDurableActionsV1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Features) != 1 || response.Features[0] != pluginsdk.RPCFeatureDurableActionsV1 {
		t.Fatalf("durable action feature acknowledgement = %v", response.Features)
	}
	if strings.Join(response.Capabilities, ",") != strings.Join(requiredGrants(), ",") {
		t.Fatalf("granted capability acknowledgement = %v", response.Capabilities)
	}
	config, err := json.Marshal(uiConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	return controller
}

type uiTrace struct {
	mu    sync.Mutex
	ui    []UIProjection
	audit []AuditRecord
	logs  []EventRecord
}

func (trace *uiTrace) addUI(record UIProjection) {
	trace.mu.Lock()
	trace.ui = append(trace.ui, record)
	trace.mu.Unlock()
}
func (trace *uiTrace) addAudit(record AuditRecord) {
	trace.mu.Lock()
	trace.audit = append(trace.audit, record)
	trace.mu.Unlock()
}
func (trace *uiTrace) addLog(record EventRecord) {
	trace.mu.Lock()
	trace.logs = append(trace.logs, record)
	trace.mu.Unlock()
}

type uiFakeSecret struct {
	version  int
	material []byte
}

type uiFakeVault struct {
	mu           sync.Mutex
	operations   map[string]TokenMetadata
	secrets      map[string]uiFakeSecret
	verifyErrors map[string]error
	effects      atomic.Int32
}

func newUIVault() *uiFakeVault {
	return &uiFakeVault{operations: map[string]TokenMetadata{}, secrets: map[string]uiFakeSecret{}, verifyErrors: map[string]error{}}
}

func (vault *uiFakeVault) Verify(_ context.Context, ref string) (TokenAttestation, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if err := vault.verifyErrors[ref]; err != nil {
		return TokenAttestation{}, err
	}
	secret, ok := vault.secrets[ref]
	if !ok {
		if strings.HasSuffix(ref, "/map/catalog") {
			return TokenAttestation{}, ErrMappingCatalogNotFound
		}
		return TokenAttestation{}, errors.New("raw missing token")
	}
	return TokenAttestation{SecretRef: ref, Version: versionName(secret.version), Permissions: []string{PermissionVaultEnroll, PermissionVaultRotate}, LastUsed: 1}, nil
}

func (vault *uiFakeVault) Enroll(_ context.Context, ref string, material []byte, operation string) (TokenMetadata, error) {
	if !strings.HasPrefix(ref, "vault/cloudflare/") || len(material) == 0 {
		return TokenMetadata{}, errors.New("raw Vault failure")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	if _, exists := vault.secrets[ref]; exists {
		return TokenMetadata{}, errors.New("raw token already exists")
	}
	vault.secrets[ref] = uiFakeSecret{version: 1, material: append([]byte(nil), material...)}
	metadata := TokenMetadata{SecretRef: ref, Version: "version-1"}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
}

func (vault *uiFakeVault) Rotate(_ context.Context, ref, expectedVersion string, material []byte, operation string) (TokenMetadata, error) {
	if !strings.HasPrefix(ref, "vault/cloudflare/") || len(material) == 0 {
		return TokenMetadata{}, errors.New("raw Vault failure")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	secret, ok := vault.secrets[ref]
	if !ok || expectedVersion != versionName(secret.version) {
		return TokenMetadata{}, ErrTokenStale
	}
	secret.version++
	secret.material = append([]byte(nil), material...)
	vault.secrets[ref] = secret
	metadata := TokenMetadata{SecretRef: ref, Version: versionName(secret.version)}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
}

func (vault *uiFakeVault) Reveal(_ context.Context, ref string) ([]byte, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	secret, ok := vault.secrets[ref]
	if !ok {
		return nil, errors.New("raw missing token")
	}
	return append([]byte(nil), secret.material...), nil
}

func versionName(version int) string {
	return "version-" + strconv.Itoa(version)
}

type uiInspector struct{ vault *uiFakeVault }

func (inspector uiInspector) Inspect(_ context.Context, operation string) (OperationOutcome, error) {
	inspector.vault.mu.Lock()
	token, exists := inspector.vault.operations[operation]
	inspector.vault.mu.Unlock()
	if exists {
		return OperationOutcome{State: OperationCommitted, Token: token}, nil
	}
	return OperationOutcome{State: OperationAbsent}, nil
}

type uiFakeDNS struct{}

func (uiFakeDNS) Inspect(context.Context, string) (OperationOutcome, error) {
	return OperationOutcome{State: OperationAbsent}, nil
}
func (uiFakeDNS) ListZones(context.Context, TokenAttestation, string) ([]Zone, error) {
	return nil, nil
}
func (uiFakeDNS) ListRecords(context.Context, TokenAttestation, string, int) ([]DNSRecord, error) {
	return nil, nil
}
func (uiFakeDNS) Create(context.Context, TokenAttestation, DNSRecord, string) (DNSRecord, error) {
	return DNSRecord{}, errors.New("dns records are not the mapping UI")
}
func (uiFakeDNS) Update(context.Context, TokenAttestation, DNSRecord, string) (DNSRecord, error) {
	return DNSRecord{}, errors.New("dns records are not the mapping UI")
}
func (uiFakeDNS) Delete(context.Context, TokenAttestation, string, string, string) error {
	return errors.New("dns records are not the mapping UI")
}

func TestDomesticRecordRoutesUseFakeProviderAndHideCredentials(t *testing.T) {
	t.Parallel()
	fake := newDomesticFake()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	service, _, _ := newUIHarness(t, nil)
	client := newProviderDNSClient(map[string]string{
		ProviderAliyun: server.URL, ProviderDNSPodCN: server.URL, ProviderDNSPodCOM: server.URL, ProviderTencentDNS: server.URL,
	})
	client.now = func() time.Time { return time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC) }
	client.nonce = func() string { return "nonce-fixed" }
	service.domestic = client

	secrets := map[string]string{
		ProviderAliyun:     "exampleAccessKeySecretValue",
		ProviderDNSPodCN:   "exampleDnspodCnTokenValue",
		ProviderDNSPodCOM:  "exampleDnspodComTokenValue",
		ProviderTencentDNS: "exampleTencentSecretKeyValue",
	}
	creates := map[string]string{
		ProviderAliyun:     `{"suffix":"aliyun.test","provider":"aliyun","access_key_id":"LTAIexampleAccessKeyId","access_key_secret":"exampleAccessKeySecretValue"}`,
		ProviderDNSPodCN:   `{"suffix":"cn.test","provider":"dnspod-cn","token_id":"10001","token":"exampleDnspodCnTokenValue"}`,
		ProviderDNSPodCOM:  `{"suffix":"com.test","provider":"dnspod-com","token_id":"20002","token":"exampleDnspodComTokenValue"}`,
		ProviderTencentDNS: `{"suffix":"tencent.test","provider":"tencent-dns","secret_id":"AKIDexampleSecretId","secret_key":"exampleTencentSecretKeyValue"}`,
	}
	for provider, payload := range creates {
		created := httptest.NewRecorder()
		service.ServeHTTP(created, uiJSONRequest(http.MethodPost, "/api/mappings", payload, "operation/create-"+provider))
		if created.Code != http.StatusOK || strings.Contains(created.Body.String(), secrets[provider]) || strings.Contains(created.Body.String(), `"token"`) || !strings.Contains(created.Body.String(), `"provider":"`+provider+`"`) {
			t.Fatalf("create %s status=%d body=%s", provider, created.Code, created.Body.String())
		}
		fake.mu.Lock()
		fake.secret = secrets[provider]
		fake.accessKey = map[string]string{ProviderAliyun: "LTAIexampleAccessKeyId", ProviderDNSPodCN: "10001", ProviderDNSPodCOM: "20002", ProviderTencentDNS: "AKIDexampleSecretId"}[provider]
		fake.mu.Unlock()
		zone := strings.TrimPrefix(provider, "dnspod-")
		domain := map[string]string{ProviderAliyun: "www.aliyun.test", ProviderDNSPodCN: "www.cn.test", ProviderDNSPodCOM: "www.com.test", ProviderTencentDNS: "www.tencent.test"}[provider]
		suffix := map[string]string{ProviderAliyun: "aliyun.test", ProviderDNSPodCN: "cn.test", ProviderDNSPodCOM: "com.test", ProviderTencentDNS: "tencent.test"}[provider]
		_ = zone
		ensureBody := `{"domain":"` + domain + `","type":"A","name":"` + domain + `","content":"192.0.2.10","ttl":120}`
		fake.resetCalls()
		first := postRecord(t, service, internalDNSEnsurePath, ensureBody, "operation/ensure-"+provider)
		if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"outcome":"created"`) || strings.Contains(first.Body.String(), secrets[provider]) {
			t.Fatalf("ensure %s status=%d body=%s calls=%v", provider, first.Code, first.Body.String(), fake.actions())
		}
		if !fake.sawMutation(provider) {
			t.Fatalf("ensure %s did not write: %v", provider, fake.actions())
		}
		fake.resetCalls()
		second := postRecord(t, service, internalDNSEnsurePath, ensureBody, "operation/ensure-same-"+provider)
		if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"outcome":"unchanged"`) || fake.sawMutation(provider) {
			t.Fatalf("unchanged %s status=%d body=%s calls=%v", provider, second.Code, second.Body.String(), fake.actions())
		}
		fake.failSecret = secrets[provider]
		failed := postRecord(t, service, internalDNSEnsurePath, `{"domain":"`+domain+`","type":"A","name":"`+domain+`","content":"192.0.2.11","ttl":120}`, "operation/ensure-fail-"+provider)
		if failed.Code != http.StatusBadGateway || strings.Contains(failed.Body.String(), secrets[provider]) || strings.Contains(failed.Body.String(), suffix) && false {
			t.Fatalf("failure %s status=%d body=%s", provider, failed.Code, failed.Body.String())
		}
		if strings.Contains(failed.Body.String(), secrets[provider]) {
			t.Fatalf("failure leaked credential: %s", failed.Body.String())
		}
		fake.failSecret = ""
		listed := httptest.NewRecorder()
		service.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/list-"+provider))
		if strings.Contains(listed.Body.String(), secrets[provider]) {
			t.Fatalf("list leaked credential: %s", listed.Body.String())
		}
		resolved := httptest.NewRecorder()
		service.ServeHTTP(resolved, uiJSONRequest(http.MethodPost, internalDNSResolvePath, `{"domain":"`+domain+`"}`, "operation/resolve-"+provider))
		if resolved.Code != http.StatusOK || strings.Contains(resolved.Body.String(), `"token"`) || strings.Contains(resolved.Body.String(), secrets[provider]) || !strings.Contains(resolved.Body.String(), `"provider":"`+provider+`"`) {
			t.Fatalf("token %s status=%d body=%s", provider, resolved.Code, resolved.Body.String())
		}
	}

	cloudflare := httptest.NewRecorder()
	service.ServeHTTP(cloudflare, uiJSONRequest(http.MethodPost, "/api/mappings", `{"suffix":"example.com","token":"super-secret-cf-token-route"}`, "operation/create-cf-route"))
	if cloudflare.Code != http.StatusOK || strings.Contains(cloudflare.Body.String(), "super-secret-cf-token-route") {
		t.Fatalf("cloudflare create status=%d body=%s", cloudflare.Code, cloudflare.Body.String())
	}
	fake.resetCalls()
	blocked := postRecord(t, service, internalDNSEnsurePath, `{"domain":"www.example.com","type":"A","name":"www.example.com","content":"192.0.2.10","ttl":120}`, "operation/ensure-cf")
	if blocked.Code != http.StatusNotFound || len(fake.actions()) != 0 {
		t.Fatalf("cloudflare ensure status=%d calls=%v body=%s", blocked.Code, fake.actions(), blocked.Body.String())
	}
	missing := postRecord(t, service, internalDNSDeletePath, `{"domain":"unmapped.test","type":"TXT","name":"_acme-challenge.unmapped.test","content":"challenge"}`, "operation/delete-missing")
	if missing.Code != http.StatusNotFound || len(fake.actions()) != 0 {
		t.Fatalf("unmapped delete status=%d calls=%v", missing.Code, fake.actions())
	}

	txtEnsure := postRecord(t, service, internalDNSEnsurePath, `{"domain":"alias.aliyun.test","type":"TXT","name":"_acme-challenge.aliyun.test","content":"keep-me","ttl":120}`, "operation/ensure-txt-keep")
	if txtEnsure.Code != http.StatusOK {
		t.Fatalf("txt ensure status=%d body=%s", txtEnsure.Code, txtEnsure.Body.String())
	}
	other := postRecord(t, service, internalDNSEnsurePath, `{"domain":"alias.aliyun.test","type":"TXT","name":"_acme-challenge.aliyun.test","content":"drop-me","ttl":120}`, "operation/ensure-txt-drop")
	if other.Code != http.StatusOK {
		t.Fatalf("second txt status=%d body=%s", other.Code, other.Body.String())
	}
	fake.resetCalls()
	deleted := postRecord(t, service, internalDNSDeletePath, `{"domain":"alias.aliyun.test","type":"TXT","name":"_acme-challenge.aliyun.test","content":"drop-me"}`, "operation/delete-txt")
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"outcome":"deleted"`) || !fake.contains("DeleteDomainRecord") {
		t.Fatalf("delete status=%d body=%s calls=%v", deleted.Code, deleted.Body.String(), fake.actions())
	}
	if !fake.hasContent(ProviderAliyun, "aliyun.test", "TXT", "_acme-challenge", "keep-me") || fake.hasContent(ProviderAliyun, "aliyun.test", "TXT", "_acme-challenge", "drop-me") {
		t.Fatalf("delete matched the wrong txt: %#v", fake.snapshot())
	}
	rejected := postRecord(t, service, internalDNSDeletePath, `{"domain":"www.aliyun.test","type":"A","name":"www.aliyun.test","content":"192.0.2.10"}`, "operation/delete-a")
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("delete A status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func postRecord(t *testing.T, service *Service, path, body, operation string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	service.ServeHTTP(recorder, uiJSONRequest(http.MethodPost, path, body, operation))
	return recorder
}

type domesticFake struct {
	mu         sync.Mutex
	calls      []string
	records    map[string][]providerRecord
	secret     string
	accessKey  string
	failSecret string
	nextID     int
}

func newDomesticFake() *domesticFake {
	return &domesticFake{records: map[string][]providerRecord{}}
}

func (fake *domesticFake) resetCalls() {
	fake.mu.Lock()
	fake.calls = nil
	fake.mu.Unlock()
}

func (fake *domesticFake) actions() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]string(nil), fake.calls...)
}

func (fake *domesticFake) sawMutation(provider string) bool {
	for _, action := range fake.actions() {
		switch action {
		case provider + ":AddDomainRecord", provider + ":UpdateDomainRecord", provider + ":Record.Create", provider + ":Record.Modify", provider + ":CreateRecord", provider + ":ModifyRecord":
			return true
		}
	}
	return false
}

func (fake *domesticFake) contains(action string) bool {
	for _, current := range fake.actions() {
		if strings.Contains(current, action) {
			return true
		}
	}
	return false
}

func (fake *domesticFake) hasContent(provider, zone, recordType, name, content string) bool {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, record := range fake.records[fake.key(provider, zone, recordType, name)] {
		if record.Content == content {
			return true
		}
	}
	return false
}

func (fake *domesticFake) snapshot() map[string][]providerRecord {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.records
}

func (fake *domesticFake) key(provider, zone, recordType, name string) string {
	return provider + "|" + zone + "|" + strings.ToLower(recordType) + "|" + strings.ToLower(name)
}

func (fake *domesticFake) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	writer.Header().Set("Content-Type", "application/json")
	if request.Header.Get("X-TC-Action") != "" {
		fake.serveTencent(writer, request, body)
		return
	}
	if strings.Contains(request.URL.Path, "Record.") {
		fake.serveDNSPod(writer, request, body)
		return
	}
	fake.serveAliyun(writer, request, body)
}

func (fake *domesticFake) note(provider, action, raw string) {
	fake.calls = append(fake.calls, provider+":"+action)
	if fake.secret != "" && strings.Contains(raw, fake.secret) && provider != ProviderDNSPodCN && provider != ProviderDNSPodCOM {
		fake.calls = append(fake.calls, "leaked-secret")
	}
}

func (fake *domesticFake) serveAliyun(writer http.ResponseWriter, request *http.Request, body []byte) {
	values, _ := url.ParseQuery(string(body))
	action := values.Get("Action")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.note(ProviderAliyun, action, string(body))
	if values.Get("Version") != aliyunEndpointVersion || values.Get("AccessKeyId") == "" || strings.Contains(string(body), "exampleAccessKeySecretValue") {
		http.Error(writer, `{"Code":"BadSignature","Message":"rejected"}`, http.StatusBadRequest)
		return
	}
	parsed := url.Values{}
	for key, list := range values {
		parsed[key] = append([]string(nil), list...)
	}
	if values.Get("Signature") != aliyunSignature(http.MethodPost, "exampleAccessKeySecretValue", parsed) {
		http.Error(writer, `{"Code":"SignatureDoesNotMatch","Message":"rejected"}`, http.StatusForbidden)
		return
	}
	if fake.failSecret != "" && action != "DescribeDomainRecords" {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"Code":"Denied","Message":"rejected ` + fake.failSecret + `"}`))
		return
	}
	zone, name, recordType := values.Get("DomainName"), values.Get("RR"), values.Get("Type")
	switch action {
	case "DescribeDomainRecords":
		records := fake.records[fake.key(ProviderAliyun, values.Get("DomainName"), values.Get("TypeKeyWord"), values.Get("RRKeyWord"))]
		payload := map[string]any{"TotalCount": len(records), "DomainRecords": map[string]any{"Record": fake.aliyunRecords(records)}}
		_ = json.NewEncoder(writer).Encode(payload)
	case "AddDomainRecord":
		fake.nextID++
		record := providerRecord{ID: strconv.Itoa(fake.nextID), Type: recordType, Name: name, Content: values.Get("Value")}
		key := fake.key(ProviderAliyun, zone, recordType, name)
		fake.records[key] = append(fake.records[key], record)
		_ = json.NewEncoder(writer).Encode(map[string]string{"RecordId": record.ID})
	case "UpdateDomainRecord":
		key := fake.key(ProviderAliyun, zone, recordType, name)
		replaced := false
		for index, record := range fake.records[key] {
			if record.ID == values.Get("RecordId") {
				record.Content = values.Get("Value")
				fake.records[key][index] = record
				replaced = true
			}
		}
		if !replaced {
			http.Error(writer, `{"Code":"DomainRecordNotBelongToUser","Message":"missing"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"RecordId": values.Get("RecordId")})
	case "DeleteDomainRecord":
		fake.deleteByID(ProviderAliyun, values.Get("RecordId"))
		_ = json.NewEncoder(writer).Encode(map[string]string{"RecordId": values.Get("RecordId")})
	default:
		http.Error(writer, `{"Code":"InvalidAction","Message":"unexpected"}`, http.StatusBadRequest)
	}
}

func (fake *domesticFake) aliyunRecords(records []providerRecord) []map[string]string {
	if len(records) == 0 {
		return nil
	}
	result := make([]map[string]string, len(records))
	for index, record := range records {
		result[index] = map[string]string{"RecordId": record.ID, "RR": record.Name, "Type": record.Type, "Value": record.Content}
	}
	return result
}

func (fake *domesticFake) serveDNSPod(writer http.ResponseWriter, request *http.Request, body []byte) {
	values, _ := url.ParseQuery(string(body))
	action := strings.TrimPrefix(request.URL.Path, "/")
	provider := ProviderDNSPodCN
	if values.Get("lang") == "en" {
		provider = ProviderDNSPodCOM
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.note(provider, action, string(body))
	token := values.Get("login_token")
	if !strings.Contains(token, ",") || values.Get("format") != "json" {
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "8", "message": "missing token"}})
		return
	}
	if fake.failSecret != "" && action != "Record.List" && strings.Contains(token, fake.failSecret) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "8", "message": "rejected " + fake.failSecret}})
		return
	}
	zone, name, recordType := values.Get("domain"), values.Get("sub_domain"), values.Get("record_type")
	switch action {
	case "Record.List":
		records := fake.records[fake.key(provider, zone, recordType, name)]
		if len(records) == 0 {
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "10", "message": "empty"}})
			return
		}
		listed := make([]map[string]string, len(records))
		for index, record := range records {
			listed[index] = map[string]string{"id": record.ID, "name": record.Name, "type": record.Type, "value": record.Content, "line": record.Line}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "1", "message": "ok"}, "records": listed})
	case "Record.Create":
		fake.nextID++
		record := providerRecord{ID: strconv.Itoa(fake.nextID), Type: recordType, Name: name, Content: values.Get("value"), Line: values.Get("record_line")}
		key := fake.key(provider, zone, recordType, name)
		fake.records[key] = append(fake.records[key], record)
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "1", "message": "ok"}, "record": map[string]string{"id": record.ID}})
	case "Record.Modify":
		key := fake.key(provider, zone, recordType, name)
		for index, record := range fake.records[key] {
			if record.ID == values.Get("record_id") {
				record.Content = values.Get("value")
				fake.records[key][index] = record
				_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "1", "message": "ok"}})
				return
			}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "8", "message": "missing"}})
	case "Record.Remove":
		fake.deleteByID(provider, values.Get("record_id"))
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "1", "message": "ok"}})
	default:
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": map[string]string{"code": "8", "message": "unexpected"}})
	}
}

func (fake *domesticFake) serveTencent(writer http.ResponseWriter, request *http.Request, body []byte) {
	action := request.Header.Get("X-TC-Action")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.note(ProviderTencentDNS, action, string(body)+" "+request.Header.Get("Authorization"))
	if strings.Contains(string(body), "exampleTencentSecretKeyValue") || request.Header.Get("X-TC-Version") != tencentDNSVersion {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure","Message":"rejected"},"RequestId":"req"}}`))
		return
	}
	want := tencentAuthorization("AKIDexampleSecretId", "exampleTencentSecretKeyValue", request.Host, request.Header.Get("X-TC-Timestamp"), body)
	if request.Header.Get("Authorization") != want {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"rejected"},"RequestId":"req"}}`))
		return
	}
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if fake.failSecret != "" && action != "DescribeRecordList" {
		_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"Error": map[string]string{"Code": "AuthFailure", "Message": "rejected " + fake.failSecret}, "RequestId": "req"}})
		return
	}
	zone, _ := payload["Domain"].(string)
	name, _ := payload["SubDomain"].(string)
	if action == "DescribeRecordList" {
		if text, ok := payload["Subdomain"].(string); ok {
			name = text
		}
	}
	recordType, _ := payload["RecordType"].(string)
	switch action {
	case "DescribeRecordList":
		records := fake.records[fake.key(ProviderTencentDNS, zone, recordType, name)]
		if len(records) == 0 {
			_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"Error": map[string]string{"Code": "ResourceNotFound.NoDataOfRecord", "Message": "empty"}, "RequestId": "req"}})
			return
		}
		listed := make([]map[string]any, len(records))
		for index, record := range records {
			id, _ := strconv.Atoi(record.ID)
			listed[index] = map[string]any{"RecordId": id, "Name": record.Name, "Type": record.Type, "Value": record.Content, "Line": record.Line}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"RecordList": listed, "RecordCountInfo": map[string]int{"TotalCount": len(records)}, "RequestId": "req"}})
	case "CreateRecord":
		fake.nextID++
		value, _ := payload["Value"].(string)
		line, _ := payload["RecordLine"].(string)
		record := providerRecord{ID: strconv.Itoa(fake.nextID), Type: recordType, Name: name, Content: value, Line: line}
		key := fake.key(ProviderTencentDNS, zone, recordType, name)
		fake.records[key] = append(fake.records[key], record)
		id, _ := strconv.Atoi(record.ID)
		_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"RecordId": id, "RequestId": "req"}})
	case "ModifyRecord":
		key := fake.key(ProviderTencentDNS, zone, recordType, name)
		id := fmtID(payload["RecordId"])
		for index, record := range fake.records[key] {
			if record.ID == id {
				record.Content, _ = payload["Value"].(string)
				fake.records[key][index] = record
				_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"RecordId": payload["RecordId"], "RequestId": "req"}})
				return
			}
		}
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"Response":{"Error":{"Code":"ResourceNotFound","Message":"missing"},"RequestId":"req"}}`))
	case "DeleteRecord":
		fake.deleteByID(ProviderTencentDNS, fmtID(payload["RecordId"]))
		_ = json.NewEncoder(writer).Encode(map[string]any{"Response": map[string]any{"RequestId": "req"}})
	default:
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"Response":{"Error":{"Code":"InvalidAction","Message":"unexpected"},"RequestId":"req"}}`))
	}
}

func (fake *domesticFake) deleteByID(provider, id string) {
	for key, records := range fake.records {
		if !strings.HasPrefix(key, provider+"|") {
			continue
		}
		kept := records[:0]
		for _, record := range records {
			if record.ID != id {
				kept = append(kept, record)
			}
		}
		fake.records[key] = kept
	}
}

func fmtID(value any) string {
	switch typed := value.(type) {
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case string:
		return typed
	default:
		return ""
	}
}
