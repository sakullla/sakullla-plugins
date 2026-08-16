package cloudflaredns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMappingUIAuthorizedCRUDPersistsAcrossRefresh(t *testing.T) {
	t.Parallel()
	service, trace := newUIService(t, nil)
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
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `data-suffix="example.com"`) {
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

	restarted := newMappingHandler(service)
	refreshed := httptest.NewRecorder()
	restarted.ServeHTTP(refreshed, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-list"))
	if refreshed.Code != http.StatusOK || !strings.Contains(refreshed.Body.String(), `"suffix":"other.test"`) || strings.Contains(refreshed.Body.String(), "rotated-secret-cf-token-ui") {
		t.Fatalf("restarted list=%s status=%d", refreshed.Body.String(), refreshed.Code)
	}

	deleted := httptest.NewRecorder()
	service.ServeHTTP(deleted, uiJSONRequest(http.MethodPost, "/api/mappings/other.test/delete", `{"confirm":"other.test"}`, "operation/ui-delete"))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	empty := httptest.NewRecorder()
	service.ServeHTTP(empty, uiRequest(http.MethodGet, "/api/mappings", "", "operation/ui-list-empty"))
	if empty.Code != http.StatusOK || strings.Contains(empty.Body.String(), `"suffix"`) {
		t.Fatalf("after delete list=%s", empty.Body.String())
	}
	assertUITraceRedacted(t, trace, []string{"super-secret-cf-token-ui", "rotated-secret-cf-token-ui"})
}

func TestMappingUIUnauthorizedIsExplicitRejection(t *testing.T) {
	t.Parallel()
	service, _ := newUIService(t, func(action ActionContext) error { return errors.New("raw denied") })
	page := httptest.NewRecorder()
	service.ServeHTTP(page, uiRequest(http.MethodGet, "/", "", "operation/ui-denied"))
	if page.Code != http.StatusForbidden {
		t.Fatalf("denied page status=%d", page.Code)
	}
	body := page.Body.String()
	if body == "" || !strings.Contains(body, "明确拒绝") || !strings.Contains(body, `id="mapping-denied"`) {
		t.Fatalf("denied page was blank or unclear: %q", body)
	}
	if strings.Contains(body, `id="mapping-create"`) || strings.Contains(body, `data-action="delete"`) {
		t.Fatal("denied page still exposes write entry")
	}

	anonymous := httptest.NewRecorder()
	service.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code != http.StatusForbidden || !strings.Contains(anonymous.Body.String(), "明确拒绝") {
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
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "example.com") {
		t.Fatalf("readonly page status=%d body=%s", page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), `id="mapping-create"`) || strings.Contains(page.Body.String(), `data-action="delete"`) || strings.Contains(page.Body.String(), `data-action="rotate"`) {
		t.Fatal("read-only page still shows write entry")
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
	if err != nil || !bytes.Contains(script, []byte("取消不会更改映射")) || !bytes.Contains(script, []byte("window.confirm")) {
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
	for _, route := range []string{"/app.js", "/style.css"} {
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
			t.Fatalf("asset %s status=%d", route, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "http://") || strings.Contains(recorder.Body.String(), "https://") {
			t.Fatalf("asset %s has external dependency", route)
		}
	}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	inactive := httptest.NewRecorder()
	controller.ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "/", nil))
	if inactive.Code != http.StatusServiceUnavailable || !strings.Contains(inactive.Body.String(), "unavailable") || inactive.Body.Len() == 0 {
		t.Fatalf("inactive controller status=%d body=%s", inactive.Code, inactive.Body.String())
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

func newMappingHandler(service *Service) http.Handler {
	return service
}

func uiRequest(method, path, body, operation string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set(mappingActorHeader, "actor/admin")
	request.Header.Set(mappingGroupHeader, "group/main")
	request.Header.Set(mappingOperationHeader, operation)
	return request
}

func uiJSONRequest(method, path, body, operation string) *http.Request {
	request := uiRequest(method, path, body, operation)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func uiAction(operation string) ActionRequest {
	return ActionRequest{Actor: "actor/admin", ResourceGroupRef: "group/main", OperationKey: operation}
}

func newUIService(t *testing.T, authorize func(ActionContext) error) (*Service, *uiTrace) {
	t.Helper()
	if authorize == nil {
		authorize = func(ActionContext) error { return nil }
	}
	vault := newUIVault()
	trace := &uiTrace{}
	service, err := NewService(Configuration{Generation: "generation-1", SecretRef: "vault/cloudflare", ResourceGroupRef: "group/main"}, RuntimeAdapters{
		Vault:      vault,
		DNS:        uiFakeDNS{},
		Operations: uiInspector{vault: vault},
		Lease:      GenerationLeaseFunc(func() {}),
		Authorizer: AuthorizerFunc(func(_ context.Context, action ActionContext) error { return authorize(action) }),
		UI:         DynamicUIFunc(func(_ context.Context, projection UIProjection) error { trace.addUI(projection); return nil }),
		Auditor:    AuditorFunc(func(_ context.Context, record AuditRecord) error { trace.addAudit(record); return nil }),
		Logger:     EventLoggerFunc(func(_ context.Context, record EventRecord) error { trace.addLog(record); return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, trace
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
	mu         sync.Mutex
	operations map[string]TokenMetadata
	secrets    map[string]uiFakeSecret
	effects    atomic.Int32
}

func newUIVault() *uiFakeVault {
	return &uiFakeVault{operations: map[string]TokenMetadata{}, secrets: map[string]uiFakeSecret{}}
}

func (vault *uiFakeVault) Verify(_ context.Context, ref string) (TokenAttestation, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	secret, ok := vault.secrets[ref]
	if !ok {
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
