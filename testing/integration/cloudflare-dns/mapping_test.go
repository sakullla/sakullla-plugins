package cloudflaredns_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cloudflaredns "github.com/sakullla/sakullla-plugins/plugins/cloudflare-dns"
)

func TestMappingDifferentAndSharedTokenRefs(t *testing.T) {
	service, trace := newMappingService(t)
	first, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-alpha"))
	if err != nil || first.Suffix != "example.com" || first.SecretRef == "" || first.SecretRef == "vault/cloudflare" || !first.Configured {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := service.CreateMapping(context.Background(), validAction(""), "other.test", []byte("token-beta"))
	if err != nil || second.SecretRef == first.SecretRef {
		t.Fatalf("second=%#v first=%#v err=%v", second, first, err)
	}
	shared, err := service.ShareMapping(context.Background(), validAction(""), "shared.test", "example.com")
	if err != nil || shared.SecretRef != first.SecretRef || shared.Version != first.Version {
		t.Fatalf("shared=%#v first=%#v err=%v", shared, first, err)
	}
	alpha, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer alpha.Clear()
	beta, err := service.ResolveToken(context.Background(), validAction(""), "other.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer beta.Clear()
	same, err := service.ResolveToken(context.Background(), validAction(""), "api.shared.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer same.Clear()
	if !bytes.Equal(alpha.Token(), []byte("token-alpha")) || !bytes.Equal(beta.Token(), []byte("token-beta")) || !bytes.Equal(same.Token(), []byte("token-alpha")) {
		t.Fatalf("tokens alpha=%q beta=%q shared=%q", alpha.Token(), beta.Token(), same.Token())
	}
	if alpha.SecretRef != first.SecretRef || same.SecretRef != first.SecretRef || beta.SecretRef != second.SecretRef {
		t.Fatalf("resolved refs alpha=%q beta=%q shared=%q", alpha.SecretRef, beta.SecretRef, same.SecretRef)
	}
	assertNoTokenPlaintext(t, trace, []string{"token-alpha", "token-beta"})
}

func TestLongestSuffixResolution(t *testing.T) {
	service, _ := newMappingService(t)
	if _, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-root")); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"example.com", "www.example.com", "Example.COM."} {
		resolved, err := service.ResolveToken(context.Background(), validAction(""), domain, []byte("token-fallback"))
		if err != nil {
			t.Fatalf("domain %q err=%v", domain, err)
		}
		if resolved.Fallback || resolved.Suffix != "example.com" || !bytes.Equal(resolved.Token(), []byte("token-root")) {
			t.Fatalf("domain %q resolved=%#v token=%q", domain, resolved, resolved.Token())
		}
		resolved.Clear()
	}
	if _, err := service.CreateMapping(context.Background(), validAction(""), "api.example.com", []byte("token-api")); err != nil {
		t.Fatal(err)
	}
	api, err := service.ResolveToken(context.Background(), validAction(""), "api.example.com", []byte("token-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Clear()
	www, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", []byte("token-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	defer www.Clear()
	if api.Suffix != "api.example.com" || !bytes.Equal(api.Token(), []byte("token-api")) || api.Fallback {
		t.Fatalf("api=%#v token=%q", api, api.Token())
	}
	if www.Suffix != "example.com" || !bytes.Equal(www.Token(), []byte("token-root")) || www.Fallback {
		t.Fatalf("www=%#v token=%q", www, www.Token())
	}
}

func TestNonSuffixAndDuplicateNormalizedRejected(t *testing.T) {
	service, _ := newMappingService(t)
	created, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-root"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := validAction("")
	duplicate.OperationKey = "operation/duplicate-suffix"
	if _, err := service.CreateMapping(context.Background(), duplicate, "Example.COM.", []byte("token-other")); !errors.Is(err, cloudflaredns.ErrMappingConflict) {
		t.Fatalf("duplicate err=%v", err)
	}
	listed, err := service.ListMappings(context.Background(), validAction(""))
	if err != nil || len(listed) != 1 || listed[0].Suffix != created.Suffix || listed[0].SecretRef != created.SecretRef {
		t.Fatalf("list after duplicate=%#v err=%v", listed, err)
	}
	for _, domain := range []string{"notexample.com", "other.test", "example.com.evil.test"} {
		if _, err := service.LookupMapping(context.Background(), validAction(""), domain); !errors.Is(err, cloudflaredns.ErrMappingNotFound) {
			t.Fatalf("lookup %q err=%v", domain, err)
		}
		fallback := []byte("token-fallback")
		resolved, err := service.ResolveToken(context.Background(), validAction(""), domain, fallback)
		if err != nil || !resolved.Fallback || !bytes.Equal(resolved.Token(), []byte("token-fallback")) || resolved.SecretRef != "" {
			t.Fatalf("resolve %q = %#v token=%q err=%v", domain, resolved, resolved.Token(), err)
		}
		resolved.Clear()
		for _, value := range fallback {
			if value != 0 {
				t.Fatalf("fallback retained for %q", domain)
			}
		}
	}
}

func TestResolveUsesMappingNotGlobalSecretRef(t *testing.T) {
	service, _ := newMappingService(t)
	mapping, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("mapping-token"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveToken(context.Background(), validAction(""), "cdn.example.com", []byte("env-global-token"))
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if resolved.SecretRef == "vault/cloudflare" || resolved.SecretRef != mapping.SecretRef || resolved.Fallback {
		t.Fatalf("resolved=%#v mapping=%#v", resolved, mapping)
	}
	if !bytes.Equal(resolved.Token(), []byte("mapping-token")) || bytes.Equal(resolved.Token(), []byte("vault-only-token-material")) {
		t.Fatalf("token=%q", resolved.Token())
	}
}

func TestResolveAfterDeleteAndRotate(t *testing.T) {
	service, _ := newMappingService(t)
	if _, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-before")); err != nil {
		t.Fatal(err)
	}
	rotated, err := service.RotateMappingToken(context.Background(), validAction(""), "example.com", []byte("token-after"))
	if err != nil || rotated.Version == "version-1" {
		t.Fatalf("rotate=%#v err=%v", rotated, err)
	}
	afterRotate, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", []byte("token-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRotate.Token(), []byte("token-after")) || afterRotate.Fallback || afterRotate.Version != rotated.Version {
		t.Fatalf("after rotate=%#v token=%q", afterRotate, afterRotate.Token())
	}
	afterRotate.Clear()
	if err := service.DeleteMapping(context.Background(), validAction(""), "example.com"); err != nil {
		t.Fatal(err)
	}
	afterDelete, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", []byte("token-fallback"))
	if err != nil || !afterDelete.Fallback || !bytes.Equal(afterDelete.Token(), []byte("token-fallback")) {
		t.Fatalf("after delete=%#v token=%q err=%v", afterDelete, afterDelete.Token(), err)
	}
	afterDelete.Clear()
	recreate := validAction("")
	recreated, err := service.CreateMapping(context.Background(), recreate, "example.com", []byte("token-recreated"))
	if err != nil || recreated.SecretRef == "" {
		t.Fatalf("recreate=%#v err=%v", recreated, err)
	}
	afterRecreate, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", []byte("token-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if afterRecreate.Fallback || !bytes.Equal(afterRecreate.Token(), []byte("token-recreated")) || afterRecreate.SecretRef != recreated.SecretRef {
		t.Fatalf("after recreate=%#v token=%q", afterRecreate, afterRecreate.Token())
	}
	afterRecreate.Clear()
}

func TestCreateMappingRetryKeepsCommittedIdentity(t *testing.T) {
	service, _ := newMappingService(t)
	create := validAction("")
	create.OperationKey = "operation/create-example"
	first, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-first"))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-retry"))
	if err != nil || retry.SecretRef != first.SecretRef || retry.Version != first.Version {
		t.Fatalf("retry=%#v first=%#v err=%v", retry, first, err)
	}
	resolved, err := service.ResolveToken(context.Background(), validAction(""), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if !bytes.Equal(resolved.Token(), []byte("token-first")) {
		t.Fatalf("retry resolved token=%q", resolved.Token())
	}
}

func TestCreateAfterDeleteRebindsVaultIdentity(t *testing.T) {
	service, _ := newMappingService(t)
	create := validAction("")
	create.OperationKey = "operation/create-example"
	first, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-before"))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteMapping(context.Background(), validAction(""), "example.com"); err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-after"))
	if err != nil || second.SecretRef == "" || second.SecretRef == first.SecretRef {
		t.Fatalf("second=%#v first=%#v err=%v", second, first, err)
	}
	resolved, err := service.ResolveToken(context.Background(), validAction(""), "example.com", []byte("token-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if resolved.Fallback || !bytes.Equal(resolved.Token(), []byte("token-after")) || resolved.SecretRef != second.SecretRef {
		t.Fatalf("resolved=%#v token=%q", resolved, resolved.Token())
	}
}

func TestCreateAfterRenameRebindsVacatedSuffix(t *testing.T) {
	service, _ := newMappingService(t)
	create := validAction("")
	create.OperationKey = "operation/create-example"
	first, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-original"))
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := service.RenameMapping(context.Background(), validAction(""), "example.com", "other.test")
	if err != nil || renamed.SecretRef != first.SecretRef {
		t.Fatalf("rename=%#v first=%#v err=%v", renamed, first, err)
	}
	second, err := service.CreateMapping(context.Background(), create, "example.com", []byte("token-new"))
	if err != nil || second.SecretRef == "" || second.SecretRef == first.SecretRef {
		t.Fatalf("second=%#v first=%#v err=%v", second, first, err)
	}
	original, err := service.ResolveToken(context.Background(), validAction(""), "www.other.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Clear()
	recreated, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recreated.Clear()
	if !bytes.Equal(original.Token(), []byte("token-original")) || !bytes.Equal(recreated.Token(), []byte("token-new")) {
		t.Fatalf("original=%q recreated=%q", original.Token(), recreated.Token())
	}
}

func TestMappingWriteAfterCancelFailsClosed(t *testing.T) {
	vault := newFakeVault()
	started, release := make(chan struct{}), make(chan struct{})
	capture := materialCaptureVault{fakeVault: vault, started: started, release: release, observed: make(chan string, 1)}
	service := newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{
		Vault:      capture,
		DNS:        newFakeDNS(vault),
		Operations: fakeInspector{vault: vault},
		Lease:      cloudflaredns.GenerationLeaseFunc(func() {}),
		Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }),
		UI:         cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error { return nil }),
		Auditor:    cloudflaredns.AuditorFunc(func(context.Context, cloudflaredns.AuditRecord) error { return nil }),
		Logger:     cloudflaredns.EventLoggerFunc(func(context.Context, cloudflaredns.EventRecord) error { return nil }),
	})
	result := make(chan error, 1)
	go func() {
		_, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-inflight"))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("mapping enroll did not start")
	}
	service.Cancel()
	close(release)
	if err := <-result; !errors.Is(err, cloudflaredns.ErrRevoked) && !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight create after cancel err=%v", err)
	}
	if _, err := service.CreateMapping(context.Background(), validAction(""), "other.test", []byte("token-late")); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("create after cancel err=%v", err)
	}
	if _, err := service.ShareMapping(context.Background(), validAction(""), "shared.test", "example.com"); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("share after cancel err=%v", err)
	}
	if _, err := service.RenameMapping(context.Background(), validAction(""), "example.com", "renamed.test"); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("rename after cancel err=%v", err)
	}
	if _, err := service.RotateMappingToken(context.Background(), validAction(""), "example.com", []byte("token-rotate")); !errors.Is(err, cloudflaredns.ErrRevoked) {
		t.Fatalf("rotate after cancel err=%v", err)
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatalf("close after cancel err=%v", err)
	}
}

func TestResolveFallbackOnlyOnMiss(t *testing.T) {
	service, _ := newMappingService(t)
	if _, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-mapped")); err != nil {
		t.Fatal(err)
	}
	hitFallback := []byte("token-fallback")
	hit, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", hitFallback)
	if err != nil {
		t.Fatal(err)
	}
	defer hit.Clear()
	if hit.Fallback || !bytes.Equal(hit.Token(), []byte("token-mapped")) {
		t.Fatalf("hit used fallback: %#v token=%q", hit, hit.Token())
	}
	for _, value := range hitFallback {
		if value != 0 {
			t.Fatal("hit fallback retained")
		}
	}
	missFallback := []byte("token-fallback")
	miss, err := service.ResolveToken(context.Background(), validAction(""), "other.test", missFallback)
	if err != nil {
		t.Fatal(err)
	}
	defer miss.Clear()
	if !miss.Fallback || !bytes.Equal(miss.Token(), []byte("token-fallback")) || miss.Suffix != "" {
		t.Fatalf("miss=%#v token=%q", miss, miss.Token())
	}
}

func TestResolveUnmappedWithoutFallbackFails(t *testing.T) {
	service, trace := newMappingService(t)
	_, err := service.ResolveToken(context.Background(), validAction(""), "missing.example", nil)
	if !errors.Is(err, cloudflaredns.ErrTokenUnavailable) || !strings.Contains(err.Error(), "missing.example") {
		t.Fatalf("unmapped err=%v", err)
	}
	if strings.Contains(err.Error(), "token-") || strings.Contains(err.Error(), "vault-only") {
		t.Fatalf("error leaked token: %v", err)
	}
	assertNoTokenPlaintext(t, trace, []string{"vault-only-token-material"})
}

func TestMappedTokenFailureDoesNotUseFallback(t *testing.T) {
	vault := newFakeVault()
	trace := &safeTrace{}
	service := newTestService(t, vault, newFakeDNS(vault), trace, nil)
	created, err := service.CreateMapping(context.Background(), validAction(""), "example.com", []byte("token-mapped"))
	if err != nil {
		t.Fatal(err)
	}
	vault.mu.Lock()
	delete(vault.secrets, created.SecretRef)
	vault.mu.Unlock()
	fallback := []byte("token-fallback")
	_, err = service.ResolveToken(context.Background(), validAction(""), "www.example.com", fallback)
	if !errors.Is(err, cloudflaredns.ErrMappedTokenUnavailable) {
		t.Fatalf("missing mapped token err=%v", err)
	}
	if strings.Contains(err.Error(), "token-mapped") || strings.Contains(err.Error(), "token-fallback") {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestMappingSurfacesRedactTokenMaterial(t *testing.T) {
	service, trace := newMappingService(t)
	material := []byte("super-secret-cf-token")
	created, err := service.CreateMapping(context.Background(), validAction(""), "example.com", material)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range material {
		if value != 0 {
			t.Fatal("create material retained")
		}
	}
	listed, err := service.ListMappings(context.Background(), validAction(""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.GetMapping(context.Background(), validAction(""), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	looked, err := service.LookupMapping(context.Background(), validAction(""), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveToken(context.Background(), validAction(""), "www.example.com", []byte("fallback-secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resolved.Token(), []byte("super-secret-cf-token")) {
		t.Fatalf("resolve token=%q", resolved.Token())
	}
	rotateMaterial := []byte("rotated-secret-cf-token")
	if _, err := service.RotateMappingToken(context.Background(), validAction(""), "example.com", rotateMaterial); err != nil {
		t.Fatal(err)
	}
	for _, value := range rotateMaterial {
		if value != 0 {
			t.Fatal("rotate material retained")
		}
	}
	if err := service.DeleteMapping(context.Background(), validAction(""), "Example.COM."); err != nil {
		t.Fatal(err)
	}
	configuration, status := service.Snapshot()
	wire, err := json.Marshal(struct {
		Created       cloudflaredns.TokenMapping
		Listed        []cloudflaredns.TokenMapping
		Got           cloudflaredns.TokenMapping
		Looked        cloudflaredns.TokenMapping
		Resolved      cloudflaredns.IssuedToken
		Configuration cloudflaredns.Configuration
		Status        cloudflaredns.TokenAttestation
		UI            []cloudflaredns.UIProjection
		Audit         []cloudflaredns.AuditRecord
		Log           []cloudflaredns.EventRecord
	}{created, listed, got, looked, resolved, configuration, status, trace.ui, trace.audit, trace.logs})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret-cf-token", "rotated-secret-cf-token", "fallback-secret-token"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("secret %q leaked: %s", secret, wire)
		}
	}
	resolved.Clear()
}

func TestUnauthorizedMappingWriteIsDenied(t *testing.T) {
	vault := newFakeVault()
	trace := &safeTrace{}
	service := newTestService(t, vault, newFakeDNS(vault), trace, func(action cloudflaredns.ActionContext) error {
		if action.Permission == cloudflaredns.PermissionVaultEnroll {
			return errors.New("raw mapping denied")
		}
		return nil
	})
	material := []byte("denied-secret-token")
	_, err := service.CreateMapping(context.Background(), validAction(""), "example.com", material)
	if !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) {
		t.Fatalf("create err=%v", err)
	}
	for _, value := range material {
		if value != 0 {
			t.Fatal("denied material retained")
		}
	}
	if strings.Contains(err.Error(), "denied-secret-token") {
		t.Fatal("authorization error leaked token")
	}
	listed, err := service.ListMappings(context.Background(), validAction(""))
	if err != nil || len(listed) != 0 {
		t.Fatalf("list=%#v err=%v", listed, err)
	}
	assertNoTokenPlaintext(t, trace, []string{"denied-secret-token", "raw mapping denied"})
}

func newMappingService(t *testing.T) (*cloudflaredns.Service, *safeTrace) {
	t.Helper()
	vault := newFakeVault()
	trace := &safeTrace{}
	return newTestService(t, vault, newFakeDNS(vault), trace, nil), trace
}

func assertNoTokenPlaintext(t *testing.T, trace *safeTrace, secrets []string) {
	t.Helper()
	wire, err := json.Marshal(struct {
		UI    []cloudflaredns.UIProjection
		Audit []cloudflaredns.AuditRecord
		Log   []cloudflaredns.EventRecord
	}{trace.ui, trace.audit, trace.logs})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("secret %q leaked: %s", secret, wire)
		}
	}
}
