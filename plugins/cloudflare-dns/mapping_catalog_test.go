package cloudflaredns

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestVaultCatalogLoadFailsClosedOnGenericVerify(t *testing.T) {
	t.Parallel()
	catalog := newVaultMappingCatalog(catalogVerifyVault{err: errors.New("raw vault down")}, "vault/cloudflare")
	_, err := catalog.Load(context.Background())
	if err == nil || errors.Is(err, ErrMappingCatalogNotFound) {
		t.Fatalf("load err=%v", err)
	}
	_, err = NewService(uiConfiguration(), uiRuntimeWithCatalog(t, catalog))
	if err == nil {
		t.Fatal("NewService accepted unrestored catalog")
	}
}

func TestVaultCatalogLoadEmptyOnNotFound(t *testing.T) {
	t.Parallel()
	catalog := newVaultMappingCatalog(catalogVerifyVault{err: ErrMappingCatalogNotFound}, "vault/cloudflare")
	snapshot, err := catalog.Load(context.Background())
	if err != nil || len(snapshot.Mappings) != 0 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestVaultCatalogSaveDoesNotRotateUnrestored(t *testing.T) {
	t.Parallel()
	vault := newUIVault()
	catalog := newVaultMappingCatalog(vault, "vault/cloudflare")
	service, err := NewService(uiConfiguration(), uiRuntimeWithCatalog(t, catalog))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateMapping(context.Background(), uiAction("operation/catalog-create"), "example.com", []byte("catalog-secret-token")); err != nil {
		t.Fatal(err)
	}
	original, err := vault.Reveal(context.Background(), mappingCatalogRef("vault/cloudflare"))
	if err != nil {
		t.Fatal(err)
	}
	unrestored := newVaultMappingCatalog(vault, "vault/cloudflare")
	if err := unrestored.Save(context.Background(), mappingCatalogSnapshot{}); err == nil {
		t.Fatal("unrestored save overwrote catalog")
	}
	current, err := vault.Reveal(context.Background(), mappingCatalogRef("vault/cloudflare"))
	if err != nil || !bytes.Equal(current, original) || !bytes.Contains(current, []byte("example.com")) {
		t.Fatalf("catalog mutated: %s err=%v", current, err)
	}
}

func TestMappingPersistFailureRollsBackAndRetiresEpoch(t *testing.T) {
	t.Parallel()
	failing := &failSaveCatalog{inner: newMemoryMappingCatalog(), fail: true}
	service, err := NewService(uiConfiguration(), uiRuntimeWithCatalog(t, failing))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateMapping(context.Background(), uiAction("operation/catalog-fail"), "example.com", []byte("persist-secret-token")); err == nil {
		t.Fatal("create succeeded after catalog save failure")
	}
	listed, err := service.ListMappings(context.Background(), uiAction("operation/catalog-list"))
	if err != nil || len(listed) != 0 {
		t.Fatalf("live mapping retained after persist failure: %#v err=%v", listed, err)
	}
	failing.fail = false
	created, err := service.CreateMapping(context.Background(), uiAction("operation/catalog-retry"), "example.com", []byte("persist-secret-token-2"))
	if err != nil {
		t.Fatal(err)
	}
	if created.SecretRef == "" || strings.Contains(created.SecretRef, "persist-secret") {
		t.Fatalf("created=%#v", created)
	}
	resolved, err := service.ResolveToken(context.Background(), uiAction("operation/catalog-resolve"), "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Clear()
	if !bytes.Equal(resolved.Token(), []byte("persist-secret-token-2")) {
		t.Fatalf("token=%q", resolved.Token())
	}
}

func uiRuntimeWithCatalog(t *testing.T, catalog mappingCatalog) RuntimeAdapters {
	t.Helper()
	vault := newUIVault()
	return RuntimeAdapters{
		Vault:      vault,
		DNS:        uiFakeDNS{},
		Operations: uiInspector{vault: vault},
		Lease:      GenerationLeaseFunc(func() {}),
		Authorizer: AuthorizerFunc(func(context.Context, ActionContext) error { return nil }),
		UI:         DynamicUIFunc(func(context.Context, UIProjection) error { return nil }),
		Auditor:    AuditorFunc(func(context.Context, AuditRecord) error { return nil }),
		Logger:     EventLoggerFunc(func(context.Context, EventRecord) error { return nil }),
		Catalog:    catalog,
	}
}

type catalogVerifyVault struct{ err error }

func (vault catalogVerifyVault) Verify(context.Context, string) (TokenAttestation, error) {
	return TokenAttestation{}, vault.err
}
func (vault catalogVerifyVault) Enroll(context.Context, string, []byte, string) (TokenMetadata, error) {
	return TokenMetadata{}, errors.New("raw unused")
}
func (vault catalogVerifyVault) Rotate(context.Context, string, string, []byte, string) (TokenMetadata, error) {
	return TokenMetadata{}, errors.New("raw unused")
}
func (vault catalogVerifyVault) Reveal(context.Context, string) ([]byte, error) {
	return nil, errors.New("raw unused")
}

type failSaveCatalog struct {
	inner mappingCatalog
	fail  bool
}

func (catalog *failSaveCatalog) Load(ctx context.Context) (mappingCatalogSnapshot, error) {
	if catalog.inner == nil {
		return mappingCatalogSnapshot{}, nil
	}
	return catalog.inner.Load(ctx)
}

func (catalog *failSaveCatalog) Save(ctx context.Context, snapshot mappingCatalogSnapshot) error {
	if catalog.fail {
		return errors.New("raw catalog save failed")
	}
	if catalog.inner == nil {
		return nil
	}
	return catalog.inner.Save(ctx, snapshot)
}
