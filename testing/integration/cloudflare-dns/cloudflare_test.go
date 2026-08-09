package cloudflaredns_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	cloudflaredns "github.com/sakullla/sakullla-plugins/plugins/cloudflare-dns"
)

func TestCloudflareTokenStatusZoneGuidanceAndSecretRedaction(t *testing.T) {
	vault := newFakeVault()
	vault.permissions = []string{cloudflaredns.PermissionZoneRead}
	trace := &safeTrace{}
	service := newTestService(t, vault, newFakeDNS(vault), trace, nil)
	status, err := service.TokenStatus(context.Background(), validAction(""))
	if err != nil {
		t.Fatal(err)
	}
	if status.SecretRef != "vault/cloudflare" || status.Version != "version-1" || len(status.ZoneIDs) != 1 {
		t.Fatalf("status=%#v", status)
	}
	configuration, snapshot := service.Snapshot()
	wire, _ := json.Marshal(struct {
		Configuration cloudflaredns.Configuration
		Status        cloudflaredns.TokenAttestation
		UI            []cloudflaredns.UIProjection
		Audit         []cloudflaredns.AuditRecord
		Log           []cloudflaredns.EventRecord
	}{configuration, snapshot, trace.ui, trace.audit, trace.logs})
	if strings.Contains(string(wire), vault.material) || strings.Contains(string(wire), "raw-cloudflare-body") {
		t.Fatalf("secret leaked: %s", wire)
	}
	if len(trace.ui) != 1 || len(trace.ui[0].MissingPermissions) != 1 || trace.ui[0].MissingPermissions[0] != cloudflaredns.PermissionDNSEdit || trace.ui[0].LastUsed != 42 {
		t.Fatalf("guidance=%#v", trace.ui)
	}
}

func TestCloudflareZoneScopedDNSCRUDReauthorizesEveryAction(t *testing.T) {
	vault := newFakeVault()
	dns := newFakeDNS(vault)
	trace := &safeTrace{}
	var authorizations atomic.Int32
	service := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		authorizations.Add(1)
		if action.Actor != "actor/admin" || action.ResourceGroupRef != "group/main" || action.SecretRef != "vault/cloudflare" || action.SecretVersion != vault.currentVersion() {
			return errors.New("raw authorization state")
		}
		return nil
	})
	zones, err := service.ListZones(context.Background(), validAction(""))
	if err != nil || len(zones) != 1 || zones[0].ID != "zone/allowed" {
		t.Fatalf("zones=%#v err=%v", zones, err)
	}
	records, err := service.ListRecords(context.Background(), validAction("zone/allowed"))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	created, err := service.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "A", Name: "app.example.com", Content: "192.0.2.10", TTL: 60})
	if err != nil || created.ID == "" {
		t.Fatalf("create=%#v err=%v", created, err)
	}
	created.Content = "192.0.2.11"
	if _, err := service.Update(context.Background(), validAction("zone/allowed"), created); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background(), validAction("zone/allowed"), created.ID); err != nil {
		t.Fatal(err)
	}
	if authorizations.Load() != 5 || dns.effects.Load() != 3 {
		t.Fatalf("authorizations=%d effects=%d", authorizations.Load(), dns.effects.Load())
	}

	before := dns.effects.Load()
	if _, err := service.Create(context.Background(), validAction("zone/denied"), cloudflaredns.DNSRecord{Type: "A", Name: "bad.example.com", Content: "192.0.2.1", TTL: 60}); !errors.Is(err, cloudflaredns.ErrZoneDenied) || dns.effects.Load() != before {
		t.Fatalf("zone scope err=%v effects=%d", err, dns.effects.Load())
	}
	wrongGroup := validAction("zone/allowed")
	wrongGroup.ResourceGroupRef = "group/other"
	if err := service.Delete(context.Background(), wrongGroup, "record/1"); !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) || dns.effects.Load() != before {
		t.Fatalf("group scope err=%v effects=%d", err, dns.effects.Load())
	}
}

func TestCloudflareRotateOneTimeMaterialAndStaleHandleFailClosed(t *testing.T) {
	vault := newFakeVault()
	dns := newFakeDNS(vault)
	trace := &safeTrace{}
	service := newTestService(t, vault, dns, trace, nil)
	material := []byte("one-time-token-material")
	metadata, err := service.RotateToken(context.Background(), validAction(""), material)
	if err != nil || metadata.SecretRef != "vault/cloudflare" || metadata.Version != "version-2" {
		t.Fatalf("rotate=%#v err=%v", metadata, err)
	}
	for _, value := range material {
		if value != 0 {
			t.Fatal("rotation material remained retrievable")
		}
	}
	configuration, status := service.Snapshot()
	wire, _ := json.Marshal(struct {
		C cloudflaredns.Configuration
		S cloudflaredns.TokenAttestation
	}{configuration, status})
	if strings.Contains(string(wire), "one-time-token-material") {
		t.Fatalf("snapshot leaked material=%s", wire)
	}

	// Rotation after attestation but before the DNS broker effect makes the
	// generation-owned zone handle stale; the broker rejects it with zero effect.
	rotated := atomic.Bool{}
	staleService := newTestService(t, vault, dns, trace, func(cloudflaredns.ActionContext) error {
		if rotated.CompareAndSwap(false, true) {
			vault.forceRotate()
		}
		return nil
	})
	before := dns.effects.Load()
	_, err = staleService.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "TXT", Name: "stale.example.com", Content: "safe-value", TTL: 60})
	if !errors.Is(err, cloudflaredns.ErrTokenStale) || dns.effects.Load() != before {
		t.Fatalf("stale err=%v effects=%d", err, dns.effects.Load())
	}
}

func TestCloudflareTokenBootstrapAuthorizationAndIdempotentRotate(t *testing.T) {
	vault := newFakeVault()
	vault.mu.Lock()
	vault.exists = false
	vault.mu.Unlock()
	dns, trace := newFakeDNS(vault), &safeTrace{}
	denied := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		if action.Permission != cloudflaredns.PermissionVaultEnroll || action.SecretVersion != "" {
			t.Fatalf("bootstrap action=%#v", action)
		}
		return errors.New("raw authorization")
	})
	deniedMaterial := []byte("bootstrap-secret")
	if _, err := denied.EnrollToken(context.Background(), validAction(""), deniedMaterial); !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) || vault.effects.Load() != 0 {
		t.Fatalf("unauthorized enroll err=%v effects=%d", err, vault.effects.Load())
	}
	for _, value := range deniedMaterial {
		if value != 0 {
			t.Fatal("denied bootstrap material retained")
		}
	}

	service := newTestService(t, vault, dns, trace, nil)
	material := []byte("bootstrap-secret")
	metadata, err := service.EnrollToken(context.Background(), validAction(""), material)
	if err != nil || metadata.Version != "version-1" || vault.effects.Load() != 1 {
		t.Fatalf("bootstrap=%#v effects=%d err=%v", metadata, vault.effects.Load(), err)
	}
	for _, value := range material {
		if value != 0 {
			t.Fatal("bootstrap material retained")
		}
	}
	rotateRequest := validAction("")
	rotateRequest.OperationKey = "operation/rotate-current"
	first, err := service.RotateToken(context.Background(), rotateRequest, []byte("new-token"))
	if err != nil || first.Version != "version-2" || vault.effects.Load() != 2 {
		t.Fatalf("rotate=%#v effects=%d err=%v", first, vault.effects.Load(), err)
	}
	second, err := service.RotateToken(context.Background(), rotateRequest, []byte("retry-token"))
	if err != nil || second != first || vault.effects.Load() != 2 {
		t.Fatalf("idempotent rotate=%#v effects=%d err=%v", second, vault.effects.Load(), err)
	}
}

func TestCloudflareDNSCommittedEffectReconcilesWithoutOppositeAudit(t *testing.T) {
	vault, trace := newFakeVault(), &safeTrace{}
	dns := newFakeDNS(vault)
	var uiCalls atomic.Int32
	runtime := cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, projection cloudflaredns.UIProjection) error {
		trace.addUI(projection)
		if projection.Kind == "dns-create" && uiCalls.Add(1) == 1 {
			return errors.New("raw UI failure")
		}
		return nil
	}), Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error { trace.addAudit(record); return nil }), Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error { trace.addLog(record); return nil })}
	service, err := cloudflaredns.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	request := validAction("zone/allowed")
	request.OperationKey = "operation/stable-create"
	record := cloudflaredns.DNSRecord{Type: "A", Name: "stable.example.com", Content: "192.0.2.22", TTL: 60}
	if _, err := service.Create(context.Background(), request, record); !errors.Is(err, cloudflaredns.ErrReconcilePending) || dns.effects.Load() != 1 {
		t.Fatalf("first reconcile err=%v effects=%d", err, dns.effects.Load())
	}
	if _, err := service.Create(context.Background(), request, record); err != nil || dns.effects.Load() != 1 {
		t.Fatalf("retry err=%v effects=%d", err, dns.effects.Load())
	}
	var terminalKey string
	for _, audit := range trace.audit {
		if audit.Outcome == "failed" {
			t.Fatalf("committed effect emitted opposite audit=%#v", trace.audit)
		}
		if audit.Outcome == "succeeded" {
			if terminalKey == "" {
				terminalKey = audit.OperationKey
			}
			if audit.OperationKey != terminalKey {
				t.Fatalf("unstable terminal keys=%#v", trace.audit)
			}
		}
	}
}

func TestCloudflareAuditRedactsRawAPIErrorsAndBounds(t *testing.T) {
	vault := newFakeVault()
	dns := newFakeDNS(vault)
	dns.rawFailure.Store(true)
	trace := &safeTrace{}
	service := newTestService(t, vault, dns, trace, nil)
	secret := "raw-cloudflare-body-token"
	_, err := service.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "TXT", Name: "audit.example.com", Content: secret, TTL: 60})
	if !errors.Is(err, cloudflaredns.ErrDNSOperationFailed) || strings.Contains(fmt.Sprint(err), secret) || strings.Contains(fmt.Sprint(err), "raw") {
		t.Fatalf("unsafe error=%v", err)
	}
	wire, _ := json.Marshal(struct {
		Audit []cloudflaredns.AuditRecord
		Log   []cloudflaredns.EventRecord
		UI    []cloudflaredns.UIProjection
	}{trace.audit, trace.logs, trace.ui})
	if strings.Contains(string(wire), secret) || strings.Contains(string(wire), "raw-cloudflare-body") {
		t.Fatalf("unsafe event=%s", wire)
	}
	if len(trace.audit) != 2 || trace.audit[0].Outcome != "started" || trace.audit[1].Outcome != "pending" {
		t.Fatalf("audit=%#v", trace.audit)
	}

	vault.zoneIDs = make([]string, cloudflaredns.MaxZones+1)
	for index := range vault.zoneIDs {
		vault.zoneIDs[index] = fmt.Sprintf("zone/%03d", index)
	}
	bounded := newTestService(t, vault, newFakeDNS(vault), &safeTrace{}, nil)
	if _, err := bounded.ListZones(context.Background(), validAction("")); !errors.Is(err, cloudflaredns.ErrBoundExceeded) {
		t.Fatalf("zone bound err=%v", err)
	}
}

type fakeVault struct {
	mu                   sync.Mutex
	version              int
	exists               bool
	permissions, zoneIDs []string
	material             string
	effects              atomic.Int32
	operations           map[string]cloudflaredns.TokenMetadata
}

func newFakeVault() *fakeVault {
	return &fakeVault{version: 1, exists: true, permissions: []string{cloudflaredns.PermissionZoneRead, cloudflaredns.PermissionDNSEdit}, zoneIDs: []string{"zone/allowed"}, material: "vault-only-token-material", operations: make(map[string]cloudflaredns.TokenMetadata)}
}
func (vault *fakeVault) currentVersion() string {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return fmt.Sprintf("version-%d", vault.version)
}
func (vault *fakeVault) Verify(context.Context, string) (cloudflaredns.TokenAttestation, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if !vault.exists {
		return cloudflaredns.TokenAttestation{}, errors.New("raw missing token")
	}
	return cloudflaredns.TokenAttestation{SecretRef: "vault/cloudflare", Version: fmt.Sprintf("version-%d", vault.version), Permissions: append([]string(nil), vault.permissions...), ZoneIDs: append([]string(nil), vault.zoneIDs...), LastUsed: 42}, nil
}
func (vault *fakeVault) Enroll(_ context.Context, ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	return vault.change(ref, material, operation, true)
}
func (vault *fakeVault) Rotate(_ context.Context, ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	return vault.change(ref, material, operation, false)
}
func (vault *fakeVault) change(ref string, material []byte, operation string, enroll bool) (cloudflaredns.TokenMetadata, error) {
	if ref != "vault/cloudflare" || len(material) == 0 {
		return cloudflaredns.TokenMetadata{}, errors.New("raw Vault failure")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	if enroll {
		if vault.exists {
			return cloudflaredns.TokenMetadata{}, errors.New("raw token already exists")
		}
		vault.exists = true
		vault.version = 1
	} else {
		if !vault.exists {
			return cloudflaredns.TokenMetadata{}, errors.New("raw missing token")
		}
		vault.version++
	}
	version := fmt.Sprintf("version-%d", vault.version)
	metadata := cloudflaredns.TokenMetadata{SecretRef: ref, Version: version}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
}
func (vault *fakeVault) forceRotate() { vault.mu.Lock(); vault.version++; vault.mu.Unlock() }

type fakeDNS struct {
	vault      *fakeVault
	effects    atomic.Int32
	rawFailure atomic.Bool
	mu         sync.Mutex
	operations map[string]cloudflaredns.DNSRecord
}

func newFakeDNS(vault *fakeVault) *fakeDNS {
	return &fakeDNS{vault: vault, operations: make(map[string]cloudflaredns.DNSRecord)}
}
func (dns *fakeDNS) check(attestation cloudflaredns.TokenAttestation) error {
	if attestation.Version != dns.vault.currentVersion() {
		return cloudflaredns.ErrTokenStale
	}
	if dns.rawFailure.Load() {
		return errors.New("raw-cloudflare-body-token")
	}
	return nil
}
func (dns *fakeDNS) ListZones(_ context.Context, attestation cloudflaredns.TokenAttestation, _ string) ([]cloudflaredns.Zone, error) {
	if err := dns.check(attestation); err != nil {
		return nil, err
	}
	return []cloudflaredns.Zone{{ID: "zone/allowed", Name: "example.com"}}, nil
}
func (dns *fakeDNS) ListRecords(_ context.Context, attestation cloudflaredns.TokenAttestation, zone string, _ int) ([]cloudflaredns.DNSRecord, error) {
	if err := dns.check(attestation); err != nil {
		return nil, err
	}
	return []cloudflaredns.DNSRecord{{ID: "record/1", ZoneID: zone, Type: "A", Name: "www.example.com", Content: "192.0.2.1", TTL: 60}}, nil
}
func (dns *fakeDNS) Create(_ context.Context, attestation cloudflaredns.TokenAttestation, record cloudflaredns.DNSRecord, operation string) (cloudflaredns.DNSRecord, error) {
	if err := dns.check(attestation); err != nil {
		return cloudflaredns.DNSRecord{}, err
	}
	dns.mu.Lock()
	defer dns.mu.Unlock()
	if previous, exists := dns.operations[operation]; exists {
		return previous, nil
	}
	dns.effects.Add(1)
	record.ID = "record/new"
	dns.operations[operation] = record
	return record, nil
}
func (dns *fakeDNS) Update(_ context.Context, attestation cloudflaredns.TokenAttestation, record cloudflaredns.DNSRecord, operation string) (cloudflaredns.DNSRecord, error) {
	if err := dns.check(attestation); err != nil {
		return cloudflaredns.DNSRecord{}, err
	}
	dns.mu.Lock()
	defer dns.mu.Unlock()
	if previous, exists := dns.operations[operation]; exists {
		return previous, nil
	}
	dns.effects.Add(1)
	dns.operations[operation] = record
	return record, nil
}
func (dns *fakeDNS) Delete(_ context.Context, attestation cloudflaredns.TokenAttestation, _, recordID, operation string) error {
	if err := dns.check(attestation); err != nil {
		return err
	}
	dns.mu.Lock()
	defer dns.mu.Unlock()
	if _, exists := dns.operations[operation]; exists {
		return nil
	}
	dns.effects.Add(1)
	dns.operations[operation] = cloudflaredns.DNSRecord{ID: recordID}
	return nil
}

type safeTrace struct {
	mu    sync.Mutex
	ui    []cloudflaredns.UIProjection
	audit []cloudflaredns.AuditRecord
	logs  []cloudflaredns.EventRecord
}

func (trace *safeTrace) addUI(record cloudflaredns.UIProjection) {
	trace.mu.Lock()
	trace.ui = append(trace.ui, record)
	trace.mu.Unlock()
}
func (trace *safeTrace) addAudit(record cloudflaredns.AuditRecord) {
	trace.mu.Lock()
	trace.audit = append(trace.audit, record)
	trace.mu.Unlock()
}
func (trace *safeTrace) addLog(record cloudflaredns.EventRecord) {
	trace.mu.Lock()
	trace.logs = append(trace.logs, record)
	trace.mu.Unlock()
}

func newTestService(t *testing.T, vault *fakeVault, dns *fakeDNS, trace *safeTrace, authorize func(cloudflaredns.ActionContext) error) *cloudflaredns.Service {
	t.Helper()
	if authorize == nil {
		authorize = func(cloudflaredns.ActionContext) error { return nil }
	}
	service, err := cloudflaredns.NewService(testConfiguration(), cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Authorizer: cloudflaredns.AuthorizerFunc(func(_ context.Context, action cloudflaredns.ActionContext) error { return authorize(action) }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, projection cloudflaredns.UIProjection) error {
		trace.addUI(projection)
		return nil
	}), Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error { trace.addAudit(record); return nil }), Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error { trace.addLog(record); return nil })})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validAction(zone string) cloudflaredns.ActionRequest {
	return cloudflaredns.ActionRequest{Actor: "actor/admin", ResourceGroupRef: "group/main", ZoneID: zone, OperationKey: "operation/default"}
}
func testConfiguration() cloudflaredns.Configuration {
	return cloudflaredns.Configuration{Generation: "generation-1", SecretRef: "vault/cloudflare", ResourceGroupRef: "group/main"}
}
