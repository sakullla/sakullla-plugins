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
	"time"

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
		if action.Actor != "actor/admin" || action.ResourceGroupRef != "group/main" {
			return errors.New("raw authorization state")
		}
		if action.Phase == "exact" && (action.SecretRef != "vault/cloudflare" || action.SecretVersion != vault.currentVersion()) {
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
	if authorizations.Load() != 10 || dns.effects.Load() != 3 {
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
	staleService := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		if action.Phase == "exact" && rotated.CompareAndSwap(false, true) {
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

func TestCloudflareRotateCASAndCoarseAuthorizationZeroSecretCalls(t *testing.T) {
	vault, dns, trace := newFakeVault(), newFakeDNS(newFakeVault()), &safeTrace{}
	dns.vault = vault
	denied := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		if action.Phase == "coarse" {
			return errors.New("raw denied actor")
		}
		return nil
	})
	beforeVerify := vault.verifyCalls.Load()
	if _, err := denied.ListZones(context.Background(), validAction("")); !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) || vault.verifyCalls.Load() != beforeVerify || dns.effects.Load() != 0 {
		t.Fatalf("coarse denial err=%v verify=%d effects=%d", err, vault.verifyCalls.Load(), dns.effects.Load())
	}
	wrongGroup := validAction("")
	wrongGroup.ResourceGroupRef = "group/other"
	if _, err := denied.ListZones(context.Background(), wrongGroup); !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) || vault.verifyCalls.Load() != beforeVerify {
		t.Fatalf("group denial err=%v verify=%d", err, vault.verifyCalls.Load())
	}
	secretDenied := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		if action.SecretRef == "vault/cloudflare" {
			return errors.New("raw secret scope denied")
		}
		return nil
	})
	beforeVerify = vault.verifyCalls.Load()
	if _, err := secretDenied.ListZones(context.Background(), validAction("")); !errors.Is(err, cloudflaredns.ErrAuthorizationDenied) || vault.verifyCalls.Load() != beforeVerify {
		t.Fatalf("secret-scope denial err=%v verify=%d", err, vault.verifyCalls.Load())
	}

	rotated := atomic.Bool{}
	service := newTestService(t, vault, dns, trace, func(action cloudflaredns.ActionContext) error {
		if action.Phase == "exact" && action.Permission == cloudflaredns.PermissionVaultRotate && rotated.CompareAndSwap(false, true) {
			vault.forceRotate()
		}
		return nil
	})
	beforeEffects := vault.effects.Load()
	if _, err := service.RotateToken(context.Background(), validAction(""), []byte("stale-rotation")); !errors.Is(err, cloudflaredns.ErrTokenStale) || vault.effects.Load() != beforeEffects {
		t.Fatalf("rotation CAS err=%v effects=%d", err, vault.effects.Load())
	}
}

func TestCloudflareDNSCommittedEffectReconcilesWithoutOppositeAudit(t *testing.T) {
	vault, trace := newFakeVault(), &safeTrace{}
	dns := newFakeDNS(vault)
	var uiCalls atomic.Int32
	runtime := cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Operations: fakeInspector{vault: vault}, Lease: cloudflaredns.GenerationLeaseFunc(func() {}), Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, projection cloudflaredns.UIProjection) error {
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

func TestCloudflareDNSCommitBeforeErrorRestartAndAuditReconcile(t *testing.T) {
	vault, dns, trace := newFakeVault(), newFakeDNS(newFakeVault()), &safeTrace{}
	dns.vault = vault
	dns.commitBeforeError.Store(true)
	var failAudit atomic.Bool
	failAudit.Store(true)
	runtime := cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Operations: fakeInspector{vault: vault}, Lease: cloudflaredns.GenerationLeaseFunc(func() {}), Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, projection cloudflaredns.UIProjection) error {
		trace.addUI(projection)
		return nil
	}), Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error {
		trace.addAudit(record)
		if record.Outcome == "succeeded" && failAudit.CompareAndSwap(true, false) {
			return errors.New("raw audit outage")
		}
		return nil
	}), Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error { trace.addLog(record); return nil })}
	request := validAction("zone/allowed")
	request.OperationKey = "operation/commit-before-error"
	record := cloudflaredns.DNSRecord{Type: "A", Name: "restart.example.com", Content: "192.0.2.44", TTL: 60}
	first, err := cloudflaredns.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Create(context.Background(), request, record); !errors.Is(err, cloudflaredns.ErrReconcilePending) || dns.effects.Load() != 1 {
		t.Fatalf("ambiguous commit err=%v effects=%d", err, dns.effects.Load())
	}
	// A new service instance models restart. The authoritative inspector returns
	// the committed record and the stable operation is reconciled without a
	// second Cloudflare effect.
	second, err := cloudflaredns.NewService(testConfiguration(), runtime)
	if err != nil {
		t.Fatal(err)
	}
	result, err := second.Create(context.Background(), request, record)
	if err != nil || result.ID != "record/new" || dns.effects.Load() != 1 {
		t.Fatalf("restart result=%#v err=%v effects=%d", result, err, dns.effects.Load())
	}
	for _, audit := range trace.audit {
		if audit.Outcome == "failed" {
			t.Fatalf("ambiguous committed operation emitted failed audit=%#v", trace.audit)
		}
	}
}

func TestCloudflareDNSExactlyOnceConcurrentOperationAndMalformedState(t *testing.T) {
	vault, dns, trace := newFakeVault(), newFakeDNS(newFakeVault()), &safeTrace{}
	dns.vault = vault
	dns.inspectStarted = make(chan struct{}, 2)
	dns.inspectRelease = make(chan struct{})
	service := newTestService(t, vault, dns, trace, nil)
	request := validAction("zone/allowed")
	request.OperationKey = "operation/concurrent"
	record := cloudflaredns.DNSRecord{Type: "A", Name: "once.example.com", Content: "192.0.2.80", TTL: 60}
	results := make(chan struct {
		record cloudflaredns.DNSRecord
		err    error
	}, 2)
	for index := 0; index < 2; index++ {
		go func() {
			result, err := service.Create(context.Background(), request, record)
			results <- struct {
				record cloudflaredns.DNSRecord
				err    error
			}{result, err}
		}()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-dns.inspectStarted:
		case <-time.After(time.Second):
			t.Fatal("concurrent requests did not both observe the pre-claim state")
		}
	}
	close(dns.inspectRelease)
	for index := 0; index < 2; index++ {
		result := <-results
		if result.err != nil || result.record.ID != "record/new" {
			t.Fatalf("concurrent result=%#v err=%v", result.record, result.err)
		}
	}
	if dns.effects.Load() != 1 {
		t.Fatalf("same operation committed %d effects", dns.effects.Load())
	}

	corruptDNS := malformedStateDNS{fakeDNS: newFakeDNS(vault)}
	corrupt := newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{
		Vault:      vault,
		DNS:        corruptDNS,
		Operations: fakeInspector{vault: vault},
		Lease:      cloudflaredns.GenerationLeaseFunc(func() {}),
		Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }),
		UI:         cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error { return nil }),
		Auditor:    cloudflaredns.AuditorFunc(func(context.Context, cloudflaredns.AuditRecord) error { return nil }),
		Logger:     cloudflaredns.EventLoggerFunc(func(context.Context, cloudflaredns.EventRecord) error { return nil }),
	})
	if _, err := corrupt.Create(context.Background(), request, record); !errors.Is(err, cloudflaredns.ErrReconcilePending) || corruptDNS.effects.Load() != 0 {
		t.Fatalf("malformed journal state err=%v effects=%d", err, corruptDNS.effects.Load())
	}
}

func TestCloudflareStopBoundsNoncooperativeHostAwaitsAndNoLateSuccess(t *testing.T) {
	for _, stage := range []string{"vault", "authorizer", "dns", "ui", "audit", "log"} {
		t.Run(stage, func(t *testing.T) {
			vault, dns := newFakeVault(), newFakeDNS(newFakeVault())
			dns.vault = vault
			started, release := make(chan struct{}), make(chan struct{})
			var startedOnce sync.Once
			var revoked atomic.Bool
			var lateSuccess atomic.Int32
			block := func() error {
				startedOnce.Do(func() { close(started) })
				<-release
				if revoked.Load() {
					return context.Canceled
				}
				lateSuccess.Add(1)
				return nil
			}
			var vaultHandle cloudflaredns.Vault = vault
			var dnsHandle cloudflaredns.DNSHandle = dns
			if stage == "vault" {
				vaultHandle = blockingVault{fakeVault: vault, block: block}
			}
			if stage == "dns" {
				dnsHandle = blockingDNS{fakeDNS: dns, block: block}
			}
			runtime := cloudflaredns.RuntimeAdapters{Vault: vaultHandle, DNS: dnsHandle, Operations: fakeInspector{vault: vault}, Lease: cloudflaredns.GenerationLeaseFunc(func() { revoked.Store(true) }), Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error {
				if stage == "authorizer" {
					return block()
				}
				return nil
			}), UI: cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error {
				if stage == "ui" {
					return block()
				}
				return nil
			}), Auditor: cloudflaredns.AuditorFunc(func(context.Context, cloudflaredns.AuditRecord) error {
				if stage == "audit" {
					return block()
				}
				return nil
			}), Logger: cloudflaredns.EventLoggerFunc(func(context.Context, cloudflaredns.EventRecord) error {
				if stage == "log" {
					return block()
				}
				return nil
			})}
			service, err := cloudflaredns.NewService(testConfiguration(), runtime)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				if stage == "dns" {
					_, err := service.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "A", Name: "blocked.example.com", Content: "192.0.2.60", TTL: 60})
					result <- err
				} else {
					_, err := service.TokenStatus(context.Background(), validAction(""))
					result <- err
				}
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("host await did not start")
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			if err := service.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
				cancel()
				t.Fatalf("noncooperative drain err=%v", err)
			}
			cancel()
			if err := <-result; err == nil {
				t.Fatal("revoked action reported late success")
			}
			close(release)
			drainCtx, drainCancel := context.WithTimeout(context.Background(), time.Second)
			if err := service.Close(drainCtx); err != nil {
				drainCancel()
				t.Fatalf("drain after host release err=%v", err)
			}
			drainCancel()
			if lateSuccess.Load() != 0 || dns.effects.Load() != 0 {
				t.Fatalf("late success=%d DNS effects=%d", lateSuccess.Load(), dns.effects.Load())
			}
		})
	}
}

func TestCloudflareLateHostCallsRemainBoundedAfterRequestCancellation(t *testing.T) {
	vault, dns := newFakeVault(), newFakeDNS(newFakeVault())
	dns.vault = vault
	started := make(chan struct{}, cloudflaredns.MaxActiveCalls)
	release := make(chan struct{})
	blocked := blockingVault{fakeVault: vault, block: func() error {
		started <- struct{}{}
		<-release
		return nil
	}}
	service := newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{
		Vault:      blocked,
		DNS:        dns,
		Operations: fakeInspector{vault: vault},
		Lease:      cloudflaredns.GenerationLeaseFunc(func() {}),
		Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }),
		UI:         cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error { return nil }),
		Auditor:    cloudflaredns.AuditorFunc(func(context.Context, cloudflaredns.AuditRecord) error { return nil }),
		Logger:     cloudflaredns.EventLoggerFunc(func(context.Context, cloudflaredns.EventRecord) error { return nil }),
	})
	cancels := make([]context.CancelFunc, cloudflaredns.MaxActiveCalls)
	results := make(chan error, cloudflaredns.MaxActiveCalls)
	for index := 0; index < cloudflaredns.MaxActiveCalls; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[index] = cancel
		go func() {
			_, err := service.TokenStatus(ctx, validAction(""))
			results <- err
		}()
	}
	for index := 0; index < cloudflaredns.MaxActiveCalls; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("late-call pool did not fill")
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	for index := 0; index < cloudflaredns.MaxActiveCalls; index++ {
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled request err=%v", err)
		}
	}
	if _, err := service.TokenStatus(context.Background(), validAction("")); !errors.Is(err, cloudflaredns.ErrBoundExceeded) {
		t.Fatalf("late-call pool admitted another Host call: %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := service.TokenStatus(context.Background(), validAction("")); err == nil {
			break
		} else if !errors.Is(err, cloudflaredns.ErrBoundExceeded) || time.Now().After(deadline) {
			t.Fatalf("late-call pool did not recover: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCloudflarePendingOutcomePreservesAuditAndLogFailures(t *testing.T) {
	vault, dns := newFakeVault(), newFakeDNS(newFakeVault())
	dns.vault = vault
	dns.rawFailure.Store(true)
	service := newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{
		Vault:      vault,
		DNS:        dns,
		Operations: fakeInspector{vault: vault},
		Lease:      cloudflaredns.GenerationLeaseFunc(func() {}),
		Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }),
		UI:         cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error { return nil }),
		Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error {
			if record.Outcome == "pending" {
				return errors.New("raw audit outage")
			}
			return nil
		}),
		Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error {
			if record.Outcome == "pending" {
				return errors.New("raw log outage")
			}
			return nil
		}),
	})
	_, err := service.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "A", Name: "pending.example.com", Content: "192.0.2.70", TTL: 60})
	if !errors.Is(err, cloudflaredns.ErrReconcilePending) || !errors.Is(err, cloudflaredns.ErrAuditUnavailable) || !errors.Is(err, cloudflaredns.ErrLogUnavailable) {
		t.Fatalf("pending failure classes lost: %v", err)
	}
	if strings.Contains(err.Error(), "raw") {
		t.Fatalf("pending failure leaked adapter text: %v", err)
	}
}

func TestCloudflareTokenMaterialIsSnapshottedBeforeLateVaultCall(t *testing.T) {
	vault, dns := newFakeVault(), newFakeDNS(newFakeVault())
	dns.vault = vault
	started, release := make(chan struct{}), make(chan struct{})
	observed := make(chan string, 1)
	capture := materialCaptureVault{fakeVault: vault, started: started, release: release, observed: observed}
	service := newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{
		Vault:      capture,
		DNS:        dns,
		Operations: fakeInspector{vault: vault},
		Lease:      cloudflaredns.GenerationLeaseFunc(func() {}),
		Authorizer: cloudflaredns.AuthorizerFunc(func(context.Context, cloudflaredns.ActionContext) error { return nil }),
		UI:         cloudflaredns.DynamicUIFunc(func(context.Context, cloudflaredns.UIProjection) error { return nil }),
		Auditor:    cloudflaredns.AuditorFunc(func(context.Context, cloudflaredns.AuditRecord) error { return nil }),
		Logger:     cloudflaredns.EventLoggerFunc(func(context.Context, cloudflaredns.EventRecord) error { return nil }),
	})
	material := []byte("original-bootstrap-token")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := service.EnrollToken(ctx, validAction(""), material)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Vault enrollment did not start")
	}
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late enrollment err=%v", err)
	}
	copy(material, []byte("caller-mutated-token!!!"))
	close(release)
	select {
	case value := <-observed:
		if value != "original-bootstrap-token" {
			t.Fatalf("Vault observed mutable caller bytes: %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("late Vault call did not finish")
	}
}

type blockingVault struct {
	fakeVault *fakeVault
	block     func() error
}

type materialCaptureVault struct {
	fakeVault *fakeVault
	started   chan struct{}
	release   chan struct{}
	observed  chan string
}

func (vault materialCaptureVault) Verify(ctx context.Context, ref string) (cloudflaredns.TokenAttestation, error) {
	return vault.fakeVault.Verify(ctx, ref)
}
func (vault materialCaptureVault) Enroll(ctx context.Context, ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	close(vault.started)
	<-vault.release
	vault.observed <- string(append([]byte(nil), material...))
	return vault.fakeVault.Enroll(ctx, ref, material, operation)
}
func (vault materialCaptureVault) Rotate(ctx context.Context, ref, version string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	return vault.fakeVault.Rotate(ctx, ref, version, material, operation)
}
func (vault materialCaptureVault) Reveal(ctx context.Context, ref string) ([]byte, error) {
	return vault.fakeVault.Reveal(ctx, ref)
}

func (vault blockingVault) Verify(ctx context.Context, ref string) (cloudflaredns.TokenAttestation, error) {
	if err := vault.block(); err != nil {
		return cloudflaredns.TokenAttestation{}, err
	}
	return vault.fakeVault.Verify(ctx, ref)
}
func (vault blockingVault) Enroll(ctx context.Context, ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	return vault.fakeVault.Enroll(ctx, ref, material, operation)
}
func (vault blockingVault) Rotate(ctx context.Context, ref, version string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	return vault.fakeVault.Rotate(ctx, ref, version, material, operation)
}
func (vault blockingVault) Reveal(ctx context.Context, ref string) ([]byte, error) {
	if err := vault.block(); err != nil {
		return nil, err
	}
	return vault.fakeVault.Reveal(ctx, ref)
}

type blockingDNS struct {
	fakeDNS *fakeDNS
	block   func() error
}

func (dns blockingDNS) Inspect(ctx context.Context, operation string) (cloudflaredns.OperationOutcome, error) {
	return dns.fakeDNS.Inspect(ctx, operation)
}

func (dns blockingDNS) ListZones(ctx context.Context, att cloudflaredns.TokenAttestation, operation string) ([]cloudflaredns.Zone, error) {
	return dns.fakeDNS.ListZones(ctx, att, operation)
}
func (dns blockingDNS) ListRecords(ctx context.Context, att cloudflaredns.TokenAttestation, zone string, max int) ([]cloudflaredns.DNSRecord, error) {
	return dns.fakeDNS.ListRecords(ctx, att, zone, max)
}
func (dns blockingDNS) Create(ctx context.Context, att cloudflaredns.TokenAttestation, record cloudflaredns.DNSRecord, operation string) (cloudflaredns.DNSRecord, error) {
	if err := dns.block(); err != nil {
		return cloudflaredns.DNSRecord{}, err
	}
	return dns.fakeDNS.Create(ctx, att, record, operation)
}
func (dns blockingDNS) Update(ctx context.Context, att cloudflaredns.TokenAttestation, record cloudflaredns.DNSRecord, operation string) (cloudflaredns.DNSRecord, error) {
	return dns.fakeDNS.Update(ctx, att, record, operation)
}
func (dns blockingDNS) Delete(ctx context.Context, att cloudflaredns.TokenAttestation, zone, record, operation string) error {
	return dns.fakeDNS.Delete(ctx, att, zone, record, operation)
}

func TestCloudflareAuditRedactsRawAPIErrorsAndBounds(t *testing.T) {
	vault := newFakeVault()
	dns := newFakeDNS(vault)
	dns.rawFailure.Store(true)
	trace := &safeTrace{}
	service := newTestService(t, vault, dns, trace, nil)
	secret := "raw-cloudflare-body-token"
	_, err := service.Create(context.Background(), validAction("zone/allowed"), cloudflaredns.DNSRecord{Type: "TXT", Name: "audit.example.com", Content: secret, TTL: 60})
	if !errors.Is(err, cloudflaredns.ErrReconcilePending) || strings.Contains(fmt.Sprint(err), secret) || strings.Contains(fmt.Sprint(err), "raw") {
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

type fakeSecret struct {
	version  int
	material []byte
}

type fakeVault struct {
	mu                   sync.Mutex
	version              int
	exists               bool
	permissions, zoneIDs []string
	material             string
	effects              atomic.Int32
	verifyCalls          atomic.Int32
	operations           map[string]cloudflaredns.TokenMetadata
	secrets              map[string]fakeSecret
}

func newFakeVault() *fakeVault {
	return &fakeVault{version: 1, exists: true, permissions: []string{cloudflaredns.PermissionZoneRead, cloudflaredns.PermissionDNSEdit}, zoneIDs: []string{"zone/allowed"}, material: "vault-only-token-material", operations: make(map[string]cloudflaredns.TokenMetadata), secrets: make(map[string]fakeSecret)}
}
func (vault *fakeVault) currentVersion() string {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return fmt.Sprintf("version-%d", vault.version)
}
func (vault *fakeVault) acceptedRef(ref string) bool {
	return ref == "vault/cloudflare" || strings.HasPrefix(ref, "vault/cloudflare/")
}
func (vault *fakeVault) Verify(_ context.Context, ref string) (cloudflaredns.TokenAttestation, error) {
	vault.verifyCalls.Add(1)
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if ref != "vault/cloudflare" {
		secret, ok := vault.secrets[ref]
		if !ok {
			return cloudflaredns.TokenAttestation{}, errors.New("raw missing token")
		}
		return cloudflaredns.TokenAttestation{SecretRef: ref, Version: fmt.Sprintf("version-%d", secret.version), Permissions: append([]string(nil), vault.permissions...), ZoneIDs: append([]string(nil), vault.zoneIDs...), LastUsed: 42}, nil
	}
	if !vault.exists {
		return cloudflaredns.TokenAttestation{}, errors.New("raw missing token")
	}
	return cloudflaredns.TokenAttestation{SecretRef: "vault/cloudflare", Version: fmt.Sprintf("version-%d", vault.version), Permissions: append([]string(nil), vault.permissions...), ZoneIDs: append([]string(nil), vault.zoneIDs...), LastUsed: 42}, nil
}
func (vault *fakeVault) Enroll(_ context.Context, ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	if strings.HasPrefix(ref, "vault/cloudflare/") {
		return vault.enrollMapping(ref, material, operation)
	}
	return vault.change(ref, material, operation, true)
}
func (vault *fakeVault) Rotate(_ context.Context, ref, expectedVersion string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	if strings.HasPrefix(ref, "vault/cloudflare/") {
		return vault.rotateMapping(ref, expectedVersion, material, operation)
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if expectedVersion != fmt.Sprintf("version-%d", vault.version) {
		return cloudflaredns.TokenMetadata{}, cloudflaredns.ErrTokenStale
	}
	if ref != "vault/cloudflare" || len(material) == 0 || !vault.exists {
		return cloudflaredns.TokenMetadata{}, errors.New("raw Vault failure")
	}
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	vault.version++
	metadata := cloudflaredns.TokenMetadata{SecretRef: ref, Version: fmt.Sprintf("version-%d", vault.version)}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
}
func (vault *fakeVault) Reveal(_ context.Context, ref string) ([]byte, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if ref != "vault/cloudflare" {
		secret, ok := vault.secrets[ref]
		if !ok || len(secret.material) == 0 {
			return nil, errors.New("raw missing token")
		}
		return append([]byte(nil), secret.material...), nil
	}
	if !vault.exists {
		return nil, errors.New("raw missing token")
	}
	return append([]byte(nil), vault.material...), nil
}
func (vault *fakeVault) enrollMapping(ref string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	if !vault.acceptedRef(ref) || len(material) == 0 {
		return cloudflaredns.TokenMetadata{}, errors.New("raw Vault failure")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	if _, exists := vault.secrets[ref]; exists {
		return cloudflaredns.TokenMetadata{}, errors.New("raw token already exists")
	}
	vault.secrets[ref] = fakeSecret{version: 1, material: append([]byte(nil), material...)}
	metadata := cloudflaredns.TokenMetadata{SecretRef: ref, Version: "version-1"}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
}
func (vault *fakeVault) rotateMapping(ref, expectedVersion string, material []byte, operation string) (cloudflaredns.TokenMetadata, error) {
	if !vault.acceptedRef(ref) || len(material) == 0 {
		return cloudflaredns.TokenMetadata{}, errors.New("raw Vault failure")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if previous, exists := vault.operations[operation]; exists {
		return previous, nil
	}
	secret, ok := vault.secrets[ref]
	if !ok || expectedVersion != fmt.Sprintf("version-%d", secret.version) {
		return cloudflaredns.TokenMetadata{}, cloudflaredns.ErrTokenStale
	}
	secret.version++
	secret.material = append([]byte(nil), material...)
	vault.secrets[ref] = secret
	metadata := cloudflaredns.TokenMetadata{SecretRef: ref, Version: fmt.Sprintf("version-%d", secret.version)}
	vault.operations[operation] = metadata
	vault.effects.Add(1)
	return metadata, nil
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
	vault             *fakeVault
	effects           atomic.Int32
	rawFailure        atomic.Bool
	commitBeforeError atomic.Bool
	mu                sync.Mutex
	operations        map[string]cloudflaredns.DNSRecord
	inspectStarted    chan struct{}
	inspectRelease    chan struct{}
}

type malformedStateDNS struct{ *fakeDNS }

func (dns malformedStateDNS) Inspect(context.Context, string) (cloudflaredns.OperationOutcome, error) {
	return cloudflaredns.OperationOutcome{State: cloudflaredns.OperationState("corrupt")}, nil
}

type fakeInspector struct {
	vault *fakeVault
}

func (inspector fakeInspector) Inspect(_ context.Context, operation string) (cloudflaredns.OperationOutcome, error) {
	inspector.vault.mu.Lock()
	token, vaultExists := inspector.vault.operations[operation]
	inspector.vault.mu.Unlock()
	if vaultExists {
		return cloudflaredns.OperationOutcome{State: cloudflaredns.OperationCommitted, Token: token}, nil
	}
	return cloudflaredns.OperationOutcome{State: cloudflaredns.OperationAbsent}, nil
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
func (dns *fakeDNS) Inspect(_ context.Context, operation string) (cloudflaredns.OperationOutcome, error) {
	dns.mu.Lock()
	record, exists := dns.operations[operation]
	started, release := dns.inspectStarted, dns.inspectRelease
	dns.mu.Unlock()
	if exists {
		return cloudflaredns.OperationOutcome{State: cloudflaredns.OperationCommitted, Record: record}, nil
	}
	if started != nil {
		started <- struct{}{}
		<-release
	}
	return cloudflaredns.OperationOutcome{State: cloudflaredns.OperationAbsent}, nil
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
	if dns.commitBeforeError.Load() {
		return cloudflaredns.DNSRecord{}, errors.New("raw commit-before-error")
	}
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
	return newTestServiceWithRuntime(t, cloudflaredns.RuntimeAdapters{Vault: vault, DNS: dns, Operations: fakeInspector{vault: vault}, Lease: cloudflaredns.GenerationLeaseFunc(func() {}), Authorizer: cloudflaredns.AuthorizerFunc(func(_ context.Context, action cloudflaredns.ActionContext) error { return authorize(action) }), UI: cloudflaredns.DynamicUIFunc(func(_ context.Context, projection cloudflaredns.UIProjection) error {
		trace.addUI(projection)
		return nil
	}), Auditor: cloudflaredns.AuditorFunc(func(_ context.Context, record cloudflaredns.AuditRecord) error { trace.addAudit(record); return nil }), Logger: cloudflaredns.EventLoggerFunc(func(_ context.Context, record cloudflaredns.EventRecord) error { trace.addLog(record); return nil })})
}

func newTestServiceWithRuntime(t *testing.T, runtime cloudflaredns.RuntimeAdapters) *cloudflaredns.Service {
	t.Helper()
	service, err := cloudflaredns.NewService(testConfiguration(), runtime)
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
