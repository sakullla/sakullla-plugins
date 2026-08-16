package cloudflaredns

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
)

type ActionRequest struct {
	Actor, ResourceGroupRef, ZoneID, OperationKey, Suffix, Domain string
}

func (service *Service) operationKey(action string, request ActionRequest) string {
	return stableOperationKey(service.configuration.Generation, action, request.OperationKey, request.Actor, request.ResourceGroupRef, request.ZoneID)
}

func (service *Service) recordOperationKey(action string, request ActionRequest, record DNSRecord) string {
	base := service.operationKey(action, request)
	return stableOperationKey(base, record.ID, record.Type, record.Name, record.Content, strconv.FormatUint(uint64(record.TTL), 10))
}

func stableOperationKey(fields ...string) string {
	digest := sha256.New()
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(field))
	}
	return "cloudflare:" + hex.EncodeToString(digest.Sum(nil))
}

func NewService(configuration Configuration, runtime RuntimeAdapters) (*Service, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if !runtime.valid() {
		return nil, ErrTypedHandlesUnavailable
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	service := &Service{
		configuration: configuration,
		runtime:       runtime,
		mappings:      make(map[string]storedMapping),
		rootCtx:       rootCtx,
		cancel:        cancel,
		slots:         make(chan struct{}, MaxActiveCalls),
		hostCalls:     make(chan struct{}, MaxActiveCalls),
	}
	service.live.Store(true)
	return service, nil
}

func (service *Service) TokenStatus(ctx context.Context, request ActionRequest) (TokenAttestation, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return TokenAttestation{}, err
	}
	defer finish()
	operation := service.operationKey("token-status", request)
	attestation, err := service.authorize(ctx, "token-status", request, PermissionZoneRead, operation)
	if err != nil {
		return TokenAttestation{}, err
	}
	missing := missingPermissions(attestation)
	projection := UIProjection{Kind: "token-status", Outcome: "succeeded", OperationKey: operation, MissingPermissions: missing, LastUsed: attestation.LastUsed, VisibleZones: append([]string(nil), attestation.ZoneIDs...)}
	if err := service.emitUI(ctx, projection); err != nil {
		return TokenAttestation{}, service.fail(ctx, "token-status", operation, request, "ui", ErrUIUnavailable)
	}
	if err := service.success(ctx, "token-status", operation, request); err != nil {
		return TokenAttestation{}, err
	}
	return cloneAttestation(attestation), nil
}

func (service *Service) ListZones(ctx context.Context, request ActionRequest) ([]Zone, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	operation := service.operationKey("zone-list", request)
	attestation, err := service.authorize(ctx, "zone-list", request, PermissionZoneRead, operation)
	if err != nil {
		return nil, err
	}
	zones, err := await(service, ctx, func(callCtx context.Context) ([]Zone, error) {
		return service.runtime.DNS.ListZones(callCtx, attestation, operation)
	})
	if err != nil {
		return nil, service.fail(ctx, "zone-list", operation, request, "dns", safeExternal(err, ErrDNSOperationFailed))
	}
	if err := service.checkLive(ctx); err != nil {
		return nil, service.fail(ctx, "zone-list", operation, request, "revoked", err)
	}
	if len(zones) > MaxZones {
		return nil, service.fail(ctx, "zone-list", operation, request, "bound", ErrBoundExceeded)
	}
	allowed := make(map[string]struct{}, len(attestation.ZoneIDs))
	for _, id := range attestation.ZoneIDs {
		allowed[id] = struct{}{}
	}
	for _, zone := range zones {
		if !refPattern.MatchString(zone.ID) || len(zone.Name) == 0 || len(zone.Name) > 253 {
			return nil, service.fail(ctx, "zone-list", operation, request, "invalid", ErrInvalidInput)
		}
		if _, ok := allowed[zone.ID]; !ok {
			return nil, service.fail(ctx, "zone-list", operation, request, "scope", ErrZoneDenied)
		}
	}
	sort.Slice(zones, func(left, right int) bool {
		if zones[left].Name != zones[right].Name {
			return zones[left].Name < zones[right].Name
		}
		return zones[left].ID < zones[right].ID
	})
	visible := make([]string, len(zones))
	for index := range zones {
		visible[index] = zones[index].ID
	}
	if err := service.emitUI(ctx, UIProjection{Kind: "zone-list", Outcome: "succeeded", OperationKey: operation, VisibleZones: visible, MissingPermissions: missingPermissions(attestation), LastUsed: attestation.LastUsed}); err != nil {
		return nil, service.fail(ctx, "zone-list", operation, request, "ui", ErrUIUnavailable)
	}
	if err := service.success(ctx, "zone-list", operation, request); err != nil {
		return nil, err
	}
	return append([]Zone(nil), zones...), nil
}

func (service *Service) ListRecords(ctx context.Context, request ActionRequest) ([]DNSRecord, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	operation := service.operationKey("dns-list", request)
	attestation, err := service.authorize(ctx, "dns-list", request, PermissionZoneRead, operation)
	if err != nil {
		return nil, err
	}
	records, err := await(service, ctx, func(callCtx context.Context) ([]DNSRecord, error) {
		return service.runtime.DNS.ListRecords(callCtx, attestation, request.ZoneID, MaxRecords)
	})
	if err != nil {
		return nil, service.fail(ctx, "dns-list", operation, request, "dns", safeExternal(err, ErrDNSOperationFailed))
	}
	if err := service.checkLive(ctx); err != nil {
		return nil, service.fail(ctx, "dns-list", operation, request, "revoked", err)
	}
	if len(records) > MaxRecords {
		return nil, service.fail(ctx, "dns-list", operation, request, "bound", ErrBoundExceeded)
	}
	for _, record := range records {
		if record.ZoneID != request.ZoneID || !refPattern.MatchString(record.ID) || record.Validate(true) != nil {
			return nil, service.fail(ctx, "dns-list", operation, request, "invalid", ErrInvalidInput)
		}
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].Name != records[right].Name {
			return records[left].Name < records[right].Name
		}
		if records[left].Type != records[right].Type {
			return records[left].Type < records[right].Type
		}
		return records[left].ID < records[right].ID
	})
	if err := service.success(ctx, "dns-list", operation, request); err != nil {
		return nil, err
	}
	return append([]DNSRecord(nil), records...), nil
}

func (service *Service) Create(ctx context.Context, request ActionRequest, record DNSRecord) (DNSRecord, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return DNSRecord{}, err
	}
	defer finish()
	record.ID, record.ZoneID = "", request.ZoneID
	return service.mutate(ctx, "dns-create", request, record, func(ctx context.Context, attestation TokenAttestation, operation string) (DNSRecord, error) {
		return service.runtime.DNS.Create(ctx, attestation, record, operation)
	})
}

func (service *Service) Update(ctx context.Context, request ActionRequest, record DNSRecord) (DNSRecord, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return DNSRecord{}, err
	}
	defer finish()
	if record.ID == "" {
		return DNSRecord{}, ErrInvalidInput
	}
	record.ZoneID = request.ZoneID
	return service.mutate(ctx, "dns-update", request, record, func(ctx context.Context, attestation TokenAttestation, operation string) (DNSRecord, error) {
		return service.runtime.DNS.Update(ctx, attestation, record, operation)
	})
}

func (service *Service) mutate(ctx context.Context, action string, request ActionRequest, record DNSRecord, effect func(context.Context, TokenAttestation, string) (DNSRecord, error)) (DNSRecord, error) {
	if err := record.Validate(true); err != nil {
		return DNSRecord{}, err
	}
	operation := service.recordOperationKey(action, request, record)
	attestation, err := service.authorize(ctx, action, request, PermissionDNSEdit, operation)
	if err != nil {
		return DNSRecord{}, err
	}
	if outcome, outcomeErr := service.inspectDNS(ctx, operation); outcomeErr != nil {
		return DNSRecord{}, ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.finishMutation(ctx, action, operation, request, outcome.Record)
	} else if outcome.State == OperationUnknown {
		return DNSRecord{}, service.pending(ctx, action, operation, request, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return DNSRecord{}, service.fail(ctx, action, operation, request, "dns", ErrDNSOperationFailed)
	} else if outcome.State != OperationAbsent {
		return DNSRecord{}, ErrReconcilePending
	}
	result, err := await(service, ctx, func(callCtx context.Context) (DNSRecord, error) { return effect(callCtx, attestation, operation) })
	if err != nil {
		failure := safeExternal(err, ErrDNSOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return DNSRecord{}, service.fail(ctx, action, operation, request, "dns", failure)
		}
		outcome, inspectErr := service.inspectDNS(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.finishMutation(ctx, action, operation, request, outcome.Record)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return DNSRecord{}, service.fail(ctx, action, operation, request, "dns", failure)
		}
		return DNSRecord{}, service.pending(ctx, action, operation, request, "dns", ErrReconcilePending)
	}
	return service.finishMutation(ctx, action, operation, request, result)
}

func (service *Service) finishMutation(ctx context.Context, action, operation string, request ActionRequest, result DNSRecord) (DNSRecord, error) {
	if err := service.checkLive(ctx); err != nil {
		return DNSRecord{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if result.ZoneID != request.ZoneID || !refPattern.MatchString(result.ID) || result.Validate(true) != nil {
		return DNSRecord{}, service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
	}
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, ZoneID: request.ZoneID, RecordID: result.ID, RecordType: result.Type, RecordName: result.Name}); err != nil {
		_ = service.success(ctx, action, operation, request)
		return DNSRecord{}, ErrReconcilePending
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return DNSRecord{}, err
	}
	return result, nil
}

func (service *Service) Delete(ctx context.Context, request ActionRequest, recordID string) error {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if !refPattern.MatchString(recordID) {
		return ErrInvalidInput
	}
	operation := service.recordOperationKey("dns-delete", request, DNSRecord{ID: recordID, ZoneID: request.ZoneID})
	attestation, err := service.authorize(ctx, "dns-delete", request, PermissionDNSEdit, operation)
	if err != nil {
		return err
	}
	if outcome, outcomeErr := service.inspectDNS(ctx, operation); outcomeErr != nil {
		return ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.finishDelete(ctx, operation, request, recordID)
	} else if outcome.State == OperationUnknown {
		return service.pendingRecord(ctx, "dns-delete", operation, request, recordID, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return service.failRecord(ctx, "dns-delete", operation, request, recordID, "dns", ErrDNSOperationFailed)
	} else if outcome.State != OperationAbsent {
		return ErrReconcilePending
	}
	_, effectErr := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.DNS.Delete(callCtx, attestation, request.ZoneID, recordID, operation)
	})
	if effectErr != nil {
		failure := safeExternal(effectErr, ErrDNSOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return service.failRecord(ctx, "dns-delete", operation, request, recordID, "dns", failure)
		}
		outcome, inspectErr := service.inspectDNS(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.finishDelete(ctx, operation, request, recordID)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return service.failRecord(ctx, "dns-delete", operation, request, recordID, "dns", failure)
		}
		return service.pendingRecord(ctx, "dns-delete", operation, request, recordID, "dns", ErrReconcilePending)
	}
	return service.finishDelete(ctx, operation, request, recordID)
}

func (service *Service) finishDelete(ctx context.Context, operation string, request ActionRequest, recordID string) error {
	if err := service.checkLive(ctx); err != nil {
		return service.failRecord(ctx, "dns-delete", operation, request, recordID, "revoked", err)
	}
	if err := service.emitUI(ctx, UIProjection{Kind: "dns-delete", Outcome: "succeeded", OperationKey: operation, ZoneID: request.ZoneID, RecordID: recordID}); err != nil {
		_ = service.successRecord(ctx, "dns-delete", operation, request, recordID)
		return ErrReconcilePending
	}
	return service.successRecord(ctx, "dns-delete", operation, request, recordID)
}

func (service *Service) EnrollToken(ctx context.Context, request ActionRequest, material []byte) (TokenMetadata, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		clear(material)
		return TokenMetadata{}, err
	}
	defer finish()
	return service.changeToken(ctx, "token-enroll", request, material, true, service.runtime.Vault.Enroll)
}
func (service *Service) RotateToken(ctx context.Context, request ActionRequest, material []byte) (TokenMetadata, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		clear(material)
		return TokenMetadata{}, err
	}
	defer finish()
	return service.rotateToken(ctx, request, material)
}

func (service *Service) changeToken(ctx context.Context, action string, request ActionRequest, material []byte, bootstrap bool, effect func(context.Context, string, []byte, string) (TokenMetadata, error)) (TokenMetadata, error) {
	if len(material) == 0 || len(material) > MaxTokenBytes {
		clear(material)
		return TokenMetadata{}, ErrInvalidInput
	}
	secret := append([]byte(nil), material...)
	clear(material)
	defer func() {
		if secret != nil {
			clear(secret)
		}
	}()
	operation := service.operationKey(action, request)
	if bootstrap {
		if err := service.authorizeBootstrap(ctx, action, request, operation); err != nil {
			return TokenMetadata{}, err
		}
	} else {
		if _, err := service.authorize(ctx, action, request, "", operation); err != nil {
			return TokenMetadata{}, err
		}
	}
	if outcome, inspectErr := service.inspect(ctx, operation); inspectErr != nil {
		return TokenMetadata{}, ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.finishToken(ctx, action, operation, request, outcome.Token)
	} else if outcome.State == OperationUnknown {
		return TokenMetadata{}, service.pending(ctx, action, operation, request, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", ErrVaultOperationFailed)
	} else if outcome.State != OperationAbsent {
		return TokenMetadata{}, ErrReconcilePending
	}
	ownedSecret := secret
	metadata, err := awaitOwned(service, ctx, func(callCtx context.Context) (TokenMetadata, error) {
		return effect(callCtx, service.configuration.SecretRef, ownedSecret, operation)
	}, func() { clear(ownedSecret) })
	secret = nil
	if err != nil {
		failure := safeExternal(err, ErrVaultOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		outcome, inspectErr := service.inspect(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.finishToken(ctx, action, operation, request, outcome.Token)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		return TokenMetadata{}, service.pending(ctx, action, operation, request, "vault", ErrReconcilePending)
	}
	return service.finishToken(ctx, action, operation, request, metadata)
}

func (service *Service) rotateToken(ctx context.Context, request ActionRequest, material []byte) (TokenMetadata, error) {
	if len(material) == 0 || len(material) > MaxTokenBytes {
		clear(material)
		return TokenMetadata{}, ErrInvalidInput
	}
	secret := append([]byte(nil), material...)
	clear(material)
	defer func() {
		if secret != nil {
			clear(secret)
		}
	}()
	action := "token-rotate"
	operation := service.operationKey(action, request)
	attestation, err := service.authorize(ctx, action, request, "", operation)
	if err != nil {
		return TokenMetadata{}, err
	}
	if outcome, inspectErr := service.inspect(ctx, operation); inspectErr != nil {
		return TokenMetadata{}, ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.finishToken(ctx, action, operation, request, outcome.Token)
	} else if outcome.State == OperationUnknown {
		return TokenMetadata{}, service.pending(ctx, action, operation, request, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", ErrVaultOperationFailed)
	} else if outcome.State != OperationAbsent {
		return TokenMetadata{}, ErrReconcilePending
	}
	ownedSecret := secret
	metadata, err := awaitOwned(service, ctx, func(callCtx context.Context) (TokenMetadata, error) {
		return service.runtime.Vault.Rotate(callCtx, service.configuration.SecretRef, attestation.Version, ownedSecret, operation)
	}, func() { clear(ownedSecret) })
	secret = nil
	if err != nil {
		failure := safeExternal(err, ErrVaultOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		outcome, inspectErr := service.inspect(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.finishToken(ctx, action, operation, request, outcome.Token)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return TokenMetadata{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		return TokenMetadata{}, service.pending(ctx, action, operation, request, "vault", ErrReconcilePending)
	}
	return service.finishToken(ctx, action, operation, request, metadata)
}

func (service *Service) finishToken(ctx context.Context, action, operation string, request ActionRequest, metadata TokenMetadata) (TokenMetadata, error) {
	if err := service.checkLive(ctx); err != nil {
		return TokenMetadata{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if metadata.SecretRef != service.configuration.SecretRef || !refPattern.MatchString(metadata.Version) {
		return TokenMetadata{}, service.fail(ctx, action, operation, request, "stale", ErrTokenStale)
	}
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation}); err != nil {
		_ = service.success(ctx, action, operation, request)
		return TokenMetadata{}, ErrReconcilePending
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return TokenMetadata{}, err
	}
	return metadata, nil
}

func (service *Service) authorize(ctx context.Context, action string, request ActionRequest, permission, operation string) (TokenAttestation, error) {
	if err := service.validateAction(request); err != nil {
		return TokenAttestation{}, ErrInvalidInput
	}
	if err := service.audit(ctx, AuditRecord{Action: action, Outcome: "started", OperationKey: operation + ":started", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, Suffix: request.Suffix, Domain: request.Domain}); err != nil {
		return TokenAttestation{}, err
	}
	if request.ResourceGroupRef != service.configuration.ResourceGroupRef {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	authorizationPermission := permission
	if action == "token-rotate" {
		authorizationPermission = PermissionVaultRotate
	}
	coarse := ActionContext{Phase: "coarse", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, Permission: authorizationPermission, SecretRef: service.configuration.SecretRef, OperationKey: operation}
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, coarse)
	}); err != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	attestation, err := await(service, ctx, func(callCtx context.Context) (TokenAttestation, error) {
		return service.runtime.Vault.Verify(callCtx, service.configuration.SecretRef)
	})
	if err != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "token", safeExternal(err, ErrTokenInvalid))
	}
	if err := service.checkLive(ctx); err != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	permissions, permissionErr := sortedUnique(attestation.Permissions, 32)
	if permissionErr != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "attestation", permissionErr)
	}
	zones, zoneErr := sortedUnique(attestation.ZoneIDs, MaxZones)
	if zoneErr != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "attestation", zoneErr)
	}
	if attestation.SecretRef != service.configuration.SecretRef || !refPattern.MatchString(attestation.Version) {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "attestation", ErrTokenStale)
	}
	attestation.Permissions, attestation.ZoneIDs = permissions, zones
	authorization := ActionContext{Phase: "exact", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, Permission: authorizationPermission, SecretRef: attestation.SecretRef, SecretVersion: attestation.Version, OperationKey: operation}
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, authorization)
	}); err != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	if permission != "" && !attestation.hasPermission(permission) {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "permission", ErrPermissionMissing)
	}
	if request.ZoneID != "" && !attestation.hasZone(request.ZoneID) {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "zone", ErrZoneDenied)
	}
	if err := service.checkLive(ctx); err != nil {
		return TokenAttestation{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	service.mu.Lock()
	service.status = cloneAttestation(attestation)
	service.mu.Unlock()
	return attestation, nil
}

func (service *Service) authorizeBootstrap(ctx context.Context, action string, request ActionRequest, operation string) error {
	if err := service.validateAction(request); err != nil {
		return err
	}
	if err := service.audit(ctx, AuditRecord{Action: action, Outcome: "started", OperationKey: operation + ":started", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, Suffix: request.Suffix, Domain: request.Domain}); err != nil {
		return err
	}
	if request.ResourceGroupRef != service.configuration.ResourceGroupRef {
		return service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	authorization := ActionContext{Phase: "coarse", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, Permission: PermissionVaultEnroll, SecretRef: service.configuration.SecretRef, OperationKey: operation}
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, authorization)
	}); err != nil {
		return service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	return service.checkLive(ctx)
}

func (service *Service) validateAction(request ActionRequest) error {
	if !refPattern.MatchString(request.Actor) || !refPattern.MatchString(request.ResourceGroupRef) || !refPattern.MatchString(request.OperationKey) || (request.ZoneID != "" && !refPattern.MatchString(request.ZoneID)) {
		return ErrInvalidInput
	}
	return nil
}

func (service *Service) checkLive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !service.live.Load() {
		return ErrRevoked
	}
	return nil
}

func (service *Service) begin(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	service.mu.Lock()
	if !service.live.Load() {
		service.mu.Unlock()
		return nil, nil, ErrRevoked
	}
	service.active.Add(1)
	service.mu.Unlock()
	select {
	case service.slots <- struct{}{}:
	default:
		service.active.Done()
		return nil, nil, ErrBoundExceeded
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(service.rootCtx, cancel)
	return ctx, func() { stop(); cancel(); <-service.slots; service.active.Done() }, nil
}

func await[T any](service *Service, ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	return awaitOwned(service, ctx, call, func() {})
}

func awaitOwned[T any](service *Service, ctx context.Context, call func(context.Context) (T, error), cleanup func()) (T, error) {
	var zero T
	if err := service.checkLive(ctx); err != nil {
		cleanup()
		return zero, err
	}
	select {
	case service.hostCalls <- struct{}{}:
		service.active.Add(1)
	case <-ctx.Done():
		cleanup()
		return zero, ctx.Err()
	default:
		cleanup()
		return zero, ErrBoundExceeded
	}
	if err := service.checkLive(ctx); err != nil {
		<-service.hostCalls
		service.active.Done()
		cleanup()
		return zero, err
	}
	result := make(chan struct {
		value T
		err   error
	}, 1)
	go func() {
		defer func() {
			cleanup()
			<-service.hostCalls
			service.active.Done()
		}()
		value, err := call(ctx)
		result <- struct {
			value T
			err   error
		}{value, err}
	}()
	select {
	case completed := <-result:
		if err := service.checkLive(ctx); err != nil {
			return zero, err
		}
		return completed.value, completed.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
func (service *Service) success(ctx context.Context, action, operation string, request ActionRequest) error {
	return service.successRecord(ctx, action, operation, request, "")
}
func (service *Service) successRecord(ctx context.Context, action, operation string, request ActionRequest, recordID string) error {
	_, logErr := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Logger.Log(callCtx, EventRecord{Action: action, Outcome: "succeeded", ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain})
	})
	auditErr := service.audit(ctx, AuditRecord{Action: action, Outcome: "succeeded", OperationKey: operation + ":terminal", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain})
	if logErr != nil || auditErr != nil {
		var failures []error
		failures = append(failures, ErrReconcilePending)
		if logErr != nil {
			failures = append(failures, safeExternal(logErr, ErrLogUnavailable))
		}
		if auditErr != nil {
			failures = append(failures, ErrAuditUnavailable)
		}
		return errors.Join(failures...)
	}
	return nil
}
func (service *Service) fail(ctx context.Context, action, operation string, request ActionRequest, class string, failure error) error {
	return service.failRecord(ctx, action, operation, request, "", class, failure)
}
func (service *Service) failRecord(ctx context.Context, action, operation string, request ActionRequest, recordID, class string, failure error) error {
	_, logErr := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Logger.Log(callCtx, EventRecord{Action: action, Outcome: "failed", ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain, ErrorClass: class})
	})
	auditErr := service.audit(ctx, AuditRecord{Action: action, Outcome: "failed", OperationKey: operation + ":terminal", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain})
	if auditErr != nil || logErr != nil {
		failures := []error{failure}
		if logErr != nil {
			failures = append(failures, safeExternal(logErr, ErrLogUnavailable))
		}
		if auditErr != nil {
			failures = append(failures, ErrAuditUnavailable)
		}
		return errors.Join(failures...)
	}
	return failure
}
func (service *Service) pending(ctx context.Context, action, operation string, request ActionRequest, class string, failure error) error {
	return service.pendingRecord(ctx, action, operation, request, "", class, failure)
}
func (service *Service) pendingRecord(ctx context.Context, action, operation string, request ActionRequest, recordID, class string, failure error) error {
	_, logErr := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Logger.Log(callCtx, EventRecord{Action: action, Outcome: "pending", ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain, ErrorClass: class})
	})
	auditErr := service.audit(ctx, AuditRecord{Action: action, Outcome: "pending", OperationKey: operation + ":progress", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, RecordID: recordID, Suffix: request.Suffix, Domain: request.Domain})
	failures := []error{ErrReconcilePending}
	if logErr != nil {
		failures = append(failures, safeExternal(logErr, ErrLogUnavailable))
	}
	if auditErr != nil {
		failures = append(failures, ErrAuditUnavailable)
	}
	return errors.Join(failures...)
}
func (service *Service) audit(ctx context.Context, record AuditRecord) error {
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Auditor.Audit(callCtx, record)
	}); err != nil {
		return safeExternal(err, ErrAuditUnavailable)
	}
	return nil
}

func (service *Service) emitUI(ctx context.Context, projection UIProjection) error {
	_, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.UI.Emit(callCtx, projection)
	})
	return err
}

func (service *Service) inspect(ctx context.Context, operation string) (OperationOutcome, error) {
	return await(service, ctx, func(callCtx context.Context) (OperationOutcome, error) {
		return service.runtime.Operations.Inspect(callCtx, operation)
	})
}

func (service *Service) inspectDNS(ctx context.Context, operation string) (OperationOutcome, error) {
	return await(service, ctx, func(callCtx context.Context) (OperationOutcome, error) {
		return service.runtime.DNS.Inspect(callCtx, operation)
	})
}

func (service *Service) Snapshot() (Configuration, TokenAttestation) {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.configuration, cloneAttestation(service.status)
}
func (service *Service) Cancel() {
	revoke := false
	service.mu.Lock()
	service.closeOnce.Do(func() {
		service.live.Store(false)
		service.cancel()
		revoke = true
	})
	service.status = TokenAttestation{}
	service.mappings = nil
	service.mu.Unlock()
	if revoke {
		service.runtime.Lease.Revoke()
	}
}

func (service *Service) Close(ctx context.Context) error {
	service.Cancel()
	done := make(chan struct{})
	go func() { service.active.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cloneAttestation(attestation TokenAttestation) TokenAttestation {
	attestation.Permissions = append([]string(nil), attestation.Permissions...)
	attestation.ZoneIDs = append([]string(nil), attestation.ZoneIDs...)
	return attestation
}
func missingPermissions(attestation TokenAttestation) []string {
	var result []string
	for _, permission := range []string{PermissionZoneRead, PermissionDNSEdit} {
		if !attestation.hasPermission(permission) {
			result = append(result, permission)
		}
	}
	return result
}
func safeExternal(err, fallback error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrRevoked):
		return ErrRevoked
	case errors.Is(err, ErrTokenStale):
		return ErrTokenStale
	case errors.Is(err, ErrBoundExceeded):
		return ErrBoundExceeded
	default:
		return fallback
	}
}
