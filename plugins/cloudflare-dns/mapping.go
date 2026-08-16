package cloudflaredns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

type storedMapping struct {
	Suffix    string
	SecretRef string
	Version   string
	UpdatedAt uint64
	Epoch     uint64
}

func (mapping storedMapping) public() TokenMapping {
	return TokenMapping{
		Suffix:     mapping.Suffix,
		SecretRef:  mapping.SecretRef,
		Version:    mapping.Version,
		Configured: mapping.SecretRef != "" && mapping.Version != "",
		UpdatedAt:  mapping.UpdatedAt,
	}
}

func mappingSecretRef(base, suffix string, epoch uint64) string {
	digest := sha256.Sum256([]byte(suffix + "\x00" + strconv.FormatUint(epoch, 10)))
	return base + "/map/" + hex.EncodeToString(digest[:16])
}

func (service *Service) mappingOperationKey(action string, request ActionRequest, suffix string, epoch uint64) string {
	return stableOperationKey(service.configuration.Generation, action, request.OperationKey, request.Actor, request.ResourceGroupRef, suffix, strconv.FormatUint(epoch, 10))
}

func (service *Service) CreateMapping(ctx context.Context, request ActionRequest, suffix string, material []byte) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		clear(material)
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		clear(material)
		return TokenMapping{}, err
	}
	request.Suffix = normalized
	if len(material) == 0 || len(material) > MaxTokenBytes {
		clear(material)
		return TokenMapping{}, ErrInvalidInput
	}
	secret := append([]byte(nil), material...)
	clear(material)
	defer func() {
		if secret != nil {
			clear(secret)
		}
	}()
	action := "mapping-create"
	epoch := service.nextMappingEpoch(normalized)
	operation := service.mappingOperationKey(action, request, normalized, epoch)
	if err := service.authorizeBare(ctx, action, PermissionVaultEnroll, operation, request); err != nil {
		return TokenMapping{}, err
	}
	if outcome, inspectErr := service.inspect(ctx, operation); inspectErr != nil {
		return TokenMapping{}, ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.finishCommittedMapping(ctx, action, operation, request, normalized, epoch, outcome.Token)
	} else if outcome.State == OperationUnknown {
		return TokenMapping{}, service.pending(ctx, action, operation, request, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", ErrVaultOperationFailed)
	} else if outcome.State != OperationAbsent {
		return TokenMapping{}, ErrReconcilePending
	}
	if err := service.reserveMapping(normalized, epoch); err != nil {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", err)
	}
	secretRef := mappingSecretRef(service.configuration.SecretRef, normalized, epoch)
	ownedSecret := secret
	metadata, err := awaitOwned(service, ctx, func(callCtx context.Context) (TokenMetadata, error) {
		return service.runtime.Vault.Enroll(callCtx, secretRef, ownedSecret, operation)
	}, func() { clear(ownedSecret) })
	secret = nil
	if err != nil {
		service.releaseMapping(normalized)
		failure := safeExternal(err, ErrVaultOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		outcome, inspectErr := service.inspect(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.finishCommittedMapping(ctx, action, operation, request, normalized, epoch, outcome.Token)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		return TokenMapping{}, service.pending(ctx, action, operation, request, "vault", ErrReconcilePending)
	}
	return service.storeMapping(ctx, action, operation, request, storedMapping{Suffix: normalized, SecretRef: metadata.SecretRef, Version: metadata.Version, Epoch: epoch})
}

func (service *Service) ShareMapping(ctx context.Context, request ActionRequest, suffix, sourceSuffix string) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		return TokenMapping{}, err
	}
	source, err := NormalizeDomain(sourceSuffix)
	if err != nil {
		return TokenMapping{}, err
	}
	request.Suffix = normalized
	action := "mapping-share"
	epoch := service.nextMappingEpoch(normalized)
	operation := service.mappingOperationKey(action, request, normalized, epoch)
	if err := service.authorizeBare(ctx, action, PermissionVaultEnroll, operation, request); err != nil {
		return TokenMapping{}, err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	existing, exists := service.mappings[normalized]
	origin, originOK := service.configuredMapping(source)
	if exists && existing.public().Configured {
		if existing.SecretRef == origin.SecretRef && originOK {
			current := existing.public()
			service.mu.Unlock()
			return service.finishMapping(ctx, action, operation, request, current)
		}
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingConflict)
	}
	if !originOK {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	if len(service.mappings) >= MaxMappings && !exists {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "bound", ErrBoundExceeded)
	}
	service.revision++
	stored := storedMapping{Suffix: normalized, SecretRef: origin.SecretRef, Version: origin.Version, UpdatedAt: service.revision, Epoch: epoch}
	service.mappings[normalized] = stored
	current := stored.public()
	service.mu.Unlock()
	return service.finishMapping(ctx, action, operation, request, current)
}

func (service *Service) RenameMapping(ctx context.Context, request ActionRequest, suffix, newSuffix string) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		return TokenMapping{}, err
	}
	renamed, err := NormalizeDomain(newSuffix)
	if err != nil {
		return TokenMapping{}, err
	}
	request.Suffix = renamed
	action := "mapping-rename"
	epoch := service.mappingEpoch(normalized)
	operation := service.mappingOperationKey(action, request, normalized, epoch)
	if err := service.authorizeBare(ctx, action, PermissionVaultEnroll, operation, request); err != nil {
		return TokenMapping{}, err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	current, ok := service.configuredMapping(normalized)
	if !ok {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	if renamed == normalized {
		public := current.public()
		service.mu.Unlock()
		return service.finishMapping(ctx, action, operation, request, public)
	}
	if _, exists := service.configuredMapping(renamed); exists {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingConflict)
	}
	service.revision++
	service.retireSuffixLocked(normalized, current.Epoch)
	delete(service.mappings, normalized)
	current.Suffix = renamed
	current.UpdatedAt = service.revision
	service.mappings[renamed] = current
	public := current.public()
	service.mu.Unlock()
	return service.finishMapping(ctx, action, operation, request, public)
}

func (service *Service) RotateMappingToken(ctx context.Context, request ActionRequest, suffix string, material []byte) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		clear(material)
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		clear(material)
		return TokenMapping{}, err
	}
	request.Suffix = normalized
	if len(material) == 0 || len(material) > MaxTokenBytes {
		clear(material)
		return TokenMapping{}, ErrInvalidInput
	}
	secret := append([]byte(nil), material...)
	clear(material)
	defer func() {
		if secret != nil {
			clear(secret)
		}
	}()
	action := "mapping-rotate"
	epoch := service.mappingEpoch(normalized)
	operation := service.mappingOperationKey(action, request, normalized, epoch)
	if err := service.authorizeBare(ctx, action, PermissionVaultRotate, operation, request); err != nil {
		return TokenMapping{}, err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	current, ok := service.configuredMapping(normalized)
	service.mu.Unlock()
	if !ok {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	if outcome, inspectErr := service.inspect(ctx, operation); inspectErr != nil {
		return TokenMapping{}, ErrReconcilePending
	} else if outcome.State == OperationCommitted {
		return service.applyRotatedMapping(ctx, action, operation, request, current.SecretRef, outcome.Token)
	} else if outcome.State == OperationUnknown {
		return TokenMapping{}, service.pending(ctx, action, operation, request, "operation", ErrReconcilePending)
	} else if outcome.State == OperationFailed {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", ErrVaultOperationFailed)
	} else if outcome.State != OperationAbsent {
		return TokenMapping{}, ErrReconcilePending
	}
	ownedSecret := secret
	metadata, err := awaitOwned(service, ctx, func(callCtx context.Context) (TokenMetadata, error) {
		return service.runtime.Vault.Rotate(callCtx, current.SecretRef, current.Version, ownedSecret, operation)
	}, func() { clear(ownedSecret) })
	secret = nil
	if err != nil {
		failure := safeExternal(err, ErrVaultOperationFailed)
		if errors.Is(failure, ErrTokenStale) || errors.Is(failure, ErrRevoked) {
			return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		outcome, inspectErr := service.inspect(ctx, operation)
		if inspectErr == nil && outcome.State == OperationCommitted {
			return service.applyRotatedMapping(ctx, action, operation, request, current.SecretRef, outcome.Token)
		}
		if inspectErr == nil && outcome.State == OperationFailed {
			return TokenMapping{}, service.fail(ctx, action, operation, request, "vault", failure)
		}
		return TokenMapping{}, service.pending(ctx, action, operation, request, "vault", ErrReconcilePending)
	}
	return service.applyRotatedMapping(ctx, action, operation, request, current.SecretRef, metadata)
}

func (service *Service) DeleteMapping(ctx context.Context, request ActionRequest, suffix string) error {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		return err
	}
	request.Suffix = normalized
	action := "mapping-delete"
	epoch := service.mappingEpoch(normalized)
	operation := service.mappingOperationKey(action, request, normalized, epoch)
	if err := service.authorizeBare(ctx, action, PermissionVaultEnroll, operation, request); err != nil {
		return err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return service.fail(ctx, action, operation, request, "revoked", err)
	}
	current, ok := service.configuredMapping(normalized)
	if !ok {
		service.mu.Unlock()
		return service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	service.retireSuffixLocked(normalized, current.Epoch)
	delete(service.mappings, normalized)
	service.mu.Unlock()
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Suffix: normalized, Domain: request.Domain}); err != nil {
		_ = service.success(ctx, action, operation, request)
		return ErrReconcilePending
	}
	return service.success(ctx, action, operation, request)
}

func (service *Service) ListMappings(ctx context.Context, request ActionRequest) ([]TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	action := "mapping-list"
	operation := service.mappingOperationKey(action, request, "", 0)
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return nil, err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return nil, service.fail(ctx, action, operation, request, "revoked", err)
	}
	result := make([]TokenMapping, 0, len(service.mappings))
	for _, mapping := range service.mappings {
		if mapping.public().Configured {
			result = append(result, mapping.public())
		}
	}
	service.mu.Unlock()
	sort.Slice(result, func(left, right int) bool { return result[left].Suffix < result[right].Suffix })
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Domain: request.Domain}); err != nil {
		return nil, service.fail(ctx, action, operation, request, "ui", ErrUIUnavailable)
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return nil, err
	}
	return result, nil
}

func (service *Service) GetMapping(ctx context.Context, request ActionRequest, suffix string) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(suffix)
	if err != nil {
		return TokenMapping{}, err
	}
	request.Suffix = normalized
	action := "mapping-get"
	operation := service.mappingOperationKey(action, request, normalized, service.mappingEpoch(normalized))
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return TokenMapping{}, err
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	mapping, ok := service.configuredMapping(normalized)
	service.mu.Unlock()
	if !ok {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	current := mapping.public()
	return service.finishMapping(ctx, action, operation, request, current)
}

func (service *Service) LookupMapping(ctx context.Context, request ActionRequest, domain string) (TokenMapping, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return TokenMapping{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return TokenMapping{}, err
	}
	request.Domain = normalized
	action := "mapping-lookup"
	operation := service.mappingOperationKey(action, request, normalized, 0)
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return TokenMapping{}, err
	}
	mapping, ok := service.lookupStored(normalized)
	if err := service.checkLive(ctx); err != nil {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if !ok {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "unmapped", ErrMappingNotFound)
	}
	request.Suffix = mapping.Suffix
	return service.finishMapping(ctx, action, operation, request, mapping.public())
}

func (service *Service) ResolveToken(ctx context.Context, request ActionRequest, domain string, fallback []byte) (issued IssuedToken, err error) {
	defer clear(fallback)
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return IssuedToken{}, err
	}
	defer finish()
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return IssuedToken{}, err
	}
	request.Domain = normalized
	action := "token-resolve"
	operation := service.mappingOperationKey(action, request, normalized, 0)
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return IssuedToken{}, err
	}
	mapping, ok := service.lookupStored(normalized)
	if err := service.checkLive(ctx); err != nil {
		return IssuedToken{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if !ok {
		if len(fallback) == 0 {
			return IssuedToken{}, service.fail(ctx, action, operation, request, "unmapped", domainTokenUnavailable(normalized))
		}
		issued = IssuedToken{Domain: normalized, Fallback: true, material: append([]byte(nil), fallback...)}
		if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Domain: normalized}); err != nil {
			issued.Clear()
			return IssuedToken{}, service.fail(ctx, action, operation, request, "ui", ErrUIUnavailable)
		}
		if err := service.success(ctx, action, operation, request); err != nil {
			issued.Clear()
			return IssuedToken{}, err
		}
		return issued, nil
	}
	request.Suffix = mapping.Suffix
	attestation, err := await(service, ctx, func(callCtx context.Context) (TokenAttestation, error) {
		return service.runtime.Vault.Verify(callCtx, mapping.SecretRef)
	})
	if err != nil {
		return IssuedToken{}, service.fail(ctx, action, operation, request, "token", safeExternal(err, ErrMappedTokenUnavailable))
	}
	if attestation.SecretRef != mapping.SecretRef || !refPattern.MatchString(attestation.Version) {
		return IssuedToken{}, service.fail(ctx, action, operation, request, "attestation", ErrMappedTokenUnavailable)
	}
	exact := ActionContext{Phase: "exact", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, Permission: "", SecretRef: attestation.SecretRef, SecretVersion: attestation.Version, OperationKey: operation}
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, exact)
	}); err != nil {
		return IssuedToken{}, service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	material, err := await(service, ctx, func(callCtx context.Context) ([]byte, error) {
		return service.runtime.Vault.Reveal(callCtx, mapping.SecretRef)
	})
	if err != nil || len(material) == 0 {
		clear(material)
		return IssuedToken{}, service.fail(ctx, action, operation, request, "token", ErrMappedTokenUnavailable)
	}
	issued = IssuedToken{Domain: normalized, Suffix: mapping.Suffix, SecretRef: mapping.SecretRef, Version: attestation.Version, material: append([]byte(nil), material...)}
	clear(material)
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Suffix: mapping.Suffix, Domain: normalized}); err != nil {
		issued.Clear()
		return IssuedToken{}, service.fail(ctx, action, operation, request, "ui", ErrUIUnavailable)
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		issued.Clear()
		return IssuedToken{}, err
	}
	return issued, nil
}

func (service *Service) authorizeBare(ctx context.Context, action, permission, operation string, request ActionRequest) error {
	if err := service.validateAction(request); err != nil {
		return err
	}
	if err := service.audit(ctx, AuditRecord{Action: action, Outcome: "started", OperationKey: operation + ":started", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, ZoneID: request.ZoneID, Suffix: request.Suffix, Domain: request.Domain}); err != nil {
		return err
	}
	if request.ResourceGroupRef != service.configuration.ResourceGroupRef {
		return service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	authorization := ActionContext{Phase: "coarse", Actor: request.Actor, ResourceGroupRef: request.ResourceGroupRef, Permission: permission, SecretRef: service.configuration.SecretRef, OperationKey: operation}
	if _, err := await(service, ctx, func(callCtx context.Context) (struct{}, error) {
		return struct{}{}, service.runtime.Authorizer.Authorize(callCtx, authorization)
	}); err != nil {
		return service.fail(ctx, action, operation, request, "authorization", ErrAuthorizationDenied)
	}
	return service.checkLive(ctx)
}

func (service *Service) reserveMapping(suffix string, epoch uint64) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.guardMappingsLocked(); err != nil {
		return err
	}
	if mapping, exists := service.mappings[suffix]; exists && mapping.public().Configured {
		return ErrMappingConflict
	}
	if len(service.mappings) >= MaxMappings {
		if _, exists := service.mappings[suffix]; !exists {
			return ErrBoundExceeded
		}
	}
	service.mappings[suffix] = storedMapping{Suffix: suffix, Epoch: epoch}
	return nil
}

func (service *Service) releaseMapping(suffix string) {
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return
	}
	if mapping, exists := service.mappings[suffix]; exists && !mapping.public().Configured {
		delete(service.mappings, suffix)
	}
	service.mu.Unlock()
}

func (service *Service) guardMappingsLocked() error {
	if !service.live.Load() || service.mappings == nil {
		return ErrRevoked
	}
	return nil
}

func (service *Service) mappingEpoch(suffix string) uint64 {
	service.mu.Lock()
	defer service.mu.Unlock()
	if mapping, ok := service.configuredMapping(suffix); ok {
		return mapping.Epoch
	}
	return 0
}

func (service *Service) nextMappingEpoch(suffix string) uint64 {
	service.mu.Lock()
	defer service.mu.Unlock()
	if mapping, ok := service.configuredMapping(suffix); ok {
		return mapping.Epoch
	}
	return service.retired[suffix] + 1
}

func (service *Service) retireSuffixLocked(suffix string, epoch uint64) {
	if epoch == 0 {
		return
	}
	if current := service.retired[suffix]; epoch > current {
		service.retired[suffix] = epoch
	}
}

func (service *Service) configuredMapping(suffix string) (storedMapping, bool) {
	mapping, ok := service.mappings[suffix]
	if !ok || !mapping.public().Configured {
		return storedMapping{}, false
	}
	return mapping, true
}

func (service *Service) lookupStored(domain string) (storedMapping, bool) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if !service.live.Load() || service.mappings == nil {
		return storedMapping{}, false
	}
	best := storedMapping{}
	found := false
	for suffix, mapping := range service.mappings {
		if !mapping.public().Configured || !DomainMatchesSuffix(domain, suffix) {
			continue
		}
		if !found || len(suffix) > len(best.Suffix) {
			best = mapping
			found = true
		}
	}
	return best, found
}

func (service *Service) storeMapping(ctx context.Context, action, operation string, request ActionRequest, mapping storedMapping) (TokenMapping, error) {
	if mapping.SecretRef == "" || !refPattern.MatchString(mapping.SecretRef) || !refPattern.MatchString(mapping.Version) {
		service.releaseMapping(mapping.Suffix)
		return TokenMapping{}, service.fail(ctx, action, operation, request, "stale", ErrTokenStale)
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	service.revision++
	mapping.UpdatedAt = service.revision
	service.mappings[mapping.Suffix] = mapping
	current := mapping.public()
	service.mu.Unlock()
	return service.finishMapping(ctx, action, operation, request, current)
}

func (service *Service) finishCommittedMapping(ctx context.Context, action, operation string, request ActionRequest, suffix string, epoch uint64, metadata TokenMetadata) (TokenMapping, error) {
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if current, ok := service.configuredMapping(suffix); ok {
		public := current.public()
		service.mu.Unlock()
		return service.finishMapping(ctx, action, operation, request, public)
	}
	if epoch != 0 && service.retired[suffix] >= epoch {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	service.mu.Unlock()
	return service.storeMapping(ctx, action, operation, request, storedMapping{Suffix: suffix, SecretRef: metadata.SecretRef, Version: metadata.Version, Epoch: epoch})
}

func (service *Service) applyRotatedMapping(ctx context.Context, action, operation string, request ActionRequest, secretRef string, metadata TokenMetadata) (TokenMapping, error) {
	if metadata.SecretRef != secretRef || !refPattern.MatchString(metadata.Version) {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "stale", ErrTokenStale)
	}
	service.mu.Lock()
	if err := service.guardMappingsLocked(); err != nil {
		service.mu.Unlock()
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	var current TokenMapping
	found := false
	service.revision++
	for suffix, mapping := range service.mappings {
		if mapping.SecretRef != secretRef || !mapping.public().Configured {
			continue
		}
		mapping.Version = metadata.Version
		mapping.UpdatedAt = service.revision
		service.mappings[suffix] = mapping
		if suffix == request.Suffix {
			current = mapping.public()
			found = true
		}
	}
	service.mu.Unlock()
	if !found {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "mapping", ErrMappingNotFound)
	}
	return service.finishMapping(ctx, action, operation, request, current)
}

func (service *Service) finishMapping(ctx context.Context, action, operation string, request ActionRequest, mapping TokenMapping) (TokenMapping, error) {
	if err := service.checkLive(ctx); err != nil {
		return TokenMapping{}, service.fail(ctx, action, operation, request, "revoked", err)
	}
	if err := service.emitUI(ctx, UIProjection{Kind: action, Outcome: "succeeded", OperationKey: operation, Suffix: mapping.Suffix, Domain: request.Domain}); err != nil {
		_ = service.success(ctx, action, operation, request)
		return TokenMapping{}, ErrReconcilePending
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return TokenMapping{}, err
	}
	return mapping, nil
}

func domainTokenUnavailable(domain string) error {
	return fmt.Errorf("%w: %s", ErrTokenUnavailable, domain)
}
