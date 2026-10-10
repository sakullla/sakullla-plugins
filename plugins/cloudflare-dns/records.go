package cloudflaredns

import (
	"context"
)

func (service *Service) EnsureDomesticRecord(ctx context.Context, request ActionRequest, domain, recordType, name, content string, ttl uint32) (string, string, error) {
	return service.changeDomesticRecord(ctx, "record-ensure", request, domain, recordType, name, content, ttl, true)
}

func (service *Service) DeleteDomesticRecord(ctx context.Context, request ActionRequest, domain, recordType, name, content string) (string, string, error) {
	return service.changeDomesticRecord(ctx, "record-delete", request, domain, recordType, name, content, 0, false)
}

func (service *Service) changeDomesticRecord(ctx context.Context, action string, request ActionRequest, domain, recordType, name, content string, ttl uint32, ensure bool) (string, string, error) {
	ctx, finish, err := service.begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer finish()
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	request.Domain = normalized
	operation := service.mappingOperationKey(action, request, normalized, 0)
	if err := service.authorizeBare(ctx, action, "", operation, request); err != nil {
		return "", "", err
	}
	mapping, ok := service.lookupStored(normalized)
	if err := service.checkLive(ctx); err != nil {
		return "", "", service.fail(ctx, action, operation, request, "revoked", err)
	}
	providerID := ""
	if ok {
		providerID = displayProvider(mapping.Provider)
		request.Suffix = mapping.Suffix
	}
	if !ok || !isDomesticProvider(providerID) {
		return "", "", service.fail(ctx, action, operation, request, "unmapped", ErrRecordRouteUnmapped)
	}
	recordType = upperRecordType(recordType)
	if ensure {
		if recordType != "A" && recordType != "AAAA" && recordType != "TXT" {
			return "", "", service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
		}
		if ttl < 1 || ttl > 86400 {
			return "", "", service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
		}
	} else if recordType != "TXT" {
		return "", "", service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
	}
	if err := validateRecordContent(recordType, content); err != nil {
		return "", "", service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
	}
	relative, err := relativeRecordName(mapping.Suffix, name)
	if err != nil {
		return "", "", service.fail(ctx, action, operation, request, "invalid", ErrInvalidInput)
	}
	material, err := await(service, ctx, func(callCtx context.Context) ([]byte, error) {
		return service.runtime.Vault.Reveal(callCtx, mapping.SecretRef)
	})
	if err != nil || len(material) == 0 {
		clear(material)
		return "", "", service.fail(ctx, action, operation, request, "token", ErrMappedTokenUnavailable)
	}
	credential, err := decodeProviderCredential(material)
	clear(material)
	if err != nil || credential.Provider != providerID {
		credential.clear()
		return "", "", service.fail(ctx, action, operation, request, "token", ErrMappedTokenUnavailable)
	}
	defer credential.clear()
	if service.domestic == nil {
		return "", "", service.fail(ctx, action, operation, request, "dns", ErrDomesticDNSFailed)
	}
	wanted := domesticRecord{Type: recordType, Name: relative, Content: content, TTL: ttl}
	var outcome string
	if ensure {
		outcome, err = service.domestic.Ensure(ctx, credential, mapping.Suffix, wanted)
	} else {
		outcome, err = service.domestic.DeleteTXT(ctx, credential, mapping.Suffix, wanted)
	}
	if err != nil {
		return "", "", service.fail(ctx, action, operation, request, "dns", redactDomesticError(err, credential))
	}
	if outcome != domesticOutcomeCreated && outcome != domesticOutcomeUpdated && outcome != domesticOutcomeUnchanged && outcome != domesticOutcomeDeleted && outcome != domesticOutcomeAbsent {
		return "", "", service.fail(ctx, action, operation, request, "dns", ErrDomesticDNSFailed)
	}
	if err := service.success(ctx, action, operation, request); err != nil {
		return "", "", err
	}
	return providerID, outcome, nil
}

func upperRecordType(value string) string {
	switch value {
	case "a", "A":
		return "A"
	case "aaaa", "AAAA":
		return "AAAA"
	case "txt", "TXT":
		return "TXT"
	default:
		return value
	}
}

func redactDomesticError(err error, credential providerCredential) error {
	if err == nil {
		return ErrDomesticDNSFailed
	}
	redacted := redactText(err.Error(), credential.secretValues())
	if redacted == "" {
		return ErrDomesticDNSFailed
	}
	return &providerAPIError{provider: credential.Provider, detail: redacted}
}
