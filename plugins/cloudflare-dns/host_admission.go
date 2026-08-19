package cloudflaredns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

type hostAdmission struct{}

type hostRuntimeCaller interface {
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

func (hostAdmission) Prepare(_ context.Context, request pluginsdk.RPCHandshakeRequest, configuration Configuration) (PreparedAdmission, error) {
	for _, required := range requiredGrants() {
		if !containsString(request.GrantedScopes, required) {
			return nil, ErrAuthorizationDenied
		}
	}
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err != nil {
		return nil, ErrTypedHandlesUnavailable
	}
	return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
		journal := newHostOperationJournal(client)
		vault := &hostVault{client: client}
		dns := &hostDNS{client: client}
		lease := &hostLease{}
		lease.live.Store(true)
		events := hostEvents{client: client}
		return RuntimeAdapters{
			Vault:      vault,
			DNS:        dns,
			Operations: journal,
			Lease:      lease,
			Authorizer: hostAuthorizer{configuration: configuration, live: &lease.live},
			UI:         events,
			Auditor:    events,
			Logger:     events,
			Catalog:    hostMappingCatalog{client: client},
		}, nil
	}, AbortFunc: func() {}}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type hostLease struct{ live atomic.Bool }

func (lease *hostLease) Revoke() { lease.live.Store(false) }

type hostAuthorizer struct {
	configuration Configuration
	live          *atomic.Bool
}

func (authorizer hostAuthorizer) Authorize(ctx context.Context, action ActionContext) error {
	if ctx.Err() != nil || authorizer.live == nil || !authorizer.live.Load() {
		return ErrRevoked
	}
	if action.ResourceGroupRef != authorizer.configuration.ResourceGroupRef || !refPattern.MatchString(action.Actor) {
		return ErrAuthorizationDenied
	}
	return nil
}

type hostOperationJournal struct {
	client hostRuntimeCaller
}

func newHostOperationJournal(client hostRuntimeCaller) *hostOperationJournal {
	return &hostOperationJournal{client: client}
}

func (journal *hostOperationJournal) Inspect(ctx context.Context, operation string) (OperationOutcome, error) {
	var inspection struct {
		State    string                        `json:"state"`
		Response pluginsdk.HostRuntimeResponse `json:"response"`
	}
	if err := callHost(ctx, journal.client, "operation.inspect", map[string]any{"operation_id": operation}, &inspection); err != nil {
		return OperationOutcome{}, err
	}
	switch inspection.State {
	case "absent":
		return OperationOutcome{State: OperationAbsent}, nil
	case "unknown":
		return OperationOutcome{State: OperationUnknown}, nil
	case "failed":
		return OperationOutcome{State: OperationFailed}, nil
	case "committed":
		return committedHostOutcome(inspection.Response)
	default:
		return OperationOutcome{}, ErrReconcilePending
	}
}

type hostVault struct {
	client hostRuntimeCaller
}

type hostSecretResult struct {
	Found    bool   `json:"found"`
	Ref      string `json:"ref"`
	Version  string `json:"version"`
	Material []byte `json:"material"`
}

func (vault *hostVault) Verify(ctx context.Context, ref string) (TokenAttestation, error) {
	metadata, err := vault.describe(ctx, ref)
	if err != nil || !metadata.Found {
		if strings.HasSuffix(ref, "/map/catalog") {
			return TokenAttestation{}, ErrMappingCatalogNotFound
		}
		return TokenAttestation{}, ErrTokenInvalid
	}
	var verifyEnvelope struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if _, err := cloudflareRequest(ctx, vault.client, ref, "GET", cloudflareAPIBase+"/user/tokens/verify", "", nil, &verifyEnvelope); err != nil || !validCloudflareID(verifyEnvelope.ID) || verifyEnvelope.Status != "active" {
		return TokenAttestation{}, ErrTokenInvalid
	}
	zones, err := listCloudflareZones(ctx, vault.client, ref)
	if err != nil {
		return TokenAttestation{}, err
	}
	zoneIDs := make([]string, len(zones))
	for index := range zones {
		zoneIDs[index] = zones[index].ID
	}
	return TokenAttestation{SecretRef: ref, Version: metadata.Version, Permissions: []string{PermissionDNSEdit, PermissionZoneRead, PermissionVaultEnroll, PermissionVaultRotate}, ZoneIDs: zoneIDs, LastUsed: uint64(time.Now().Unix())}, nil
}

func (vault *hostVault) Enroll(ctx context.Context, ref string, material []byte, operation string) (TokenMetadata, error) {
	defer clear(material)
	if !validCloudflareToken(material) {
		return TokenMetadata{}, ErrTokenInvalid
	}
	var result hostSecretResult
	err := callHostOperation(ctx, vault.client, "secret.put", operation, map[string]any{"ref": ref, "material": string(material)}, &result)
	if err != nil || !result.Found {
		return TokenMetadata{}, ErrVaultOperationFailed
	}
	metadata := TokenMetadata{SecretRef: result.Ref, Version: result.Version}
	return metadata, nil
}

func (vault *hostVault) Rotate(ctx context.Context, ref, expectedVersion string, material []byte, operation string) (TokenMetadata, error) {
	defer clear(material)
	if !validCloudflareToken(material) {
		return TokenMetadata{}, ErrTokenInvalid
	}
	var result hostSecretResult
	err := callHostOperation(ctx, vault.client, "secret.put", operation, map[string]any{"ref": ref, "expected_version": expectedVersion, "material": string(material)}, &result)
	if err != nil || !result.Found {
		return TokenMetadata{}, ErrVaultOperationFailed
	}
	metadata := TokenMetadata{SecretRef: result.Ref, Version: result.Version}
	return metadata, nil
}

func validCloudflareToken(material []byte) bool {
	if len(material) == 0 || len(material) > 4096 || string(material) != strings.TrimSpace(string(material)) {
		return false
	}
	return !strings.ContainsAny(string(material), "\r\n\x00")
}

func (vault *hostVault) Reveal(ctx context.Context, ref string) ([]byte, error) {
	var result hostSecretResult
	if err := callHost(ctx, vault.client, "secret.reveal", map[string]any{"ref": ref}, &result); err != nil || len(result.Material) == 0 {
		return nil, ErrMappedTokenUnavailable
	}
	return append([]byte(nil), result.Material...), nil
}

func (vault *hostVault) describe(ctx context.Context, ref string) (hostSecretResult, error) {
	var result hostSecretResult
	err := callHost(ctx, vault.client, "secret.describe", map[string]any{"ref": ref}, &result)
	return result, err
}

type hostMappingCatalog struct{ client hostRuntimeCaller }

func (catalog hostMappingCatalog) Load(ctx context.Context) (mappingCatalogSnapshot, error) {
	var result struct {
		Found bool                   `json:"found"`
		Value mappingCatalogSnapshot `json:"value"`
	}
	if err := callHost(ctx, catalog.client, "state.get", map[string]any{"key": "mapping-catalog"}, &result); err != nil {
		return mappingCatalogSnapshot{}, err
	}
	if !result.Found {
		return mappingCatalogSnapshot{}, nil
	}
	return result.Value, nil
}

func (catalog hostMappingCatalog) Save(ctx context.Context, snapshot mappingCatalogSnapshot) error {
	var result struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, catalog.client, "state.put", map[string]any{"key": "mapping-catalog", "value": snapshot}, &result); err != nil || !result.Stored {
		return ErrVaultOperationFailed
	}
	return nil
}

type hostEvents struct{ client hostRuntimeCaller }

func (events hostEvents) Emit(ctx context.Context, projection UIProjection) error {
	return events.emit(ctx, "plugin.ui."+projection.Kind, projection.Outcome, "ui", projection.RecordID, projection)
}

func (events hostEvents) Audit(ctx context.Context, record AuditRecord) error {
	return events.emit(ctx, "plugin.audit."+record.Action, record.Outcome, "operation", record.OperationKey, record)
}

func (events hostEvents) Log(ctx context.Context, record EventRecord) error {
	return events.emit(ctx, "plugin.event."+record.Action, record.Outcome, "dns_record", record.RecordID, record)
}

func (events hostEvents) emit(ctx context.Context, action, result, targetKind, targetID string, metadata any) error {
	if result != "success" && result != "failure" && result != "pending" {
		if result == "succeeded" {
			result = "success"
		} else if result == "failed" {
			result = "failure"
		} else {
			result = "pending"
		}
	}
	return callHost(ctx, events.client, "event.emit", map[string]any{"action": action, "result": result, "target_kind": targetKind, "target_id": targetID, "metadata": metadata}, nil)
}

func callHost(ctx context.Context, client hostRuntimeCaller, operation string, payload any, result any) error {
	return callHostOperation(ctx, client, operation, "", payload, result)
}

func callHostOperation(ctx context.Context, client hostRuntimeCaller, operation, operationID string, payload any, result any) error {
	if client == nil {
		return ErrTypedHandlesUnavailable
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := client.Call(ctx, pluginsdk.HostRuntimeCall{Operation: operation, OperationID: operationID, Payload: encoded}, result); err != nil {
		var runtimeError *pluginsdk.RuntimeError
		if errors.As(err, &runtimeError) && runtimeError.Code == pluginsdk.ErrorPermissionDenied {
			return ErrAuthorizationDenied
		}
		return fmt.Errorf("host capability %s: %w", operation, err)
	}
	return nil
}
