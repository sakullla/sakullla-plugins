package dockerapp

import (
	"context"
	"encoding/json"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

// Backup destination settings, hostInjected mode. The management page edits
// the settings through the plugin API; credentials material goes to the Host
// scoped-secret store (create/rotate) and only the returned
// ScopedSecretReference is persisted inside the config overlay's
// backup.s3.credentials_secret field. The rewritten overlay is committed
// through the host instance.config operation, which re-injects it into the
// plugin lifecycle (prepare) as the authoritative settings source.

// BackupRuntime is the control-plane handle the management UI drives backup
// operations through.
type BackupRuntime interface {
	ListBackups(context.Context) ([]BackupRecord, error)
	RunBackup(ctx context.Context, appID string, settings BackupSettings, destination, targetAgentID string) (BackupRecord, error)
	RestoreBackup(ctx context.Context, recordID, targetAgentID, confirm string, settings BackupSettings) (App, error)
	DeleteBackup(ctx context.Context, recordID, confirm string, settings BackupSettings) error
	ManagedBackupAgents(context.Context) ([]string, error)
	StoreInstanceConfig(ctx context.Context, config json.RawMessage) error
}

// StoreInstanceConfig commits one instance config overlay through the host
// instance.config operation. The host validates it against the config schema
// and re-injects it into the lifecycle.
func (runtime *hostCapabilityRuntime) StoreInstanceConfig(ctx context.Context, config json.RawMessage) error {
	if runtime == nil || runtime.client == nil {
		return ErrTypedHandlesUnavailable
	}
	request := pluginsdk.InstanceConfigRequest{Config: config}
	if err := request.Validate(); err != nil {
		return ErrOperationFailed
	}
	var response pluginsdk.InstanceConfigResponse
	if err := callHost(ctx, runtime.client, pluginsdk.HostRuntimeInstanceConfig, request, &response); err != nil {
		return safeFailure(ErrOperationFailed, err)
	}
	if !response.Stored {
		return ErrOperationFailed
	}
	return nil
}

// mergeBackupSettingsConfig rewrites the backup group of the retained host
// config overlay. Only the backup key is replaced; every other injected field
// (including host-written apps) passes through unchanged.
func mergeBackupSettingsConfig(document []byte, settings BackupSettings) (json.RawMessage, error) {
	overlay := map[string]json.RawMessage{}
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.UseNumber()
	if len(strings.TrimSpace(string(document))) == 0 {
		overlay["apps"] = json.RawMessage("[]")
	} else if err := decoder.Decode(&overlay); err != nil {
		return nil, ErrInvalidCompose
	}
	if _, exists := overlay["apps"]; !exists {
		overlay["apps"] = json.RawMessage("[]")
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, ErrOperationFailed
	}
	overlay["backup"] = json.RawMessage(encoded)
	merged, err := json.Marshal(overlay)
	if err != nil || len(merged) > MaxConfigBytes {
		return nil, ErrOperationFailed
	}
	return merged, nil
}
