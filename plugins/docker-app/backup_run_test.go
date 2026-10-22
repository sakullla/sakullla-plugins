package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const backupRunTestSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const backupRunTestCompose = `services:
  app:
    image: example/app:1
    volumes:
      - appdata:/var/lib/app
      - ./data:/data
      - /host/mount:/host
      - configs/app:/etc/configs
`

func backupRunTestSettings(s3 bool, node bool) BackupSettings {
	settings := BackupSettings{}
	if s3 {
		settings.S3 = BackupS3Settings{
			Endpoint: testBackupS3Endpoint, Bucket: testBackupS3Bucket, Prefix: testBackupS3Prefix,
			CredentialsSecret: testBackupS3CredentialsReferenceJSON,
		}
	}
	settings.Node.Enabled = node
	return settings
}

// backupRunStub stands in for the Host transport: it serves the plugin calls
// and the backups/app state keys the orchestration uses and records every
// dispatch for assertions.
type backupRunStub struct {
	t    *testing.T
	mu   sync.Mutex
	apps []App

	volumeSpecs     []string
	failVolume      string
	packPayloads    []map[string]any
	cleanCalls      int
	discardPayloads []string
	uploadPayloads  []map[string]any
	failUpload      error
	deletePayloads  []map[string]any
	failDelete      error
	failPut         error

	putCount int
	stored   backupStoreSnapshot
}

func (stub *backupRunStub) call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.t.Helper()
	switch call.Operation {
	case "state.get":
		var request struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			stub.t.Fatalf("state.get payload: %v", err)
		}
		switch request.Key {
		case pluginAppsStateKey:
			return copyHostResult(map[string]any{"found": true, "value": stub.apps}, target)
		case pluginBackupsStateKey:
			if stub.putCount == 0 {
				return copyHostResult(map[string]any{"found": false}, target)
			}
			return copyHostResult(map[string]any{"found": true, "value": stub.stored}, target)
		default:
			stub.t.Fatalf("unexpected state.get key %q", request.Key)
		}
	case "state.put":
		var request struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			stub.t.Fatalf("state.put payload: %v", err)
		}
		if request.Key != pluginBackupsStateKey {
			stub.t.Fatalf("unexpected state.put key %q", request.Key)
		}
		if stub.failPut != nil {
			return stub.failPut
		}
		if err := json.Unmarshal(request.Value, &stub.stored); err != nil {
			stub.t.Fatalf("state.put value: %v", err)
		}
		stub.putCount++
		return copyHostResult(map[string]any{"stored": true}, target)
	case pluginsdk.HostRuntimePluginCall:
		request := decodePluginCallRequest(stub.t, call)
		payload := decodePluginCallInner(stub.t, request)
		switch request.Name {
		case pluginCallVolumeName:
			spec, _ := payload["volume"].(string)
			stub.volumeSpecs = append(stub.volumeSpecs, spec)
			if spec == stub.failVolume {
				return errors.New("volume archive failed: volume was not found (appdata)")
			}
			staged := stagedSpecName(stub.t, spec)
			return copyHostResult(map[string]any{
				"accepted":     true,
				"archive_path": path.Join("media", pluginsdk.DockerVolumeStagingDir, staged+".tar"),
			}, target)
		case pluginCallBackupPackName:
			action, _ := payload["action"].(string)
			switch action {
			case backupPackActionPack:
				stub.packPayloads = append(stub.packPayloads, payload)
				created, _ := payload["created"].(string)
				instant, err := time.Parse(time.RFC3339, created)
				if err != nil {
					stub.t.Fatalf("pack created = %q: %v", created, err)
				}
				name := "media-" + instant.Format(backupTimestampLayout) + backupArtifactSuffix
				return copyHostResult(map[string]any{
					"accepted": true, "path": backupArtifactDir + "/" + name, "name": name,
					"size": 4096, "sha256": backupRunTestSHA256, "created": created,
				}, target)
			case backupPackActionClean:
				stub.cleanCalls++
				return copyHostResult(map[string]any{"accepted": true}, target)
			case backupPackActionDiscard:
				discard, _ := payload["path"].(string)
				stub.discardPayloads = append(stub.discardPayloads, discard)
				return copyHostResult(map[string]any{"accepted": true}, target)
			default:
				stub.t.Fatalf("backup-pack action = %q", action)
			}
		case pluginCallBackupS3Name:
			action, _ := payload["action"].(string)
			switch action {
			case backupS3ActionUpload:
				stub.uploadPayloads = append(stub.uploadPayloads, payload)
				if stub.failUpload != nil {
					return stub.failUpload
				}
				object, _ := payload["object"].(string)
				return copyHostResult(map[string]any{
					"accepted": true, "object": testBackupS3Prefix + "/" + object,
					"size": 4096, "sha256": backupRunTestSHA256,
				}, target)
			case backupS3ActionDelete:
				stub.deletePayloads = append(stub.deletePayloads, payload)
				if stub.failDelete != nil {
					return stub.failDelete
				}
				return copyHostResult(map[string]any{"accepted": true}, target)
			default:
				stub.t.Fatalf("backup-s3 action = %q", action)
			}
		case pluginCallComposeName:
			stub.t.Fatal("backup run must not touch the app lifecycle")
		default:
			stub.t.Fatalf("unexpected plugin.call name %q", request.Name)
		}
	default:
		stub.t.Fatalf("unexpected host operation %q", call.Operation)
	}
	return nil
}

func stagedSpecName(t *testing.T, spec string) string {
	t.Helper()
	source := volumeSource(spec)
	if classifyBindSource(source) == bindNamed {
		return source
	}
	staged, ok := stagedVolumeMemberName(source)
	if !ok {
		t.Fatalf("staged name for spec %q", spec)
	}
	return staged
}

func newBackupRunRuntime(t *testing.T, apps []App) (*hostCapabilityRuntime, *backupRunStub) {
	t.Helper()
	stub := &backupRunStub{t: t, apps: apps}
	runtime := newHostCapabilityRuntime(hostCallFunc(stub.call))
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	return runtime, stub
}

func backupRunTestApp(compose string) []App {
	return []App{{ID: "media", AgentID: "agent-1", Compose: compose, Generation: "generation-1"}}
}

func TestRunBackupRejectsUnconfiguredDestination(t *testing.T) {
	tests := []struct {
		name     string
		settings BackupSettings
	}{
		{name: "empty", settings: BackupSettings{}},
		{name: "endpoint only", settings: BackupSettings{S3: BackupS3Settings{Endpoint: testBackupS3Endpoint}}},
		{name: "bucket only", settings: BackupSettings{S3: BackupS3Settings{Bucket: testBackupS3Bucket}}},
		{name: "credentials only", settings: BackupSettings{S3: BackupS3Settings{CredentialsSecret: testBackupS3CredentialsReferenceJSON}}},
		{name: "node disabled", settings: backupRunTestSettings(false, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newHostCapabilityRuntime(hostCallFunc(func(context.Context, pluginsdk.HostRuntimeCall, any) error {
				t.Fatal("unconfigured destination still dispatched to the host")
				return nil
			}))
			record, err := runtime.RunBackup(context.Background(), "media", test.settings, "", "")
			if !errors.Is(err, ErrBackupDestinationUnconfigured) {
				t.Fatalf("err = %v want %v", err, ErrBackupDestinationUnconfigured)
			}
			if record != (BackupRecord{}) {
				t.Fatalf("record = %#v", record)
			}
		})
	}
}

func TestRunBackupGatesUnknownAppAndInvalidInput(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	if _, err := runtime.RunBackup(context.Background(), "other", backupRunTestSettings(true, false), "", ""); !errors.Is(err, ErrBackupRunAppUnknown) {
		t.Fatalf("unknown app err = %v", err)
	}
	if _, err := runtime.RunBackup(context.Background(), "Bad_ID", backupRunTestSettings(true, false), "", ""); err == nil || !strings.Contains(err.Error(), backupRunStageAppInvalid) {
		t.Fatalf("invalid app id err = %v", err)
	}
	if len(stub.volumeSpecs) != 0 || len(stub.packPayloads) != 0 || stub.putCount != 0 {
		t.Fatalf("gates dispatched work: volumes=%v packs=%d puts=%d", stub.volumeSpecs, len(stub.packPayloads), stub.putCount)
	}
}

func TestRunBackupSuccessUploadsAndStoresRecord(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	record, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Host binds never reach the operation face; the remaining volumes archive
	// in deterministic member order.
	wantSpecs := []string{"configs/app", "./data", "appdata"}
	if strings.Join(stub.volumeSpecs, ",") != strings.Join(wantSpecs, ",") {
		t.Fatalf("volume specs = %v want %v", stub.volumeSpecs, wantSpecs)
	}
	if len(stub.packPayloads) != 1 {
		t.Fatalf("pack payloads = %d", len(stub.packPayloads))
	}
	pack := stub.packPayloads[0]
	if pack["action"] != backupPackActionPack || pack["agent_id"] != "agent-1" || pack["app_id"] != "media" {
		t.Fatalf("pack payload = %#v", pack)
	}
	if pack["compose"] != backupRunTestCompose {
		t.Fatalf("pack compose = %#v", pack["compose"])
	}
	if _, err := time.Parse(time.RFC3339, pack["created"].(string)); err != nil {
		t.Fatalf("pack created = %#v", pack["created"])
	}
	volumes, _ := pack["volumes"].([]any)
	wantMembers := []string{"bind-configs_app", "bind-data", "vol-appdata"}
	if len(volumes) != len(wantMembers) {
		t.Fatalf("pack volumes = %#v", pack["volumes"])
	}
	for index, entry := range volumes {
		volume, _ := entry.(map[string]any)
		if volume["member"] != wantMembers[index] {
			t.Fatalf("pack volume[%d] = %#v want member %q", index, volume, wantMembers[index])
		}
	}
	if volume, _ := volumes[0].(map[string]any); volume["staged"] != "configs_app" || volume["spec"] != "configs/app" {
		t.Fatalf("pack bind volume = %#v", volumes[0])
	}
	// Upload carries the destination parameters and the packed artifact.
	if len(stub.uploadPayloads) != 1 {
		t.Fatalf("upload payloads = %d", len(stub.uploadPayloads))
	}
	upload := stub.uploadPayloads[0]
	if upload["endpoint"] != testBackupS3Endpoint || upload["bucket"] != testBackupS3Bucket ||
		upload["prefix"] != testBackupS3Prefix || upload["credentials_secret"] != testBackupS3CredentialsReferenceJSON {
		t.Fatalf("upload destination = %#v", upload)
	}
	wantName := record.ID
	if upload["object"] != wantName || upload["path"] != backupArtifactDir+"/"+wantName {
		t.Fatalf("upload artifact = %#v", upload)
	}
	// The stored record matches the packed artifact and the destination.
	want := BackupRecord{
		ID: wantName, AppID: "media", OriginAgentID: "agent-1", Created: record.Created,
		SizeBytes: 4096, SHA256: backupRunTestSHA256,
		Destination: BackupDestinationRef{Type: BackupDestinationS3, Location: testBackupS3Prefix + "/" + wantName},
	}
	if record != want {
		t.Fatalf("record = %#v want %#v", record, want)
	}
	if _, err := time.Parse(time.RFC3339, record.Created); err != nil {
		t.Fatalf("record created = %q: %v", record.Created, err)
	}
	if stub.putCount != 1 || len(stub.stored.Records) != 1 || stub.stored.Records[wantName] != want {
		t.Fatalf("stored snapshot = %#v puts=%d", stub.stored, stub.putCount)
	}
	// No lifecycle calls and no cleanup residue on success.
	if stub.cleanCalls != 0 || len(stub.discardPayloads) != 0 || len(stub.deletePayloads) != 0 {
		t.Fatalf("cleanup calls clean=%d discard=%v delete=%v", stub.cleanCalls, stub.discardPayloads, stub.deletePayloads)
	}
}

func TestRunBackupNodeDestinationKeepsArtifactOnAgent(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	record, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(false, true), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if record.Destination != (BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-1"}) {
		t.Fatalf("destination = %#v", record.Destination)
	}
	if len(stub.uploadPayloads) != 0 {
		t.Fatalf("node destination uploaded: %#v", stub.uploadPayloads)
	}
	if stub.putCount != 1 || len(stub.stored.Records) != 1 {
		t.Fatalf("stored snapshot = %#v puts=%d", stub.stored, stub.putCount)
	}
}

func TestRunBackupVolumePlanFailuresDispatchNothing(t *testing.T) {
	tests := []struct {
		name    string
		compose string
		want    string
	}{
		{
			name:    "named volume and relative bind collide",
			compose: "services: {app: {volumes: ['data:/a', './data:/b']}}",
			want:    backupRunStageConflict,
		},
		{
			name:    "relative bind flatten collides with named volume",
			compose: "services: {app: {volumes: ['configs/app:/a', 'configs_app:/b']}}",
			want:    backupRunStageConflict,
		},
		{
			name:    "bind source inside the staging tree",
			compose: "services: {app: {volumes: ['./backup-staging/volumes/appdata.tar:/a']}}",
			want:    backupRunStageStagingSource,
		},
		{
			name:    "bind source is inside the staging tree without ./ prefix",
			compose: "services: {app: {volumes: ['backup-staging/volumes/appdata.tar:/a']}}",
			want:    backupRunStageStagingSource,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, stub := newBackupRunRuntime(t, backupRunTestApp(test.compose))
			_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
			if err == nil || !strings.Contains(err.Error(), "backup run failed") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v want stage %q", err, test.want)
			}
			if len(stub.volumeSpecs) != 0 || len(stub.packPayloads) != 0 || stub.putCount != 0 || len(stub.uploadPayloads) != 0 {
				t.Fatalf("planning failure dispatched work: volumes=%v packs=%d puts=%d", stub.volumeSpecs, len(stub.packPayloads), stub.putCount)
			}
		})
	}
}

func TestRunBackupVolumeArchiveFailureCleansStagingWithoutRecord(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	stub.failVolume = "appdata"
	_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
	if err == nil || !strings.Contains(err.Error(), "backup run failed at volume archive (appdata)") || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if stub.cleanCalls != 1 {
		t.Fatalf("clean calls = %d", stub.cleanCalls)
	}
	if stub.putCount != 0 || len(stub.uploadPayloads) != 0 || len(stub.packPayloads) != 0 {
		t.Fatalf("failed run stored state: puts=%d uploads=%d packs=%d", stub.putCount, len(stub.uploadPayloads), len(stub.packPayloads))
	}
}

func TestRunBackupUploadFailureDiscardsArtifactWithoutRecord(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	stub.failUpload = errors.New("backup-s3 upload failed: access was denied")
	_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
	if err == nil || !strings.Contains(err.Error(), "backup run failed at upload") || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if stub.putCount != 0 {
		t.Fatalf("failed upload still stored a record: puts=%d", stub.putCount)
	}
	if len(stub.discardPayloads) != 1 {
		t.Fatalf("discard payloads = %v", stub.discardPayloads)
	}
	if !strings.HasPrefix(stub.discardPayloads[0], backupArtifactDir+"/") || !strings.HasSuffix(stub.discardPayloads[0], backupArtifactSuffix) {
		t.Fatalf("discard payload = %q", stub.discardPayloads[0])
	}
	if stub.cleanCalls != 1 {
		t.Fatalf("clean calls = %d", stub.cleanCalls)
	}
}

func TestRunBackupRecordStoreFailureCompensatesDestination(t *testing.T) {
	storeFailure := errors.New("state backend refused")
	t.Run("object removed", func(t *testing.T) {
		runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
		stub.failPut = storeFailure
		_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
		if err == nil || !strings.Contains(err.Error(), backupRunStageRecordStore) {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "could not be removed") {
			t.Fatalf("compensated run still reports cleanup failure: %v", err)
		}
		if len(stub.deletePayloads) != 1 {
			t.Fatalf("delete payloads = %v", stub.deletePayloads)
		}
		// The stored key carries the prefix; the delete call re-joins it.
		if object, _ := stub.deletePayloads[0]["object"].(string); !strings.HasPrefix(object, "media-") || !strings.HasSuffix(object, backupArtifactSuffix) {
			t.Fatalf("delete object = %#v", stub.deletePayloads[0]["object"])
		}
		if stub.putCount != 0 {
			t.Fatalf("failed store counted as put: %d", stub.putCount)
		}
	})
	t.Run("object removal fails", func(t *testing.T) {
		runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
		stub.failPut = storeFailure
		stub.failDelete = errors.New("backup-s3 delete failed: access was denied")
		_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
		if err == nil || !strings.Contains(err.Error(), backupRunStageRecordStore) || !strings.Contains(err.Error(), "destination object could not be removed") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("node artifact discarded", func(t *testing.T) {
		runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
		stub.failPut = storeFailure
		_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(false, true), "", "")
		if err == nil || !strings.Contains(err.Error(), backupRunStageRecordStore) {
			t.Fatalf("err = %v", err)
		}
		if len(stub.discardPayloads) != 1 || !strings.HasPrefix(stub.discardPayloads[0], backupArtifactDir+"/") {
			t.Fatalf("discard payloads = %v", stub.discardPayloads)
		}
	})
}

func TestRunBackupUnavailableWithoutHostClient(t *testing.T) {
	var runtime *hostCapabilityRuntime
	if _, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", ""); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil runtime err = %v", err)
	}
	if _, err := newHostCapabilityRuntime(nil).RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", ""); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil client err = %v", err)
	}
}

func TestPlanBackupVolumes(t *testing.T) {
	plans, err := planBackupVolumes(backupRunTestCompose)
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, plan := range plans {
		members = append(members, plan.Member)
	}
	want := []string{"bind-configs_app", "bind-data", "vol-appdata"}
	if strings.Join(members, ",") != strings.Join(want, ",") {
		t.Fatalf("members = %v want %v", members, want)
	}
	if plans, err = planBackupVolumes(""); err != nil || len(plans) != 0 {
		t.Fatalf("empty compose plans = %v err = %v", plans, err)
	}
	if _, err = planBackupVolumes("services: {app: {volumes: ['/host:/a']}}"); err != nil {
		t.Fatalf("host-only compose err = %v", err)
	}
	duplicate := "services: {app: {volumes: ['appdata:/a']}, sidecar: {volumes: ['appdata:/b']}}"
	if plans, err = planBackupVolumes(duplicate); err != nil || len(plans) != 1 {
		t.Fatalf("duplicate spec plans = %v err = %v", plans, err)
	}
}

func callBackupPackAction(t *testing.T, controller *Controller, payload map[string]any) ([]byte, error) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", pluginCallBackupPackName, raw)
}

func writeStagedVolumeArchive(t *testing.T, root, name string) {
	t.Helper()
	staged := volumeStagedArchivePath(root, "media", name)
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("volume-tar:"+name), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCallBackupPackCreatesArtifact(t *testing.T) {
	root := t.TempDir()
	workdir := filepath.Join(root, "media")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "notes.txt"), []byte("workspace-note"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workdir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "sub", "deep.txt"), []byte("deep-note"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStagedVolumeArchive(t, root, "appdata")
	writeStagedVolumeArchive(t, root, "configs_app")
	if err := os.MkdirAll(filepath.Join(workdir, backupArtifactDir), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(workdir, backupArtifactDir, "media-old"+backupArtifactSuffix)
	if err := os.WriteFile(previous, []byte("previous artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := newCallController(t, root, unusedDockerRunner(t), nil)
	raw, err := callBackupPackAction(t, controller, map[string]any{
		"action": backupPackActionPack, "agent_id": "agent-1", "app_id": "media",
		"compose": "services: {app: {image: example/app:1}}", "created": "2026-10-22T08:09:10Z",
		"volumes": []map[string]any{
			{"spec": "appdata", "staged": "appdata", "member": "vol-appdata"},
			{"spec": "configs/app", "staged": "configs_app", "member": "bind-configs_app"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Accepted bool   `json:"accepted"`
		Path     string `json:"path"`
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
		Created  string `json:"created"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	wantName := "media-20261022T080910Z" + backupArtifactSuffix
	if !result.Accepted || result.Name != wantName || result.Path != backupArtifactDir+"/"+wantName {
		t.Fatalf("result = %s", raw)
	}
	if result.Created != "2026-10-22T08:09:10Z" || result.Size <= 0 || !sha256Hex(result.SHA256) {
		t.Fatalf("result = %s", raw)
	}
	// The artifact verifies and carries the class-prefixed volume members.
	reader, err := OpenBackupArtifact(filepath.Join(workdir, backupArtifactDir, wantName))
	if err != nil {
		t.Fatal(err)
	}
	members := map[string]bool{}
	for _, member := range reader.Manifest().Members {
		members[member.Name] = true
	}
	for _, want := range []string{
		backupComposeMember, "workspace/notes.txt", "workspace/sub/deep.txt",
		"volumes/vol-appdata.tar", "volumes/bind-configs_app.tar",
	} {
		if !members[want] {
			t.Fatalf("member %q missing from %v", want, members)
		}
	}
	for _, forbidden := range []string{"workspace/" + backupArtifactDir, "workspace/" + backupStagingDir} {
		for name := range members {
			if strings.HasPrefix(name, forbidden) {
				t.Fatalf("plugin-owned tree packed as workspace member %q", name)
			}
		}
	}
	// Staging is consumed; previous artifacts survive.
	for _, staged := range []string{"appdata", "configs_app"} {
		if _, err := os.Stat(volumeStagedArchivePath(root, "media", staged)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staged archive %s still present: %v", staged, err)
		}
	}
	if _, err := os.Stat(previous); err != nil {
		t.Fatalf("previous artifact removed: %v", err)
	}
}

func TestCallBackupPackFailures(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "media"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeStagedVolumeArchive(t, root, "appdata")
	controller := newCallController(t, root, unusedDockerRunner(t), nil)
	base := map[string]any{
		"action": backupPackActionPack, "agent_id": "agent-1", "app_id": "media",
		"compose": "services: {app: {image: example/app:1}}", "created": "2026-10-22T08:09:10Z",
	}
	tests := []struct {
		name    string
		mutate  func(payload map[string]any)
		want    string
		arrange func(t *testing.T, root string)
	}{
		{
			name: "staged archive missing",
			mutate: func(payload map[string]any) {
				payload["volumes"] = []map[string]any{{"spec": "ghost", "staged": "ghost", "member": "vol-ghost"}}
			},
			want: "backup pack failed: staged volume archive is missing",
		},
		{
			name: "invalid member name",
			mutate: func(payload map[string]any) {
				payload["volumes"] = []map[string]any{{"spec": "appdata", "staged": "appdata", "member": "bad/name"}}
			},
			want: "backup pack failed: pack request is invalid",
		},
		{
			name: "duplicate staged name",
			mutate: func(payload map[string]any) {
				payload["volumes"] = []map[string]any{
					{"spec": "appdata", "staged": "appdata", "member": "vol-appdata"},
					{"spec": "appdata", "staged": "appdata", "member": "bind-appdata"},
				}
			},
			want: "backup pack failed: pack request is invalid",
		},
		{
			name: "invalid created timestamp",
			mutate: func(payload map[string]any) {
				payload["created"] = "not-a-time"
				payload["volumes"] = []map[string]any{{"spec": "appdata", "staged": "appdata", "member": "vol-appdata"}}
			},
			want: "backup pack failed: pack request is invalid",
		},
		{
			name: "empty compose",
			mutate: func(payload map[string]any) {
				payload["compose"] = ""
			},
			want: "backup pack failed: pack request is invalid",
		},
		{
			name: "artifact already exists",
			arrange: func(t *testing.T, root string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(root, "media", backupArtifactDir), 0o755); err != nil {
					t.Fatal(err)
				}
				name := "media-20261022T080910Z" + backupArtifactSuffix
				if err := os.WriteFile(filepath.Join(root, "media", backupArtifactDir, name), []byte("existing"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(payload map[string]any) {
				payload["volumes"] = []map[string]any{{"spec": "appdata", "staged": "appdata", "member": "vol-appdata"}}
			},
			want: "backup pack failed: artifact could not be created",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Earlier subtests consume the staged archive; every case starts
			// from a fresh one.
			writeStagedVolumeArchive(t, root, "appdata")
			if test.arrange != nil {
				test.arrange(t, root)
			}
			payload := map[string]any{}
			for key, value := range base {
				payload[key] = value
			}
			test.mutate(payload)
			_, err := callBackupPackAction(t, controller, payload)
			if err == nil || err.Error() != test.want {
				t.Fatalf("err = %v want %q", err, test.want)
			}
		})
	}
	if _, err := callBackupPackAction(t, controller, map[string]any{
		"action": backupPackActionPack, "agent_id": "agent-1", "app_id": "Bad_ID",
	}); err == nil || err.Error() != "backup pack failed: pack request is invalid" {
		t.Fatalf("app id err = %v", err)
	}
	if _, err := callBackupPackAction(t, controller, map[string]any{
		"action": "explode", "agent_id": "agent-1", "app_id": "media",
	}); err == nil || err.Error() != `backup-pack action "explode" is unknown` {
		t.Fatalf("action err = %v", err)
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallBackupPackName, []byte("{not-json")); err == nil || err.Error() != "backup pack failed: pack request is invalid" {
		t.Fatalf("payload err = %v", err)
	}
	// Failed packs leave no artifact behind.
	entries, readErr := os.ReadDir(filepath.Join(root, "media", backupArtifactDir))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if entry.Name() == "media-20261022T080910Z"+backupArtifactSuffix {
			continue // pre-arranged by the artifact-exists case
		}
		t.Fatalf("unexpected artifact residue %q", entry.Name())
	}
}

func TestCallBackupPackCleanAndDiscard(t *testing.T) {
	root := t.TempDir()
	workdir := filepath.Join(root, "media")
	if err := os.MkdirAll(filepath.Join(workdir, filepath.FromSlash(pluginsdk.DockerVolumeStagingDir)), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := volumeStagedArchivePath(root, "media", "junk")
	if err := os.WriteFile(staged, []byte("residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, ComposeFileName), []byte("services: {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(workdir, backupArtifactDir)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "media-partial"+backupArtifactSuffix)
	if err := os.WriteFile(artifact, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := newCallController(t, root, unusedDockerRunner(t), nil)
	if _, err := callBackupPackAction(t, controller, map[string]any{
		"action": backupPackActionClean, "agent_id": "agent-1", "app_id": "media",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(workdir, backupStagingDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging tree still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workdir, ComposeFileName)); err != nil {
		t.Fatalf("compose document removed by clean: %v", err)
	}
	if _, err := callBackupPackAction(t, controller, map[string]any{
		"action": backupPackActionDiscard, "agent_id": "agent-1", "app_id": "media",
		"path": backupArtifactDir + "/media-partial" + backupArtifactSuffix,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial artifact still present: %v", err)
	}
	for _, forbidden := range []string{
		ComposeFileName, "../escape" + backupArtifactSuffix, backupArtifactDir + "/evil.txt", "data/media.tar.zst",
	} {
		if _, err := callBackupPackAction(t, controller, map[string]any{
			"action": backupPackActionDiscard, "agent_id": "agent-1", "app_id": "media", "path": forbidden,
		}); err == nil || err.Error() != "backup pack failed: pack request is invalid" {
			t.Fatalf("discard %q err = %v", forbidden, err)
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, ComposeFileName)); err != nil {
		t.Fatalf("discard escaped the artifact tree: %v", err)
	}
}

type fakeBackupSnapshotStore struct {
	snapshot backupStoreSnapshot
	found    bool
	stored   []backupStoreSnapshot
}

func (fake *fakeBackupSnapshotStore) LoadBackups(context.Context) (backupStoreSnapshot, bool, error) {
	return fake.snapshot, fake.found, nil
}

func (fake *fakeBackupSnapshotStore) StoreBackups(_ context.Context, snapshot backupStoreSnapshot) error {
	fake.snapshot = cloneBackupStoreSnapshot(snapshot)
	fake.found = true
	fake.stored = append(fake.stored, cloneBackupStoreSnapshot(snapshot))
	return nil
}

func backupStoreTestRecord(id string) BackupRecord {
	return BackupRecord{
		ID: id, AppID: "media", OriginAgentID: "agent-1", Created: "2026-10-22T08:09:10Z",
		SizeBytes: 4096, SHA256: backupRunTestSHA256,
		Destination: BackupDestinationRef{Type: BackupDestinationS3, Location: "docker-app/" + id},
	}
}

func TestPersistedBackupStore(t *testing.T) {
	backend := &fakeBackupSnapshotStore{}
	store := newPersistedBackupStore(backend)
	if err := store.Append(context.Background(), backupStoreTestRecord("b")); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), backupStoreTestRecord("a")); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), backupStoreTestRecord("b")); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("duplicate err = %v", err)
	}
	records, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ID != "a" || records[1].ID != "b" {
		t.Fatalf("records = %#v", records)
	}
	record, found, err := store.Get(context.Background(), "b")
	if err != nil || !found || record.ID != "b" {
		t.Fatalf("get = %#v %v %v", record, found, err)
	}
	if _, found, _ := store.Get(context.Background(), "missing"); found {
		t.Fatal("missing record found")
	}
	if err := store.Remove(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background(), "a"); !errors.Is(err, ErrBackupRecordUnknown) {
		t.Fatalf("remove unknown err = %v", err)
	}
	invalid := backupStoreTestRecord("c")
	invalid.Destination.Type = "usb"
	if err := store.Append(context.Background(), invalid); !errors.Is(err, ErrBackupRecordInvalid) {
		t.Fatalf("invalid err = %v", err)
	}
	if err := store.Append(context.Background(), BackupRecord{ID: "d"}); !errors.Is(err, ErrBackupRecordInvalid) {
		t.Fatalf("empty err = %v", err)
	}
	if len(backend.stored) != 3 {
		t.Fatalf("stored snapshots = %d", len(backend.stored))
	}
	// The record bound is enforced before any state write.
	full := emptyBackupStoreSnapshot()
	for index := 0; index < MaxBackupRecords; index++ {
		full.Records[fmt.Sprintf("r%03d", index)] = backupStoreTestRecord(fmt.Sprintf("r%03d", index))
	}
	bounded := newPersistedBackupStore(&fakeBackupSnapshotStore{snapshot: full, found: true})
	if err := bounded.Append(context.Background(), backupStoreTestRecord("overflow")); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("bound err = %v", err)
	}
	var nilStore *persistedBackupStore
	if err := nilStore.Append(context.Background(), backupStoreTestRecord("x")); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("nil store err = %v", err)
	}
}

func TestHostCapabilityRuntimeBackupsStateRoundTrip(t *testing.T) {
	var stored backupStoreSnapshot
	client := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		var request struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			t.Fatalf("payload: %v", err)
		}
		switch call.Operation {
		case "state.get":
			if request.Key != pluginBackupsStateKey {
				t.Fatalf("state.get key = %q", request.Key)
			}
			if stored.Records == nil {
				return copyHostResult(map[string]any{"found": false}, target)
			}
			return copyHostResult(map[string]any{"found": true, "value": stored}, target)
		case "state.put":
			if request.Key != pluginBackupsStateKey {
				t.Fatalf("state.put key = %q", request.Key)
			}
			if err := json.Unmarshal(request.Value, &stored); err != nil {
				t.Fatalf("state.put value: %v", err)
			}
			return copyHostResult(map[string]any{"stored": true}, target)
		default:
			t.Fatalf("operation = %q", call.Operation)
		}
		return nil
	})
	runtime := newHostCapabilityRuntime(client)
	store := newPersistedBackupStore(runtime)
	record := backupStoreTestRecord("media-20261022T080910Z.tar.zst")
	if err := store.Append(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	restored, found, err := runtime.LoadBackups(context.Background())
	if err != nil || !found {
		t.Fatalf("load = %v %v", found, err)
	}
	if len(restored.Records) != 1 || restored.Records[record.ID] != record {
		t.Fatalf("restored = %#v", restored)
	}
	corrupt := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		return copyHostResult(map[string]any{"found": true, "value": []string{"not-an-object"}}, target)
	})
	if _, _, err := newHostCapabilityRuntime(corrupt).LoadBackups(context.Background()); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("corrupt err = %v", err)
	}
	invalidRecord := hostCallFunc(func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		bad := emptyBackupStoreSnapshot()
		bad.Records["x"] = BackupRecord{ID: "x"}
		return copyHostResult(map[string]any{"found": true, "value": bad}, target)
	})
	if _, _, err := newHostCapabilityRuntime(invalidRecord).LoadBackups(context.Background()); !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("invalid record err = %v", err)
	}
}

func TestParseConfigurationBackupSettings(t *testing.T) {
	full := fmt.Sprintf(`{
		"apps": [],
		"backup": {
			"s3": {
				"endpoint": %q, "bucket": %q, "prefix": %q,
				"credentials_secret": %q
			},
			"node": {"enabled": true}
		}
	}`, testBackupS3Endpoint, testBackupS3Bucket, testBackupS3Prefix, testBackupS3CredentialsReferenceJSON)
	configuration, err := ParseConfiguration([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.Backup.S3Configured() {
		t.Fatalf("s3 settings = %#v", configuration.Backup.S3)
	}
	if configuration.Backup.S3.Endpoint != testBackupS3Endpoint || configuration.Backup.S3.Bucket != testBackupS3Bucket ||
		configuration.Backup.S3.Prefix != testBackupS3Prefix || configuration.Backup.S3.CredentialsSecret != testBackupS3CredentialsReferenceJSON {
		t.Fatalf("s3 settings = %#v", configuration.Backup.S3)
	}
	if !configuration.Backup.Node.Enabled {
		t.Fatalf("node settings = %#v", configuration.Backup.Node)
	}
	minimal, err := ParseConfiguration([]byte(`{"apps": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if minimal.Backup.S3Configured() || minimal.Backup.Node.Enabled {
		t.Fatalf("default settings = %#v", minimal.Backup)
	}
	for _, invalid := range []string{
		`{"apps": [], "backup": {"s3": {"endpoint": "http://insecure.test", "bucket": "b"}}}`,
		`{"apps": [], "backup": {"s3": {"endpoint": "https://s3.test", "bucket": "Invalid"}}}`,
		`{"apps": [], "backup": {"s3": {"endpoint": "https://s3.test", "bucket": "b", "prefix": "bad prefix"}}}`,
		`{"apps": [], "backup": {"s3": {"endpoint": "https://s3.test", "bucket": "b", "credentials_secret": "not-json"}}}`,
		`{"apps": [], "backup": {"s3": {"unknown": true}}}`,
		`{"apps": [], "backup": {"node": {"enabled": "yes"}}}`,
	} {
		if _, err := ParseConfiguration([]byte(invalid)); err == nil {
			t.Fatalf("invalid config accepted: %s", invalid)
		}
	}
}

// A volume whose staged archive file name (member plus ".tar") would exceed
// the artifact name budget is rejected during planning, before any host
// dispatch.
func TestRunBackupRejectsStagedNameOverBudget(t *testing.T) {
	long := "v" + strings.Repeat("o", 124) // 125 bytes; staged + ".tar" = 129 > 128.
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp("services:\n  app:\n    image: example/app:1\n    volumes:\n      - "+long+":/data\n"))
	_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
	if err == nil || !strings.Contains(err.Error(), backupRunStageVolumeInvalid) {
		t.Fatalf("long staged name err = %v", err)
	}
	if len(stub.volumeSpecs) != 0 || len(stub.packPayloads) != 0 || stub.putCount != 0 {
		t.Fatalf("oversize staged name dispatched work")
	}
}

// A second concurrent run of the same app fails fast instead of interleaving
// staging trees of the same workspace.
func TestRunBackupSameAppConcurrentSecondRunFailsFast(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	apps := backupRunTestApp(backupRunTestCompose)
	first := &backupRunStub{t: t, apps: apps}
	firstGate := func(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		if call.Operation == pluginsdk.HostRuntimePluginCall {
			request := decodePluginCallRequest(t, call)
			if request.Name == pluginCallVolumeName {
				select {
				case started <- struct{}{}:
				default:
				}
				<-release
			}
		}
		return first.call(context.Background(), call, target)
	}
	firstRuntime := newHostCapabilityRuntime(hostCallFunc(firstGate))
	done := make(chan error, 1)
	go func() {
		_, err := firstRuntime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
		done <- err
	}()
	<-started
	secondRuntime, second := newBackupRunRuntime(t, apps)
	_, err := secondRuntime.RunBackup(context.Background(), "media", backupRunTestSettings(true, false), "", "")
	if !errors.Is(err, ErrBackupRunBusy) {
		t.Fatalf("second run err = %v want %v", err, ErrBackupRunBusy)
	}
	if len(second.packPayloads) != 0 || second.putCount != 0 {
		t.Fatalf("busy second run dispatched work")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run err = %v", err)
	}
}

// A node-destination run with an explicit target pushes the packed artifact
// to that managed agent and records the target as the destination location.
func TestRunBackupNodeDestinationPushesToTargetAgent(t *testing.T) {
	apps := []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRunTestCompose, Generation: "generation-1"},
		{ID: "other", AgentID: "agent-2", Compose: backupRunTestCompose, Generation: "generation-1"},
	}
	stub := &backupRunStub{t: t, apps: apps}
	var sends []pluginsdk.NodeTransferRequest
	runtime := newHostCapabilityRuntime(hostCallFunc(func(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
		switch call.Operation {
		case pluginsdk.HostRuntimeNodeTransfer:
			var request pluginsdk.NodeTransferRequest
			if err := json.Unmarshal(call.Payload, &request); err != nil {
				t.Fatalf("node.transfer payload: %v", err)
			}
			sends = append(sends, request)
			return copyHostResult(pluginsdk.NodeTransferResponse{
				TransferID: "nt-1", State: pluginsdk.NodeTransferStateCompleted, BytesTransferred: request.SizeBytes,
			}, target)
		case pluginsdk.HostRuntimePluginCall:
			request := decodePluginCallRequest(t, call)
			if request.Name == pluginCallEngineName {
				payload := decodePluginCallInner(t, request)
				agentID, _ := payload["agent_id"].(string)
				return copyHostResult(map[string]any{"agent_id": agentID, "online": true, "installed": true}, target)
			}
		}
		return stub.call(ctx, call, target)
	}))
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	record, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(false, true), BackupDestinationNode, "agent-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(sends) != 1 {
		t.Fatalf("send requests = %d", len(sends))
	}
	sent := sends[0]
	if sent.SourceAgentID != "agent-1" || sent.TargetAgentID != "agent-2" || sent.AppID != "media" || sent.ArtifactName != record.ID || sent.SHA256 != backupRunTestSHA256 {
		t.Fatalf("send request = %#v", sent)
	}
	if record.Destination != (BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-2"}) {
		t.Fatalf("record destination = %#v", record.Destination)
	}
	if len(stub.uploadPayloads) != 0 {
		t.Fatalf("node push run uploaded to s3: %#v", stub.uploadPayloads)
	}
	if stub.putCount != 1 || stub.stored.Records[record.ID] != record {
		t.Fatalf("stored record = %#v puts = %d", stub.stored, stub.putCount)
	}
}

// A node-destination target outside the managed agent set is rejected before
// any dispatch.
func TestRunBackupNodeTargetMustBeManaged(t *testing.T) {
	runtime, stub := newBackupRunRuntime(t, backupRunTestApp(backupRunTestCompose))
	_, err := runtime.RunBackup(context.Background(), "media", backupRunTestSettings(false, true), BackupDestinationNode, "agent-9")
	if err == nil || !strings.Contains(err.Error(), nodeStageTargetUnmanaged) {
		t.Fatalf("unmanaged target err = %v", err)
	}
	if len(stub.volumeSpecs) != 0 || len(stub.packPayloads) != 0 || stub.putCount != 0 {
		t.Fatalf("unmanaged target dispatched work")
	}
}
