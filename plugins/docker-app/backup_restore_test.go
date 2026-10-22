package dockerapp

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const backupRestoreTestCompose = `services:
  app:
    image: example/app:1
    volumes:
      - appdata:/var/lib/app
      - ./data:/data
`

var backupRestoreTestTime = time.Date(2026, 10, 22, 8, 9, 10, 0, time.UTC)

// backupRestoreFixture is one real artifact produced by the T2 library plus
// the volume tar packed into it.
type backupRestoreFixture struct {
	name      string
	content   []byte
	sha256    string
	size      int64
	volumeTar []byte
}

func buildRestoreVolumeTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range names {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func buildRestoreFixture(t *testing.T) backupRestoreFixture {
	t.Helper()
	source := t.TempDir()
	workdir := filepath.Join(source, "media")
	if err := os.MkdirAll(filepath.Join(workdir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "notes.txt"), []byte("workspace-note"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "data", "db.txt"), []byte("bind-db"), 0o644); err != nil {
		t.Fatal(err)
	}
	volumeTar := buildRestoreVolumeTar(t, map[string]string{"db.bin": "volume-db"})
	if err := os.MkdirAll(filepath.Join(workdir, backupArtifactDir), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := CreateBackupArtifact(filepath.Join(workdir, backupArtifactDir), BackupSource{
		AppID: "media", Compose: backupRestoreTestCompose, Workdir: workdir,
		Volumes:   []BackupVolumeSource{{Name: "vol-appdata", Tar: bytes.NewReader(volumeTar)}},
		CreatedAt: backupRestoreTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	return backupRestoreFixture{
		name: filepath.Base(info.Path), content: content, sha256: info.SHA256,
		size: info.Size, volumeTar: volumeTar,
	}
}

func (fixture backupRestoreFixture) s3Record() BackupRecord {
	return BackupRecord{
		ID: fixture.name, AppID: "media", OriginAgentID: "agent-1", Created: "2026-10-22T08:09:10Z",
		SizeBytes: fixture.size, SHA256: fixture.sha256,
		Destination: BackupDestinationRef{Type: BackupDestinationS3, Location: testBackupS3Prefix + "/" + fixture.name},
	}
}

// backupRestoreStub stands in for the Host transport: it serves the apps and
// backups state keys, materializes s3 downloads into the local managed root
// (mirroring the Agent execution face), and records every dispatch.
type backupRestoreStub struct {
	t    *testing.T
	mu   sync.Mutex
	root string
	apps []App

	records       backupStoreSnapshot
	storedApps    []App
	storedRecords backupStoreSnapshot
	appsPuts      int
	backupPuts    int
	failPutApps   error
	failPutBackup error

	downloadPayloads []map[string]any
	downloadBytes    []byte
	failDownload     error
	deletePayloads   []map[string]any
	failDelete       error
	discardPayloads  []map[string]any
	volumePayloads   []map[string]any
	composePayloads  []map[string]any
	failApply        error
	failStart        error
}

func (stub *backupRestoreStub) call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
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
			return copyHostResult(map[string]any{"found": len(stub.records.Records) > 0, "value": stub.records}, target)
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
		switch request.Key {
		case pluginAppsStateKey:
			if stub.failPutApps != nil {
				return stub.failPutApps
			}
			if err := json.Unmarshal(request.Value, &stub.storedApps); err != nil {
				stub.t.Fatalf("state.put apps value: %v", err)
			}
			stub.apps = append([]App(nil), stub.storedApps...)
			stub.appsPuts++
			return copyHostResult(map[string]any{"stored": true}, target)
		case pluginBackupsStateKey:
			if stub.failPutBackup != nil {
				return stub.failPutBackup
			}
			if err := json.Unmarshal(request.Value, &stub.storedRecords); err != nil {
				stub.t.Fatalf("state.put backups value: %v", err)
			}
			stub.records = cloneBackupStoreSnapshot(stub.storedRecords)
			stub.backupPuts++
			return copyHostResult(map[string]any{"stored": true}, target)
		default:
			stub.t.Fatalf("unexpected state.put key %q", request.Key)
		}
	case pluginsdk.HostRuntimePluginCall:
		request := decodePluginCallRequest(stub.t, call)
		payload := decodePluginCallInner(stub.t, request)
		switch request.Name {
		case pluginCallBackupS3Name:
			action, _ := payload["action"].(string)
			switch action {
			case backupS3ActionDownload:
				stub.downloadPayloads = append(stub.downloadPayloads, payload)
				if stub.failDownload != nil {
					return stub.failDownload
				}
				rel, _ := payload["path"].(string)
				appID, _ := payload["app_id"].(string)
				landed := filepath.Join(stub.root, appID, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(landed), 0o755); err != nil {
					stub.t.Fatalf("download land: %v", err)
				}
				if err := os.WriteFile(landed, stub.downloadBytes, 0o600); err != nil {
					stub.t.Fatalf("download write: %v", err)
				}
				digest := sha256.Sum256(stub.downloadBytes)
				return copyHostResult(map[string]any{
					"accepted": true, "path": rel, "size": len(stub.downloadBytes),
					"sha256": hex.EncodeToString(digest[:]),
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
		case pluginCallBackupPackName:
			action, _ := payload["action"].(string)
			if action != backupPackActionDiscard {
				stub.t.Fatalf("backup-pack action = %q", action)
			}
			stub.discardPayloads = append(stub.discardPayloads, payload)
			appID, _ := payload["app_id"].(string)
			rel, _ := payload["path"].(string)
			_ = os.Remove(filepath.Join(stub.root, appID, filepath.FromSlash(rel)))
			return copyHostResult(map[string]any{"accepted": true}, target)
		case pluginCallVolumeName:
			volume, _ := payload["volume"].(string)
			stub.volumePayloads = append(stub.volumePayloads, payload)
			return copyHostResult(map[string]any{"accepted": true, "archive_path": volume + ".tar"}, target)
		case pluginCallComposeName:
			action, _ := payload["action"].(string)
			switch action {
			case "apply":
				stub.composePayloads = append(stub.composePayloads, payload)
				if stub.failApply != nil {
					return stub.failApply
				}
				return copyHostResult(map[string]any{"accepted": true}, target)
			case "start":
				stub.composePayloads = append(stub.composePayloads, payload)
				if stub.failStart != nil {
					return stub.failStart
				}
				return copyHostResult(map[string]any{"accepted": true}, target)
			default:
				stub.t.Fatalf("compose action = %q", action)
			}
		default:
			stub.t.Fatalf("unexpected plugin.call name %q", request.Name)
		}
	default:
		stub.t.Fatalf("unexpected host operation %q", call.Operation)
	}
	return nil
}

func newBackupRestoreRuntime(t *testing.T, apps []App, records []BackupRecord) (string, *hostCapabilityRuntime, *backupRestoreStub) {
	t.Helper()
	root := t.TempDir()
	snapshot := emptyBackupStoreSnapshot()
	for _, record := range records {
		snapshot.Records[record.ID] = record
	}
	stub := &backupRestoreStub{t: t, root: root, apps: apps, records: snapshot, downloadBytes: nil}
	runtime := newHostCapabilityRuntime(hostCallFunc(stub.call))
	if runtime == nil {
		t.Fatal("runtime is nil")
	}
	return root, runtime, stub
}

// newRestoreCase builds the common s3 fixture: a real artifact, its record,
// and a managed agent-2 able to receive a fresh restore.
func newRestoreCase(t *testing.T, apps []App) (string, backupRestoreFixture, *hostCapabilityRuntime, *backupRestoreStub) {
	t.Helper()
	fixture := buildRestoreFixture(t)
	if apps == nil {
		apps = []App{{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-2"}}
	}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.s3Record()})
	stub.downloadBytes = fixture.content
	return root, fixture, runtime, stub
}

func assertRestoredWorkspace(t *testing.T, root string, fixture backupRestoreFixture) {
	t.Helper()
	workdir := filepath.Join(root, "media")
	compose, err := os.ReadFile(filepath.Join(workdir, ComposeFileName))
	if err != nil || string(compose) != backupRestoreTestCompose {
		t.Fatalf("restored compose = %q err = %v", compose, err)
	}
	if notes, err := os.ReadFile(filepath.Join(workdir, "notes.txt")); err != nil || string(notes) != "workspace-note" {
		t.Fatalf("restored notes = %q err = %v", notes, err)
	}
	if bind, err := os.ReadFile(filepath.Join(workdir, "data", "db.txt")); err != nil || string(bind) != "bind-db" {
		t.Fatalf("restored bind member = %q err = %v", bind, err)
	}
	staged, err := os.ReadFile(volumeStagedArchivePath(root, "media", "appdata"))
	if err != nil || !bytes.Equal(staged, fixture.volumeTar) {
		t.Fatalf("staged volume archive bytes mismatch: err = %v", err)
	}
}

func TestRestoreBackupS3FreshAgentRebuildsAndAdopts(t *testing.T) {
	t.Parallel()
	root, fixture, runtime, stub := newRestoreCase(t, nil)
	restored, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false), root)
	if err != nil {
		t.Fatal(err)
	}
	// The retrieval call carries the record's object reference and checksum.
	if len(stub.downloadPayloads) != 1 {
		t.Fatalf("download payloads = %d", len(stub.downloadPayloads))
	}
	download := stub.downloadPayloads[0]
	if download["action"] != backupS3ActionDownload || download["agent_id"] != "agent-2" || download["app_id"] != "media" {
		t.Fatalf("download payload = %#v", download)
	}
	if download["object"] != fixture.name || download["path"] != backupArtifactDir+"/"+fixture.name || download["sha256"] != fixture.sha256 {
		t.Fatalf("download artifact = %#v", download)
	}
	if download["endpoint"] != testBackupS3Endpoint || download["bucket"] != testBackupS3Bucket ||
		download["prefix"] != testBackupS3Prefix || download["credentials_secret"] != testBackupS3CredentialsReferenceJSON {
		t.Fatalf("download destination = %#v", download)
	}
	// Workspace, compose, bind members, and the staged named-volume archive.
	assertRestoredWorkspace(t, root, fixture)
	// Only the named volume reaches the restore operation face; relative
	// binds were restored as workspace members.
	if len(stub.volumePayloads) != 1 || stub.volumePayloads[0]["volume"] != "appdata" {
		t.Fatalf("volume payloads = %#v", stub.volumePayloads)
	}
	// Apply then start, both against the target agent with the artifact compose.
	if len(stub.composePayloads) != 2 {
		t.Fatalf("compose payloads = %#v", stub.composePayloads)
	}
	apply := stub.composePayloads[0]
	if apply["action"] != "apply" || apply["agent_id"] != "agent-2" || apply["app_id"] != "media" || apply["compose"] != backupRestoreTestCompose {
		t.Fatalf("apply payload = %#v", apply)
	}
	if stub.composePayloads[1]["action"] != "start" || stub.composePayloads[1]["agent_id"] != "agent-2" {
		t.Fatalf("start payload = %#v", stub.composePayloads[1])
	}
	// The restored app is adopted under the target agent with the sibling
	// generation; the record is untouched.
	if restored.AgentID != "agent-2" || restored.ID != "media" || restored.Compose != backupRestoreTestCompose || restored.Generation != "generation-2" {
		t.Fatalf("restored app = %#v", restored)
	}
	if stub.appsPuts != 1 || len(stub.storedApps) != 2 {
		t.Fatalf("stored apps = %#v puts = %d", stub.storedApps, stub.appsPuts)
	}
	adopted := false
	for _, app := range stub.storedApps {
		if app.ID == "media" {
			adopted = app.AgentID == "agent-2" && app.Compose == backupRestoreTestCompose
		}
	}
	if !adopted {
		t.Fatalf("media not adopted: %#v", stub.storedApps)
	}
	if stub.backupPuts != 0 || len(stub.records.Records) != 1 || stub.downloadPayloads[0]["object"] != fixture.name {
		t.Fatalf("record mutated: puts = %d records = %#v", stub.backupPuts, stub.records)
	}
	if len(stub.deletePayloads) != 0 || len(stub.discardPayloads) != 0 {
		t.Fatalf("restore dispatched deletion: %#v %#v", stub.deletePayloads, stub.discardPayloads)
	}
}

func TestRestoreBackupNodeSameAgentReadsWorkspaceArtifact(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{{ID: "media", AgentID: "agent-1", Compose: "services: {app: {image: example/app:0}}", Generation: "generation-1", Env: "KEY=value\n"}}
	record := fixture.s3Record()
	record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-1"}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{record})
	if err := os.MkdirAll(filepath.Join(root, "media", backupArtifactDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "media", backupArtifactDir, fixture.name), fixture.content, 0o600); err != nil {
		t.Fatal(err)
	}
	// Same-name managed app: the app id is the confirm token.
	if _, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-1", "media", backupRunTestSettings(false, false), root); err != nil {
		t.Fatal(err)
	}
	if len(stub.downloadPayloads) != 0 {
		t.Fatalf("node restore downloaded: %#v", stub.downloadPayloads)
	}
	assertRestoredWorkspace(t, root, fixture)
	if len(stub.composePayloads) != 2 || stub.composePayloads[0]["action"] != "apply" || stub.composePayloads[1]["action"] != "start" {
		t.Fatalf("compose payloads = %#v", stub.composePayloads)
	}
	// Overwrite keeps generation and environment of the managed app.
	if len(stub.storedApps) != 1 {
		t.Fatalf("stored apps = %#v", stub.storedApps)
	}
	kept := stub.storedApps[0]
	if kept.AgentID != "agent-1" || kept.Generation != "generation-1" || kept.Env != "KEY=value\n" || kept.Compose != backupRestoreTestCompose {
		t.Fatalf("overwritten app = %#v", kept)
	}
	if stub.backupPuts != 0 {
		t.Fatalf("record mutated: puts = %d", stub.backupPuts)
	}
	// A node restore never deletes the origin workspace artifact.
	if _, statErr := os.Stat(filepath.Join(root, "media", backupArtifactDir, fixture.name)); statErr != nil {
		t.Fatalf("origin artifact removed: %v", statErr)
	}
}

func TestRestoreBackupNodeCrossAgentIsExplicitT7Placeholder(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"},
		{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-1"},
	}
	record := fixture.s3Record()
	record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-1"}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{record})
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(false, false), root)
	if !errors.Is(err, ErrBackupRestoreCrossNode) {
		t.Fatalf("err = %v want %v", err, ErrBackupRestoreCrossNode)
	}
	if len(stub.downloadPayloads) != 0 || len(stub.discardPayloads) != 0 || len(stub.volumePayloads) != 0 || len(stub.composePayloads) != 0 {
		t.Fatalf("cross-node restore dispatched work")
	}
	if stub.appsPuts != 0 || stub.backupPuts != 0 {
		t.Fatalf("cross-node restore mutated state")
	}
}

func TestRestoreBackupOverwriteWithoutConfirmRejectedZeroSideEffects(t *testing.T) {
	t.Parallel()
	apps := []App{{ID: "media", AgentID: "agent-2", Compose: "services: {app: {image: example/app:0}}", Generation: "generation-1"}}
	root, fixture, runtime, stub := newRestoreCase(t, apps)
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false), root)
	if !errors.Is(err, ErrDeleteUnconfirmed) {
		t.Fatalf("err = %v want %v", err, ErrDeleteUnconfirmed)
	}
	if len(stub.downloadPayloads) != 0 || len(stub.volumePayloads) != 0 || len(stub.composePayloads) != 0 {
		t.Fatalf("unconfirmed restore dispatched work")
	}
	if stub.appsPuts != 0 || stub.backupPuts != 0 {
		t.Fatalf("unconfirmed restore mutated state")
	}
	if _, statErr := os.Stat(filepath.Join(root, "media")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unconfirmed restore touched the workspace: %v", statErr)
	}
}

func TestRestoreBackupOverwriteWithConfirmSucceeds(t *testing.T) {
	t.Parallel()
	apps := []App{{ID: "media", AgentID: "agent-2", Compose: "services: {app: {image: example/app:0}}", Generation: "generation-1"}}
	root, fixture, runtime, stub := newRestoreCase(t, apps)
	restored, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(true, false), root)
	if err != nil {
		t.Fatal(err)
	}
	if restored.AgentID != "agent-2" || restored.Compose != backupRestoreTestCompose || restored.Generation != "generation-1" {
		t.Fatalf("restored app = %#v", restored)
	}
	assertRestoredWorkspace(t, root, fixture)
	if stub.appsPuts != 1 || stub.backupPuts != 0 {
		t.Fatalf("puts apps = %d backups = %d", stub.appsPuts, stub.backupPuts)
	}
}

func TestRestoreBackupCorruptArtifactFailsExplicitly(t *testing.T) {
	t.Parallel()
	t.Run("downloaded bytes do not match the record", func(t *testing.T) {
		root, fixture, runtime, stub := newRestoreCase(t, nil)
		stub.downloadBytes = fixture.content[:len(fixture.content)-1]
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false), root)
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageChecksum) {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(root, "media")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("mismatched download left residue: %v", statErr)
		}
		if stub.appsPuts != 0 || stub.backupPuts != 0 {
			t.Fatalf("failed restore mutated state")
		}
	})
	t.Run("manifest verification fails on tampered bytes", func(t *testing.T) {
		root, fixture, runtime, stub := newRestoreCase(t, nil)
		tampered := append([]byte(nil), fixture.content...)
		tampered[len(tampered)/2] ^= 0x01
		digest := sha256.Sum256(tampered)
		record := fixture.s3Record()
		record.SHA256 = hex.EncodeToString(digest[:])
		record.SizeBytes = int64(len(tampered))
		stub.records.Records[record.ID] = record
		stub.downloadBytes = tampered
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false), root)
		if !errors.Is(err, ErrBackupArtifactCorrupt) || !strings.Contains(err.Error(), backupRestoreStageCorrupt) {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(root, "media")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("corrupt restore left residue: %v", statErr)
		}
		if stub.appsPuts != 0 || len(stub.records.Records) != 1 {
			t.Fatalf("corrupt restore mutated state: puts = %d records = %#v", stub.appsPuts, stub.records)
		}
	})
	t.Run("node artifact checksum mismatch keeps origin file", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		apps := []App{{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"}}
		record := fixture.s3Record()
		other := sha256.Sum256([]byte("not the artifact"))
		record.SHA256 = hex.EncodeToString(other[:])
		record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-1"}
		root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{record})
		artifact := filepath.Join(root, "media", backupArtifactDir, fixture.name)
		if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, fixture.content, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-1", "media", backupRunTestSettings(false, false), root)
		if !errors.Is(err, ErrBackupArtifactCorrupt) || !strings.Contains(err.Error(), backupRestoreStageChecksum) {
			t.Fatalf("err = %v", err)
		}
		// The origin workspace artifact is never deleted by a failed restore.
		if _, statErr := os.Stat(artifact); statErr != nil {
			t.Fatalf("origin artifact removed: %v", statErr)
		}
		if len(stub.volumePayloads) != 0 || len(stub.composePayloads) != 0 || stub.appsPuts != 0 {
			t.Fatalf("checksum failure dispatched work")
		}
	})
}

func TestRestoreBackupFailureCleansResidueAndKeepsRecord(t *testing.T) {
	t.Parallel()
	root, fixture, runtime, stub := newRestoreCase(t, nil)
	stub.failApply = errors.New("compose apply failed")
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false), root)
	if err == nil || !strings.Contains(err.Error(), backupRestoreStageApply) || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "media")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed restore left workspace residue: %v", statErr)
	}
	if _, statErr := os.Stat(volumeStagedArchivePath(root, "media", "appdata")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed restore left staging residue: %v", statErr)
	}
	if stub.appsPuts != 0 {
		t.Fatalf("failed restore changed managed state: puts = %d", stub.appsPuts)
	}
	if len(stub.records.Records) != 1 || stub.backupPuts != 0 {
		t.Fatalf("failed restore mutated the record: %#v", stub.records)
	}
	if len(stub.downloadPayloads) != 1 {
		t.Fatalf("download payloads = %d", len(stub.downloadPayloads))
	}
}

func TestRestoreBackupGates(t *testing.T) {
	t.Parallel()
	t.Run("nil runtime", func(t *testing.T) {
		var runtime *hostCapabilityRuntime
		if _, err := runtime.RestoreBackup(context.Background(), "record", "agent-1", "", backupRunTestSettings(true, false), ""); !errors.Is(err, ErrTypedHandlesUnavailable) {
			t.Fatalf("nil runtime err = %v", err)
		}
	})
	t.Run("unknown record", func(t *testing.T) {
		_, runtime, stub := newBackupRestoreRuntime(t, nil, nil)
		if _, err := runtime.RestoreBackup(context.Background(), "missing", "agent-1", "", backupRunTestSettings(true, false), ""); !errors.Is(err, ErrBackupRecordUnknown) {
			t.Fatalf("unknown record err = %v", err)
		}
		if len(stub.downloadPayloads) != 0 {
			t.Fatalf("unknown record dispatched work")
		}
	})
	t.Run("invalid record id", func(t *testing.T) {
		_, runtime, _ := newBackupRestoreRuntime(t, nil, nil)
		_, err := runtime.RestoreBackup(context.Background(), strings.Repeat("x", 161), "agent-1", "", backupRunTestSettings(true, false), "")
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageRecord) {
			t.Fatalf("invalid record err = %v", err)
		}
	})
	t.Run("unmanaged target agent", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		apps := []App{{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"}}
		root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.s3Record()})
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-9", "media", backupRunTestSettings(true, false), root)
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageAgent) {
			t.Fatalf("unmanaged agent err = %v", err)
		}
		if len(stub.downloadPayloads) != 0 || stub.appsPuts != 0 {
			t.Fatalf("unmanaged agent dispatched work")
		}
	})
	t.Run("offline target agent id", func(t *testing.T) {
		_, runtime, _ := newBackupRestoreRuntime(t, nil, nil)
		if _, err := runtime.RestoreBackup(context.Background(), "missing", "", "", backupRunTestSettings(true, false), ""); !errors.Is(err, ErrAgentOffline) {
			t.Fatalf("invalid agent err = %v", err)
		}
	})
	t.Run("s3 destination unconfigured", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		apps := []App{{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-2"}}
		root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.s3Record()})
		if _, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(false, false), root); !errors.Is(err, ErrBackupDestinationUnconfigured) {
			t.Fatalf("unconfigured err = %v", err)
		}
		if len(stub.downloadPayloads) != 0 {
			t.Fatalf("unconfigured destination dispatched a download")
		}
	})
}

func TestDeleteBackupRemovesDestinationAndRecord(t *testing.T) {
	t.Parallel()
	t.Run("s3 object", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{fixture.s3Record()})
		if err := runtime.DeleteBackup(context.Background(), fixture.name, "media", backupRunTestSettings(true, false)); err != nil {
			t.Fatal(err)
		}
		if len(stub.deletePayloads) != 1 {
			t.Fatalf("delete payloads = %d", len(stub.deletePayloads))
		}
		deleted := stub.deletePayloads[0]
		if deleted["action"] != backupS3ActionDelete || deleted["agent_id"] != "agent-1" || deleted["app_id"] != "media" {
			t.Fatalf("delete payload = %#v", deleted)
		}
		// The stored location carries the prefix; the delete call re-joins it.
		if deleted["object"] != fixture.name || deleted["path"] != nil {
			t.Fatalf("delete object = %#v", deleted)
		}
		if deleted["endpoint"] != testBackupS3Endpoint || deleted["bucket"] != testBackupS3Bucket || deleted["prefix"] != testBackupS3Prefix {
			t.Fatalf("delete destination = %#v", deleted)
		}
		if stub.backupPuts != 1 || len(stub.records.Records) != 0 {
			t.Fatalf("record not removed: puts = %d records = %#v", stub.backupPuts, stub.records)
		}
		if len(stub.discardPayloads) != 0 {
			t.Fatalf("s3 delete discarded workspace files: %#v", stub.discardPayloads)
		}
	})
	t.Run("node workspace artifact", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		record := fixture.s3Record()
		record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: "agent-1"}
		root, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{record})
		artifact := filepath.Join(root, "media", backupArtifactDir, fixture.name)
		if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifact, fixture.content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runtime.DeleteBackup(context.Background(), fixture.name, "media", backupRunTestSettings(false, false)); err != nil {
			t.Fatal(err)
		}
		if len(stub.discardPayloads) != 1 {
			t.Fatalf("discard payloads = %d", len(stub.discardPayloads))
		}
		discard := stub.discardPayloads[0]
		if discard["action"] != backupPackActionDiscard || discard["agent_id"] != "agent-1" || discard["app_id"] != "media" || discard["path"] != backupArtifactDir+"/"+fixture.name {
			t.Fatalf("discard payload = %#v", discard)
		}
		if _, statErr := os.Stat(artifact); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("node artifact still present: %v", statErr)
		}
		if stub.backupPuts != 1 || len(stub.records.Records) != 0 {
			t.Fatalf("record not removed: puts = %d records = %#v", stub.backupPuts, stub.records)
		}
		if len(stub.deletePayloads) != 0 {
			t.Fatalf("node delete removed an s3 object: %#v", stub.deletePayloads)
		}
	})
}

func TestDeleteBackupFailures(t *testing.T) {
	t.Parallel()
	t.Run("unconfirmed", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{fixture.s3Record()})
		if err := runtime.DeleteBackup(context.Background(), fixture.name, "wrong", backupRunTestSettings(true, false)); !errors.Is(err, ErrDeleteUnconfirmed) {
			t.Fatalf("unconfirmed err = %v", err)
		}
		if len(stub.deletePayloads) != 0 || len(stub.discardPayloads) != 0 || stub.backupPuts != 0 {
			t.Fatalf("unconfirmed delete dispatched work")
		}
	})
	t.Run("unknown record", func(t *testing.T) {
		_, runtime, _ := newBackupRestoreRuntime(t, nil, nil)
		if err := runtime.DeleteBackup(context.Background(), "missing", "media", backupRunTestSettings(true, false)); !errors.Is(err, ErrBackupRecordUnknown) {
			t.Fatalf("unknown err = %v", err)
		}
	})
	t.Run("s3 destination unconfigured keeps record", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{fixture.s3Record()})
		if err := runtime.DeleteBackup(context.Background(), fixture.name, "media", BackupSettings{}); !errors.Is(err, ErrBackupDestinationUnconfigured) {
			t.Fatalf("unconfigured err = %v", err)
		}
		if len(stub.deletePayloads) != 0 || stub.backupPuts != 0 || len(stub.records.Records) != 1 {
			t.Fatalf("unconfigured delete changed state: %#v", stub.records)
		}
	})
	t.Run("destination unreachable keeps record", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{fixture.s3Record()})
		stub.failDelete = errors.New("backup-s3 delete failed: endpoint is unreachable")
		err := runtime.DeleteBackup(context.Background(), fixture.name, "media", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), "backup delete failed") || !strings.Contains(err.Error(), backupDeleteStageDestination) {
			t.Fatalf("unreachable err = %v", err)
		}
		if stub.backupPuts != 0 || len(stub.records.Records) != 1 {
			t.Fatalf("failed delete removed the record: %#v", stub.records)
		}
	})
	t.Run("record removal failure reports retry-safe state", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{fixture.s3Record()})
		stub.failPutBackup = errors.New("state backend refused")
		err := runtime.DeleteBackup(context.Background(), fixture.name, "media", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), backupDeleteStageRecord) || !strings.Contains(err.Error(), "retried") {
			t.Fatalf("record removal err = %v", err)
		}
		if len(stub.deletePayloads) != 1 {
			t.Fatalf("delete payloads = %d", len(stub.deletePayloads))
		}
		if len(stub.records.Records) != 1 {
			t.Fatalf("record removed despite store failure: %#v", stub.records)
		}
	})
	t.Run("nil runtime", func(t *testing.T) {
		var runtime *hostCapabilityRuntime
		if err := runtime.DeleteBackup(context.Background(), "record", "media", backupRunTestSettings(true, false)); !errors.Is(err, ErrTypedHandlesUnavailable) {
			t.Fatalf("nil runtime err = %v", err)
		}
	})
}
