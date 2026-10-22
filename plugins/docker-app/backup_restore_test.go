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

func (fixture backupRestoreFixture) nodeRecord(agentID string) BackupRecord {
	record := fixture.s3Record()
	record.Destination = BackupDestinationRef{Type: BackupDestinationNode, Location: agentID}
	return record
}

// backupRestoreStub stands in for the Host transport. It serves the apps and
// backups state keys, simulates the target Agent execution face (engine
// report, node-transfer push landing, and the backup-restore call running the
// real agent restore core against the stub root), and records every dispatch.
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

	restorePayloads []map[string]any
	probePayloads   []map[string]any
	restoreBytes    []byte
	failRestore     error
	volumePayloads  []map[string]any
	deletePayloads  []map[string]any
	failDelete      error
	discardPayloads []map[string]any
	composePayloads []map[string]any
	failApply       error
	failStart       error

	sendRequests []pluginsdk.NodeTransferRequest
	sendErr      error
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
	case pluginsdk.HostRuntimeNodeTransfer:
		var request pluginsdk.NodeTransferRequest
		if err := json.Unmarshal(call.Payload, &request); err != nil {
			stub.t.Fatalf("node.transfer payload: %v", err)
		}
		if request.Action != pluginsdk.NodeTransferActionSend {
			stub.t.Fatalf("node.transfer action = %q", request.Action)
		}
		stub.sendRequests = append(stub.sendRequests, request)
		if stub.sendErr != nil {
			return stub.sendErr
		}
		// The simulated host lands the pushed bytes in the target workspace.
		landed := filepath.Join(stub.root, request.AppID, backupArtifactDir, request.ArtifactName)
		if err := os.MkdirAll(filepath.Dir(landed), 0o755); err != nil {
			stub.t.Fatalf("transfer land: %v", err)
		}
		if err := os.WriteFile(landed, stub.restoreBytes, 0o600); err != nil {
			stub.t.Fatalf("transfer write: %v", err)
		}
		return copyHostResult(pluginsdk.NodeTransferResponse{
			TransferID: "nt-media-1", State: pluginsdk.NodeTransferStateCompleted,
			BytesTransferred: request.SizeBytes,
		}, target)
	case pluginsdk.HostRuntimePluginCall:
		request := decodePluginCallRequest(stub.t, call)
		payload := decodePluginCallInner(stub.t, request)
		switch request.Name {
		case pluginCallEngineName:
			agentID, _ := payload["agent_id"].(string)
			return copyHostResult(map[string]any{"agent_id": agentID, "online": true, "installed": true}, target)
		case pluginCallVolumeName:
			volume, _ := payload["volume"].(string)
			stub.volumePayloads = append(stub.volumePayloads, payload)
			return copyHostResult(map[string]any{"accepted": true, "archive_path": volume + ".tar"}, target)
		case pluginCallBackupS3Name:
			action, _ := payload["action"].(string)
			if action != backupS3ActionDelete {
				stub.t.Fatalf("backup-s3 action = %q", action)
			}
			stub.deletePayloads = append(stub.deletePayloads, payload)
			if stub.failDelete != nil {
				return stub.failDelete
			}
			return copyHostResult(map[string]any{"accepted": true}, target)
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
		case pluginCallBackupRestoreName:
			return stub.simulateAgentRestore(payload, target)
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

// simulateAgentRestore stands in for the target Agent execution face. The s3
// retrieval transport is simulated by materializing the artifact bytes (the
// real download path is covered by the backup-s3 suite); everything after
// retrieval runs the real agent restore core against the stub root.
func (stub *backupRestoreStub) simulateAgentRestore(payload map[string]any, target any) error {
	stub.t.Helper()
	action, _ := payload["action"].(string)
	appID, _ := payload["app_id"].(string)
	rel, _ := payload["path"].(string)
	landed := filepath.Join(stub.root, appID, filepath.FromSlash(rel))
	switch action {
	case backupRestoreActionProbe:
		stub.probePayloads = append(stub.probePayloads, payload)
		present := false
		wantSHA, _ := payload["sha256"].(string)
		wantSize, _ := payload["size"].(float64)
		if digest, size, err := hashFileContents(landed); err == nil {
			present = int64(wantSize) == size && digest == strings.ToLower(strings.TrimSpace(wantSHA))
		}
		return copyHostResult(map[string]any{"present": present}, target)
	case backupRestoreActionRestore:
		stub.restorePayloads = append(stub.restorePayloads, payload)
		if stub.failRestore != nil {
			return stub.failRestore
		}
		fromS3 := payload["source"] == BackupDestinationS3
		workdir := filepath.Join(stub.root, appID)
		workdirExisted := false
		if _, statErr := os.Lstat(workdir); statErr == nil {
			workdirExisted = true
		}
		if fromS3 {
			if err := os.MkdirAll(filepath.Dir(landed), 0o755); err != nil {
				stub.t.Fatalf("restore land: %v", err)
			}
			if err := os.WriteFile(landed, stub.restoreBytes, 0o600); err != nil {
				stub.t.Fatalf("restore write: %v", err)
			}
		}
		agentPayload := map[string]any{}
		for key, value := range payload {
			agentPayload[key] = value
		}
		agentPayload["source"] = BackupDestinationNode
		encoded, err := json.Marshal(agentPayload)
		if err != nil {
			stub.t.Fatalf("agent payload: %v", err)
		}
		agent := &Controller{
			uiWorkDirRoot: stub.root,
			commandRunner: CommandRunnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
				return []byte("ok"), nil
			}),
		}
		result, agentErr := agent.callBackupRestore(context.Background(), encoded)
		if agentErr != nil {
			if fromS3 {
				_ = os.Remove(landed)
				if !workdirExisted {
					_ = os.RemoveAll(workdir)
				}
			}
			return agentErr
		}
		return copyHostResult(json.RawMessage(result), target)
	default:
		stub.t.Fatalf("backup-restore action = %q", action)
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
	stub := &backupRestoreStub{t: t, root: root, apps: apps, records: snapshot}
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
	stub.restoreBytes = fixture.content
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

func TestRestoreBackupS3RunsOnTargetAgentFaceAndAdopts(t *testing.T) {
	t.Parallel()
	root, fixture, runtime, stub := newRestoreCase(t, nil)
	restored, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false))
	if err != nil {
		t.Fatal(err)
	}
	// The restore dispatch carries the destination parameters, the object
	// reference, and the record checksum to the target agent.
	if len(stub.restorePayloads) != 1 {
		t.Fatalf("restore payloads = %d", len(stub.restorePayloads))
	}
	restore := stub.restorePayloads[0]
	if restore["action"] != backupRestoreActionRestore || restore["agent_id"] != "agent-2" || restore["app_id"] != "media" {
		t.Fatalf("restore payload = %#v", restore)
	}
	if restore["source"] != BackupDestinationS3 || restore["object"] != fixture.name || restore["path"] != backupArtifactDir+"/"+fixture.name {
		t.Fatalf("restore artifact = %#v", restore)
	}
	if restore["sha256"] != fixture.sha256 || restore["size"] != float64(fixture.size) {
		t.Fatalf("restore checksum = %#v", restore)
	}
	if restore["endpoint"] != testBackupS3Endpoint || restore["bucket"] != testBackupS3Bucket ||
		restore["prefix"] != testBackupS3Prefix || restore["credentials_secret"] != testBackupS3CredentialsReferenceJSON {
		t.Fatalf("restore destination = %#v", restore)
	}
	// The target Agent face rebuilt the workspace, compose, and bind members,
	// and staged the named-volume archive.
	assertRestoredWorkspace(t, root, fixture)
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
	if stub.backupPuts != 0 || len(stub.records.Records) != 1 {
		t.Fatalf("record mutated: puts = %d records = %#v", stub.backupPuts, stub.records)
	}
	if len(stub.deletePayloads) != 0 || len(stub.discardPayloads) != 0 {
		t.Fatalf("restore dispatched deletion: %#v %#v", stub.deletePayloads, stub.discardPayloads)
	}
}

func TestRestoreBackupNodeSameAgentRestoresOnAgentFace(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{{ID: "media", AgentID: "agent-1", Compose: "services: {app: {image: example/app:0}}", Generation: "generation-1", Env: "KEY=value\n"}}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.nodeRecord("agent-1")})
	if err := os.MkdirAll(filepath.Join(root, "media", backupArtifactDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "media", backupArtifactDir, fixture.name), fixture.content, 0o600); err != nil {
		t.Fatal(err)
	}
	// Same-name managed app: the app id is the confirm token.
	if _, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-1", "media", backupRunTestSettings(false, false)); err != nil {
		t.Fatal(err)
	}
	// The restore is dispatched to the target Agent execution face; the
	// control plane never unpacks the artifact itself, same-node or not.
	if len(stub.restorePayloads) != 1 {
		t.Fatalf("restore payloads = %#v", stub.restorePayloads)
	}
	restore := stub.restorePayloads[0]
	if restore["action"] != backupRestoreActionRestore || restore["agent_id"] != "agent-1" ||
		restore["app_id"] != "media" || restore["source"] != BackupDestinationNode ||
		restore["path"] != backupArtifactDir+"/"+fixture.name ||
		restore["sha256"] != fixture.sha256 || restore["size"] != float64(fixture.size) {
		t.Fatalf("restore payload = %#v", restore)
	}
	// Same-node: the artifact already lives on the target, so no probe and no
	// transfer push precede the dispatch.
	if len(stub.probePayloads) != 0 || len(stub.sendRequests) != 0 {
		t.Fatalf("same-node restore probed or pushed: %#v %#v", stub.probePayloads, stub.sendRequests)
	}
	// The target Agent face rebuilt the workspace, compose, and bind members,
	// and staged the named-volume archive.
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

func TestRestoreBackupNodeCrossAgentProbesPushesAndRestores(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"},
		{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-1"},
	}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.nodeRecord("agent-1")})
	stub.restoreBytes = fixture.content
	restored, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(false, true))
	if err != nil {
		t.Fatal(err)
	}
	// The target was probed for an already-present artifact first.
	if len(stub.probePayloads) != 1 {
		t.Fatalf("probe payloads = %d", len(stub.probePayloads))
	}
	probe := stub.probePayloads[0]
	if probe["action"] != backupRestoreActionProbe || probe["agent_id"] != "agent-2" ||
		probe["path"] != backupArtifactDir+"/"+fixture.name || probe["sha256"] != fixture.sha256 {
		t.Fatalf("probe payload = %#v", probe)
	}
	// The artifact was pushed from the origin to the target agent.
	if len(stub.sendRequests) != 1 {
		t.Fatalf("send requests = %#v", stub.sendRequests)
	}
	sent := stub.sendRequests[0]
	if sent.SourceAgentID != "agent-1" || sent.TargetAgentID != "agent-2" || sent.AppID != "media" ||
		sent.ArtifactName != fixture.name || sent.SHA256 != fixture.sha256 {
		t.Fatalf("send request = %#v", sent)
	}
	// The restore ran on the target agent face from the pushed workspace copy.
	if len(stub.restorePayloads) != 1 || stub.restorePayloads[0]["source"] != BackupDestinationNode {
		t.Fatalf("restore payloads = %#v", stub.restorePayloads)
	}
	assertRestoredWorkspace(t, root, fixture)
	if restored.AgentID != "agent-2" || restored.Compose != backupRestoreTestCompose {
		t.Fatalf("restored app = %#v", restored)
	}
}

func TestRestoreBackupNodeCrossAgentReusesPresentArtifactWithoutPush(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"},
		{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-1"},
	}
	root, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.nodeRecord("agent-1")})
	// The target already holds the exact artifact; the push is skipped.
	if err := os.MkdirAll(filepath.Join(root, "media", backupArtifactDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "media", backupArtifactDir, fixture.name), fixture.content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(false, true)); err != nil {
		t.Fatal(err)
	}
	if len(stub.sendRequests) != 0 {
		t.Fatalf("present artifact was pushed again: %#v", stub.sendRequests)
	}
	if len(stub.probePayloads) != 1 || len(stub.restorePayloads) != 1 {
		t.Fatalf("probe/restore payloads = %#v %#v", stub.probePayloads, stub.restorePayloads)
	}
	assertRestoredWorkspace(t, root, fixture)
}

func TestRestoreBackupNodeCrossAgentDisabledDestinationKeepsGate(t *testing.T) {
	t.Parallel()
	fixture := buildRestoreFixture(t)
	apps := []App{
		{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"},
		{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-1"},
	}
	_, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.nodeRecord("agent-1")})
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(false, false))
	if err == nil || !strings.Contains(err.Error(), nodeStageDisabled) {
		t.Fatalf("disabled cross-node err = %v", err)
	}
	if len(stub.sendRequests) != 0 || len(stub.restorePayloads) != 0 {
		t.Fatalf("disabled cross-node restore dispatched work")
	}
	if stub.appsPuts != 0 || stub.backupPuts != 0 {
		t.Fatalf("disabled cross-node restore mutated state")
	}
}

func TestRestoreBackupOverwriteWithoutConfirmRejectedZeroSideEffects(t *testing.T) {
	t.Parallel()
	apps := []App{{ID: "media", AgentID: "agent-2", Compose: "services: {app: {image: example/app:0}}", Generation: "generation-1"}}
	root, fixture, runtime, stub := newRestoreCase(t, apps)
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false))
	if !errors.Is(err, ErrDeleteUnconfirmed) {
		t.Fatalf("err = %v want %v", err, ErrDeleteUnconfirmed)
	}
	if len(stub.restorePayloads) != 0 || len(stub.composePayloads) != 0 {
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
	restored, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "media", backupRunTestSettings(true, false))
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
	t.Run("retrieved bytes do not match the record", func(t *testing.T) {
		root, fixture, runtime, stub := newRestoreCase(t, nil)
		stub.restoreBytes = fixture.content[:len(fixture.content)-1]
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageRetrieve) {
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
		stub.restoreBytes = tampered
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageRetrieve) {
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
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-1", "media", backupRunTestSettings(false, false))
		// The target Agent face rejects the checksum mismatch; the control
		// plane surfaces it as a retrieve-stage restore failure (the safe
		// failure policy keeps agent-face details off the wire message).
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageRetrieve) {
			t.Fatalf("err = %v", err)
		}
		// The origin workspace artifact is never deleted by a failed restore.
		if _, statErr := os.Stat(artifact); statErr != nil {
			t.Fatalf("origin artifact removed: %v", statErr)
		}
		if len(stub.composePayloads) != 0 || stub.appsPuts != 0 {
			t.Fatalf("checksum failure dispatched work")
		}
	})
}

func TestRestoreBackupApplyFailureKeepsRecordAndManagedState(t *testing.T) {
	t.Parallel()
	_, fixture, runtime, stub := newRestoreCase(t, nil)
	stub.failApply = errors.New("compose apply failed")
	_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(true, false))
	if err == nil || !strings.Contains(err.Error(), backupRestoreStageApply) || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if stub.appsPuts != 0 {
		t.Fatalf("failed restore changed managed state: puts = %d", stub.appsPuts)
	}
	if len(stub.records.Records) != 1 || stub.backupPuts != 0 {
		t.Fatalf("failed restore mutated the record: %#v", stub.records)
	}
	if len(stub.restorePayloads) != 1 {
		t.Fatalf("restore payloads = %d", len(stub.restorePayloads))
	}
}

func TestRestoreBackupGates(t *testing.T) {
	t.Parallel()
	t.Run("nil runtime", func(t *testing.T) {
		var runtime *hostCapabilityRuntime
		if _, err := runtime.RestoreBackup(context.Background(), "record", "agent-1", "", backupRunTestSettings(true, false)); !errors.Is(err, ErrTypedHandlesUnavailable) {
			t.Fatalf("nil runtime err = %v", err)
		}
	})
	t.Run("unknown record", func(t *testing.T) {
		_, runtime, stub := newBackupRestoreRuntime(t, nil, nil)
		if _, err := runtime.RestoreBackup(context.Background(), "missing", "agent-1", "", backupRunTestSettings(true, false)); !errors.Is(err, ErrBackupRecordUnknown) {
			t.Fatalf("unknown record err = %v", err)
		}
		if len(stub.restorePayloads) != 0 {
			t.Fatalf("unknown record dispatched work")
		}
	})
	t.Run("invalid record id", func(t *testing.T) {
		_, runtime, _ := newBackupRestoreRuntime(t, nil, nil)
		_, err := runtime.RestoreBackup(context.Background(), strings.Repeat("x", 161), "agent-1", "", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageRecord) {
			t.Fatalf("invalid record err = %v", err)
		}
	})
	t.Run("unmanaged target agent", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		apps := []App{{ID: "media", AgentID: "agent-1", Compose: backupRestoreTestCompose, Generation: "generation-1"}}
		_, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.s3Record()})
		_, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-9", "media", backupRunTestSettings(true, false))
		if err == nil || !strings.Contains(err.Error(), backupRestoreStageAgent) {
			t.Fatalf("unmanaged agent err = %v", err)
		}
		if len(stub.restorePayloads) != 0 || stub.appsPuts != 0 {
			t.Fatalf("unmanaged agent dispatched work")
		}
	})
	t.Run("offline target agent id", func(t *testing.T) {
		_, runtime, _ := newBackupRestoreRuntime(t, nil, nil)
		if _, err := runtime.RestoreBackup(context.Background(), "missing", "", "", backupRunTestSettings(true, false)); !errors.Is(err, ErrAgentOffline) {
			t.Fatalf("invalid agent err = %v", err)
		}
	})
	t.Run("s3 destination unconfigured", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		apps := []App{{ID: "other", AgentID: "agent-2", Compose: "services: {side: {image: example/side:1}}", Generation: "generation-2"}}
		_, runtime, stub := newBackupRestoreRuntime(t, apps, []BackupRecord{fixture.s3Record()})
		if _, err := runtime.RestoreBackup(context.Background(), fixture.name, "agent-2", "", backupRunTestSettings(false, false)); !errors.Is(err, ErrBackupDestinationUnconfigured) {
			t.Fatalf("unconfigured err = %v", err)
		}
		if len(stub.restorePayloads) != 0 {
			t.Fatalf("unconfigured destination dispatched a restore")
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
		record := fixture.nodeRecord("agent-1")
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
	t.Run("pushed node artifact also removed from the target agent", func(t *testing.T) {
		fixture := buildRestoreFixture(t)
		record := fixture.nodeRecord("agent-2")
		_, runtime, stub := newBackupRestoreRuntime(t, nil, []BackupRecord{record})
		if err := runtime.DeleteBackup(context.Background(), fixture.name, "media", backupRunTestSettings(false, false)); err != nil {
			t.Fatal(err)
		}
		if len(stub.discardPayloads) != 2 {
			t.Fatalf("discard payloads = %#v", stub.discardPayloads)
		}
		agents := []string{}
		for _, discard := range stub.discardPayloads {
			agents = append(agents, discard["agent_id"].(string))
		}
		sort.Strings(agents)
		if strings.Join(agents, ",") != "agent-1,agent-2" {
			t.Fatalf("discard agents = %v", agents)
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
