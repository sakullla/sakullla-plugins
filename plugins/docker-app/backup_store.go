package dockerapp

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Backup destination types recorded with each backup record.
const (
	BackupDestinationS3   = "s3"
	BackupDestinationNode = "node"
)

// MaxBackupRecords bounds the persisted backup record set, keeping the state
// snapshot well below MaxConfigBytes.
const MaxBackupRecords = 256

var (
	// ErrBackupDestinationUnconfigured gates backup dispatch on a missing
	// destination (S3 not configured and the node destination disabled).
	ErrBackupDestinationUnconfigured = errors.New("backup destination is not configured")
	// ErrBackupRecordInvalid rejects records that do not match the stored
	// shape before they reach the state snapshot.
	ErrBackupRecordInvalid = errors.New("backup record is invalid")
	// ErrBackupRecordUnknown reports a record id that is not stored.
	ErrBackupRecordUnknown = errors.New("backup record is unknown")
)

// BackupDestinationRef names where one backup artifact lives: the full S3
// object key for s3 destinations, or the origin Agent id for node
// destinations.
type BackupDestinationRef struct {
	Type     string `json:"type"`
	Location string `json:"location,omitempty"`
}

// BackupRecord is one persisted backup entry under the "backups" state key.
type BackupRecord struct {
	ID            string               `json:"id"`
	AppID         string               `json:"app_id"`
	OriginAgentID string               `json:"origin_agent_id"`
	Created       string               `json:"created"`
	SizeBytes     int64                `json:"size_bytes"`
	SHA256        string               `json:"sha256"`
	Destination   BackupDestinationRef `json:"destination"`
}

// Validate checks one record against the bounded stored shape.
func (record BackupRecord) Validate() error {
	if !boundedText(record.ID, 160) || !validID(record.AppID) || !validAgentID(record.OriginAgentID) {
		return ErrBackupRecordInvalid
	}
	if _, err := time.Parse(time.RFC3339, record.Created); err != nil {
		return ErrBackupRecordInvalid
	}
	if record.SizeBytes < 0 || !sha256Hex(record.SHA256) {
		return ErrBackupRecordInvalid
	}
	switch record.Destination.Type {
	case BackupDestinationS3, BackupDestinationNode:
	default:
		return ErrBackupRecordInvalid
	}
	if record.Destination.Location != "" && !boundedText(record.Destination.Location, 512) {
		return ErrBackupRecordInvalid
	}
	return nil
}

type backupStoreSnapshot struct {
	Records map[string]BackupRecord `json:"records"`
}

func emptyBackupStoreSnapshot() backupStoreSnapshot {
	return backupStoreSnapshot{Records: map[string]BackupRecord{}}
}

func cloneBackupStoreSnapshot(snapshot backupStoreSnapshot) backupStoreSnapshot {
	cloned := emptyBackupStoreSnapshot()
	for id, record := range snapshot.Records {
		cloned.Records[id] = record
	}
	return cloned
}

type backupSnapshotStore interface {
	LoadBackups(context.Context) (backupStoreSnapshot, bool, error)
	StoreBackups(context.Context, backupStoreSnapshot) error
}

// persistedBackupStore serializes backup record edits on top of the
// host-state backed snapshot store, following the deployment store precedent.
// It is the record layer only: removing the destination object of a record is
// the restore/delete pipeline's concern.
type persistedBackupStore struct {
	mu      sync.Mutex
	backend backupSnapshotStore
}

func newPersistedBackupStore(backend backupSnapshotStore) *persistedBackupStore {
	if backend == nil {
		return nil
	}
	return &persistedBackupStore{backend: backend}
}

// List returns every stored record sorted by creation time, then id.
func (s *persistedBackupStore) List(ctx context.Context) ([]BackupRecord, error) {
	if s == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]BackupRecord, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Created != records[j].Created {
			return records[i].Created < records[j].Created
		}
		return records[i].ID < records[j].ID
	})
	return records, nil
}

// Get returns one stored record.
func (s *persistedBackupStore) Get(ctx context.Context, id string) (BackupRecord, bool, error) {
	if s == nil {
		return BackupRecord{}, false, ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return BackupRecord{}, false, err
	}
	record, ok := snapshot.Records[strings.TrimSpace(id)]
	if !ok {
		return BackupRecord{}, false, nil
	}
	return record, true, nil
}

// Append validates and adds one record; a duplicated id conflicts.
func (s *persistedBackupStore) Append(ctx context.Context, record BackupRecord) error {
	if s == nil {
		return ErrTypedHandlesUnavailable
	}
	record.ID = strings.TrimSpace(record.ID)
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	if len(snapshot.Records) >= MaxBackupRecords {
		return ErrBoundExceeded
	}
	if _, exists := snapshot.Records[record.ID]; exists {
		return ErrStateConflict
	}
	snapshot.Records[record.ID] = record
	return s.persist(ctx, snapshot)
}

// Remove deletes one stored record.
func (s *persistedBackupStore) Remove(ctx context.Context, id string) error {
	if s == nil {
		return ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	if _, exists := snapshot.Records[strings.TrimSpace(id)]; !exists {
		return ErrBackupRecordUnknown
	}
	delete(snapshot.Records, strings.TrimSpace(id))
	return s.persist(ctx, snapshot)
}

func (s *persistedBackupStore) loadSnapshot(ctx context.Context) (backupStoreSnapshot, error) {
	if s.backend == nil {
		return backupStoreSnapshot{}, ErrTypedHandlesUnavailable
	}
	snapshot, found, err := s.backend.LoadBackups(ctx)
	if err != nil {
		return backupStoreSnapshot{}, err
	}
	if !found {
		return emptyBackupStoreSnapshot(), nil
	}
	if len(snapshot.Records) > MaxBackupRecords {
		return backupStoreSnapshot{}, ErrTypedHandlesUnavailable
	}
	return cloneBackupStoreSnapshot(snapshot), nil
}

func (s *persistedBackupStore) persist(ctx context.Context, snapshot backupStoreSnapshot) error {
	if s.backend == nil {
		return ErrTypedHandlesUnavailable
	}
	if len(snapshot.Records) > MaxBackupRecords {
		return ErrTypedHandlesUnavailable
	}
	return s.backend.StoreBackups(ctx, cloneBackupStoreSnapshot(snapshot))
}

func (runtime *hostCapabilityRuntime) LoadBackups(ctx context.Context) (backupStoreSnapshot, bool, error) {
	if runtime == nil || runtime.client == nil {
		return backupStoreSnapshot{}, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginBackupsStateKey}, &response); err != nil {
		return backupStoreSnapshot{}, false, err
	}
	if !response.Found {
		return backupStoreSnapshot{}, false, nil
	}
	var snapshot backupStoreSnapshot
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &snapshot) != nil || len(snapshot.Records) > MaxBackupRecords {
		return backupStoreSnapshot{}, false, ErrTypedHandlesUnavailable
	}
	for _, record := range snapshot.Records {
		if record.Validate() != nil {
			return backupStoreSnapshot{}, false, ErrTypedHandlesUnavailable
		}
	}
	return cloneBackupStoreSnapshot(snapshot), true, nil
}

func (runtime *hostCapabilityRuntime) StoreBackups(ctx context.Context, snapshot backupStoreSnapshot) error {
	cloned := cloneBackupStoreSnapshot(snapshot)
	if runtime == nil || runtime.client == nil || len(cloned.Records) > MaxBackupRecords {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloned)
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginBackupsStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}
