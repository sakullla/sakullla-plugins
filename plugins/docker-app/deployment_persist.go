package dockerapp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type deploymentSnapshot struct {
	Records map[string]DeploymentRecord `json:"records"`
	Fences  map[string]uint64           `json:"fences"`
}

type deploymentSnapshotStore interface {
	LoadDeployments(context.Context) (deploymentSnapshot, bool, error)
	StoreDeployments(context.Context, deploymentSnapshot) error
}

type persistedDeploymentStore struct {
	mu      sync.Mutex
	backend deploymentSnapshotStore
}

func newPersistedDeploymentStore(backend deploymentSnapshotStore) *persistedDeploymentStore {
	if backend == nil {
		return nil
	}
	return &persistedDeploymentStore{backend: backend}
}

func (s *persistedDeploymentStore) Load(ctx context.Context, id string) (DeploymentRecord, bool, error) {
	if s == nil {
		return DeploymentRecord{}, false, ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return DeploymentRecord{}, false, err
	}
	record, ok := snapshot.Records[id]
	if !ok {
		return DeploymentRecord{}, false, nil
	}
	return cloneDeploymentRecord(record), true, nil
}

func (s *persistedDeploymentStore) AcquireLease(ctx context.Context, id string, version uint64, value Deployment, until time.Time) (DeploymentRecord, error) {
	if s == nil {
		return DeploymentRecord{}, ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return DeploymentRecord{}, err
	}
	current := snapshot.Records[id]
	if current.Version != version {
		return DeploymentRecord{}, ErrStateConflict
	}
	snapshot.Fences[id]++
	value.AppID, value.FencingToken, value.Lease, value.LeaseUntil = id, snapshot.Fences[id], fmt.Sprintf("fence-%d", snapshot.Fences[id]), until
	next := DeploymentRecord{Version: version + 1, Value: value}
	snapshot.Records[id] = cloneDeploymentRecord(next)
	if err := s.persist(ctx, snapshot); err != nil {
		return DeploymentRecord{}, err
	}
	return cloneDeploymentRecord(next), nil
}

func (s *persistedDeploymentStore) CompareAndSwap(ctx context.Context, id string, version, fence uint64, value Deployment) (DeploymentRecord, error) {
	if s == nil {
		return DeploymentRecord{}, ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return DeploymentRecord{}, err
	}
	current := snapshot.Records[id]
	if current.Version != version || current.Value.FencingToken != fence {
		return DeploymentRecord{}, ErrStateConflict
	}
	value.AppID, value.FencingToken = id, fence
	next := DeploymentRecord{Version: version + 1, Value: value}
	snapshot.Records[id] = cloneDeploymentRecord(next)
	if err := s.persist(ctx, snapshot); err != nil {
		return DeploymentRecord{}, err
	}
	return cloneDeploymentRecord(next), nil
}

func (s *persistedDeploymentStore) DeleteCAS(ctx context.Context, id string, version, fence uint64) error {
	if s == nil {
		return ErrTypedHandlesUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	current, ok := snapshot.Records[id]
	if !ok || current.Version != version || current.Value.FencingToken != fence {
		return ErrStateConflict
	}
	delete(snapshot.Records, id)
	delete(snapshot.Fences, id)
	return s.persist(ctx, snapshot)
}

func (s *persistedDeploymentStore) loadSnapshot(ctx context.Context) (deploymentSnapshot, error) {
	if s.backend == nil {
		return deploymentSnapshot{}, ErrTypedHandlesUnavailable
	}
	snapshot, found, err := s.backend.LoadDeployments(ctx)
	if err != nil {
		return deploymentSnapshot{}, err
	}
	if !found {
		return emptyDeploymentSnapshot(), nil
	}
	if len(snapshot.Records) > MaxApps || len(snapshot.Fences) > MaxApps {
		return deploymentSnapshot{}, ErrTypedHandlesUnavailable
	}
	return cloneDeploymentSnapshot(snapshot), nil
}

func (s *persistedDeploymentStore) persist(ctx context.Context, snapshot deploymentSnapshot) error {
	if s.backend == nil {
		return ErrTypedHandlesUnavailable
	}
	if len(snapshot.Records) > MaxApps || len(snapshot.Fences) > MaxApps {
		return ErrTypedHandlesUnavailable
	}
	return s.backend.StoreDeployments(ctx, cloneDeploymentSnapshot(snapshot))
}

func (runtime *hostCapabilityRuntime) LoadDeployments(ctx context.Context) (deploymentSnapshot, bool, error) {
	if runtime == nil || runtime.client == nil {
		return deploymentSnapshot{}, false, ErrTypedHandlesUnavailable
	}
	var response struct {
		Found bool            `json:"found"`
		Value json.RawMessage `json:"value"`
	}
	if err := callHost(ctx, runtime.client, "state.get", map[string]any{"key": pluginDeploymentsStateKey}, &response); err != nil {
		return deploymentSnapshot{}, false, err
	}
	if !response.Found {
		return deploymentSnapshot{}, false, nil
	}
	var snapshot deploymentSnapshot
	if len(response.Value) == 0 || json.Unmarshal(response.Value, &snapshot) != nil || len(snapshot.Records) > MaxApps || len(snapshot.Fences) > MaxApps {
		return deploymentSnapshot{}, false, ErrTypedHandlesUnavailable
	}
	return cloneDeploymentSnapshot(snapshot), true, nil
}

func (runtime *hostCapabilityRuntime) StoreDeployments(ctx context.Context, snapshot deploymentSnapshot) error {
	cloned := cloneDeploymentSnapshot(snapshot)
	if runtime == nil || runtime.client == nil || len(cloned.Records) > MaxApps || len(cloned.Fences) > MaxApps {
		return ErrTypedHandlesUnavailable
	}
	value, err := json.Marshal(cloned)
	if err != nil || len(value) > MaxConfigBytes {
		return ErrTypedHandlesUnavailable
	}
	var response struct {
		Stored bool `json:"stored"`
	}
	if err := callHost(ctx, runtime.client, "state.put", map[string]any{"key": pluginDeploymentsStateKey, "value": json.RawMessage(value)}, &response); err != nil {
		return err
	}
	if !response.Stored {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func emptyDeploymentSnapshot() deploymentSnapshot {
	return deploymentSnapshot{Records: map[string]DeploymentRecord{}, Fences: map[string]uint64{}}
}

func cloneDeploymentSnapshot(snapshot deploymentSnapshot) deploymentSnapshot {
	cloned := emptyDeploymentSnapshot()
	for id, record := range snapshot.Records {
		cloned.Records[id] = cloneDeploymentRecord(record)
	}
	for id, fence := range snapshot.Fences {
		cloned.Fences[id] = fence
	}
	return cloned
}

func cloneDeploymentRecord(record DeploymentRecord) DeploymentRecord {
	record.Value.History = cloneRevisions(record.Value.History)
	return record
}
