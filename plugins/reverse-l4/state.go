package reversel4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MappingStateKey is the single durable state key holding the mapping
// catalog. Mapping records are runtime resources managed from the plugin
// page, never plugin configuration.
const MappingStateKey = "mappings"

// mappingStateSnapshot is the durable document stored under MappingStateKey.
type mappingStateSnapshot struct {
	Revision uint64    `json:"revision"`
	Mappings []Mapping `json:"mappings"`
}

func (snapshot mappingStateSnapshot) clone() mappingStateSnapshot {
	cloned := mappingStateSnapshot{Revision: snapshot.Revision, Mappings: make([]Mapping, 0, len(snapshot.Mappings))}
	for _, mapping := range snapshot.Mappings {
		cloned.Mappings = append(cloned.Mappings, mapping.Clone())
	}
	return cloned
}

func (snapshot mappingStateSnapshot) mapping(id string) (Mapping, bool) {
	for _, mapping := range snapshot.Mappings {
		if mapping.ID == id {
			return mapping.Clone(), true
		}
	}
	return Mapping{}, false
}

// mappingState is the durable mapping catalog behind the orchestration
// service. Implementations must round-trip the full snapshot atomically.
type mappingState interface {
	Load(context.Context) (mappingStateSnapshot, error)
	Save(context.Context, mappingStateSnapshot) error
}

// durableMappingState persists the catalog through the host state.get and
// state.put runtime operations, keyed by plugin instance.
type durableMappingState struct {
	runtime *hostRuntime
}

func newDurableMappingState(runtime *hostRuntime) *durableMappingState {
	return &durableMappingState{runtime: runtime}
}

func (state *durableMappingState) Load(ctx context.Context) (mappingStateSnapshot, error) {
	if state.runtime == nil || !state.runtime.available() {
		return mappingStateSnapshot{}, ErrHostRuntimeUnavailable
	}
	stored, found, err := state.runtime.stateGet(ctx, MappingStateKey)
	if err != nil {
		return mappingStateSnapshot{}, err
	}
	if !found {
		return mappingStateSnapshot{}, nil
	}
	snapshot, err := decodeMappingState(stored)
	if err != nil {
		return mappingStateSnapshot{}, err
	}
	return snapshot, nil
}

func (state *durableMappingState) Save(ctx context.Context, snapshot mappingStateSnapshot) error {
	if state.runtime == nil || !state.runtime.available() {
		return ErrHostRuntimeUnavailable
	}
	encoded, err := encodeMappingState(snapshot)
	if err != nil {
		return err
	}
	return state.runtime.statePut(ctx, MappingStateKey, encoded)
}

// memoryMappingState is the in-memory catalog used by the build-time probe
// lifecycle and tests.
type memoryMappingState struct {
	mu       sync.Mutex
	snapshot mappingStateSnapshot
}

func newMemoryMappingState() *memoryMappingState {
	return &memoryMappingState{}
}

func (state *memoryMappingState) Load(context.Context) (mappingStateSnapshot, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.snapshot.clone(), nil
}

func (state *memoryMappingState) Save(_ context.Context, snapshot mappingStateSnapshot) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.snapshot = snapshot.clone()
	return nil
}

func encodeMappingState(snapshot mappingStateSnapshot) ([]byte, error) {
	if len(snapshot.Mappings) > MaxMappings {
		return nil, fmt.Errorf("%w: mappings maximum is %d", ErrBoundExceeded, MaxMappings)
	}
	for _, mapping := range snapshot.Mappings {
		if err := mapping.Validate(); err != nil {
			return nil, fmt.Errorf("%w: stored mapping %q is invalid: %v", ErrStateUnavailable, mapping.ID, err)
		}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > pluginsdkPayloadBound {
		return nil, fmt.Errorf("%w: mapping state document is invalid", ErrStateUnavailable)
	}
	return encoded, nil
}

func decodeMappingState(encoded []byte) (mappingStateSnapshot, error) {
	if len(encoded) > pluginsdkPayloadBound {
		return mappingStateSnapshot{}, fmt.Errorf("%w: mapping state document is too large", ErrStateUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var snapshot mappingStateSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return mappingStateSnapshot{}, fmt.Errorf("%w: mapping state document is invalid: %v", ErrStateUnavailable, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return mappingStateSnapshot{}, fmt.Errorf("%w: mapping state document must be one JSON object", ErrStateUnavailable)
	}
	if len(snapshot.Mappings) > MaxMappings {
		return mappingStateSnapshot{}, fmt.Errorf("%w: mappings maximum is %d", ErrBoundExceeded, MaxMappings)
	}
	seen := make(map[string]struct{}, len(snapshot.Mappings))
	for _, mapping := range snapshot.Mappings {
		if err := mapping.Validate(); err != nil {
			return mappingStateSnapshot{}, fmt.Errorf("%w: stored mapping %q is invalid: %v", ErrStateUnavailable, mapping.ID, err)
		}
		if _, duplicate := seen[mapping.ID]; duplicate {
			return mappingStateSnapshot{}, fmt.Errorf("%w: stored mapping %q is duplicated", ErrStateUnavailable, mapping.ID)
		}
		seen[mapping.ID] = struct{}{}
	}
	return snapshot, nil
}
