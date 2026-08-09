package reversel4

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Mapping is plugin-owned configuration only. Listener, tunnel, relay,
// traffic, and Agent identity resources remain owned by the core host.
type Mapping struct {
	ID             string
	PrivateAgentID string
	PublicAgentID  string
	Protocol       Protocol
	ListenPort     uint16
	BackendHost    string
	BackendPort    uint16
	Enabled        bool
}

func (mapping Mapping) Validate() error {
	if !validIdentifier(mapping.ID) {
		return errors.New("mapping id is invalid")
	}
	for name, value := range map[string]string{
		"private agent reference": mapping.PrivateAgentID,
		"public agent reference":  mapping.PublicAgentID,
	} {
		if !validOpaqueReference(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if mapping.PrivateAgentID == mapping.PublicAgentID {
		return errors.New("private and public agents must be distinct")
	}
	if mapping.Protocol != ProtocolTCP && mapping.Protocol != ProtocolUDP {
		return fmt.Errorf("protocol %q is not tcp or udp", mapping.Protocol)
	}
	if mapping.ListenPort == 0 || mapping.BackendPort == 0 {
		return errors.New("listen and backend ports must be non-zero")
	}
	if !validBackendHost(mapping.BackendHost) {
		return errors.New("backend host must be a bounded host or IP without scheme, path, or whitespace")
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') && (current < '0' || current > '9') && current != '-' {
			return false
		}
	}
	return true
}

func validBackendHost(value string) bool {
	if value == "" || len(value) > 253 || strings.Contains(value, "://") || strings.ContainsAny(value, "/\\") {
		return false
	}
	return !strings.ContainsFunc(value, func(current rune) bool {
		return current == 0 || current == '\r' || current == '\n' || current == '\t' || current == ' '
	})
}

func validOpaqueReference(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	return !strings.ContainsFunc(value, func(current rune) bool {
		return current == 0 || current == '\r' || current == '\n' || current == '\t'
	})
}

// MappingStore owns mapping configuration without opening sockets or
// resolving any core resource.
type MappingStore struct {
	mu       sync.RWMutex
	mappings map[string]Mapping
}

func NewMappingStore() *MappingStore {
	return &MappingStore{mappings: make(map[string]Mapping)}
}

func (store *MappingStore) Put(mapping Mapping) error {
	if err := mapping.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	store.mappings[mapping.ID] = mapping
	store.mu.Unlock()
	return nil
}

func (store *MappingStore) Get(id string) (Mapping, bool) {
	store.mu.RLock()
	mapping, ok := store.mappings[id]
	store.mu.RUnlock()
	return mapping, ok
}

func (store *MappingStore) Disable(id string) (Mapping, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapping, ok := store.mappings[id]
	if !ok {
		return Mapping{}, fmt.Errorf("mapping %q does not exist", id)
	}
	mapping.Enabled = false
	store.mappings[id] = mapping
	return mapping, nil
}

func (store *MappingStore) List() []Mapping {
	store.mu.RLock()
	result := make([]Mapping, 0, len(store.mappings))
	for _, mapping := range store.mappings {
		result = append(result, mapping)
	}
	store.mu.RUnlock()
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}
