// Package reversel4 contains the control-plane mapping model for reverse L4
// tunneling: one mapping publishes an internal TCP/UDP backend through a host
// L4 rule on the entry agent and a host-managed reverse channel dialed by the
// exit agent. The plugin owns only mapping records and orchestration; the
// entry listener, channel transport, identity, and encryption stay host-owned.
package reversel4

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	PluginID                 = "reverse-l4"
	PluginVersion            = "0.3.4"
	DeclaredResourceGroupRef = "resource-group/reverse-l4"

	// MaxMappings bounds the durable mapping catalog.
	MaxMappings = 256
	// MaxRelayHops bounds the optional relay listener chain a mapping may
	// reference for channel path optimization.
	MaxRelayHops = 32
	// mappingIDRandomBytes is the entropy used when Create mints a mapping id.
	mappingIDRandomBytes = 8
	// mappingIDAllocTries bounds unique-id retries against the in-memory catalog.
	mappingIDAllocTries = 8

	ProtocolTCP = pluginsdk.L4RuleProtocolTCP
	ProtocolUDP = pluginsdk.L4RuleProtocolUDP

	// Channel connectivity states projected onto mappings.
	ChannelOnline  = "online"
	ChannelOffline = "offline"
	ChannelUnknown = "unknown"
)

var (
	ErrInvalidMapping         = errors.New("mapping is invalid")
	ErrMappingExists          = errors.New("mapping id already exists")
	ErrMappingNotFound        = errors.New("mapping is unknown")
	ErrBoundExceeded          = errors.New("bounded collection limit exceeded")
	ErrHostRuntimeUnavailable = errors.New("host runtime capabilities are unavailable")
	ErrHostOperationFailed    = errors.New("host runtime operation failed")
	ErrHostRejectedRequest    = errors.New("host runtime rejected the request")
	ErrStateUnavailable       = errors.New("mapping state store is unavailable")

	// Management-page surface errors.
	ErrUnauthorized      = errors.New("mapping page authorization denied")
	ErrDeleteUnconfirmed = errors.New("delete requires the mapping id as confirmation")
	ErrOperationFailed   = errors.New("mapping operation failed")
)

// Mapping is one user-created tunnel mapping. EntryAgentID is the publicly
// reachable agent whose host L4 rule listens; ExitAgentID is the
// outbound-only agent that dials the reverse channel and forwards to
// BackendHost:BackendPort.
type Mapping struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	EntryAgentID string `json:"entry_agent_id"`
	ExitAgentID  string `json:"exit_agent_id"`
	Protocol     string `json:"protocol"`
	ListenPort   int    `json:"listen_port"`
	BackendHost  string `json:"backend_host"`
	BackendPort  int    `json:"backend_port"`
	RelayChain   []int  `json:"relay_chain,omitempty"`
	Enabled      bool   `json:"enabled"`
	RuleRef      string `json:"rule_ref,omitempty"`
	SessionRef   string `json:"session_ref,omitempty"`
	BridgeHost   string `json:"bridge_host,omitempty"`
	BridgePort   int    `json:"bridge_port,omitempty"`
	Revision     uint64 `json:"revision"`
	// RecoveryGeneration is a monotonic attempt counter used only to mint
	// recovery host operation ids. Zero is compatible with older snapshots
	// and is not part of the user-facing mapping specification.
	RecoveryGeneration uint64 `json:"recovery_generation,omitempty"`
}

// MappingStatus is the management-page projection of one mapping: the record
// plus the current reverse-channel connectivity.
type MappingStatus struct {
	Mapping
	ChannelState string `json:"channel_state"`
	LastError    string `json:"last_error,omitempty"`
}

func (mapping Mapping) Validate() error {
	if !validMappingID(mapping.ID) {
		return fmt.Errorf("%w: id", ErrInvalidMapping)
	}
	if mapping.Name != strings.TrimSpace(mapping.Name) || len(mapping.Name) > 128 || strings.ContainsAny(mapping.Name, "\r\n\x00") {
		return fmt.Errorf("%w: name", ErrInvalidMapping)
	}
	if err := validAgentID(mapping.EntryAgentID); err != nil {
		return fmt.Errorf("%w: entry agent: %v", ErrInvalidMapping, err)
	}
	if err := validAgentID(mapping.ExitAgentID); err != nil {
		return fmt.Errorf("%w: exit agent: %v", ErrInvalidMapping, err)
	}
	if mapping.EntryAgentID == mapping.ExitAgentID {
		return fmt.Errorf("%w: entry and exit agents must differ", ErrInvalidMapping)
	}
	if mapping.Protocol != ProtocolTCP && mapping.Protocol != ProtocolUDP {
		return fmt.Errorf("%w: protocol %q is not tcp or udp", ErrInvalidMapping, mapping.Protocol)
	}
	if mapping.ListenPort <= 0 || mapping.ListenPort > 65535 {
		return fmt.Errorf("%w: listen port", ErrInvalidMapping)
	}
	if !validBackendHost(mapping.BackendHost) {
		return fmt.Errorf("%w: backend host must be a bounded host or IP without scheme, path, or whitespace", ErrInvalidMapping)
	}
	if mapping.BackendPort <= 0 || mapping.BackendPort > 65535 {
		return fmt.Errorf("%w: backend port", ErrInvalidMapping)
	}
	if len(mapping.RelayChain) > MaxRelayHops {
		return fmt.Errorf("%w: relay chain exceeds %d hops", ErrBoundExceeded, MaxRelayHops)
	}
	for _, hop := range mapping.RelayChain {
		if hop <= 0 {
			return fmt.Errorf("%w: relay chain hop", ErrInvalidMapping)
		}
	}
	if mapping.RuleRef != "" && !boundedRef(mapping.RuleRef, 128) {
		return fmt.Errorf("%w: rule reference", ErrInvalidMapping)
	}
	if mapping.SessionRef != "" && !boundedRef(mapping.SessionRef, 190) {
		return fmt.Errorf("%w: session reference", ErrInvalidMapping)
	}
	if (mapping.BridgeHost == "") != (mapping.BridgePort == 0) {
		return fmt.Errorf("%w: bridge endpoint", ErrInvalidMapping)
	}
	if mapping.BridgePort < 0 || mapping.BridgePort > 65535 {
		return fmt.Errorf("%w: bridge port", ErrInvalidMapping)
	}
	return nil
}

// Clone returns a deep copy so callers cannot alias stored slices.
func (mapping Mapping) Clone() Mapping {
	mapping.RelayChain = append([]int(nil), mapping.RelayChain...)
	return mapping
}

// sameUserSpec reports whether an update changes any user-owned mapping
// field. Nil and empty relay chains are equivalent on the management API.
func (mapping Mapping) sameUserSpec(other Mapping) bool {
	return mapping.ID == other.ID &&
		mapping.Name == other.Name &&
		mapping.EntryAgentID == other.EntryAgentID &&
		mapping.ExitAgentID == other.ExitAgentID &&
		mapping.Protocol == other.Protocol &&
		mapping.ListenPort == other.ListenPort &&
		mapping.BackendHost == other.BackendHost &&
		mapping.BackendPort == other.BackendPort &&
		slices.Equal(mapping.RelayChain, other.RelayChain)
}

func validMappingID(value string) bool {
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

func validAgentID(value string) error {
	if !boundedRef(value, 128) {
		return errors.New("agent id must be 1-128 bytes without control characters")
	}
	return nil
}

func boundedRef(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00\t ") && value == strings.TrimSpace(value)
}

func validBackendHost(value string) bool {
	if !boundedRef(value, 253) {
		return false
	}
	return !strings.Contains(value, "://") && !strings.ContainsAny(value, "/\\")
}

func sortMappings(mappings []Mapping) {
	sort.Slice(mappings, func(left, right int) bool {
		if mappings[left].ID != mappings[right].ID {
			return mappings[left].ID < mappings[right].ID
		}
		return mappings[left].Revision < mappings[right].Revision
	})
}
