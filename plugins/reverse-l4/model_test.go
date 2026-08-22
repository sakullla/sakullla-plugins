package reversel4

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestMappingValidateAcceptsTCPAndUDP(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{ProtocolTCP, ProtocolUDP} {
		mapping := Mapping{
			ID: "tcp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
			Protocol: protocol, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
			RuleRef: "12", SessionRef: "channel/entry-agent/exit-agent", BridgeHost: "127.0.0.1", BridgePort: 6001,
		}
		if err := mapping.Validate(); err != nil {
			t.Fatalf("protocol %s mapping error = %v", protocol, err)
		}
	}
}

func TestMappingValidateRejectsDegenerateInput(t *testing.T) {
	t.Parallel()
	base := Mapping{
		ID: "tcp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolTCP, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
	}
	cases := map[string]func(Mapping) Mapping{
		"empty id":                func(m Mapping) Mapping { m.ID = ""; return m },
		"upper id":                func(m Mapping) Mapping { m.ID = "Map"; return m },
		"same agents":             func(m Mapping) Mapping { m.ExitAgentID = m.EntryAgentID; return m },
		"unknown protocol":        func(m Mapping) Mapping { m.Protocol = "sctp"; return m },
		"zero listen port":        func(m Mapping) Mapping { m.ListenPort = 0; return m },
		"oversized listen port":   func(m Mapping) Mapping { m.ListenPort = 65536; return m },
		"url backend host":        func(m Mapping) Mapping { m.BackendHost = "https://backend.example/path"; return m },
		"whitespace backend host": func(m Mapping) Mapping { m.BackendHost = "127.0.0.1 "; return m },
		"zero backend port":       func(m Mapping) Mapping { m.BackendPort = 0; return m },
		"zero relay hop":          func(m Mapping) Mapping { m.RelayChain = []int{3, 0}; return m },
		"bridge host without port": func(m Mapping) Mapping {
			m.BridgeHost, m.BridgePort = "127.0.0.1", 0
			return m
		},
		"newlines in name": func(m Mapping) Mapping {
			m.Name = "mapping\nname"
			return m
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := mutate(base).Validate(); !errors.Is(err, ErrInvalidMapping) && !errors.Is(err, ErrBoundExceeded) {
				t.Fatalf("mutated mapping error = %v", err)
			}
		})
	}
}

func TestMappingStateRoundTripRejectsUnknownFieldsAndDuplicates(t *testing.T) {
	t.Parallel()
	snapshot := mappingStateSnapshot{Revision: 7, Mappings: []Mapping{{
		ID: "tcp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolTCP, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
		Enabled: true, RuleRef: "12", SessionRef: "channel/entry-agent/exit-agent",
		BridgeHost: "127.0.0.1", BridgePort: 6001, Revision: 3, RelayChain: []int{4, 5},
	}}}
	encoded, err := encodeMappingState(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeMappingState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Revision != 7 || len(decoded.Mappings) != 1 || decoded.Mappings[0].ID != "tcp-map" {
		t.Fatalf("round trip = %#v", decoded)
	}
	if chain := decoded.Mappings[0].RelayChain; len(chain) != 2 || chain[0] != 4 || chain[1] != 5 {
		t.Fatalf("round trip relay chain = %v", chain)
	}
	duplicated, err := json.Marshal(mappingStateSnapshot{Mappings: []Mapping{snapshot.Mappings[0], snapshot.Mappings[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMappingState(duplicated); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("duplicate mapping error = %v", err)
	}
	if _, err := decodeMappingState([]byte(`{"revision":1,"mappings":[],"unexpected":true}`)); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestMemoryMappingStatePersistsAcrossSaves(t *testing.T) {
	t.Parallel()
	state := newMemoryMappingState()
	service, err := NewService(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(t.Context(), mappingStateSnapshot{Revision: 1, Mappings: []Mapping{{
		ID: "udp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolUDP, ListenPort: 5353, BackendHost: "10.0.0.8", BackendPort: 53,
	}}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load(t.Context())
	if err != nil || len(loaded.Mappings) != 1 || loaded.Mappings[0].ID != "udp-map" {
		t.Fatalf("loaded = %#v err=%v", loaded, err)
	}
}

func TestServiceWithoutHostRuntimeReportsExplicitUnavailable(t *testing.T) {
	t.Parallel()
	service, err := NewService(newMemoryMappingState(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(t.Context(), Mapping{
		ID: "tcp-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolTCP, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
	}); !errors.Is(err, ErrHostRuntimeUnavailable) {
		t.Fatalf("create without host runtime error = %v", err)
	}
}

func TestRejectNonEmptyConfigEnforcesZeroConfig(t *testing.T) {
	t.Parallel()
	for _, config := range []string{"", "null", "{}", "\n"} {
		if err := rejectNonEmptyConfig([]byte(config)); err != nil {
			t.Fatalf("config %q error = %v", config, err)
		}
	}
	for _, config := range []string{`{"mappings":[]}`, `{"server":"frps.example"}`, `{"token":"secret"}`, "[]"} {
		if err := rejectNonEmptyConfig([]byte(config)); err == nil {
			t.Fatalf("config %q was accepted", config)
		}
	}
}

func TestStableOperationKeysAreDeterministicAndRevisionDistinct(t *testing.T) {
	t.Parallel()
	first := mutationOperationKey("channel.ensure", "tcp-map", 3)
	if first != mutationOperationKey("channel.ensure", "tcp-map", 3) {
		t.Fatal("operation key is not deterministic")
	}
	if first == mutationOperationKey("channel.ensure", "tcp-map", 4) {
		t.Fatal("operation key ignores the mapping revision")
	}
	if first == mutationOperationKey("rule.create", "tcp-map", 3) {
		t.Fatal("operation key ignores the action")
	}
	if len(first) > 512 {
		t.Fatalf("operation key exceeds the policy identity bound: %d", len(first))
	}
}
