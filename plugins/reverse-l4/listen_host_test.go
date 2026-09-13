package reversel4

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestListenHostManagementLifecycle(t *testing.T) {
	t.Parallel()
	controller, host := newManagementController(t)
	body := mappingWriteRequest{
		ID: "listen-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
		Protocol: ProtocolTCP, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
	}
	write := func(path string, wantStatus int) mappingAPIResponse {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		response := serveManagement(controller, managementJSONRequest(http.MethodPost, path, string(encoded)))
		if response.Code != wantStatus {
			t.Fatalf("%s: status=%d body=%s", path, response.Code, response.Body.String())
		}
		return decodeManagement(t, response)
	}
	assertRuleHost := func(action, want string) {
		t.Helper()
		call := host.onlyCall(t, pluginsdk.HostRuntimeL4Rule, action)
		var rule pluginsdk.L4RuleRequest
		if err := json.Unmarshal([]byte(call.Payload), &rule); err != nil {
			t.Fatal(err)
		}
		if rule.ListenHost != want || rule.Backends[0].Host != "127.0.0.1" {
			t.Fatalf("rule listener/bridge = %+v", rule)
		}
	}
	created := write("/api/mappings", http.StatusOK)
	if created.Mappings[0].ListenHost != "0.0.0.0" {
		t.Fatalf("default listener = %+v", created.Mappings)
	}
	assertRuleHost(pluginsdk.L4RuleActionCreate, "0.0.0.0")

	host.resetCalls()
	body.ListenHost = " ::1 "
	updated := write("/api/mappings/listen-map/update", http.StatusOK)
	if updated.Mappings[0].ListenHost != "::1" {
		t.Fatalf("IPv6 listener = %+v", updated.Mappings)
	}
	assertRuleHost(pluginsdk.L4RuleActionUpdate, "::1")

	// A failed update followed by a different address at the same revision
	// must not replay or conflict with the previous host operation.
	host.failRuleUpdateAttempts = 1
	body.ListenHost = "127.0.0.2"
	write("/api/mappings/listen-map/update", http.StatusServiceUnavailable)
	host.resetCalls()
	body.ListenHost = "127.0.0.3"
	write("/api/mappings/listen-map/update", http.StatusOK)
	assertRuleHost(pluginsdk.L4RuleActionUpdate, "127.0.0.3")

	write("/api/mappings/listen-map/disable", http.StatusOK)
	body.ListenHost = "::"
	write("/api/mappings/listen-map/update", http.StatusOK)
	host.resetCalls()
	write("/api/mappings/listen-map/enable", http.StatusOK)
	assertRuleHost(pluginsdk.L4RuleActionUpdate, "::")

	// Read from durable host state through a new Service, not the API response.
	runtime := bindHostRuntime(host)
	restarted, err := NewService(newDurableMappingState(runtime), runtime)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := restarted.List(t.Context())
	if err != nil || len(stored) != 1 || stored[0].ListenHost != "::" {
		t.Fatalf("persisted listener = %+v, err=%v", stored, err)
	}

	// Clearing an explicit address must send the default to the host on update.
	host.resetCalls()
	body.ListenHost = ""
	write("/api/mappings/listen-map/update", http.StatusOK)
	assertRuleHost(pluginsdk.L4RuleActionUpdate, "0.0.0.0")
}

func TestListenHostUsesL4Validation(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"", "0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "bad host", "https://localhost", "host\nname", strings.Repeat("a", 254)} {
		t.Run(host, func(t *testing.T) {
			mapping := Mapping{
				ID: "listen-map", EntryAgentID: "entry-agent", ExitAgentID: "exit-agent",
				Protocol: ProtocolTCP, ListenHost: host, ListenPort: 8443, BackendHost: "127.0.0.1", BackendPort: 9443,
			}
			request := pluginsdk.L4RuleRequest{Action: pluginsdk.L4RuleActionCreate, AgentID: mapping.EntryAgentID, Protocol: mapping.Protocol, ListenHost: host, ListenPort: mapping.ListenPort}
			if (mapping.Validate() == nil) != (request.Validate() == nil) {
				t.Fatalf("mapping and L4 rule disagree on listen host %q", host)
			}
		})
	}
}

func TestLegacyListenHostDefaultsWithoutChangingIntent(t *testing.T) {
	t.Parallel()
	snapshot, err := decodeMappingState([]byte(`{"revision":1,"mappings":[{"id":"listen-map","entry_agent_id":"entry-agent","exit_agent_id":"exit-agent","protocol":"tcp","listen_port":8443,"backend_host":"127.0.0.1","backend_port":9443}]}`))
	if err != nil {
		t.Fatal(err)
	}
	legacy := snapshot.Mappings[0]
	explicit := legacy
	explicit.ListenHost = "0.0.0.0"
	if !legacy.sameUserSpec(explicit) || newMappingView(MappingStatus{Mapping: legacy}).ListenHost != "0.0.0.0" {
		t.Fatal("legacy listener did not retain the L4 default")
	}
	if mutationOperationKey(t.Context(), "rule.create", legacy, 1) != mutationOperationKey(t.Context(), "rule.create", explicit, 1) {
		t.Fatal("explicit default changed legacy operation identity")
	}
	if ruleRequest(legacy, channelSession{BridgeHost: "127.0.0.1", BridgePort: 6001}).ListenHost != "0.0.0.0" {
		t.Fatal("legacy recovery rule lost its default listener")
	}
}
