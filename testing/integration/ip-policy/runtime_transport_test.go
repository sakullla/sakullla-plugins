package ippolicyintegration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ippolicy "github.com/sakullla/sakullla-plugins/plugins/ip-policy"
)

func TestManagementUIUsesRealPublicHostRuntimeTransport(t *testing.T) {
	directory, err := os.MkdirTemp("", "ip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "host.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	cookie := "integration-host-cookie"
	cookiePath := filepath.Join(directory, "cookie")
	if err := os.WriteFile(cookiePath, []byte(cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []pluginsdk.PolicyEntryTarget{
		{NodeID: "local", Kind: pluginsdk.PolicyEntryHTTP, ID: "http-7", Token: "entry-token-000000000001"},
		{NodeID: "local", Kind: pluginsdk.PolicyEntryTCP, ID: "tcp-8", Token: "entry-token-000000000002"},
		{NodeID: "local", Kind: pluginsdk.PolicyEntryUDP, ID: "udp-9", Token: "entry-token-000000000003"},
		{NodeID: "local", Kind: pluginsdk.PolicyEntryManagedTCP, ID: "ss-tcp", Token: "entry-token-000000000004"},
		{NodeID: "local", Kind: pluginsdk.PolicyEntryManagedUDP, ID: "ss-udp", Token: "entry-token-000000000005"},
	}
	mode := pluginsdk.PolicyModeObserve
	revision, instanceVersion := uint64(1), uint64(1)
	overlays := map[string]json.RawMessage{}
	entryModes := map[string]pluginsdk.PolicyMode{}
	var mutations []pluginsdk.PolicyControlRequest

	stage := pluginsdk.PolicyStageIdentity{Kind: pluginsdk.PolicyOverlayStageIP, PolicyID: "ip-instance"}
	desired := func(entry *pluginsdk.PolicyEntryTarget) pluginsdk.PolicySettingsSnapshot {
		settings := pluginsdk.PolicyModeSettings{Handling: pluginsdk.PolicyModeHandlingRaw, DefaultMode: &mode}
		if entry != nil {
			if entryMode, ok := entryModes[entry.Token]; ok {
				settings.EntryMode = &entryMode
			}
		}
		return pluginsdk.PolicySettingsSnapshot{Version: pluginsdk.PolicySettingsVersion{Revision: revision, InstanceVersion: instanceVersion}, Settings: settings}
	}
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != pluginsdk.PluginHostCallPath || request.Header.Get(pluginsdk.HeaderPluginHostCredential) != cookie {
			http.Error(writer, "denied", http.StatusForbidden)
			return
		}
		var call pluginsdk.HostRuntimeCall
		if err := json.NewDecoder(request.Body).Decode(&call); err != nil || call.Operation != pluginsdk.HostRuntimePolicyControl {
			http.Error(writer, "invalid call", http.StatusBadRequest)
			return
		}
		decoded, err := pluginsdk.DecodePolicyControlRequest(call.Payload)
		if err != nil {
			http.Error(writer, "invalid policy", http.StatusBadRequest)
			return
		}
		response := pluginsdk.PolicyControlResponse{InstanceID: "ip-instance", Stage: stage, Entry: decoded.Entry, Desired: desired(decoded.Entry)}
		switch decoded.Action {
		case pluginsdk.PolicyControlListEntries:
			response.Entry = nil
			response.Entries = make([]pluginsdk.PolicyEntrySnapshot, 0, len(entries))
			for _, entry := range entries {
				entry := entry
				response.Entries = append(response.Entries, pluginsdk.PolicyEntrySnapshot{Entry: entry, Desired: desired(&entry), Overlay: append(json.RawMessage(nil), overlays[entry.Token]...)})
			}
		case pluginsdk.PolicyControlInspect:
			if decoded.Entry != nil {
				response.Overlay = append(json.RawMessage(nil), overlays[decoded.Entry.Token]...)
			}
		case pluginsdk.PolicyControlReplaceInstance:
			if *decoded.ExpectedRevision != revision || *decoded.ExpectedInstanceVersion != instanceVersion {
				http.Error(writer, "stale", http.StatusConflict)
				return
			}
			mutations = append(mutations, decoded)
			revision, instanceVersion, mode = revision+1, instanceVersion+1, decoded.Mode
			response.OperationID, response.Desired = decoded.OperationID, desired(nil)
		case pluginsdk.PolicyControlReplaceEntry:
			if *decoded.ExpectedRevision != revision || *decoded.ExpectedInstanceVersion != instanceVersion {
				http.Error(writer, "stale", http.StatusConflict)
				return
			}
			mutations = append(mutations, decoded)
			revision, instanceVersion = revision+1, instanceVersion+1
			entryModes[decoded.Entry.Token] = decoded.Mode
			overlays[decoded.Entry.Token] = append(json.RawMessage(nil), decoded.Overlay...)
			response.OperationID, response.Desired, response.Overlay = decoded.OperationID, desired(decoded.Entry), append(json.RawMessage(nil), decoded.Overlay...)
		case pluginsdk.PolicyControlResetEntry:
			if *decoded.ExpectedRevision != revision || *decoded.ExpectedInstanceVersion != instanceVersion {
				http.Error(writer, "stale", http.StatusConflict)
				return
			}
			mutations = append(mutations, decoded)
			revision, instanceVersion = revision+1, instanceVersion+1
			delete(entryModes, decoded.Entry.Token)
			delete(overlays, decoded.Entry.Token)
			response.OperationID, response.Desired = decoded.OperationID, desired(decoded.Entry)
		}
		payload, _ := json.Marshal(response)
		_ = json.NewEncoder(writer).Encode(pluginsdk.HostRuntimeResponse{Payload: payload})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "unix:"+socket)
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", cookiePath)
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	controller, err := ippolicy.NewController(ippolicy.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", Runtime: client})
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{"ui.dynamic", "storage.read", "storage.write", "event.emit", "dataset.manage", "dataset.bind", "dataset.query", "dataset.resolve", "policy.control", "policy.entry-overlays", "policy.read", "policy.trusted-source", "http.inspect", "l4.inspect"}
	features, err := pluginsdk.RequiredRPCFeaturesForExecutionScope(grants, []string{pluginsdk.ExtensionUIRoute, pluginsdk.ExtensionHTTPRequest, pluginsdk.ExtensionL4Accept}, pluginsdk.HostScopeControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: ippolicy.PluginID, PluginVersion: ippolicy.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", Generation: "generation", GrantedScopes: grants, RequiredFeatures: features}); err != nil {
		t.Fatal(err)
	}
	config, _ := ippolicy.EncodeConfiguration(ippolicy.DefaultConfiguration())
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation", Config: config}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation"}); response.Error != nil {
		t.Fatal(response.Error)
	}

	body := []byte(`{"mode":"observe","config":{"schema":"sakullla.ip-policy/v1","default_action":"allow","datasets":[],"province_whitelist":[],"rules":[]}}`)
	configRecorder := httptest.NewRecorder()
	controller.ServeHTTP(configRecorder, uiRequest(http.MethodPost, "/api/config", body))
	if configRecorder.Code != http.StatusOK || len(mutations) != 1 || mutations[0].Action != pluginsdk.PolicyControlReplaceInstance || mutations[0].ExpectedRevision == nil || *mutations[0].ExpectedRevision != 1 || mutations[0].ExpectedInstanceVersion == nil || *mutations[0].ExpectedInstanceVersion != 1 {
		t.Fatalf("status=%d mutations=%+v body=%s", configRecorder.Code, mutations, configRecorder.Body.String())
	}

	stateRecorder := httptest.NewRecorder()
	controller.ServeHTTP(stateRecorder, uiRequest(http.MethodGet, "/api/state", nil))
	var state struct {
		Entries []pluginsdk.PolicyEntrySnapshot `json:"entries"`
	}
	if err := json.Unmarshal(stateRecorder.Body.Bytes(), &state); err != nil || len(state.Entries) != 5 {
		t.Fatalf("listed state=%s err=%v", stateRecorder.Body.String(), err)
	}

	entryRules := `[{"id":"one","action":"deny","selector":{"type":"ip","value":"192.0.2.1"}},{"id":"two","action":"allow","selector":{"type":"cidr","value":"198.51.100.0/24"}}]`
	for _, entry := range entries {
		body := []byte(fmt.Sprintf(`{"entry":{"node_id":%q,"kind":%q,"id":%q,"token":%q},"rules":%s}`, entry.NodeID, entry.Kind, entry.ID, entry.Token, entryRules))
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, uiRequest(http.MethodPost, "/api/entry-rules", body))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s/%s status=%d body=%s", entry.Kind, entry.ID, recorder.Code, recorder.Body.String())
		}
		mutation := mutations[len(mutations)-1]
		if mutation.Action != pluginsdk.PolicyControlReplaceEntry || mutation.Entry == nil || mutation.Entry.Token != entry.Token || len(mutation.Overlay) == 0 {
			t.Fatalf("entry mutation=%+v", mutation)
		}
	}

	preserved := append(json.RawMessage(nil), overlays[entries[0].Token]...)
	modeBody := []byte(fmt.Sprintf(`{"entry":{"node_id":%q,"kind":%q,"id":%q,"token":%q},"mode":"enforce"}`, entries[0].NodeID, entries[0].Kind, entries[0].ID, entries[0].Token))
	modeRecorder := httptest.NewRecorder()
	controller.ServeHTTP(modeRecorder, uiRequest(http.MethodPost, "/api/entry-mode", modeBody))
	if modeRecorder.Code != http.StatusOK || !bytes.Equal(overlays[entries[0].Token], preserved) {
		t.Fatalf("mode status=%d overlay=%s body=%s", modeRecorder.Code, overlays[entries[0].Token], modeRecorder.Body.String())
	}
	resetBody := []byte(fmt.Sprintf(`{"entry":{"node_id":%q,"kind":%q,"id":%q,"token":%q},"reset":true}`, entries[0].NodeID, entries[0].Kind, entries[0].ID, entries[0].Token))
	resetRecorder := httptest.NewRecorder()
	controller.ServeHTTP(resetRecorder, uiRequest(http.MethodPost, "/api/entry-mode", resetBody))
	if resetRecorder.Code != http.StatusOK || len(overlays[entries[0].Token]) != 0 {
		t.Fatalf("reset status=%d overlay=%s body=%s", resetRecorder.Code, overlays[entries[0].Token], resetRecorder.Body.String())
	}
	for _, mutation := range mutations[1:] {
		if mutation.Entry != nil && !strings.HasPrefix(mutation.Entry.Token, "entry-token-") {
			t.Fatalf("non-Host token=%q", mutation.Entry.Token)
		}
	}
}

func uiRequest(method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/integration")
	request.Header.Set("Content-Type", "application/json")
	return request
}
