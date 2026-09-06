package ippolicyintegration

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	var mutation pluginsdk.PolicyControlRequest
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != pluginsdk.PluginHostCallPath || request.Header.Get(pluginsdk.HeaderPluginHostCredential) != cookie {
			http.Error(writer, "denied", http.StatusForbidden)
			return
		}
		var call pluginsdk.HostRuntimeCall
		if err := json.NewDecoder(request.Body).Decode(&call); err != nil || call.Operation != pluginsdk.HostRuntimePolicyControl {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		decoded, err := pluginsdk.DecodePolicyControlRequest(call.Payload)
		if err != nil {
			http.Error(writer, "invalid policy", http.StatusBadRequest)
			return
		}
		mode := pluginsdk.PolicyModeObserve
		version := pluginsdk.PolicySettingsVersion{Revision: 1, InstanceVersion: 1}
		operationID := ""
		if decoded.Action == pluginsdk.PolicyControlReplaceInstance {
			mutation, mode, version, operationID = decoded, decoded.Mode, pluginsdk.PolicySettingsVersion{Revision: 2, InstanceVersion: 2}, decoded.OperationID
		}
		response := pluginsdk.PolicyControlResponse{OperationID: operationID, InstanceID: "ip-instance", Stage: pluginsdk.PolicyStageIdentity{Kind: "ip", PolicyID: "ip-instance"}, Desired: pluginsdk.PolicySettingsSnapshot{Version: version, Settings: pluginsdk.PolicyModeSettings{Handling: pluginsdk.PolicyModeHandlingRaw, DefaultMode: &mode}}}
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
	features := pluginsdk.RequiredRPCFeatures([]string{"ui.dynamic", "storage.read", "storage.write", "event.emit", "http.rule", "dataset.manage", "dataset.bind", "dataset.query", "dataset.resolve", "policy.control"})
	grants := []string{"ui.dynamic", "storage.read", "storage.write", "event.emit", "http.rule", "dataset.manage", "dataset.bind", "dataset.query", "dataset.resolve", "policy.control", "policy.read", "policy.trusted-source", "http.inspect", "l4.inspect"}
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
	request := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(body))
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/integration")
	recorder := httptest.NewRecorder()
	controller.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || mutation.Action != pluginsdk.PolicyControlReplaceInstance || mutation.InstanceID != "ip-instance" || mutation.ExpectedRevision == nil || *mutation.ExpectedRevision != 1 || len(mutation.Config) == 0 {
		t.Fatalf("status=%d mutation=%+v body=%s", recorder.Code, mutation, recorder.Body.String())
	}
}
