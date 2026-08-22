package webdav_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	"github.com/sakullla/sakullla-plugins/plugins/webdav"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestProductionEntrypointServesLifecycleAndPrivateProvider(t *testing.T) {
	root := shortTempDir(t)
	rpcSocket := filepath.Join(root, "rpc.sock")
	providerSocket := filepath.Join(root, "http.sock")
	cookie := "0123456789abcdef0123456789abcdef"
	cookiePath := filepath.Join(root, "cookie")
	if err := os.WriteFile(cookiePath, []byte(cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	endpointConfig := pluginsdk.HTTPBackendProviderEndpointConfig{Version: pluginsdk.HTTPBackendProviderEndpointConfigVersion, Providers: []pluginsdk.HTTPBackendProviderEndpoint{{InstanceID: "instance-one", ProviderID: webdav.ProviderID, Generation: "generation-one", Endpoint: filepath.Base(providerSocket), Credential: "abcdef0123456789abcdef0123456789"}}}
	payload, err := json.Marshal(endpointConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "providers.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(root, "empty-path"))
	t.Setenv("NRE_PLUGIN_ENDPOINT", "unix:"+rpcSocket)
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", cookiePath)
	t.Setenv(pluginsdk.EnvHTTPBackendProviderConfigFile, configPath)
	t.Setenv(pluginsdk.EnvHTTPBackendProviderEndpointDirectory, root)
	t.Chdir(root)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- webdav.RunEntrypoint(ctx, nil, os.Stdout) }()
	connection := dialUnixGRPC(t, rpcSocket)
	defer connection.Close()
	client := wireClient{connection: connection, cookie: cookie}
	request := handshakeRequest("generation-one")
	if _, err := client.handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if result, err := client.lifecycle(t.Context(), "Prepare", pluginsdk.LifecycleRequest{Generation: request.Generation, Config: []byte(`{}`)}); err != nil || result.Error != nil {
		t.Fatalf("prepare = %+v, %v", result, err)
	}
	if result, err := client.lifecycle(t.Context(), "Activate", pluginsdk.LifecycleRequest{Generation: request.Generation}); err != nil || result.Error != nil {
		t.Fatalf("activate = %+v, %v", result, err)
	}

	httpClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", providerSocket)
	}}}
	for name, mutate := range map[string]func(*http.Request){
		"credential": func(request *http.Request) {
			request.Header.Set(pluginsdk.HeaderHTTPBackendProviderCredential, "00000000000000000000000000000000")
		},
		"generation": func(request *http.Request) {
			request.Header.Set(pluginsdk.HeaderHTTPBackendProviderGeneration, "wrong-generation")
		},
	} {
		t.Run("reject-"+name, func(t *testing.T) {
			request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://provider.nre.internal/", nil)
			setProviderHeaders(request, endpointConfig.Providers[0])
			mutate(request)
			response := doEventually(t, httpClient, request)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d", response.StatusCode)
			}
		})
	}
	readyRequest, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://provider.nre.internal"+pluginsdk.HTTPBackendProviderReadyPath, nil)
	setProviderHeaders(readyRequest, endpointConfig.Providers[0])
	readyRequest.Header.Set(pluginsdk.HeaderHTTPBackendProviderProbe, "ready-v1")
	readyResponse := doEventually(t, httpClient, readyRequest)
	_ = readyResponse.Body.Close()
	if readyResponse.StatusCode != http.StatusNoContent || readyResponse.Header.Get(pluginsdk.HeaderHTTPBackendProviderID) != webdav.ProviderID {
		t.Fatalf("provider readiness = %d/%q", readyResponse.StatusCode, readyResponse.Header.Get(pluginsdk.HeaderHTTPBackendProviderID))
	}
	providerRequest, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://provider.nre.internal/", nil)
	setProviderHeaders(providerRequest, endpointConfig.Providers[0])
	response := doEventually(t, httpClient, providerRequest)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("provider status = %d", response.StatusCode)
	}
	if result, err := client.lifecycle(t.Context(), "Stop", pluginsdk.LifecycleRequest{Generation: request.Generation}); err != nil || result.Error != nil {
		t.Fatalf("stop = %+v, %v", result, err)
	}
	stoppedRequest, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://provider.nre.internal/", nil)
	setProviderHeaders(stoppedRequest, endpointConfig.Providers[0])
	stopped := doEventually(t, httpClient, stoppedRequest)
	body, _ := readLimited(stopped)
	if stopped.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stopped provider status = %d body=%q", stopped.StatusCode, body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("production entrypoint did not stop")
	}
}

func TestEntrypointHandshakeProbe(t *testing.T) {
	var output bytes.Buffer
	if err := webdav.RunEntrypoint(context.Background(), []string{webdav.CIHandshakeFlag}, &output); err != nil || strings.TrimSpace(output.String()) != pluginsdk.RPCABIV1 {
		t.Fatalf("entrypoint=%q err=%v", output.String(), err)
	}
}

type wireClient struct {
	connection grpc.ClientConnInterface
	cookie     string
}

func (client wireClient) handshake(ctx context.Context, request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	wire := newWireMessage(tester{ctx}, "HandshakeRequest")
	setWireString(wire, "abi", request.ABI)
	setWireString(wire, "plugin_id", request.PluginID)
	setWireString(wire, "plugin_version", request.PluginVersion)
	setWireString(wire, "package_digest", request.PackageDigest)
	setWireString(wire, "artifact_digest", request.ArtifactDigest)
	setWireString(wire, "generation", request.Generation)
	setWireStrings(wire, "granted_scopes", request.GrantedScopes)
	setWireStrings(wire, "required_features", request.RequiredFeatures)
	response := newWireMessage(tester{ctx}, "HandshakeResponse")
	err := client.connection.Invoke(metadata.AppendToOutgoingContext(ctx, "x-nre-plugin-cookie", client.cookie), "/nre.plugin.rpc.v1.PluginRuntime/Handshake", wire, response)
	return pluginsdk.RPCHandshakeResponse{ABI: wireString(response, "abi"), Capabilities: wireStrings(response, "capabilities"), Features: wireStrings(response, "features")}, err
}

func (client wireClient) lifecycle(ctx context.Context, method string, request pluginsdk.LifecycleRequest) (pluginsdk.LifecycleResponse, error) {
	wire := newWireMessage(tester{ctx}, "LifecycleRequest")
	setWireString(wire, "generation", request.Generation)
	wire.Set(wireField(wire, "config"), protoreflect.ValueOfBytes(request.Config))
	response := newWireMessage(tester{ctx}, "LifecycleResponse")
	err := client.connection.Invoke(metadata.AppendToOutgoingContext(ctx, "x-nre-plugin-cookie", client.cookie), "/nre.plugin.rpc.v1.PluginRuntime/"+method, wire, response)
	if err != nil {
		return pluginsdk.LifecycleResponse{}, err
	}
	if successField := wireField(response, "success"); response.Has(successField) {
		return pluginsdk.LifecycleResponse{Success: &pluginsdk.LifecycleSuccess{Ready: response.Get(successField).Message().Get(successField.Message().Fields().ByName("ready")).Bool()}}, nil
	}
	errorField := wireField(response, "error")
	failure := response.Get(errorField).Message()
	return pluginsdk.LifecycleResponse{Error: &pluginsdk.RuntimeError{Code: pluginsdk.ErrorCode(failure.Get(failure.Descriptor().Fields().ByName("code")).Enum()), Message: failure.Get(failure.Descriptor().Fields().ByName("message")).String(), Retryable: failure.Get(failure.Descriptor().Fields().ByName("retryable")).Bool()}}, nil
}

type tester struct{ context.Context }

func (tester) Helper()                 {}
func (value tester) Fatal(args ...any) { panic(args) }

func newWireMessage(t interface {
	Helper()
	Fatal(...any)
}, name string) *dynamicpb.Message {
	t.Helper()
	descriptor, err := protoschema.Message(protoreflect.FullName("nre.plugin.rpc.v1." + name))
	if err != nil {
		t.Fatal(err)
	}
	return dynamicpb.NewMessage(descriptor)
}
func wireField(message *dynamicpb.Message, name protoreflect.Name) protoreflect.FieldDescriptor {
	return message.Descriptor().Fields().ByName(name)
}
func setWireString(message *dynamicpb.Message, name protoreflect.Name, value string) {
	message.Set(wireField(message, name), protoreflect.ValueOfString(value))
}
func setWireStrings(message *dynamicpb.Message, name protoreflect.Name, values []string) {
	list := message.Mutable(wireField(message, name)).List()
	for _, value := range values {
		list.Append(protoreflect.ValueOfString(value))
	}
}
func wireString(message *dynamicpb.Message, name protoreflect.Name) string {
	return message.Get(wireField(message, name)).String()
}
func wireStrings(message *dynamicpb.Message, name protoreflect.Name) []string {
	list := message.Get(wireField(message, name)).List()
	result := make([]string, list.Len())
	for index := range result {
		result[index] = list.Get(index).String()
	}
	return result
}

func dialUnixGRPC(t *testing.T, socket string) *grpc.ClientConn {
	t.Helper()
	var connection *grpc.ClientConn
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		connection, err = grpc.NewClient("passthrough:///webdav", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
		if err == nil {
			probe, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			connection.Connect()
			if _, probeErr := (wireClient{connection: connection, cookie: "probe"}).handshake(probe, handshakeRequest("probe")); status.Code(probeErr).String() == "Unauthenticated" {
				return connection
			}
			_ = connection.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dial lifecycle socket: %v", err)
	return nil
}

func doEventually(t *testing.T, client *http.Client, request *http.Request) *http.Response {
	t.Helper()
	var response *http.Response
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		clone := request.Clone(request.Context())
		clone.Header = request.Header.Clone()
		response, err = client.Do(clone)
		if err == nil {
			return response
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("provider request: %v", err)
	return nil
}

func setProviderHeaders(request *http.Request, endpoint pluginsdk.HTTPBackendProviderEndpoint) {
	request.Header.Set(pluginsdk.HeaderHTTPBackendProviderCredential, endpoint.Credential)
	request.Header.Set(pluginsdk.HeaderHTTPBackendProviderInstance, endpoint.InstanceID)
	request.Header.Set(pluginsdk.HeaderHTTPBackendProviderID, endpoint.ProviderID)
	request.Header.Set(pluginsdk.HeaderHTTPBackendProviderGeneration, endpoint.Generation)
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(os.TempDir(), "nre-t3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func readLimited(response *http.Response) (string, error) {
	defer response.Body.Close()
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(response.Body)
	return buffer.String(), err
}
