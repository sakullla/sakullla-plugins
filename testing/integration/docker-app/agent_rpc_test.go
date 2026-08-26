package dockerapp_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestAgentExecutionFacePreparesWithoutServingUI(t *testing.T) {
	root, err := os.MkdirTemp(os.TempDir(), "nre-da-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	rpcSocket := filepath.Join(root, "rpc.sock")
	uiSocket := filepath.Join(root, "ui.sock")
	cookie := "0123456789abcdef0123456789abcdef"
	cookiePath := filepath.Join(root, "cookie")
	if err := os.WriteFile(cookiePath, []byte(cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NRE_PLUGIN_ENDPOINT", "unix:"+rpcSocket)
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", cookiePath)
	t.Setenv(pluginsdk.EnvPluginUIEndpoint, "unix:"+uiSocket)
	t.Setenv("NRE_PLUGIN_DOCKER_PROXY_ENDPOINT", "unix:"+filepath.Join(root, "docker-proxy.sock"))
	t.Setenv("NRE_PLUGIN_DOCKER_CLI", filepath.Join(root, "docker"))
	t.Setenv("NRE_APP_WORKDIR", filepath.Join(root, "apps"))
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dockerapp.RunEntrypoint(ctx, nil, os.Stdout) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("agent execution face entrypoint did not stop")
		}
	})

	connection := dialDockerAgentRPC(t, rpcSocket, cookie)
	defer connection.Close()
	client := dockerWireClient{connection: connection, cookie: cookie}
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: dockerapp.PluginID, PluginVersion: dockerapp.PluginVersion,
		PackageDigest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		GrantedScopes: []string{
			"event.emit", "http.outbound", "http.rule", "service.revocable-resource-handle",
			"storage.read", "storage.write", "ui.dynamic",
		},
		Generation: "generation-463-32417e6a4a9bc886", RequiredFeatures: []string{pluginsdk.RPCFeatureDurableActionsV1},
	}
	if _, err := client.handshake(t.Context(), request); err != nil {
		t.Fatalf("agent execution face handshake: %v", err)
	}
	config := []byte(`{"apps":[],"resource_group_ref":"resource-group/docker-app"}`)
	if result, err := client.lifecycle(t.Context(), "Prepare", pluginsdk.LifecycleRequest{Generation: request.Generation, Config: config}); err != nil || result.Error != nil {
		t.Fatalf("agent execution face prepare = %+v, %v", result, err)
	}
	if result, err := client.lifecycle(t.Context(), "Activate", pluginsdk.LifecycleRequest{Generation: request.Generation}); err != nil || result.Error != nil {
		t.Fatalf("agent execution face activate = %+v, %v", result, err)
	}
	if _, err := os.Lstat(uiSocket); !os.IsNotExist(err) {
		t.Fatalf("agent execution face listened on UI socket: err=%v", err)
	}
}

type dockerWireClient struct {
	connection grpc.ClientConnInterface
	cookie     string
}

func (client dockerWireClient) handshake(ctx context.Context, request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	wire := newDockerWireMessage("HandshakeRequest")
	setDockerWireString(wire, "abi", request.ABI)
	setDockerWireString(wire, "plugin_id", request.PluginID)
	setDockerWireString(wire, "plugin_version", request.PluginVersion)
	setDockerWireString(wire, "package_digest", request.PackageDigest)
	setDockerWireString(wire, "artifact_digest", request.ArtifactDigest)
	setDockerWireString(wire, "generation", request.Generation)
	setDockerWireStrings(wire, "granted_scopes", request.GrantedScopes)
	setDockerWireStrings(wire, "required_features", request.RequiredFeatures)
	response := newDockerWireMessage("HandshakeResponse")
	err := client.connection.Invoke(metadata.AppendToOutgoingContext(ctx, "x-nre-plugin-cookie", client.cookie), "/nre.plugin.rpc.v1.PluginRuntime/Handshake", wire, response)
	return pluginsdk.RPCHandshakeResponse{ABI: dockerWireString(response, "abi"), Capabilities: dockerWireStrings(response, "capabilities"), Features: dockerWireStrings(response, "features")}, err
}

func (client dockerWireClient) lifecycle(ctx context.Context, method string, request pluginsdk.LifecycleRequest) (pluginsdk.LifecycleResponse, error) {
	wire := newDockerWireMessage("LifecycleRequest")
	setDockerWireString(wire, "generation", request.Generation)
	wire.Set(dockerWireField(wire, "config"), protoreflect.ValueOfBytes(request.Config))
	response := newDockerWireMessage("LifecycleResponse")
	err := client.connection.Invoke(metadata.AppendToOutgoingContext(ctx, "x-nre-plugin-cookie", client.cookie), "/nre.plugin.rpc.v1.PluginRuntime/"+method, wire, response)
	if err != nil {
		return pluginsdk.LifecycleResponse{}, err
	}
	if successField := dockerWireField(response, "success"); response.Has(successField) {
		return pluginsdk.LifecycleResponse{Success: &pluginsdk.LifecycleSuccess{Ready: response.Get(successField).Message().Get(successField.Message().Fields().ByName("ready")).Bool()}}, nil
	}
	errorField := dockerWireField(response, "error")
	failure := response.Get(errorField).Message()
	return pluginsdk.LifecycleResponse{Error: &pluginsdk.RuntimeError{Code: pluginsdk.ErrorCode(failure.Get(failure.Descriptor().Fields().ByName("code")).Enum()), Message: failure.Get(failure.Descriptor().Fields().ByName("message")).String(), Retryable: failure.Get(failure.Descriptor().Fields().ByName("retryable")).Bool()}}, nil
}

func newDockerWireMessage(name string) *dynamicpb.Message {
	descriptor, err := protoschema.Message(protoreflect.FullName("nre.plugin.rpc.v1." + name))
	if err != nil {
		panic("rpc descriptor " + name + ": " + err.Error())
	}
	return dynamicpb.NewMessage(descriptor)
}

func dockerWireField(message *dynamicpb.Message, name protoreflect.Name) protoreflect.FieldDescriptor {
	return message.Descriptor().Fields().ByName(name)
}

func setDockerWireString(message *dynamicpb.Message, name protoreflect.Name, value string) {
	message.Set(dockerWireField(message, name), protoreflect.ValueOfString(value))
}

func setDockerWireStrings(message *dynamicpb.Message, name protoreflect.Name, values []string) {
	list := message.Mutable(dockerWireField(message, name)).List()
	for _, value := range values {
		list.Append(protoreflect.ValueOfString(value))
	}
}

func dockerWireString(message *dynamicpb.Message, name protoreflect.Name) string {
	return message.Get(dockerWireField(message, name)).String()
}

func dockerWireStrings(message *dynamicpb.Message, name protoreflect.Name) []string {
	list := message.Get(dockerWireField(message, name)).List()
	result := make([]string, list.Len())
	for index := range result {
		result[index] = list.Get(index).String()
	}
	return result
}

func dialDockerAgentRPC(t *testing.T, socket, cookie string) *grpc.ClientConn {
	t.Helper()
	var connection *grpc.ClientConn
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		connection, err = grpc.NewClient("passthrough:///docker-app", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
		if err == nil {
			probe, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			connection.Connect()
			_, probeErr := (dockerWireClient{connection: connection, cookie: "probe"}).handshake(probe, pluginsdk.RPCHandshakeRequest{
				ABI: pluginsdk.RPCABIV1, PluginID: dockerapp.PluginID, PluginVersion: dockerapp.PluginVersion,
				PackageDigest: "package", ArtifactDigest: "artifact", Generation: "probe",
			})
			cancel()
			if status.Code(probeErr).String() == "Unauthenticated" {
				return connection
			}
			_ = connection.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dial docker-app agent RPC socket: %v", err)
	return nil
}
