package cloudflaredns

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	envPluginEndpoint = "NRE_PLUGIN_ENDPOINT"
	envCookieFile     = "NRE_PLUGIN_COOKIE_FILE"
	cookieMetadataKey = "x-nre-plugin-cookie"
	rpcServiceName    = "nre.plugin.rpc.v1.PluginRuntime"
)

// ServeLifecycleRPC exposes the canonical local lifecycle service. Cloudflare
// data-plane effects remain Host-owned; the guest only participates in the
// supervised generation handshake.
func ServeLifecycleRPC(ctx context.Context, controller *Controller) error {
	endpoint := strings.TrimSpace(os.Getenv(envPluginEndpoint))
	network, address, ok := strings.Cut(endpoint, ":")
	if !ok || network != "unix" || !filepath.IsAbs(address) {
		return errors.New("NRE_PLUGIN_ENDPOINT must use an absolute unix socket")
	}
	cookiePath := strings.TrimSpace(os.Getenv(envCookieFile))
	if cookiePath == "" || !filepath.IsAbs(cookiePath) {
		return errors.New("NRE_PLUGIN_COOKIE_FILE must be absolute")
	}
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return err
	}
	if len(cookie) == 0 || len(cookie) > 4096 || strings.TrimSpace(string(cookie)) == "" {
		return errors.New("lifecycle cookie is invalid")
	}
	if stat, statErr := os.Lstat(address); statErr == nil {
		if stat.Mode()&os.ModeSocket == 0 {
			return errors.New("lifecycle endpoint exists and is not a socket")
		}
		if err := os.Remove(address); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	listener, err := net.Listen("unix", address)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(address)
	}()
	if err := os.Chmod(address, 0o600); err != nil {
		return err
	}
	server := grpc.NewServer()
	server.RegisterService(lifecycleServiceDesc(string(cookie), controller), controller)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			server.Stop()
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func lifecycleServiceDesc(cookie string, controller *Controller) *grpc.ServiceDesc {
	methods := []grpc.MethodDesc{{MethodName: "Handshake", Handler: dynamicUnary(cookie, "HandshakeRequest", func(ctx context.Context, request *dynamicpb.Message) (*dynamicpb.Message, error) {
		result, err := controller.Handshake(ctx, decodeHandshake(request))
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return encodeHandshake(result)
	})}}
	for _, methodName := range []string{"Prepare", "Activate", "Stop"} {
		name := methodName
		methods = append(methods, grpc.MethodDesc{MethodName: name, Handler: dynamicUnary(cookie, "LifecycleRequest", func(ctx context.Context, request *dynamicpb.Message) (*dynamicpb.Message, error) {
			wire := decodeLifecycleRequest(request)
			var result pluginsdk.LifecycleResponse
			switch name {
			case "Prepare":
				result = controller.Prepare(ctx, wire)
			case "Activate":
				result = controller.Activate(ctx, wire)
			default:
				result = controller.Stop(ctx, wire)
			}
			return encodeLifecycle(result)
		})})
	}
	return &grpc.ServiceDesc{ServiceName: rpcServiceName, HandlerType: (*interface{})(nil), Methods: methods}
}

type dynamicHandler func(context.Context, *dynamicpb.Message) (*dynamicpb.Message, error)

func dynamicUnary(cookie, requestName string, call dynamicHandler) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		incoming, _ := metadata.FromIncomingContext(ctx)
		values := incoming.Get(cookieMetadataKey)
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(cookie)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "lifecycle capability rejected")
		}
		descriptor, err := protoschema.Message(protoreflect.FullName("nre.plugin.rpc.v1." + requestName))
		if err != nil {
			return nil, err
		}
		request := dynamicpb.NewMessage(descriptor)
		if err := decode(request); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return call(ctx, request)
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/" + rpcServiceName + "/" + requestName}
		return interceptor(ctx, request, info, func(ctx context.Context, request any) (any, error) {
			return call(ctx, request.(*dynamicpb.Message))
		})
	}
}

func decodeHandshake(message *dynamicpb.Message) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{
		ABI: getString(message, "abi"), PluginID: getString(message, "plugin_id"), PluginVersion: getString(message, "plugin_version"),
		PackageDigest: getString(message, "package_digest"), ArtifactDigest: getString(message, "artifact_digest"),
		GrantedScopes: getStrings(message, "granted_scopes"), Generation: getString(message, "generation"), RequiredFeatures: getStrings(message, "required_features"),
	}
}

func encodeHandshake(result pluginsdk.RPCHandshakeResponse) (*dynamicpb.Message, error) {
	message, err := newRPCMessage("HandshakeResponse")
	if err != nil {
		return nil, err
	}
	setString(message, "abi", result.ABI)
	setStrings(message, "capabilities", result.Capabilities)
	setStrings(message, "features", result.Features)
	return message, nil
}

func decodeLifecycleRequest(message *dynamicpb.Message) pluginsdk.LifecycleRequest {
	return pluginsdk.LifecycleRequest{Generation: getString(message, "generation"), Config: append([]byte(nil), message.Get(field(message, "config")).Bytes()...)}
}

func encodeLifecycle(result pluginsdk.LifecycleResponse) (*dynamicpb.Message, error) {
	message, err := newRPCMessage("LifecycleResponse")
	if err != nil {
		return nil, err
	}
	if result.Success != nil {
		success := message.Mutable(field(message, "success")).Message()
		success.Set(success.Descriptor().Fields().ByName("ready"), protoreflect.ValueOfBool(result.Success.Ready))
		return message, nil
	}
	failure := result.Error
	if failure == nil {
		failure = &pluginsdk.RuntimeError{Code: pluginsdk.ErrorInternal, Message: "invalid lifecycle result"}
	}
	wire := message.Mutable(field(message, "error")).Message()
	wire.Set(wire.Descriptor().Fields().ByName("code"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(failure.Code)))
	wire.Set(wire.Descriptor().Fields().ByName("message"), protoreflect.ValueOfString(failure.Message))
	wire.Set(wire.Descriptor().Fields().ByName("retryable"), protoreflect.ValueOfBool(failure.Retryable))
	return message, nil
}

func newRPCMessage(name string) (*dynamicpb.Message, error) {
	descriptor, err := protoschema.Message(protoreflect.FullName("nre.plugin.rpc.v1." + name))
	if err != nil {
		return nil, err
	}
	return dynamicpb.NewMessage(descriptor), nil
}

func field(message *dynamicpb.Message, name protoreflect.Name) protoreflect.FieldDescriptor {
	return message.Descriptor().Fields().ByName(name)
}
func setString(message *dynamicpb.Message, name protoreflect.Name, value string) {
	message.Set(field(message, name), protoreflect.ValueOfString(value))
}
func setStrings(message *dynamicpb.Message, name protoreflect.Name, values []string) {
	list := message.Mutable(field(message, name)).List()
	for _, value := range values {
		list.Append(protoreflect.ValueOfString(value))
	}
}
func getString(message *dynamicpb.Message, name protoreflect.Name) string {
	return message.Get(field(message, name)).String()
}
func getStrings(message *dynamicpb.Message, name protoreflect.Name) []string {
	list := message.Get(field(message, name)).List()
	result := make([]string, list.Len())
	for index := range result {
		result[index] = list.Get(index).String()
	}
	return result
}
