package doh

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	CIHandshakeFlag   = pluginsdk.RPCHandshakeProbeFlag
	envPluginEndpoint = "NRE_PLUGIN_ENDPOINT"
	envCookieFile     = "NRE_PLUGIN_COOKIE_FILE"
	envTLSCAFile      = "NRE_PLUGIN_TLS_CA_FILE"
	envTLSCertFile    = "NRE_PLUGIN_TLS_CERT_FILE"
	envTLSKeyFile     = "NRE_PLUGIN_TLS_KEY_FILE"
	cookieMetadataKey = "x-nre-plugin-cookie"
	rpcServiceName    = "nre.plugin.rpc.v1.PluginRuntime"
)

func RunEntrypoint(ctx context.Context, args []string, output io.Writer) error {
	probeIdentity, probe, err := pluginsdk.ResolveRPCHandshakeProbe(args, pluginsdk.RPCPluginDeclaration{PluginID: PluginID, PluginVersion: PluginVersion})
	if err != nil {
		return err
	}
	if probe {
		controller, err := NewController(ControllerConfig{PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact"})
		if err != nil {
			return err
		}
		response, err := controller.Handshake(ctx, pluginsdk.RPCHandshakeRequest{
			ABI: pluginsdk.RPCABIV1, PluginID: probeIdentity.PluginID, PluginVersion: probeIdentity.PluginVersion,
			PackageDigest: "nre-ci-package", ArtifactDigest: "nre-ci-artifact",
			GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: "nre-ci-generation",
			RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
		})
		if err != nil {
			return err
		}
		if response.ABI != pluginsdk.RPCABIV1 || len(response.Features) != 1 || response.Features[0] != pluginsdk.RPCFeatureHTTPBackendProviderV1 {
			return errors.New("canonical RPC handshake mismatch")
		}
		_, err = fmt.Fprintln(output, response.ABI)
		return err
	}
	if len(args) != 0 {
		return errors.New("unexpected DoH arguments")
	}
	controller, err := NewController(ControllerConfig{})
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- ServeLifecycleRPC(runCtx, controller) }()
	go func() {
		errorsCh <- pluginsdk.ServeHTTPBackendProviders(runCtx, map[string]http.Handler{ProviderID: controller})
	}()
	first := <-errorsCh
	cancel()
	second := <-errorsCh
	if first != nil {
		return first
	}
	return second
}

type LifecycleServerConfig struct {
	Network   string
	Address   string
	Cookie    string
	TLSConfig *tls.Config
}

func LoadLifecycleServerConfig() (LifecycleServerConfig, error) {
	network, address, ok := strings.Cut(strings.TrimSpace(os.Getenv(envPluginEndpoint)), ":")
	if !ok {
		return LifecycleServerConfig{}, errors.New("NRE_PLUGIN_ENDPOINT must use unix: or tcp:")
	}
	cookiePath := strings.TrimSpace(os.Getenv(envCookieFile))
	if cookiePath == "" || !filepath.IsAbs(cookiePath) {
		return LifecycleServerConfig{}, errors.New("NRE_PLUGIN_COOKIE_FILE must be absolute")
	}
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return LifecycleServerConfig{}, fmt.Errorf("read lifecycle cookie: %w", err)
	}
	if len(cookie) == 0 || len(cookie) > 4096 || strings.TrimSpace(string(cookie)) == "" {
		return LifecycleServerConfig{}, errors.New("lifecycle cookie is invalid")
	}
	config := LifecycleServerConfig{Network: strings.ToLower(network), Address: address, Cookie: string(cookie)}
	if config.Network == "tcp" {
		config.TLSConfig, err = loadServerTLSConfig()
		if err != nil {
			return LifecycleServerConfig{}, err
		}
	}
	return config, nil
}

func ServeLifecycleRPC(ctx context.Context, controller *Controller) error {
	config, err := LoadLifecycleServerConfig()
	if err != nil {
		return err
	}
	return ServeLifecycleRPCConfig(ctx, config, controller)
}

func ServeLifecycleRPCConfig(ctx context.Context, config LifecycleServerConfig, controller *Controller) error {
	if ctx == nil || controller == nil || strings.TrimSpace(config.Cookie) == "" {
		return errors.New("lifecycle server context, controller, and cookie are required")
	}
	listener, err := listenLifecycle(config)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		if config.Network == "unix" {
			_ = os.Remove(config.Address)
		}
	}()
	options := []grpc.ServerOption{}
	if config.Network == "tcp" {
		options = append(options, grpc.Creds(credentials.NewTLS(config.TLSConfig.Clone())))
	}
	server := grpc.NewServer(options...)
	server.RegisterService(lifecycleServiceDesc(config.Cookie, controller), controller)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-stopped:
		case <-timer.C:
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

func listenLifecycle(config LifecycleServerConfig) (net.Listener, error) {
	if strings.TrimSpace(config.Address) == "" {
		return nil, errors.New("lifecycle endpoint address is required")
	}
	switch config.Network {
	case "unix":
		if !filepath.IsAbs(config.Address) {
			return nil, errors.New("lifecycle unix endpoint must be absolute")
		}
		if stat, err := os.Lstat(config.Address); err == nil {
			if stat.Mode()&os.ModeSocket == 0 {
				return nil, errors.New("lifecycle endpoint exists and is not a socket")
			}
			if err := os.Remove(config.Address); err != nil {
				return nil, fmt.Errorf("remove stale lifecycle socket: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect lifecycle endpoint: %w", err)
		}
		listener, err := net.Listen("unix", config.Address)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(config.Address, 0o600); err != nil {
			_ = listener.Close()
			return nil, err
		}
		return listener, nil
	case "tcp":
		host, _, err := net.SplitHostPort(config.Address)
		if err != nil {
			return nil, fmt.Errorf("parse lifecycle tcp endpoint: %w", err)
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("lifecycle tcp endpoint must be loopback")
		}
		if config.TLSConfig == nil || config.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || config.TLSConfig.ClientCAs == nil || len(config.TLSConfig.Certificates) == 0 {
			return nil, errors.New("lifecycle tcp endpoint requires mutual TLS")
		}
		return net.Listen("tcp", config.Address)
	default:
		return nil, errors.New("lifecycle endpoint must use unix or loopback tcp")
	}
}

func loadServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(os.Getenv(envTLSCertFile)), strings.TrimSpace(os.Getenv(envTLSKeyFile)))
	if err != nil {
		return nil, fmt.Errorf("load lifecycle server certificate: %w", err)
	}
	ca, err := os.ReadFile(strings.TrimSpace(os.Getenv(envTLSCAFile)))
	if err != nil {
		return nil, fmt.Errorf("read lifecycle client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("load lifecycle client CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

func lifecycleServiceDesc(cookie string, controller *Controller) *grpc.ServiceDesc {
	methods := []grpc.MethodDesc{
		{MethodName: "Handshake", Handler: dynamicUnary(cookie, "HandshakeRequest", func(ctx context.Context, request *dynamicpb.Message) (*dynamicpb.Message, error) {
			result, err := controller.Handshake(ctx, decodeHandshake(request))
			if err != nil {
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
			return encodeHandshake(result)
		})},
	}
	for _, name := range []string{"Prepare", "Activate", "Stop"} {
		method := name
		methods = append(methods, grpc.MethodDesc{MethodName: method, Handler: dynamicUnary(cookie, "LifecycleRequest", func(ctx context.Context, request *dynamicpb.Message) (*dynamicpb.Message, error) {
			wire := decodeLifecycleRequest(request)
			var result pluginsdk.LifecycleResponse
			switch method {
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
		info := &grpc.UnaryServerInfo{FullMethod: "/" + rpcServiceName}
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
