package acceleratorsources_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	acceleratorsources "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	endpointConfig := pluginsdk.HTTPBackendProviderEndpointConfig{Version: pluginsdk.HTTPBackendProviderEndpointConfigVersion, Providers: []pluginsdk.HTTPBackendProviderEndpoint{{InstanceID: "instance-one", ProviderID: acceleratorsources.ProviderID, Generation: "generation-one", Endpoint: filepath.Base(providerSocket), Credential: "abcdef0123456789abcdef0123456789"}}}
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

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- acceleratorsources.RunEntrypoint(ctx, nil, os.Stdout) }()
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
	if readyResponse.StatusCode != http.StatusNoContent || readyResponse.Header.Get(pluginsdk.HeaderHTTPBackendProviderID) != acceleratorsources.ProviderID {
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

func TestLifecycleRPCLoopbackMutualTLS(t *testing.T) {
	serverTLS, clientTLS := newMutualTLS(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	controller := newController(t, func() (acceleratorsources.GenerationService, error) { return &fakeService{}, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- acceleratorsources.ServeLifecycleRPCConfig(ctx, acceleratorsources.LifecycleServerConfig{Network: "tcp", Address: address, Cookie: "mtls-cookie", TLSConfig: serverTLS}, controller)
	}()
	connection := dialTCPGRPC(t, address, clientTLS)
	request := handshakeRequest("mtls-generation")
	response, err := (wireClient{connection: connection, cookie: "mtls-cookie"}).handshake(t.Context(), request)
	_ = connection.Close()
	if err != nil || len(response.Features) != 1 || response.Features[0] != pluginsdk.RPCFeatureHTTPBackendProviderV1 {
		t.Fatalf("mTLS handshake = %+v, %v", response, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSDKProviderPreservesOnlyHostProjectedExternalAuthority(t *testing.T) {
	root := shortTempDir(t)
	endpoint := pluginsdk.HTTPBackendProviderEndpoint{InstanceID: "instance-authority", ProviderID: acceleratorsources.ProviderID, Generation: "generation-authority", Endpoint: filepath.Join(root, "authority.sock"), Credential: "0123456789abcdef0123456789abcdef"}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(pluginsdk.HeaderHTTPBackendProviderCredential) != "" || request.Header.Get(pluginsdk.HeaderHTTPBackendProviderGeneration) != "" {
			http.Error(writer, "capability header leaked", http.StatusInternalServerError)
			return
		}
		if values := request.Header.Values("Forwarded"); len(values) != 1 || values[0] != `for=203.0.113.9;proto=https;host=public.example.test` || len(request.Header.Values("X-Forwarded-Proto")) != 1 || len(request.Header.Values("X-Forwarded-Host")) != 1 {
			http.Error(writer, "authority rejected", http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- pluginsdk.ServeHTTPBackendProviderConfig(ctx, pluginsdk.HTTPBackendProviderEndpointConfig{Version: pluginsdk.HTTPBackendProviderEndpointConfigVersion, Providers: []pluginsdk.HTTPBackendProviderEndpoint{endpoint}}, map[string]http.Handler{acceleratorsources.ProviderID: handler})
	}()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", endpoint.Endpoint)
	}}}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://provider.nre.internal/check", nil)
	setProviderHeaders(request, endpoint)
	request.Header.Set("Forwarded", `for=203.0.113.9;proto=https;host=public.example.test`)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "public.example.test")
	response := doEventually(t, client, request)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("canonical authority status = %d", response.StatusCode)
	}
	spoofed := request.Clone(t.Context())
	spoofed.Header = request.Header.Clone()
	spoofed.Header.Add("X-Forwarded-Host", "attacker.example")
	response, err := client.Do(spoofed)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicated authority status = %d", response.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleRPCRejectsWrongCookieAndTCPWithoutMTLS(t *testing.T) {
	controller := newController(t, func() (acceleratorsources.GenerationService, error) { return &fakeService{}, nil })
	root := shortTempDir(t)
	socket := filepath.Join(root, "rpc.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- acceleratorsources.ServeLifecycleRPCConfig(ctx, acceleratorsources.LifecycleServerConfig{Network: "unix", Address: socket, Cookie: "correct-cookie"}, controller)
	}()
	connection := dialUnixGRPC(t, socket)
	defer connection.Close()
	_, err := (wireClient{connection: connection, cookie: "wrong-cookie"}).handshake(t.Context(), handshakeRequest("generation"))
	if err == nil || status.Code(err).String() != "Unauthenticated" {
		t.Fatalf("wrong-cookie error = %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := acceleratorsources.ServeLifecycleRPCConfig(t.Context(), acceleratorsources.LifecycleServerConfig{Network: "tcp", Address: "127.0.0.1:0", Cookie: "cookie"}, controller); err == nil {
		t.Fatal("tcp lifecycle server accepted missing mutual TLS")
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
		connection, err = grpc.NewClient("passthrough:///accelerator-sources", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
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

func dialTCPGRPC(t *testing.T, address string, tlsConfig *tls.Config) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient("passthrough:///accelerator-sources", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		probe, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		_, probeErr := (wireClient{connection: connection, cookie: "wrong"}).handshake(probe, handshakeRequest("probe"))
		cancel()
		if status.Code(probeErr).String() == "Unauthenticated" {
			return connection
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = connection.Close()
	t.Fatal("mTLS lifecycle endpoint did not become ready")
	return nil
}

func newMutualTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nre-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPair := signedPair(t, caCert, caKey, "nre-plugin", true, big.NewInt(2), now)
	clientPair := signedPair(t, caCert, caKey, "nre-host", false, big.NewInt(3), now)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	client := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "nre-plugin", Certificates: []tls.Certificate{clientPair}, RootCAs: roots}
	return server, client
}

func signedPair(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, server bool, serial *big.Int, now time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"nre-plugin"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
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
