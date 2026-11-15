package shadowsocksserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestDefaultPaddingAndShare(t *testing.T) {
	if defaultAnyTLSPaddingScheme != "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000" {
		t.Fatalf("default scheme = %q", defaultAnyTLSPaddingScheme)
	}
	if strings.HasSuffix(defaultAnyTLSPaddingScheme, "\n") {
		t.Fatal("default scheme must not add a trailing newline")
	}
	for _, raw := range []string{"", "stop=9\n0=1-1\n1=c", "stop=1\n0=30-30,c", "stop=1\n0=0-1", "nope", "stop=1\n0=1-5000"} {
		if _, err := canonicalPaddingScheme(raw); raw != "" && err == nil {
			t.Fatalf("accepted illegal scheme %q", raw)
		}
	}
	if got, err := canonicalPaddingScheme("  " + defaultAnyTLSPaddingScheme + "\n"); err != nil || got != defaultAnyTLSPaddingScheme {
		t.Fatalf("canonical default = %q %v", got, err)
	}
	share, err := BuildAnyTLSShare(AnyTLSShareAccount{Password: "a b/c", Host: "2001:db8::1", Port: 8443, SNI: "cert.example", Name: "手机"})
	if err != nil {
		t.Fatal(err)
	}
	want := "anytls://a%20b%2Fc@[2001:db8::1]:8443/?sni=cert.example#%E6%89%8B%E6%9C%BA"
	if share.URI != want || share.QR.Content != share.URI || len(share.QR.PNG) == 0 {
		t.Fatalf("share=%q qr=%q", share.URI, share.QR.Content)
	}
	if strings.Contains(share.URI, "insecure=") || strings.Contains(strings.ToLower(share.URI), "reality") {
		t.Fatalf("share leaked transport flags: %s", share.URI)
	}
	endpoint := ProjectShareEndpoint(ListenBinding{Port: 8443, TCP: true, UDP: true}, NodeAddresses{})
	if endpoint.Reason != MissingShareHost || endpoint.Available {
		t.Fatalf("missing host = %+v", endpoint)
	}
}

func TestAnyTLSUpstreamSNIRules(t *testing.T) {
	domain := Upstream{ID: "edge", Host: "proxy.example", Port: 443, Protocol: ProtocolAnyTLS, SecretRef: "secret/edge", SecretVersion: "v1", Enabled: true, TCP: true, UDP: true}
	if err := normalizeUpstream(&domain); err != nil || domain.SNI != "proxy.example" || domain.PaddingScheme != defaultAnyTLSPaddingScheme || domain.Method != "" {
		t.Fatalf("domain upstream = %+v %v", domain, err)
	}
	ip := Upstream{ID: "edge", Host: "203.0.113.10", Port: 443, Protocol: ProtocolAnyTLS, SecretRef: "secret/edge", SecretVersion: "v1", Enabled: true, TCP: true, UDP: true}
	if err := normalizeUpstream(&ip); err == nil {
		t.Fatal("ip without sni was saved")
	}
	ip.SNI = "cert.example"
	if err := normalizeUpstream(&ip); err != nil || ip.SNI != "cert.example" {
		t.Fatalf("ip with sni = %+v %v", ip, err)
	}
	if !isUoTv2Target("sp.v2.udp-over-tcp.arpa") || isUoTv2Target("sp.udp-over-tcp.arpa") || isUoTv2Target("not-sp.v2.udp-over-tcp.arpa.example") {
		t.Fatal("uot magic comparison changed")
	}
}

type anytlsRecordingDialer struct {
	mu    sync.Mutex
	calls []string
}

func (d *anytlsRecordingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil, ErrDenied
}

func (d *anytlsRecordingDialer) dial(network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+address)
	d.mu.Unlock()
	left, right := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, right)
		_ = right.Close()
	}()
	return left, nil
}

func (d *anytlsRecordingDialer) DialContextRecord(_ context.Context, network, address string) (net.Conn, error) {
	return d.dial(network, address)
}

type staticSecrets map[string]string

func (s staticSecrets) Verify(context.Context, string, string, []byte) error { return nil }

func (s staticSecrets) Resolve(_ context.Context, ref, version string) ([]byte, error) {
	value, ok := s[ref+"\x00"+version]
	if !ok {
		return nil, ErrDenied
	}
	return []byte(value), nil
}

func testAnyTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "anytls.example"},
		DNSNames:     []string{"anytls.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func applyAnyTLS(t *testing.T, exec *listenExecutor, port int, users []ListenApplyUser) {
	t.Helper()
	payload, err := json.Marshal(listenApplyRequest{AgentID: "agent-1", Routing: RoutingConfiguration{DefaultAction: RouteDirect}, Listens: []ListenApplyItem{{
		ID: "listen-any", Port: port, Protocol: ProtocolAnyTLS, CertificateID: 7, CertificateDomain: "anytls.example",
		PaddingScheme: defaultAnyTLSPaddingScheme, Users: users,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = exec.apply(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSListenIsTCPOnlyAndFailClosed(t *testing.T) {
	cert, pool := testAnyTLSCertificate(t)
	port := freePort(t)
	dialer := &anytlsRecordingDialer{}
	exec := newListenExecutor(netListenBinder{})
	exec.bindHost = "127.0.0.1"
	exec.secrets = staticSecrets{"secret/alice\x00v1": "correct-password", "secret/bob\x00v1": "disabled-password"}
	var failTLS atomic.Bool
	exec.tlsTerminate = func(_ context.Context, id int, conn net.Conn) (net.Conn, error) {
		if id != 7 || failTLS.Load() {
			return nil, ErrTypedHandlesUnavailable
		}
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	}
	t.Cleanup(exec.stopAll)
	applyAnyTLS(t, exec, port, []ListenApplyUser{
		{ID: "alice", Enabled: true, SecretRef: "secret/alice", SecretVersion: "v1"},
		{ID: "bob", Enabled: false, SecretRef: "secret/bob", SecretVersion: "v1"},
	})
	exec.mu.Lock()
	bound := exec.bound["listen-any"]
	bound.dialer = dialerDial{dialer}
	status := exec.viewsLocked()
	exec.mu.Unlock()
	if len(status) != 1 || !status[0].TCP || status[0].UDP {
		t.Fatalf("listen status = %+v", status)
	}
	packet, err := exec.binder.ListenPacket("udp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatal(err)
	}
	_ = packet.Close()

	reject := dialAnyTLS(t, pool, port, "disabled-password", "example.com:80", nil)
	if reject == nil {
		t.Fatal("disabled user authenticated")
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("auth failure dialed %+v", calls)
	}

	failTLS.Store(true)
	if err := dialAnyTLS(t, pool, port, "correct-password", "example.com:80", nil); err == nil {
		t.Fatal("tls failure accepted")
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("tls failure dialed %+v", calls)
	}
}

func TestAnyTLSAcceptTerminatesWithoutCertificateList(t *testing.T) {
	cert, pool := testAnyTLSCertificate(t)
	port := freePort(t)
	fake := &managedRuntimeFake{listErr: errors.New("unsupported")}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	dialer := &anytlsRecordingDialer{}
	exec := newListenExecutor(netListenBinder{})
	exec.bindHost = "127.0.0.1"
	exec.secrets = staticSecrets{"secret/alice\x00v1": "correct-password"}
	var terminated atomic.Int32
	exec.tlsTerminate = func(_ context.Context, id int, conn net.Conn) (net.Conn, error) {
		if id != 7 {
			return nil, ErrTypedHandlesUnavailable
		}
		terminated.Add(1)
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	}
	t.Cleanup(exec.stopAll)
	// Prepare the native test listener before attaching the managed certificate
	// API. Publish only after all dependencies are configured.
	routes, err := prepareRouteSnapshot(t.Context(), RoutingConfiguration{DefaultAction: RouteDirect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := exec.prepareAnyTLSLocked(t.Context(), "agent-1", ListenApplyItem{
		ID: "listen-any", Port: port, Protocol: ProtocolAnyTLS, CertificateID: 7, CertificateDomain: "anytls.example",
		PaddingScheme: defaultAnyTLSPaddingScheme,
		Users:         []ListenApplyUser{{ID: "alice", Enabled: true, SecretRef: "secret/alice", SecretVersion: "v1"}},
	}, routes)
	if err != nil {
		t.Fatal(err)
	}
	exec.managed = runtime
	prepared.bound.dialer = dialerDial{dialer}
	exec.commitPrepared(prepared)

	if err := dialAnyTLS(t, pool, port, "correct-password", "example.com:80", nil); err != nil && !isTimeout(err) {
		t.Fatal(err)
	}
	fake.mu.Lock()
	listed := fake.listCalls
	fake.mu.Unlock()
	if terminated.Load() != 1 || listed != 0 {
		t.Fatalf("terminated=%d listCalls=%d", terminated.Load(), listed)
	}
	if calls := dialer.snapshot(); len(calls) == 0 {
		t.Fatal("authenticated connection did not reach decide")
	}
}

type dialerDial struct{ *anytlsRecordingDialer }

func (d dialerDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.DialContextRecord(ctx, network, address)
}

func (d *anytlsRecordingDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func dialAnyTLS(t *testing.T, pool *x509.CertPool, port int, password, target string, after func(net.Conn) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		return err
	}
	defer raw.Close()
	tlsConn, err := handshakeAnyTLSClient(ctx, raw, "anytls.example", pool)
	if err != nil {
		return err
	}
	defer tlsConn.Close()
	session, err := startClientAnyTLSSession(tlsConn, []byte(password), defaultAnyTLSPaddingScheme, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	stream, err := session.openStream()
	if err != nil {
		return err
	}
	address, err := encodeSocksAddr(target)
	if err != nil {
		return err
	}
	if _, err = stream.Write(address); err != nil {
		return err
	}
	if after != nil {
		return after(stream)
	}
	_ = stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = stream.Read(buf)
	if err == nil {
		return nil
	}
	return err
}

func itoa(value int) string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.ReplaceAll(jsonNumber(value), " ", ""), "\n", ""), "")
}

func jsonNumber(value int) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestAnyTLSRoutesTCPAndUoT(t *testing.T) {
	cert, pool := testAnyTLSCertificate(t)
	port := freePort(t)
	dialer := &anytlsRecordingDialer{}
	exec := newListenExecutor(netListenBinder{})
	exec.bindHost = "127.0.0.1"
	exec.secrets = staticSecrets{"secret/alice\x00v1": "correct-password"}
	exec.tlsTerminate = func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) {
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	}
	t.Cleanup(exec.stopAll)
	applyAnyTLS(t, exec, port, []ListenApplyUser{{ID: "alice", Enabled: true, SecretRef: "secret/alice", SecretVersion: "v1"}})
	exec.mu.Lock()
	exec.bound["listen-any"].dialer = dialerDial{dialer}
	exec.mu.Unlock()

	if err := dialAnyTLS(t, pool, port, "correct-password", "example.com:80", nil); err != nil && !isTimeout(err) {
		t.Fatal(err)
	}
	if err := dialAnyTLS(t, pool, port, "correct-password", net.JoinHostPort(uotMagicLegacy, "443"), nil); err != nil && !isTimeout(err) {
		t.Fatal(err)
	}
	if err := dialAnyTLS(t, pool, port, "correct-password", net.JoinHostPort(uotMagicV2, "443"), func(stream net.Conn) error {
		if err := writeUoTRequest(stream, true, "203.0.113.8:53"); err != nil {
			return err
		}
		_ = stream.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := stream.Read(buf)
		if err == nil || isTimeout(err) {
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	calls := dialer.snapshot()
	joined := strings.Join(calls, ",")
	if !strings.Contains(joined, "tcp example.com:80") || !strings.Contains(joined, "tcp "+net.JoinHostPort(uotMagicLegacy, "443")) || !strings.Contains(joined, "udp 203.0.113.8:53") {
		t.Fatalf("dials = %+v", calls)
	}
	if strings.Contains(joined, "udp "+uotMagicV2) || strings.Contains(joined, "tcp "+uotMagicV2) {
		t.Fatalf("magic address was dialed: %+v", calls)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	network, ok := err.(net.Error)
	return ok && network.Timeout() || strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline")
}

func TestAnyTLSPaddingUpdateAppliesToNextSession(t *testing.T) {
	client, server := net.Pipe()
	updated := make(chan string, 1)
	alternate := "stop=1\n0=30-30"
	go func() {
		defer server.Close()
		if _, err := readAnyTLSClientHello(server, []anytlsIdentity{{id: "alice", hash: anytlsPasswordHash([]byte("correct-password"))}}); err != nil {
			return
		}
		var session *anytlsSession
		session = newServerAnyTLSSession(server, defaultAnyTLSPaddingScheme, func(stream *anytlsStream) {
			_, _ = readSocksAddr(stream)
			_ = session.handshakeSuccess(stream)
		})
		session.recvLoop()
	}()
	session, err := startClientAnyTLSSession(client, []byte("correct-password"), alternate, func(scheme string) {
		updated <- scheme
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.openStream()
	if err != nil {
		t.Fatal(err)
	}
	address, err := encodeSocksAddr("example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write(address); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-updated:
		if got != defaultAnyTLSPaddingScheme {
			t.Fatalf("updated scheme = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not send cmdUpdatePaddingScheme")
	}
	exec := newListenExecutor(netListenBinder{})
	exec.rememberUpstreamPadding("edge", defaultAnyTLSPaddingScheme)
	if exec.paddingForUpstream(Upstream{ID: "edge", PaddingScheme: alternate}) != defaultAnyTLSPaddingScheme {
		t.Fatal("next session did not use the remote padding scheme")
	}
}

func TestAnyTLSProbeStaysReadOnly(t *testing.T) {
	cert, pool := testAnyTLSCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 64)
		_, _ = io.ReadFull(conn, buffer)
		_, _ = io.Copy(io.Discard, conn)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	exec := newListenExecutor(netListenBinder{})
	exec.clientRoots = pool
	exec.secrets = staticSecrets{"secret/edge\x00v1": "probe-password"}
	upstream := Upstream{ID: "edge", Host: "127.0.0.1", Port: port, Protocol: ProtocolAnyTLS, SNI: "anytls.example", PaddingScheme: defaultAnyTLSPaddingScheme, SecretRef: "secret/edge", SecretVersion: "v1", Enabled: true, TCP: true, UDP: true}
	result := upstreamTestResult{UpstreamID: upstream.ID}
	exec.probeUpstream(context.Background(), upstream, &result)
	raw, _ := json.Marshal(result)
	if !result.Reachable || strings.Contains(string(raw), "probe-password") || !upstream.Enabled {
		t.Fatalf("probe = %s enabled=%v", raw, upstream.Enabled)
	}
}

func TestAnyTLSCreateRequiresCertificateAndKeepsShadowsocks(t *testing.T) {
	fake := &managedRuntimeFake{certificates: []pluginsdk.PublicCertificateProjection{{ID: 7, Domain: "cert.example", Enabled: true, MaterialAvailable: true}}}
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "share.example"}}
	state := &uiMemoryListenState{}
	managed := newHostCapabilityRuntime(fake)
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a",
		ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: state,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(),
		Generation: "generation-a", RequiredFeatures: supportedFeatures(),
	}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "generation-a"})
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	missing := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","protocol":"anytls","name":"alice"}`)
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), ErrPublicCertificate.Error()) {
		t.Fatalf("missing certificate = %d %s", missing.Code, missing.Body.String())
	}
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","protocol":"anytls","certificate_id":7,"name":"alice"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create = %d %s", created.Code, created.Body.String())
	}
	listen := decodeListenAPI(t, created).Listen
	if listen == nil || listen.Protocol != ProtocolAnyTLS || listen.Method != "" || listen.Family != AccountFamilyAnyTLS || listen.PaddingScheme != defaultAnyTLSPaddingScheme || listen.CertificateDomain != "cert.example" {
		t.Fatalf("listen = %+v", listen)
	}
	if len(listen.Users) != 1 || !strings.HasPrefix(listen.Users[0].URI, "anytls://") || listen.Users[0].QRContent != listen.Users[0].URI || !strings.Contains(listen.Users[0].URI, "sni=cert.example") || !strings.HasSuffix(listen.Users[0].URI, "#alice") {
		t.Fatalf("share = %+v", listen.Users)
	}
	host.mu.Lock()
	applied := append([]listenApplyRequest(nil), host.apply...)
	host.mu.Unlock()
	if len(applied) == 0 || len(applied[0].Listens) != 1 || applied[0].Listens[0].Protocol != ProtocolAnyTLS || applied[0].Listens[0].Method != "" {
		t.Fatalf("apply = %+v", applied)
	}
	shadow := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm","port":9001,"name":"bob"}`)
	if shadow.Code != http.StatusOK {
		t.Fatalf("shadowsocks = %d %s", shadow.Code, shadow.Body.String())
	}
	ss := decodeListenAPI(t, shadow).Listen
	if ss == nil || ss.Protocol != "" || ss.Method != "aes-256-gcm" || ss.PaddingScheme != "" || !strings.HasPrefix(ss.Users[0].URI, "ss://") {
		t.Fatalf("shadowsocks listen = %+v user=%+v", ss, ss.Users)
	}
}

func TestAnyTLSUpstreamFailureDoesNotChangeEnabled(t *testing.T) {
	current := RoutingConfiguration{DefaultAction: RouteUpstream, DefaultUpstreamID: "edge", Upstreams: []Upstream{{
		ID: "edge", Host: "203.0.113.10", Port: 443, Protocol: ProtocolAnyTLS, SNI: "cert.example", PaddingScheme: defaultAnyTLSPaddingScheme,
		SecretRef: "secret/edge", SecretVersion: "v1", Enabled: true, TCP: true, UDP: false,
	}}}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}
	decision, err := (&routeSnapshot{configuration: current}).decide(context.Background(), "udp", "203.0.113.8:53")
	if err == nil || decision.Action == RouteDirect {
		t.Fatalf("udp fell back to direct: %+v %v", decision, err)
	}
	if !current.Upstreams[0].Enabled {
		t.Fatal("failure changed enabled")
	}
}

// udpUpstreamDialer sends every UDP dial to one local Shadowsocks peer and
// leaves that association open after the first datagram.
type udpUpstreamDialer struct{ address string }

func (d udpUpstreamDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "udp" {
		return nil, ErrDenied
	}
	return (&net.Dialer{}).DialContext(ctx, "udp", d.address)
}

func TestAnyTLSUoTShadowsocksUpstreamWritesReplyOnSameStream(t *testing.T) {
	cert, pool := testAnyTLSCertificate(t)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	engine, err := NewProtocolEngine("aes-128-gcm", []byte("upstream-password"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer engine.Destroy()
		buffer := make([]byte, 65535)
		for {
			n, addr, readErr := packet.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			request, openErr := engine.OpenUDPPacket(append([]byte(nil), buffer[:n]...), time.Now())
			if openErr != nil {
				continue
			}
			salt := make([]byte, engine.SaltSize())
			if _, saltErr := rand.Read(salt); saltErr != nil {
				return
			}
			wire, sealErr := engine.SealUDPResponse(salt, 0, 0, request.Target, append([]byte("reply:"), request.Payload...), time.Now(), nil)
			if sealErr != nil {
				continue
			}
			if _, writeErr := packet.WriteTo(wire, addr); writeErr != nil {
				return
			}
		}
	}()

	port := freePort(t)
	exec := newListenExecutor(netListenBinder{})
	exec.bindHost = "127.0.0.1"
	exec.secrets = staticSecrets{"secret/alice\x00v1": "correct-password", "secret/edge\x00v1": "upstream-password"}
	exec.tlsTerminate = func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) {
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	}
	t.Cleanup(exec.stopAll)
	routing := RoutingConfiguration{DefaultAction: RouteUpstream, DefaultUpstreamID: "edge", Upstreams: []Upstream{{
		ID: "edge", Host: "203.0.113.10", Port: 8388, Method: "aes-128-gcm", SecretRef: "secret/edge", SecretVersion: "v1", Enabled: true, TCP: true, UDP: true,
	}}}
	payload, err := json.Marshal(listenApplyRequest{AgentID: "agent-1", Routing: routing, Listens: []ListenApplyItem{{
		ID: "listen-any", Port: port, Protocol: ProtocolAnyTLS, CertificateID: 7, CertificateDomain: "anytls.example",
		PaddingScheme: defaultAnyTLSPaddingScheme, Users: []ListenApplyUser{{ID: "alice", Enabled: true, SecretRef: "secret/alice", SecretVersion: "v1"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = exec.apply(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	exec.mu.Lock()
	exec.bound["listen-any"].dialer = udpUpstreamDialer{address: packet.LocalAddr().String()}
	exec.mu.Unlock()

	exchange := func(connect bool, query []byte) {
		t.Helper()
		target := "203.0.113.8:53"
		if err := dialAnyTLS(t, pool, port, "correct-password", net.JoinHostPort(uotMagicV2, "443"), func(stream net.Conn) error {
			if err := writeUoTRequest(stream, connect, target); err != nil {
				return err
			}
			if err := writeUoTPacket(stream, connect, target, query); err != nil {
				return err
			}
			// The old association read waits out the idle socket, so a reply
			// that already arrived never reaches this stream inside two seconds.
			_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, got, err := readUoTPacket(stream, uotRequest{isConnect: connect, destination: target})
			if err != nil {
				return err
			}
			if string(got) != "reply:"+string(query) {
				return io.ErrUnexpectedEOF
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	exchange(true, []byte("connect-ping"))
	exchange(false, []byte("packet-ping"))
}
