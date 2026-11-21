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
	"net/url"
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

func TestAnyTLSWildcardShareWithExplicitPassword(t *testing.T) {
	const password = " reality:@/#?&=% 中文 "
	for _, tt := range []struct{ host, sni string }{
		{"203.0.113.5", "anytls.example.org"},
		{"2001:db8::1", "anytls.example.org"},
		{"edge.example.org", "edge.example.org"},
		{"other.edge.example.org", "anytls.example.org"},
	} {
		share, err := BuildAnyTLSShare(AnyTLSShareAccount{Host: tt.host, SNI: "*.example.org", Port: 8443, Password: password})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(share.URI)
		if err != nil || parsed.Hostname() != tt.host || parsed.User.Username() != password || parsed.Query().Get("sni") != tt.sni || len(parsed.Query()) != 1 || share.QR.Content != share.URI {
			t.Fatalf("invalid share for %s: %v", tt.host, err)
		}
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

	for _, password := range []string{"unknown-password", "disabled-password"} {
		if err := dialAnyTLS(t, pool, port, password, "example.com:80", nil); err == nil || isTimeout(err) {
			t.Fatalf("expected immediate auth rejection, got %v", err)
		}
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

func TestAnyTLSRemoveListenerWithIdleAuthenticatedClient(t *testing.T) {
	cert, roots := testAnyTLSCertificate(t)
	exec := newListenExecutor(netListenBinder{})
	exec.bindHost = "127.0.0.1"
	exec.secrets = staticSecrets{"secret/alice\x00v1": "correct-password"}
	exec.tlsTerminate = func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) {
		return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
	}
	t.Cleanup(exec.stopAll)
	port := freePort(t)
	applyAnyTLS(t, exec, port, []ListenApplyUser{{ID: "alice", Enabled: true, SecretRef: "secret/alice", SecretVersion: "v1"}})
	address := net.JoinHostPort(exec.bindHost, itoa(port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: "anytls.example", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeAnyTLSClientHello(conn, []byte("correct-password"), defaultAnyTLSPaddingScheme); err != nil {
		t.Fatal(err)
	}
	client := &anytlsSession{conn: conn}
	if err := client.writeFrame(anytlsCmdSettings, 0, []byte("v=2\npadding-md5="+paddingMD5(defaultAnyTLSPaddingScheme))); err != nil {
		t.Fatal(err)
	}
	if cmd, _, _, err := readAnyTLSFrame(conn); cmd != anytlsCmdServerSettings || err != nil {
		t.Fatalf("client settings were not acknowledged: cmd=%d, err=%v", cmd, err)
	}
	_ = conn.SetDeadline(time.Time{})
	stopped := make(chan error, 1)
	go func() {
		_, err := exec.stop([]byte(`{"agent_id":"agent-1","listen_ids":["listen-any"]}`))
		stopped <- err
	}()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener removal waited for the idle client")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("port was not released: %v", err)
	}
	_ = listener.Close()
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

func TestAnyTLSCancellationReleasesIdleDestination(t *testing.T) {
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	_ = destination.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := newServerAnyTLSSession(&frameInputConn{}, defaultAnyTLSPaddingScheme, nil)
	stream, err := session.openStream()
	if err != nil {
		t.Fatal(err)
	}
	bound := &boundListen{dialer: &nativeNetworkDialer{}}
	ended := make(chan struct{})
	go func() {
		bound.serveAnyTLSTCP(ctx, stream, destination.Addr().String())
		close(ended)
	}()
	peer, err := destination.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancel()
	_ = session.Close()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("relay retained the idle destination after listener cancellation")
	}
}

func TestAnyTLSStreamFINClosesOnlyItsIdleDestination(t *testing.T) {
	client, inbound := net.Pipe()
	defer client.Close()
	destinations := make(chan net.Conn, 2)
	bound := &boundListen{
		certificateID: 7,
		exec:          &listenExecutor{tlsTerminate: func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) { return conn, nil }},
		secrets:       staticSecrets{"alice\x00v1": "password"},
		anytlsUsers:   []ListenApplyUser{{ID: "alice", Enabled: true, SecretRef: "alice", SecretVersion: "v1"}},
		dialer: &recordingDialer{open: func() net.Conn {
			conn, peer := net.Pipe()
			destinations <- peer
			return conn
		}},
	}
	go bound.handleAnyTLS(t.Context(), inbound)
	session, err := startClientAnyTLSSession(client, []byte("password"), defaultAnyTLSPaddingScheme, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	open := func() (*anytlsStream, net.Conn) {
		t.Helper()
		stream, err := session.openStream()
		if err != nil {
			t.Fatal(err)
		}
		address, err := encodeSocksAddr("example.org:443")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write(address); err != nil {
			t.Fatal(err)
		}
		select {
		case peer := <-destinations:
			t.Cleanup(func() { _ = peer.Close() })
			return stream, peer
		case <-time.After(time.Second):
			t.Fatal("stream did not reach its destination")
			return nil, nil
		}
	}
	first, idle := open()
	second, live := open()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle.Read(buf[:]); err != io.EOF {
		t.Fatalf("FIN retained the first destination: %v", err)
	}
	_ = live.SetDeadline(time.Now().Add(time.Second))
	if _, err := second.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(live, buf[:]); err != nil || buf[0] != 'x' {
		t.Fatalf("second stream lost its connection: %v", err)
	}
	if _, err := live.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(second, buf[:]); err != nil || buf[0] != 'y' {
		t.Fatalf("second stream lost its reply: %v", err)
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

func newAnyTLSUIController(t *testing.T, managed *hostCapabilityRuntime, host *uiListenHost, state ListenCatalogStore) *Controller {
	t.Helper()
	return startManagedUIController(t, managed, host, state, "generation-a")
}

func startManagedUIController(t *testing.T, managed *hostCapabilityRuntime, host hostRuntimeCaller, state ListenCatalogStore, generation string) *Controller {
	t.Helper()
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
		Generation: generation, RequiredFeatures: supportedFeatures(),
	}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: generation})
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: generation, Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: generation}); result.Error != nil {
		t.Fatal(result.Error)
	}
	t.Cleanup(controller.stopListenReconciler)
	return controller
}

func TestAnyTLSCreateRequiresCertificateAndKeepsShadowsocks(t *testing.T) {
	fake := &managedRuntimeFake{certificates: []pluginsdk.PublicCertificateProjection{{ID: 7, Domain: "cert.example", Enabled: true, MaterialAvailable: true}}}
	host := &uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.9"}}
	controller := newAnyTLSUIController(t, newHostCapabilityRuntime(fake), host, &uiMemoryListenState{})
	missing := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","protocol":"anytls","name":"alice"}`)
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), ErrPublicCertificate.Error()) {
		t.Fatalf("missing certificate = %d %s", missing.Code, missing.Body.String())
	}
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","protocol":"anytls","certificate_id":7,"name":"alice","password":" a:@b/c "}`)
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
	parseShare := func(view listenUserView) *url.URL {
		t.Helper()
		result, err := url.Parse(view.URI)
		if err != nil || result.Scheme != "anytls" || result.User == nil || result.Hostname() != host.node.IPv4 {
			t.Fatalf("invalid share for %s: %v", view.Name, err)
		}
		return result
	}
	if parseShare(listen.Users[0]).User.Username() != " a:@b/c " {
		t.Fatal("first password changed")
	}
	duplicate := uiJSON(t, controller, http.MethodPost, "/api/listens/"+listen.ID+"/users", `{"agent_id":"agent-1","name":"different username","password":" a:@b/c "}`)
	if duplicate.Code != http.StatusBadRequest || !strings.Contains(duplicate.Body.String(), ErrDuplicateAnyTLSPassword.Error()) || fake.createCalls != 1 {
		t.Fatalf("duplicate password response=%d, created credentials=%d", duplicate.Code, fake.createCalls)
	}
	hash := anytlsPasswordHash([]byte("shared"))
	if matchAnyTLSPassword(hash[:], []anytlsIdentity{{id: "one", hash: hash}, {id: "two", hash: hash}}) != "" {
		t.Fatal("accepted an ambiguous password from a legacy configuration")
	}
	for _, tt := range []struct{ name, password string }{{"explicit", " @:/?# "}, {"generated", ""}} {
		body, err := json.Marshal(map[string]string{"agent_id": "agent-1", "name": tt.name, "password": tt.password})
		if err != nil {
			t.Fatal(err)
		}
		reply := uiJSON(t, controller, http.MethodPost, "/api/listens/"+listen.ID+"/users", string(body))
		result := decodeListenAPI(t, reply).Listen
		if reply.Code != http.StatusOK || result == nil {
			t.Fatalf("append %s = %d", tt.name, reply.Code)
		}
		found := false
		for _, user := range result.Users {
			if user.Name == tt.name {
				got := parseShare(user).User.Username()
				found = got != "" && (tt.password == "" || tt.password == got)
			}
		}
		if !found {
			t.Fatalf("appended %s password missing or changed", tt.name)
		}
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

type listenerStateRequest struct {
	Key   string
	Grant string `json:"listener_grant"`
	Value json.RawMessage
}

type listenerGrantTestHost struct {
	managedRuntimeFake
	ready  bool
	writes []listenerStateRequest
}

func (host *listenerGrantTestHost) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	var request listenerStateRequest
	if err := json.Unmarshal(call.Payload, &request); err != nil {
		return err
	}
	if request.Key == listenerSecretJournalKey || strings.HasPrefix(request.Key, "listener-secret-version/") {
		return host.managedRuntimeFake.Call(ctx, call, target)
	}
	switch call.Operation {
	case "state.put":
		if request.Key == pluginListensStateKey {
			host.writes = append(host.writes, request)
		}
		return copyHostResult(map[string]bool{"stored": true}, target)
	case "state.get":
		if request.Key == "listener-certificate-ready/listen-granted" {
			return copyHostResult(map[string]bool{"found": true, "value": host.ready}, target)
		}
		return copyHostResult(map[string]bool{"found": false}, target)
	}
	return nil
}

func TestAnyTLSListenerGrantAndCertificateReadiness(t *testing.T) {
	fake := &listenerGrantTestHost{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.5"}}
	controller := newAnyTLSUIController(t, managed, host, managed)
	grant := func(id, domain, token string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-NRE-Listener-ID", id)
			r.Header.Set("X-NRE-Listener-Grant", token)
			r.Header.Set("X-NRE-Listener-Certificate-Domain", domain)
			controller.ServeHTTP(w, r)
		})
	}
	const create = `{"agent_id":"agent-1","protocol":"anytls","name":"alice","certificate_id":42,"password":"test-password"}`
	const agent = `{"agent_id":"agent-1"}`
	const path = "/api/listens/listen-granted"
	partial := uiJSON(t, grant("listen-granted", "", "short-lived"), http.MethodPost, "/api/listens", create)
	if partial.Code != http.StatusNotFound || len(fake.writes) != 0 || fake.createCalls != 0 {
		t.Fatalf("partial grant = %d", partial.Code)
	}
	created := uiJSON(t, grant("listen-granted", "*.self.example", "short-lived"), http.MethodPost, "/api/listens", create)
	listen := decodeListenAPI(t, created).Listen
	if created.Code != http.StatusOK || listen == nil || listen.ID != "listen-granted" || listen.CertificateID != 42 || listen.CertificateDomain != "*.self.example" || !listen.CertificatePending || listen.Bound || len(listen.Users) != 1 || listen.Users[0].ShareAvailable || listen.Users[0].URI != "" || fake.listCalls != 0 {
		t.Fatalf("pending = %d %+v, catalog reads=%d", created.Code, listen, fake.listCalls)
	}
	if len(fake.writes) != 1 || fake.writes[0].Grant != "short-lived" || strings.Contains(string(fake.writes[0].Value), "short-lived") {
		t.Fatal("create grant missing from state request or persisted with listeners")
	}
	fake.ready = true
	active := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, path, "")).Listen
	if active == nil || active.CertificatePending || !active.Bound || !active.Users[0].ShareAvailable || !strings.Contains(active.Users[0].URI, "sni=anytls.self.example") {
		t.Fatalf("ready = %+v", active)
	}
	wrong := uiJSON(t, grant("listen-other", "", "delete-token"), http.MethodPost, path+"/delete", agent)
	if wrong.Code != http.StatusNotFound || len(fake.writes) != 1 {
		t.Fatalf("wrong deletion = %d, writes=%d", wrong.Code, len(fake.writes))
	}
	removed := uiJSON(t, grant("listen-granted", "", "delete-token"), http.MethodPost, path+"/delete", agent)
	if removed.Code != http.StatusOK || len(fake.writes) != 2 || fake.writes[1].Grant != "delete-token" || len(controller.directory().Listeners) != 0 {
		t.Fatalf("delete = %d writes=%d", removed.Code, len(fake.writes))
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
