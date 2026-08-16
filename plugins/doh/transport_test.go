package doh

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestQUICShortHeaderUsesLocalSCID(t *testing.T) {
	keys := deriveQUICKeys(bytesRepeat(0x11, 32), 16)
	local := bytesRepeat(0x22, 4)
	peer := bytesRepeat(0x33, 8)
	header := encodeShortHeader(local, 7)
	packet, err := sealQUICPacket(header, []byte{0x01}, 7, keys)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, _, pn, err := unprotectQUICPacket(packet, spaceApplication, keys, local)
	if err != nil || pn != 7 || len(payload) < 1 || payload[0] != 0x01 {
		t.Fatalf("local scid payload=%x pn=%d err=%v", payload, pn, err)
	}
	if _, _, _, _, err := unprotectQUICPacket(packet, spaceApplication, keys, peer); err == nil {
		t.Fatal("peer CID length opened a short header addressed to the local scid")
	}
}

func TestQUICPacketSealOpen(t *testing.T) {
	secret := bytesRepeat(0x11, 32)
	keys := deriveQUICKeys(secret, 16)
	dcid := bytesRepeat(0x22, 8)
	scid := bytesRepeat(0x33, 8)
	frames := []byte{0x01}
	header := encodeLongHeader(spaceInitial, dcid, scid, 1, 0)
	packet, err := sealQUICPacket(header, frames, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	gotHeader, payload, _, pn, err := unprotectQUICPacket(packet, spaceInitial, keys, nil)
	if err != nil || pn != 1 || len(payload) < 1 || payload[0] != 0x01 {
		t.Fatalf("header=%x payload=%x pn=%d err=%v", gotHeader, payload, pn, err)
	}
}

func TestParseTransportSpecDoesNotRewriteBareIPToHTTPS(t *testing.T) {
	spec, err := parseTransportSpec("8.8.8.8")
	if err != nil || spec.kind != transportUDP || spec.address != "8.8.8.8:53" {
		t.Fatalf("spec=%#v err=%v", spec, err)
	}
	if _, err := normalizeUpstreamEndpoint("8.8.8.8"); err == nil {
		t.Fatal("bare IP accepted as HTTPS")
	}
}

func TestParseTransportSpecR3Kinds(t *testing.T) {
	cases := []struct {
		token string
		kind  transportKind
	}{
		{"94.140.14.140", transportUDP},
		{"2a10:50c0::1:ff", transportUDP},
		{"94.140.14.140:53", transportUDP},
		{"[2a10:50c0::1:ff]:53", transportUDP},
		{"udp://unfiltered.adguard-dns.com", transportUDP},
		{"tcp://94.140.14.140", transportTCP},
		{"tls://unfiltered.adguard-dns.com", transportTLS},
		{"https://unfiltered.adguard-dns.com/dns-query", transportHTTPS},
		{"h3://unfiltered.adguard-dns.com/dns-query", transportH3},
		{"quic://unfiltered.adguard-dns.com", transportQUIC},
	}
	for _, test := range cases {
		spec, err := parseTransportSpec(test.token)
		if err != nil || spec.kind != test.kind {
			t.Fatalf("token=%q spec=%#v err=%v", test.token, spec, err)
		}
	}
}

func TestUpstreamResolverUDPAndTCP(t *testing.T) {
	udp := startDNSPacketServer(t)
	tcp, _ := startDNSStreamServer(t, nil)
	resolver := newUpstreamResolver()
	query := testDNSQuery(1, "udp.example")
	got, err := resolver.Resolve(context.Background(), ResolveRequest{Endpoint: udp, DNSMessage: query, MaxBytes: MaxDNSResponseBytes})
	if err != nil || len(got) < 12 || binary.BigEndian.Uint16(got[:2]) != 1 {
		t.Fatalf("udp got=%x err=%v", got, err)
	}
	got, err = resolver.Resolve(context.Background(), ResolveRequest{Endpoint: "tcp://" + tcp, DNSMessage: query, MaxBytes: MaxDNSResponseBytes})
	if err != nil || binary.BigEndian.Uint16(got[:2]) != 1 {
		t.Fatalf("tcp got=%x err=%v", got, err)
	}
}

func TestUpstreamResolverTLS(t *testing.T) {
	tlsAddr, serverTLS := startDNSStreamServer(t, testTLSConfig(t))
	pool := x509.NewCertPool()
	if len(serverTLS.Certificates) == 0 {
		t.Fatal("missing test certificate")
	}
	parsed, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	resolver := newUpstreamResolver()
	resolver.tls = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: "localhost"}
	got, err := resolver.Resolve(context.Background(), ResolveRequest{
		Endpoint:   "tls://" + tlsAddr,
		DNSMessage: testDNSQuery(2, "tls.example"),
		MaxBytes:   MaxDNSResponseBytes,
	})
	if err != nil || binary.BigEndian.Uint16(got[:2]) != 2 {
		t.Fatalf("tls got=%x err=%v", got, err)
	}
}

func TestDoQZerosMessageID(t *testing.T) {
	query := testDNSQuery(9, "doq-id.example")
	if binary.BigEndian.Uint16(query[:2]) != 9 {
		t.Fatal(query)
	}
	outbound := append([]byte(nil), query...)
	outbound[0], outbound[1] = 0, 0
	if binary.BigEndian.Uint16(outbound[:2]) != 0 {
		t.Fatal(outbound)
	}
}

func TestQUICSkipsHandshakeDoneAndMaxData(t *testing.T) {
	conn := &quicConn{streams: map[uint64]*quicStream{}}
	payload := []byte{0x1e, 0x10, 0x20, 0x01}
	if err := conn.handleFrames(spaceApplication, payload); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCryptISO7816Padding(t *testing.T) {
	query := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	padded := padDNSCryptQuery(query)
	if padded[len(query)] != 0x80 {
		t.Fatalf("missing 0x80 marker: %x", padded)
	}
	if len(padded)%64 != 0 || len(padded) < 256 {
		t.Fatalf("len=%d", len(padded))
	}
	if got := trimDNSCryptPadding(padded); string(got) != string(query) {
		t.Fatalf("unpad=%x", got)
	}
}

func TestSecretboxRoundTrip(t *testing.T) {
	key := bytesRepeat(0x42, 32)
	nonce := bytesRepeat(0x11, 24)
	plain := []byte("dns-crypt-query-body")
	boxed := secretboxSeal(key, nonce, plain)
	got, ok := secretboxOpen(key, nonce, boxed)
	if !ok || string(got) != string(plain) {
		t.Fatalf("roundtrip ok=%v got=%q", ok, got)
	}
}

func TestParseDNSStampKinds(t *testing.T) {
	doh := encodeTestStamp(0x02, "8.8.8.8:443", nil, "dns.google", "/dns-query")
	spec, err := parseTransportSpec(doh)
	if err != nil || spec.kind != transportHTTPS || spec.httpsURL != "https://dns.google/dns-query" {
		t.Fatalf("doh stamp spec=%#v err=%v", spec, err)
	}
	dot := encodeTestStamp(0x03, "8.8.8.8:853", nil, "dns.google", "")
	spec, err = parseTransportSpec(dot)
	if err != nil || spec.kind != transportTLS {
		t.Fatalf("dot stamp spec=%#v err=%v", spec, err)
	}
	doq := encodeTestStamp(0x04, "8.8.8.8:853", nil, "dns.google", "")
	spec, err = parseTransportSpec(doq)
	if err != nil || spec.kind != transportQUIC {
		t.Fatalf("doq stamp spec=%#v err=%v", spec, err)
	}
}

func TestUpstreamResolverDNSCrypt(t *testing.T) {
	providerPub, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	magic := []byte("01234567")
	now := uint32(time.Now().Unix())
	cert := buildDNSCryptCert(providerPriv, resolverKey.PublicKey().Bytes(), magic, now-60, now+3600)
	addr, stamp := startDNSCryptServer(t, providerPub, resolverKey, cert, magic, "2.dnscrypt-cert.test")
	_ = addr
	resolver := newUpstreamResolver()
	query := testDNSQuery(9, "dnscrypt.example")
	got, err := resolver.Resolve(context.Background(), ResolveRequest{Endpoint: stamp, DNSMessage: query, MaxBytes: MaxDNSResponseBytes})
	if err != nil || len(got) < 12 || binary.BigEndian.Uint16(got[:2]) != 9 {
		t.Fatalf("dnscrypt got=%x err=%v", got, err)
	}
}

func TestH3DoesNotUseHTTPSClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	resolver := newUpstreamResolver()
	_, err = resolver.Resolve(context.Background(), ResolveRequest{
		Endpoint:   "h3://" + listener.Addr().String() + "/dns-query",
		DNSMessage: testDNSQuery(3, "h3.example"),
		MaxBytes:   MaxDNSResponseBytes,
	})
	if err == nil {
		t.Fatal("h3 fell back to a TCP HTTP listener")
	}
}

func TestUpstreamResolverDoQAndH3(t *testing.T) {
	doq := startQUICDNSServer(t, []string{"doq"})
	h3 := startQUICDNSServer(t, []string{"h3"})
	resolver := newUpstreamResolver()
	resolver.tls = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	query := testDNSQuery(4, "quic.example")
	got, err := resolver.Resolve(context.Background(), ResolveRequest{Endpoint: "quic://" + doq, DNSMessage: query, MaxBytes: MaxDNSResponseBytes})
	if err != nil || len(got) < 12 || binary.BigEndian.Uint16(got[:2]) != 4 {
		t.Fatalf("doq got=%x err=%v", got, err)
	}
	got, err = resolver.Resolve(context.Background(), ResolveRequest{Endpoint: "h3://" + h3 + "/dns-query", DNSMessage: query, MaxBytes: MaxDNSResponseBytes})
	if err != nil || len(got) < 12 {
		t.Fatalf("h3 got=%x err=%v", got, err)
	}
}

func startDNSPacketServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, MaxDNSResponseBytes)
		for {
			read, addr, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:read], addr)
		}
	}()
	return conn.LocalAddr().String()
}

func startDNSStreamServer(t *testing.T, tlsConfig *tls.Config) (string, *tls.Config) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		query, readErr := readDNSMessage(conn, MaxDNSResponseBytes)
		if readErr != nil {
			return
		}
		_ = writeDNSMessage(conn, query)
	}()
	return listener.Addr().String(), tlsConfig
}

func startQUICDNSServer(t *testing.T, alpns []string) string {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	tlsConfig := testTLSConfig(t)
	tlsConfig.NextProtos = append([]string(nil), alpns...)
	tlsConfig.MinVersion = tls.VersionTLS13
	errc := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("quic server: %v", err)
			}
		default:
		}
	})
	go func() {
		buffer := make([]byte, quicMaxDatagram)
		read, addr, readErr := udp.ReadFrom(buffer)
		if readErr != nil {
			errc <- readErr
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, acceptErr := acceptQUIC(ctx, udp, buffer[:read], addr, tlsConfig)
		if acceptErr != nil {
			errc <- acceptErr
			return
		}
		defer conn.close()
		if err := conn.handshake(ctx); err != nil {
			errc <- err
			return
		}
		if containsString(alpns, "h3") {
			body, err := conn.readStream(ctx, 0)
			if err != nil {
				errc <- err
				return
			}
			dns, err := parseHTTP3DNS(body, MaxDNSResponseBytes)
			if err != nil {
				errc <- err
				return
			}
			errc <- conn.writeStream(0, append(http3HeadersFrame("localhost", DNSQueryPath), http3DataFrame(dns)...), true)
			return
		}
		body, err := conn.readStream(ctx, 0)
		if err != nil || len(body) < 4 {
			errc <- err
			return
		}
		if containsString(alpns, "doq") && (body[2] != 0 || body[3] != 0) {
			errc <- fmt.Errorf("doq query id=%x", body[2:4])
			return
		}
		errc <- conn.writeStream(0, body, true)
	}()
	return udp.LocalAddr().String()
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func testDNSQuery(id uint16, name string) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:2], id)
	binary.BigEndian.PutUint16(wire[4:6], 1)
	for _, part := range splitName(name) {
		wire = append(wire, byte(len(part)))
		wire = append(wire, part...)
	}
	wire = append(wire, 0, 0, 1, 0, 1)
	return wire
}

func splitName(name string) [][]byte {
	var parts [][]byte
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			if index > start {
				parts = append(parts, []byte(name[start:index]))
			}
			start = index + 1
		}
	}
	return parts
}

func encodeTestStamp(protocol byte, address string, pk []byte, hostname, path string) string {
	payload := []byte{protocol, 0, 0, 0, 0, 0, 0, 0, 0}
	payload = append(payload, byte(len(address)))
	payload = append(payload, address...)
	switch protocol {
	case 0x01:
		payload = append(payload, pk...)
		payload = append(payload, byte(len(hostname)))
		payload = append(payload, hostname...)
	case 0x02, 0x03, 0x04:
		payload = append(payload, 0)
		payload = append(payload, byte(len(hostname)))
		payload = append(payload, hostname...)
		if protocol == 0x02 {
			payload = append(payload, byte(len(path)))
			payload = append(payload, path...)
		}
	}
	return "sdns://" + base64.RawURLEncoding.EncodeToString(payload)
}

func buildDNSCryptCert(providerPriv ed25519.PrivateKey, resolverPK, magic []byte, start, end uint32) []byte {
	cert := make([]byte, 124)
	binary.BigEndian.PutUint32(cert[:4], dnsCryptCertMagic)
	binary.BigEndian.PutUint16(cert[4:6], 1)
	copy(cert[72:104], resolverPK)
	copy(cert[104:112], magic)
	binary.BigEndian.PutUint32(cert[112:116], 1)
	binary.BigEndian.PutUint32(cert[116:120], start)
	binary.BigEndian.PutUint32(cert[120:124], end)
	copy(cert[8:72], ed25519.Sign(providerPriv, cert[72:124]))
	return cert
}

func startDNSCryptServer(t *testing.T, providerPub ed25519.PublicKey, resolverKey *ecdh.PrivateKey, cert, magic []byte, providerName string) (string, string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			read, addr, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			packet := buffer[:read]
			if len(packet) >= 12 && binary.BigEndian.Uint16(packet[4:6]) == 1 {
				name := questionName(packet[12:])
				if name == providerName {
					_, _ = conn.WriteTo(txtAnswer(packet, cert), addr)
					continue
				}
			}
			if read < 8+32+12+16 {
				continue
			}
			clientPK, err := ecdh.X25519().NewPublicKey(packet[8:40])
			if err != nil {
				continue
			}
			shared, err := resolverKey.ECDH(clientPK)
			if err != nil {
				continue
			}
			boxKey := hsalsa20(shared, make([]byte, 16))
			nonce := make([]byte, 24)
			copy(nonce[:12], packet[40:52])
			plain, ok := secretboxOpen(boxKey, nonce, packet[52:read])
			if !ok {
				continue
			}
			plain = trimDNSCryptPadding(plain)
			if _, err := rand.Read(nonce[12:]); err != nil {
				continue
			}
			boxed := secretboxSeal(boxKey, nonce, padDNSCryptQuery(plain))
			reply := append(append([]byte(dnsCryptResolverMagic), nonce[12:]...), boxed...)
			_, _ = conn.WriteTo(reply, addr)
		}
	}()
	host, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	stamp := encodeTestStamp(0x01, net.JoinHostPort(host, port), providerPub, providerName, "")
	return conn.LocalAddr().String(), stamp
}

func txtAnswer(query, txt []byte) []byte {
	reply := append([]byte(nil), query...)
	reply[2] = 0x81
	reply[3] = 0x80
	binary.BigEndian.PutUint16(reply[6:8], 1)
	nameEnd, err := skipDNSName(query, 12)
	if err != nil {
		return reply
	}
	reply = append(reply, query[12:nameEnd]...)
	reply = append(reply, 0, 16, 0, 1, 0, 0, 0, 60, 0, byte(len(txt)+1), byte(len(txt)))
	return append(reply, txt...)
}

func bytesRepeat(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
