package doh

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

type transportKind int

const (
	transportUDP transportKind = iota
	transportTCP
	transportTLS
	transportHTTPS
	transportH3
	transportQUIC
	transportDNSCrypt
)

const (
	quicVersionV1         = 0x00000001
	quicInitialMinSize    = 1200
	quicMaxDatagram       = 65535
	dnsCryptMinPad        = 256
	dnsCryptPadAlign      = 64
	dnsCryptCertMagic     = 0x444e5343
	dnsCryptResolverMagic = "r6fnvWj8"
)

var quicInitialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

type transportSpec struct {
	kind     transportKind
	network  string
	address  string
	sni      string
	path     string
	httpsURL string
	stamp    dnsStamp
}

type dnsStamp struct {
	protocol  byte
	address   string
	hostname  string
	path      string
	publicKey []byte
}

type upstreamResolver struct {
	https *httpUpstreamResolver
	tls   *tls.Config
}

func newUpstreamResolver() *upstreamResolver {
	return &upstreamResolver{https: newHTTPClientResolver()}
}

func newHTTPUpstreamResolver() Resolver {
	return newUpstreamResolver()
}

func (resolver *upstreamResolver) Resolve(ctx context.Context, request ResolveRequest) ([]byte, error) {
	spec, err := parseTransportSpec(request.Endpoint)
	if err != nil {
		return nil, err
	}
	limit := request.MaxBytes
	if limit <= 0 || limit > MaxDNSResponseBytes {
		limit = MaxDNSResponseBytes
	}
	switch spec.kind {
	case transportHTTPS:
		return resolver.https.Resolve(ctx, ResolveRequest{Endpoint: spec.httpsURL, DNSMessage: request.DNSMessage, MaxBytes: limit})
	case transportUDP:
		return exchangePacket(ctx, "udp", spec.address, request.DNSMessage, limit)
	case transportTCP:
		return exchangeStream(ctx, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", spec.address)
		}, request.DNSMessage, limit)
	case transportTLS:
		return exchangeStream(ctx, func(ctx context.Context) (net.Conn, error) {
			return (&tls.Dialer{Config: resolver.clientTLS(spec.sni, nil)}).DialContext(ctx, "tcp", spec.address)
		}, request.DNSMessage, limit)
	case transportH3:
		return exchangeHTTP3(ctx, spec, request.DNSMessage, limit, resolver.clientTLS(spec.sni, []string{"h3"}))
	case transportQUIC:
		return exchangeDoQ(ctx, spec, request.DNSMessage, limit, resolver.clientTLS(spec.sni, []string{"doq"}))
	case transportDNSCrypt:
		return exchangeDNSCrypt(ctx, spec, request.DNSMessage, limit)
	default:
		return nil, ErrInvalidRequest
	}
}

func (resolver *upstreamResolver) clientTLS(sni string, alpns []string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, NextProtos: append([]string(nil), alpns...)}
	if resolver.tls != nil {
		config = resolver.tls.Clone()
		if sni != "" {
			config.ServerName = sni
		}
		if len(alpns) > 0 {
			config.NextProtos = append([]string(nil), alpns...)
		}
	}
	if len(alpns) > 0 && config.MinVersion < tls.VersionTLS13 {
		config.MinVersion = tls.VersionTLS13
	}
	return config
}

func parseTransportSpec(endpoint string) (transportSpec, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return transportSpec{}, ErrInvalidRequest
	}
	if strings.HasPrefix(endpoint, "sdns://") {
		stamp, err := parseDNSStamp(endpoint)
		if err != nil {
			return transportSpec{}, err
		}
		return specFromStamp(stamp)
	}
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" {
			return transportSpec{}, ErrInvalidRequest
		}
		host := parsed.Hostname()
		port := parsed.Port()
		sni := host
		switch parsed.Scheme {
		case "udp":
			return udpSpec(host, defaultPort(port, "53")), nil
		case "tcp":
			return tcpSpec(host, defaultPort(port, "53")), nil
		case "tls":
			return tlsSpec(host, defaultPort(port, "853"), sni), nil
		case "quic":
			return quicSpec(host, defaultPort(port, "853"), sni), nil
		case "h3":
			return h3Spec(host, defaultPort(port, "443"), sni, dohPath(parsed.Path)), nil
		case "https", "http":
			normalized, err := normalizeHTTPSEndpoint(parsed)
			if err != nil {
				return transportSpec{}, err
			}
			return transportSpec{kind: transportHTTPS, httpsURL: normalized}, nil
		default:
			return transportSpec{}, ErrInvalidRequest
		}
	}
	if ip := net.ParseIP(endpoint); ip != nil {
		return udpSpec(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return transportSpec{}, ErrInvalidRequest
	}
	return udpSpec(host, port), nil
}

func udpSpec(host, port string) transportSpec {
	return transportSpec{kind: transportUDP, network: "udp", address: net.JoinHostPort(host, port)}
}

func tcpSpec(host, port string) transportSpec {
	return transportSpec{kind: transportTCP, network: "tcp", address: net.JoinHostPort(host, port)}
}

func tlsSpec(host, port, sni string) transportSpec {
	return transportSpec{kind: transportTLS, address: net.JoinHostPort(host, port), sni: sni}
}

func quicSpec(host, port, sni string) transportSpec {
	return transportSpec{kind: transportQUIC, address: net.JoinHostPort(host, port), sni: sni}
}

func h3Spec(host, port, sni, path string) transportSpec {
	return transportSpec{kind: transportH3, address: net.JoinHostPort(host, port), sni: sni, path: path}
}

func defaultPort(port, fallback string) string {
	if port == "" {
		return fallback
	}
	return port
}

func dohPath(path string) string {
	if path == "" || path == "/" {
		return DNSQueryPath
	}
	return path
}

func normalizeHTTPSEndpoint(parsed *url.URL) (string, error) {
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", ErrInvalidRequest
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = DNSQueryPath
	}
	return parsed.String(), nil
}

func specFromStamp(stamp dnsStamp) (transportSpec, error) {
	host, port := stampHostPort(stamp)
	if host == "" && stamp.hostname == "" {
		return transportSpec{}, ErrInvalidRequest
	}
	if host == "" {
		host = stamp.hostname
	}
	switch stamp.protocol {
	case 0x00:
		return udpSpec(host, defaultPort(port, "53")), nil
	case 0x01:
		if len(stamp.publicKey) != 32 {
			return transportSpec{}, ErrInvalidRequest
		}
		return transportSpec{kind: transportDNSCrypt, address: net.JoinHostPort(host, defaultPort(port, "443")), stamp: stamp}, nil
	case 0x02:
		path := stamp.path
		if path == "" {
			path = DNSQueryPath
		}
		hostname := stamp.hostname
		if hostname == "" {
			hostname = host
		}
		if port != "" && port != "443" {
			return transportSpec{kind: transportHTTPS, httpsURL: "https://" + net.JoinHostPort(hostname, port) + path}, nil
		}
		return transportSpec{kind: transportHTTPS, httpsURL: "https://" + hostname + path}, nil
	case 0x03:
		sni := stamp.hostname
		if sni == "" {
			sni = host
		}
		return tlsSpec(host, defaultPort(port, "853"), sni), nil
	case 0x04:
		sni := stamp.hostname
		if sni == "" {
			sni = host
		}
		return quicSpec(host, defaultPort(port, "853"), sni), nil
	default:
		return transportSpec{}, ErrInvalidRequest
	}
}

func stampHostPort(stamp dnsStamp) (string, string) {
	address := strings.TrimSpace(stamp.address)
	if address == "" {
		return "", ""
	}
	if ip := net.ParseIP(address); ip != nil {
		return ip.String(), ""
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address, ""
	}
	return host, port
}

func parseDNSStamp(token string) (dnsStamp, error) {
	raw := strings.TrimPrefix(token, "sdns://")
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(raw)
	}
	if err != nil || len(payload) < 10 {
		return dnsStamp{}, ErrInvalidRequest
	}
	stamp := dnsStamp{protocol: payload[0]}
	offset := 9
	address, offset, err := readStampString(payload, offset)
	if err != nil {
		return dnsStamp{}, err
	}
	stamp.address = address
	switch stamp.protocol {
	case 0x00:
		return stamp, nil
	case 0x01:
		if offset+32 > len(payload) {
			return dnsStamp{}, ErrInvalidRequest
		}
		stamp.publicKey = append([]byte(nil), payload[offset:offset+32]...)
		offset += 32
		stamp.hostname, _, err = readStampString(payload, offset)
		return stamp, err
	case 0x02, 0x03, 0x04:
		_, offset, err = readStampString(payload, offset)
		if err != nil {
			return dnsStamp{}, err
		}
		stamp.hostname, offset, err = readStampString(payload, offset)
		if err != nil {
			return dnsStamp{}, err
		}
		if stamp.protocol == 0x02 {
			stamp.path, _, err = readStampString(payload, offset)
		}
		return stamp, err
	default:
		return dnsStamp{}, ErrInvalidRequest
	}
}

func readStampString(payload []byte, offset int) (string, int, error) {
	if offset >= len(payload) {
		return "", 0, ErrInvalidRequest
	}
	length := int(payload[offset])
	offset++
	if offset+length > len(payload) {
		return "", 0, ErrInvalidRequest
	}
	return string(payload[offset : offset+length]), offset + length, nil
}

func exchangePacket(ctx context.Context, network, address string, query []byte, limit int) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, ErrUpstreamFailed
	}
	buffer := make([]byte, limit)
	read, err := conn.Read(buffer)
	if err != nil || read == 0 {
		return nil, ErrUpstreamFailed
	}
	return append([]byte(nil), buffer[:read]...), nil
}

func exchangeStream(ctx context.Context, dial func(context.Context) (net.Conn, error), query []byte, limit int) ([]byte, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeDNSMessage(conn, query); err != nil {
		return nil, err
	}
	return readDNSMessage(conn, limit)
}

func writeDNSMessage(writer io.Writer, message []byte) error {
	if len(message) == 0 || len(message) > 65535 {
		return ErrRequestTooLarge
	}
	framed := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(message)))
	copy(framed[2:], message)
	if _, err := writer.Write(framed); err != nil {
		return ErrUpstreamFailed
	}
	return nil
}

func readDNSMessage(reader io.Reader, limit int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrUpstreamFailed
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 || length > limit {
		return nil, ErrResponseTooLarge
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, ErrUpstreamFailed
	}
	return body, nil
}

func exchangeHTTP3(ctx context.Context, spec transportSpec, query []byte, limit int, tlsConfig *tls.Config) ([]byte, error) {
	conn, err := dialQUIC(ctx, spec.address, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.close()
	if err := conn.handshake(ctx); err != nil {
		return nil, err
	}
	if err := conn.writeStream(2, append([]byte{0x00}, http3Settings()...), false); err != nil {
		return nil, err
	}
	request := append(http3HeadersFrame(spec.sni, spec.path), http3DataFrame(query)...)
	if err := conn.writeStream(0, request, true); err != nil {
		return nil, err
	}
	body, err := conn.readStream(ctx, 0)
	if err != nil {
		return nil, err
	}
	return parseHTTP3DNS(body, limit)
}

func exchangeDoQ(ctx context.Context, spec transportSpec, query []byte, limit int, tlsConfig *tls.Config) ([]byte, error) {
	conn, err := dialQUIC(ctx, spec.address, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.close()
	if err := conn.handshake(ctx); err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if err := conn.writeStream(0, framed, true); err != nil {
		return nil, err
	}
	body, err := conn.readStream(ctx, 0)
	if err != nil || len(body) < 2 {
		return nil, ErrUpstreamFailed
	}
	length := int(binary.BigEndian.Uint16(body[:2]))
	if length == 0 || length > limit || len(body) < 2+length {
		return nil, ErrResponseTooLarge
	}
	return append([]byte(nil), body[2:2+length]...), nil
}

func http3Settings() []byte {
	return http3Frame(0x04, nil)
}

func http3DataFrame(payload []byte) []byte {
	return http3Frame(0x00, payload)
}

func http3HeadersFrame(authority, path string) []byte {
	if path == "" {
		path = DNSQueryPath
	}
	var qpack []byte
	qpack = append(qpack, 0x00, 0x00) // required insert count + delta base
	qpack = append(qpack, 0xc0|20)    // :method POST
	qpack = append(qpack, 0xc0|23)    // :scheme https
	qpack = append(qpack, qpackLiteralNameRef(1, path)...)
	qpack = append(qpack, qpackLiteralNameRef(0, authority)...)
	qpack = append(qpack, qpackLiteralPair("content-type", dnsMediaType)...)
	qpack = append(qpack, qpackLiteralPair("accept", dnsMediaType)...)
	return http3Frame(0x01, qpack)
}

func qpackLiteralNameRef(index int, value string) []byte {
	out := []byte{0x50 | byte(index)}
	out = append(out, byte(len(value)))
	return append(out, value...)
}

func qpackLiteralPair(name, value string) []byte {
	out := []byte{0x20 | byte(len(name))}
	out = append(out, name...)
	out = append(out, byte(len(value)))
	return append(out, value...)
}

func http3Frame(kind uint64, payload []byte) []byte {
	out := append(appendVarint(nil, kind), appendVarint(nil, uint64(len(payload)))...)
	return append(out, payload...)
}

func parseHTTP3DNS(payload []byte, limit int) ([]byte, error) {
	for offset := 0; offset < len(payload); {
		kind, next, err := readVarint(payload, offset)
		if err != nil {
			return nil, ErrUpstreamFailed
		}
		length, next, err := readVarint(payload, next)
		if err != nil || next+int(length) > len(payload) {
			return nil, ErrUpstreamFailed
		}
		if kind == 0x00 {
			if int(length) == 0 || int(length) > limit {
				return nil, ErrResponseTooLarge
			}
			return append([]byte(nil), payload[next:next+int(length)]...), nil
		}
		offset = next + int(length)
	}
	return nil, ErrUpstreamFailed
}

type quicSpace int

const (
	spaceInitial quicSpace = iota
	spaceHandshake
	spaceApplication
)

type quicKeys struct {
	key []byte
	iv  []byte
	hp  []byte
}

type quicStream struct {
	inbound []byte
	fin     bool
}

type quicConn struct {
	udp           net.Conn
	tls           *tls.QUICConn
	client        bool
	dcid          []byte
	scid          []byte
	peerCID       []byte
	keys          [3]quicKeys
	readKeys      [3]quicKeys
	writePN       [3]uint64
	largestRecv   [3]int64
	cryptoIn      [3][]byte
	cryptoOut     [3][]byte
	cryptoWrite   [3]uint64
	cryptoRead    [3]uint64
	streams       map[uint64]*quicStream
	handshakeDone bool
}

func dialQUIC(ctx context.Context, address string, tlsConfig *tls.Config) (*quicConn, error) {
	udp, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = udp.SetDeadline(deadline)
	}
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil || func() error { _, err := rand.Read(scid); return err }() != nil {
		_ = udp.Close()
		return nil, ErrUpstreamFailed
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	conn := &quicConn{
		udp:     udp,
		tls:     tls.QUICClient(&tls.QUICConfig{TLSConfig: tlsConfig}),
		client:  true,
		dcid:    dcid,
		scid:    scid,
		peerCID: dcid,
		streams: map[uint64]*quicStream{},
	}
	conn.largestRecv = [3]int64{-1, -1, -1}
	conn.installInitial(dcid)
	conn.tls.SetTransportParameters(encodeTransportParams(scid))
	if err := conn.tls.Start(ctx); err != nil {
		conn.close()
		return nil, quicFail(err)
	}
	return conn, nil
}

func acceptQUIC(ctx context.Context, udp net.PacketConn, first []byte, addr net.Addr, tlsConfig *tls.Config) (*quicConn, error) {
	dcid, scid, rest, err := peekLongHeaderCIDs(first)
	if err != nil {
		return nil, err
	}
	_ = rest
	serverCID := make([]byte, 8)
	if _, err := rand.Read(serverCID); err != nil {
		return nil, ErrUpstreamFailed
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	connected := &packetConn{PacketConn: udp, remote: addr}
	conn := &quicConn{
		udp:     connected,
		tls:     tls.QUICServer(&tls.QUICConfig{TLSConfig: tlsConfig}),
		dcid:    scid,
		scid:    serverCID,
		peerCID: scid,
		streams: map[uint64]*quicStream{},
	}
	conn.largestRecv = [3]int64{-1, -1, -1}
	conn.installInitial(dcid)
	conn.tls.SetTransportParameters(encodeTransportParams(serverCID))
	if err := conn.tls.Start(ctx); err != nil {
		return nil, quicFail(err)
	}
	if err := conn.handleDatagram(first); err != nil {
		return nil, quicFail(err)
	}
	return conn, nil
}

type packetConn struct {
	net.PacketConn
	remote net.Addr
}

func (conn *packetConn) Read(buffer []byte) (int, error) {
	read, addr, err := conn.PacketConn.ReadFrom(buffer)
	if err == nil && addr != nil {
		conn.remote = addr
	}
	return read, err
}

func (conn *packetConn) Write(buffer []byte) (int, error) {
	return conn.PacketConn.WriteTo(buffer, conn.remote)
}

func (conn *packetConn) RemoteAddr() net.Addr { return conn.remote }
func (conn *packetConn) SetDeadline(t time.Time) error {
	return conn.PacketConn.SetDeadline(t)
}

func (conn *quicConn) close() {
	if conn.tls != nil {
		_ = conn.tls.Close()
	}
	if conn.udp != nil {
		_ = conn.udp.Close()
	}
}

func (conn *quicConn) installInitial(destCID []byte) {
	secret, _ := hkdf.Extract(sha256.New, destCID, quicInitialSaltV1)
	client, _ := quicExpandSecret(secret, "client in")
	server, _ := quicExpandSecret(secret, "server in")
	write, read := client, server
	if !conn.client {
		write, read = server, client
	}
	conn.keys[spaceInitial] = deriveQUICKeys(write, 16)
	conn.readKeySet(spaceInitial, deriveQUICKeys(read, 16))
}

func (conn *quicConn) readKeySet(space quicSpace, keys quicKeys) {
	conn.readKeys[space] = keys
}

func deriveQUICKeys(secret []byte, keyLen int) quicKeys {
	return quicKeys{
		key: mustExpand(secret, "quic key", keyLen),
		iv:  mustExpand(secret, "quic iv", 12),
		hp:  mustExpand(secret, "quic hp", 16),
	}
}

func quicExpandSecret(secret []byte, label string) ([]byte, error) {
	return tlsExpandLabel(secret, label, nil, 32)
}

func mustExpand(secret []byte, label string, length int) []byte {
	out, err := tlsExpandLabel(secret, label, nil, length)
	if err != nil {
		return make([]byte, length)
	}
	return out
}

func tlsExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func encodeTransportParams(scid []byte) []byte {
	var out []byte
	out = appendTransportParam(out, 0x01, appendVarint(nil, 30_000))
	out = appendTransportParam(out, 0x03, appendVarint(nil, 1472))
	out = appendTransportParam(out, 0x04, appendVarint(nil, 1<<20))
	out = appendTransportParam(out, 0x05, appendVarint(nil, 1<<20))
	out = appendTransportParam(out, 0x06, appendVarint(nil, 1<<20))
	out = appendTransportParam(out, 0x07, appendVarint(nil, 1<<20))
	out = appendTransportParam(out, 0x08, appendVarint(nil, 16))
	out = appendTransportParam(out, 0x09, appendVarint(nil, 16))
	out = appendTransportParam(out, 0x0f, scid)
	return out
}

func appendTransportParam(dst []byte, id uint64, value []byte) []byte {
	dst = appendVarint(dst, id)
	dst = appendVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

func quicFail(err error) error {
	if err == nil {
		return ErrUpstreamFailed
	}
	return fmt.Errorf("%w: %v", ErrUpstreamFailed, err)
}

func (conn *quicConn) handshake(ctx context.Context) error {
	if err := conn.drainTLS(); err != nil {
		return quicFail(err)
	}
	if err := conn.flush(ctx); err != nil {
		return quicFail(err)
	}
	for !conn.handshakeDone {
		if err := ctx.Err(); err != nil {
			return quicFail(err)
		}
		if err := conn.receive(ctx); err != nil {
			return quicFail(err)
		}
		if err := conn.drainTLS(); err != nil {
			return quicFail(err)
		}
		if err := conn.flush(ctx); err != nil {
			return quicFail(err)
		}
	}
	return nil
}

func (conn *quicConn) drainTLS() error {
	for {
		event := conn.tls.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetReadSecret:
			space, keys, err := keysFromSecret(event.Suite, event.Data)
			if err != nil {
				return err
			}
			if event.Level == tls.QUICEncryptionLevelHandshake {
				conn.readKeySet(spaceHandshake, keys)
			} else if event.Level == tls.QUICEncryptionLevelApplication {
				conn.readKeySet(spaceApplication, keys)
			}
			_ = space
		case tls.QUICSetWriteSecret:
			keys, err := suiteKeys(event.Suite, event.Data)
			if err != nil {
				return err
			}
			switch event.Level {
			case tls.QUICEncryptionLevelHandshake:
				conn.keys[spaceHandshake] = keys
			case tls.QUICEncryptionLevelApplication:
				conn.keys[spaceApplication] = keys
			}
		case tls.QUICWriteData:
			space := spaceFromLevel(event.Level)
			conn.cryptoOut[space] = append(conn.cryptoOut[space], event.Data...)
		case tls.QUICHandshakeDone:
			conn.handshakeDone = true
		case tls.QUICTransportParameters, tls.QUICStoreSession, tls.QUICResumeSession, tls.QUICRejectedEarlyData:
		case tls.QUICErrorEvent:
			return quicFail(event.Err)
		default:
		}
	}
}

func spaceFromLevel(level tls.QUICEncryptionLevel) quicSpace {
	switch level {
	case tls.QUICEncryptionLevelHandshake:
		return spaceHandshake
	case tls.QUICEncryptionLevelApplication:
		return spaceApplication
	default:
		return spaceInitial
	}
}

func keysFromSecret(suite uint16, secret []byte) (quicSpace, quicKeys, error) {
	keys, err := suiteKeys(suite, secret)
	return 0, keys, err
}

func suiteKeys(suite uint16, secret []byte) (quicKeys, error) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return deriveQUICKeys(secret, 16), nil
	case tls.TLS_AES_256_GCM_SHA384:
		return deriveQUICKeys(secret, 32), nil
	default:
		return quicKeys{}, ErrUpstreamFailed
	}
}

func (conn *quicConn) flush(ctx context.Context) error {
	_ = ctx
	for _, space := range []quicSpace{spaceInitial, spaceHandshake, spaceApplication} {
		if len(conn.cryptoOut[space]) == 0 && conn.largestRecv[space] < 0 {
			continue
		}
		frames := []byte{}
		if conn.largestRecv[space] >= 0 {
			frames = append(frames, encodeACK(uint64(conn.largestRecv[space]))...)
		}
		if len(conn.cryptoOut[space]) > 0 {
			frames = append(frames, 0x06)
			frames = appendVarint(frames, conn.cryptoWrite[space])
			frames = appendVarint(frames, uint64(len(conn.cryptoOut[space])))
			frames = append(frames, conn.cryptoOut[space]...)
			conn.cryptoWrite[space] += uint64(len(conn.cryptoOut[space]))
			conn.cryptoOut[space] = nil
		}
		if len(frames) == 0 {
			continue
		}
		if err := conn.sendPacket(space, frames, space == spaceInitial); err != nil {
			return err
		}
	}
	return nil
}

func (conn *quicConn) sendPacket(space quicSpace, frames []byte, padInitial bool) error {
	keys := conn.keys[space]
	if len(keys.key) == 0 {
		return ErrUpstreamFailed
	}
	pn := conn.writePN[space]
	conn.writePN[space]++
	header := encodeLongHeader(space, conn.peerCID, conn.scid, pn, 0)
	if space == spaceApplication {
		header = encodeShortHeader(conn.peerCID, pn)
	}
	payload := append([]byte(nil), frames...)
	if padInitial {
		need := quicInitialMinSize - (len(header) + 4 + len(payload) + 16)
		if need > 0 {
			payload = append(payload, make([]byte, need)...)
		}
	}
	packet, err := sealQUICPacket(header, payload, pn, keys)
	if err != nil {
		return err
	}
	if _, err := conn.udp.Write(packet); err != nil {
		return ErrUpstreamFailed
	}
	return nil
}

func (conn *quicConn) writeStream(id uint64, data []byte, fin bool) error {
	frame := []byte{0x0a}
	if fin {
		frame[0] = 0x0b
	}
	frame = appendVarint(frame, id)
	frame = appendVarint(frame, uint64(len(data)))
	frame = append(frame, data...)
	return conn.sendPacket(spaceApplication, frame, false)
}

func (conn *quicConn) readStream(ctx context.Context, id uint64) ([]byte, error) {
	for {
		if stream := conn.streams[id]; stream != nil && stream.fin && len(stream.inbound) > 0 {
			return append([]byte(nil), stream.inbound...), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, ErrUpstreamFailed
		}
		if err := conn.receive(ctx); err != nil {
			return nil, err
		}
		_ = conn.drainTLS()
		_ = conn.flush(ctx)
	}
}

func (conn *quicConn) receive(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.udp.SetDeadline(deadline)
	} else {
		_ = conn.udp.SetDeadline(time.Now().Add(2 * time.Second))
	}
	buffer := make([]byte, quicMaxDatagram)
	read, err := conn.udp.Read(buffer)
	if err != nil || read == 0 {
		return ErrUpstreamFailed
	}
	return conn.handleDatagram(buffer[:read])
}

func (conn *quicConn) handleDatagram(datagram []byte) error {
	offset := 0
	for offset < len(datagram) {
		consumed, err := conn.handlePacket(datagram[offset:])
		if err != nil || consumed == 0 {
			return ErrUpstreamFailed
		}
		offset += consumed
	}
	return nil
}

func (conn *quicConn) handlePacket(packet []byte) (int, error) {
	if len(packet) < 5 {
		return 0, ErrUpstreamFailed
	}
	space := spaceApplication
	if packet[0]&0x80 != 0 {
		_, _, rest, err := peekLongHeaderCIDs(packet)
		if err != nil {
			return 0, err
		}
		space = longHeaderSpace(packet[0])
		_ = rest
	}
	readKeys := conn.readKeys[space]
	header, payload, consumed, pn, err := unprotectQUICPacket(packet, space, readKeys, conn.peerCID)
	if err != nil {
		return 0, quicFail(fmt.Errorf("unprotect space=%d first=%x len=%d: %v", space, packet[0], len(packet), err))
	}
	if space != spaceApplication {
		if dcid, scid, _, peekErr := peekLongHeaderCIDs(header); peekErr == nil && len(scid) > 0 && conn.client {
			conn.peerCID = append([]byte(nil), scid...)
			_ = dcid
		}
	}
	if int64(pn) > conn.largestRecv[space] {
		conn.largestRecv[space] = int64(pn)
	}
	if err := conn.handleFrames(space, payload); err != nil {
		return 0, err
	}
	return consumed, nil
}

func longHeaderSpace(first byte) quicSpace {
	switch (first >> 4) & 0x03 {
	case 0:
		return spaceInitial
	case 2:
		return spaceHandshake
	default:
		return spaceApplication
	}
}

func (conn *quicConn) handleFrames(space quicSpace, payload []byte) error {
	offset := 0
	for offset < len(payload) {
		kind := payload[offset]
		offset++
		switch {
		case kind == 0x00:
			continue
		case kind == 0x01:
			continue
		case kind == 0x02 || kind == 0x03:
			_, next, err := readVarint(payload, offset)
			if err != nil {
				return err
			}
			_, next, err = readVarint(payload, next)
			if err != nil {
				return err
			}
			count, next, err := readVarint(payload, next)
			if err != nil {
				return err
			}
			_, next, err = readVarint(payload, next)
			if err != nil {
				return err
			}
			for i := uint64(0); i < count; i++ {
				_, next, err = readVarint(payload, next)
				if err != nil {
					return err
				}
				_, next, err = readVarint(payload, next)
				if err != nil {
					return err
				}
			}
			if kind == 0x03 {
				_, next, err = readVarint(payload, next)
				if err != nil {
					return err
				}
				_, next, err = readVarint(payload, next)
				if err != nil {
					return err
				}
			}
			offset = next
		case kind == 0x06:
			cryptoOff, next, err := readVarint(payload, offset)
			if err != nil {
				return err
			}
			length, next, err := readVarint(payload, next)
			if err != nil || next+int(length) > len(payload) {
				return ErrUpstreamFailed
			}
			data := payload[next : next+int(length)]
			offset = next + int(length)
			needed := int(cryptoOff) + len(data)
			if len(conn.cryptoIn[space]) < needed {
				grown := make([]byte, needed)
				copy(grown, conn.cryptoIn[space])
				conn.cryptoIn[space] = grown
			}
			copy(conn.cryptoIn[space][cryptoOff:], data)
			level := tls.QUICEncryptionLevelInitial
			if space == spaceHandshake {
				level = tls.QUICEncryptionLevelHandshake
			} else if space == spaceApplication {
				level = tls.QUICEncryptionLevelApplication
			}
			for int(conn.cryptoRead[space]) < len(conn.cryptoIn[space]) {
				next := conn.cryptoIn[space][conn.cryptoRead[space]:]
				if err := conn.tls.HandleData(level, next); err != nil {
					return quicFail(err)
				}
				conn.cryptoRead[space] += uint64(len(next))
			}
		case kind >= 0x08 && kind <= 0x0f:
			offBit := kind&0x04 != 0
			lenBit := kind&0x02 != 0
			fin := kind&0x01 != 0
			id, next, err := readVarint(payload, offset)
			if err != nil {
				return err
			}
			streamOff := uint64(0)
			if offBit {
				streamOff, next, err = readVarint(payload, next)
				if err != nil {
					return err
				}
			}
			var data []byte
			if lenBit {
				length, n, readErr := readVarint(payload, next)
				if readErr != nil || n+int(length) > len(payload) {
					return ErrUpstreamFailed
				}
				data = payload[n : n+int(length)]
				offset = n + int(length)
			} else {
				data = payload[next:]
				offset = len(payload)
			}
			stream := conn.streams[id]
			if stream == nil {
				stream = &quicStream{}
				conn.streams[id] = stream
			}
			if streamOff == 0 {
				stream.inbound = append(stream.inbound, data...)
			} else {
				needed := int(streamOff) + len(data)
				if len(stream.inbound) < needed {
					grown := make([]byte, needed)
					copy(grown, stream.inbound)
					stream.inbound = grown
				}
				copy(stream.inbound[streamOff:], data)
			}
			if fin {
				stream.fin = true
			}
		case kind == 0x1c || kind == 0x1d:
			return ErrUpstreamFailed
		default:
			return ErrUpstreamFailed
		}
	}
	return nil
}

func encodeACK(largest uint64) []byte {
	out := []byte{0x02}
	out = appendVarint(out, largest)
	out = appendVarint(out, 0)
	out = appendVarint(out, 0)
	out = appendVarint(out, largest)
	return out
}

func encodeLongHeader(space quicSpace, dcid, scid []byte, pn uint64, length int) []byte {
	first := byte(0xc0 | 0x03)
	switch space {
	case spaceHandshake:
		first = 0xe0 | 0x03
	case spaceApplication:
		return encodeShortHeader(dcid, pn)
	}
	out := []byte{first, 0, 0, 0, 1, byte(len(dcid))}
	out = append(out, dcid...)
	out = append(out, byte(len(scid)))
	out = append(out, scid...)
	if space == spaceInitial {
		out = appendVarint(out, 0)
	}
	if length == 0 {
		length = 4
	}
	out = appendVarint2(out, uint64(length))
	return out
}

func encodeShortHeader(dcid []byte, pn uint64) []byte {
	out := []byte{0x43}
	return append(out, dcid...)
}

func sealQUICPacket(header, payload []byte, pn uint64, keys quicKeys) ([]byte, error) {
	pnBytes := []byte{byte(pn >> 24), byte(pn >> 16), byte(pn >> 8), byte(pn)}
	fullHeader := append(append([]byte(nil), header...), pnBytes...)
	if header[0]&0x80 != 0 {
		// patch Length to cover PN + ciphertext
		fullHeader = patchLongLength(header, 4+len(payload)+16)
		fullHeader = append(fullHeader, pnBytes...)
	}
	nonce := aeadNonce(keys.iv, pn)
	aead, err := aesGCM(keys.key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, payload, fullHeader)
	packet := append(fullHeader, ciphertext...)
	return protectHeader(packet, len(fullHeader)-4, keys.hp), nil
}

func patchLongLength(header []byte, payloadLen int) []byte {
	dcid, scid, rest, err := peekLongHeaderCIDs(header)
	if err != nil {
		return header
	}
	_ = dcid
	_ = scid
	offset := len(header) - len(rest)
	if (header[0]>>4)&0x03 == 0 {
		_, next, readErr := readVarint(header, offset)
		if readErr != nil {
			return header
		}
		offset = next
	}
	out := append([]byte(nil), header[:offset]...)
	out = appendVarint2(out, uint64(payloadLen))
	return out
}

func unprotectQUICPacket(packet []byte, space quicSpace, keys quicKeys, shortCID []byte) ([]byte, []byte, int, uint64, error) {
	if len(keys.key) == 0 || len(packet) < 20 {
		return nil, nil, 0, 0, ErrUpstreamFailed
	}
	pnOffset, hdrLenGuess, err := headerPNOffset(packet, space, shortCID)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	unprotected := unprotectHeader(append([]byte(nil), packet...), pnOffset, keys.hp)
	pnLen := int(unprotected[0]&0x03) + 1
	if pnOffset+pnLen > len(unprotected) {
		return nil, nil, 0, 0, ErrUpstreamFailed
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(unprotected[pnOffset+i])
	}
	header := unprotected[:pnOffset+pnLen]
	aead, err := aesGCM(keys.key)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	body, err := aead.Open(nil, aeadNonce(keys.iv, pn), unprotected[pnOffset+pnLen:], header)
	if err != nil {
		return nil, nil, 0, 0, ErrUpstreamFailed
	}
	consumed := len(packet)
	if space != spaceApplication {
		consumed = pnOffset + pnLen + len(body) + 16
		if consumed > len(packet) {
			consumed = len(packet)
		}
	}
	_ = hdrLenGuess
	return header, body, consumed, pn, nil
}

func headerPNOffset(packet []byte, space quicSpace, shortCID []byte) (int, int, error) {
	if packet[0]&0x80 == 0 {
		return 1 + len(shortCID), 1 + len(shortCID) + 4, nil
	}
	_, _, rest, err := peekLongHeaderCIDs(packet)
	if err != nil {
		return 0, 0, err
	}
	offset := len(packet) - len(rest)
	if space == spaceInitial {
		_, offset, err = readVarint(packet, offset)
		if err != nil {
			return 0, 0, err
		}
	}
	_, offset, err = readVarint(packet, offset)
	if err != nil {
		return 0, 0, err
	}
	return offset, offset + 4, nil
}

func protectHeader(packet []byte, pnOffset int, hp []byte) []byte {
	sample := packet[pnOffset+4 : pnOffset+20]
	mask := aesECB(hp, sample)
	out := append([]byte(nil), packet...)
	pnLen := int(out[0]&0x03) + 1
	if out[0]&0x80 != 0 {
		out[0] ^= mask[0] & 0x0f
	} else {
		out[0] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen && pnOffset+i < len(out); i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

func unprotectHeader(packet []byte, pnOffset int, hp []byte) []byte {
	sample := packet[pnOffset+4 : pnOffset+20]
	mask := aesECB(hp, sample)
	out := append([]byte(nil), packet...)
	if out[0]&0x80 != 0 {
		out[0] ^= mask[0] & 0x0f
	} else {
		out[0] ^= mask[0] & 0x1f
	}
	pnLen := int(out[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

func aesECB(key, sample []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	out := make([]byte, 16)
	block.Encrypt(out, sample[:16])
	return out
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aeadNonce(iv []byte, pn uint64) []byte {
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	return nonce
}

func peekLongHeaderCIDs(packet []byte) (dcid, scid, rest []byte, err error) {
	if len(packet) < 6 || packet[0]&0x80 == 0 {
		return nil, nil, nil, ErrInvalidRequest
	}
	offset := 5
	if offset >= len(packet) {
		return nil, nil, nil, ErrInvalidRequest
	}
	dcidLen := int(packet[offset])
	offset++
	if offset+dcidLen >= len(packet) {
		return nil, nil, nil, ErrInvalidRequest
	}
	dcid = packet[offset : offset+dcidLen]
	offset += dcidLen
	scidLen := int(packet[offset])
	offset++
	if offset+scidLen > len(packet) {
		return nil, nil, nil, ErrInvalidRequest
	}
	scid = packet[offset : offset+scidLen]
	offset += scidLen
	return dcid, scid, packet[offset:], nil
}

func appendVarint2(dst []byte, value uint64) []byte {
	return append(dst, byte(0x40|value>>8), byte(value))
}

func appendVarint(dst []byte, value uint64) []byte {
	switch {
	case value <= 63:
		return append(dst, byte(value))
	case value <= 16383:
		return append(dst, byte(0x40|value>>8), byte(value))
	case value <= 1073741823:
		return append(dst, byte(0x80|value>>24), byte(value>>16), byte(value>>8), byte(value))
	default:
		return append(dst, byte(0xc0|value>>56), byte(value>>48), byte(value>>40), byte(value>>32), byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
}

func readVarint(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, ErrInvalidRequest
	}
	first := data[offset]
	switch first >> 6 {
	case 0:
		return uint64(first & 0x3f), offset + 1, nil
	case 1:
		if offset+2 > len(data) {
			return 0, 0, ErrInvalidRequest
		}
		return uint64(first&0x3f)<<8 | uint64(data[offset+1]), offset + 2, nil
	case 2:
		if offset+4 > len(data) {
			return 0, 0, ErrInvalidRequest
		}
		return uint64(first&0x3f)<<24 | uint64(data[offset+1])<<16 | uint64(data[offset+2])<<8 | uint64(data[offset+3]), offset + 4, nil
	default:
		if offset+8 > len(data) {
			return 0, 0, ErrInvalidRequest
		}
		var value uint64
		value = uint64(first&0x3f) << 56
		for i := 1; i < 8; i++ {
			value |= uint64(data[offset+i]) << uint((7-i)*8)
		}
		return value, offset + 8, nil
	}
}

func exchangeDNSCrypt(ctx context.Context, spec transportSpec, query []byte, limit int) ([]byte, error) {
	cert, err := fetchDNSCryptCert(ctx, spec)
	if err != nil {
		return nil, err
	}
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	resolverPub, err := ecdh.X25519().NewPublicKey(cert.resolverPK)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	shared, err := clientPriv.ECDH(resolverPub)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	boxKey := hsalsa20(shared, make([]byte, 16))
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce[:12]); err != nil {
		return nil, ErrUpstreamFailed
	}
	boxed := secretboxSeal(boxKey, nonce, padDNSCryptQuery(query))
	packet := append(append(append(append([]byte(nil), cert.clientMagic...), clientPriv.PublicKey().Bytes()...), nonce[:12]...), boxed...)
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", spec.address)
	if err != nil {
		return nil, ErrUpstreamFailed
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, ErrUpstreamFailed
	}
	buffer := make([]byte, max(limit+64, 4096))
	read, err := conn.Read(buffer)
	if err != nil || read < 8+12+16 {
		return nil, ErrUpstreamFailed
	}
	if string(buffer[:8]) != dnsCryptResolverMagic {
		return nil, ErrUpstreamFailed
	}
	copy(nonce[12:], buffer[8:20])
	plain, ok := secretboxOpen(boxKey, nonce, buffer[20:read])
	if !ok {
		return nil, ErrUpstreamFailed
	}
	plain = trimDNSCryptPadding(plain)
	if len(plain) < 12 || len(plain) > limit {
		return nil, ErrResponseTooLarge
	}
	return plain, nil
}

type dnsCryptCert struct {
	resolverPK  []byte
	clientMagic []byte
}

func fetchDNSCryptCert(ctx context.Context, spec transportSpec) (dnsCryptCert, error) {
	name := spec.stamp.hostname
	if name == "" {
		return dnsCryptCert{}, ErrInvalidRequest
	}
	query := dnsQuestionMessage(name, 16)
	response, err := exchangePacket(ctx, "udp", spec.address, query, MaxDNSResponseBytes)
	if err != nil {
		return dnsCryptCert{}, err
	}
	records := txtRecords(response)
	now := uint32(time.Now().Unix())
	for _, record := range records {
		cert, ok := parseDNSCryptCert(record, spec.stamp.publicKey, now)
		if ok {
			return cert, nil
		}
	}
	return dnsCryptCert{}, ErrUpstreamFailed
}

func parseDNSCryptCert(record, providerPK []byte, now uint32) (dnsCryptCert, bool) {
	if len(record) < 124 || binary.BigEndian.Uint32(record[:4]) != dnsCryptCertMagic {
		return dnsCryptCert{}, false
	}
	if binary.BigEndian.Uint16(record[4:6]) != 1 {
		return dnsCryptCert{}, false
	}
	signed := record[72:124]
	if !ed25519.Verify(providerPK, signed, record[8:72]) {
		return dnsCryptCert{}, false
	}
	start := binary.BigEndian.Uint32(record[116:120])
	end := binary.BigEndian.Uint32(record[120:124])
	if now < start || now > end {
		return dnsCryptCert{}, false
	}
	return dnsCryptCert{resolverPK: append([]byte(nil), record[72:104]...), clientMagic: append([]byte(nil), record[104:112]...)}, true
}

func dnsQuestionMessage(name string, qtype uint16) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire[0:2], 1)
	binary.BigEndian.PutUint16(wire[2:4], 0x0100)
	binary.BigEndian.PutUint16(wire[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return wire
}

func txtRecords(message []byte) [][]byte {
	if len(message) < 12 {
		return nil
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	offset := 12
	for i := 0; i < questions; i++ {
		next, err := skipDNSName(message, offset)
		if err != nil || next+4 > len(message) {
			return nil
		}
		offset = next + 4
	}
	var records [][]byte
	for i := 0; i < answers; i++ {
		next, err := skipDNSName(message, offset)
		if err != nil || next+10 > len(message) {
			return nil
		}
		typ := binary.BigEndian.Uint16(message[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(message) {
			return nil
		}
		if typ == 16 {
			records = append(records, concatTXT(message[rdata:rdata+rdlen]))
		}
		offset = rdata + rdlen
	}
	return records
}

func concatTXT(rdata []byte) []byte {
	var out []byte
	for offset := 0; offset < len(rdata); {
		n := int(rdata[offset])
		offset++
		if offset+n > len(rdata) {
			return out
		}
		out = append(out, rdata[offset:offset+n]...)
		offset += n
	}
	return out
}

func padDNSCryptQuery(query []byte) []byte {
	padded := append([]byte(nil), query...)
	if len(padded) < dnsCryptMinPad {
		padded = append(padded, make([]byte, dnsCryptMinPad-len(padded))...)
	}
	for len(padded)%dnsCryptPadAlign != 0 {
		padded = append(padded, 0)
	}
	return padded
}

func trimDNSCryptPadding(plain []byte) []byte {
	for len(plain) > 12 && plain[len(plain)-1] == 0 {
		plain = plain[:len(plain)-1]
	}
	return plain
}

func secretboxSeal(key, nonce, message []byte) []byte {
	subkey := hsalsa20(key, nonce[:16])
	stream := salsa20XOR(subkey, nonce[16:], make([]byte, 32+len(message)))
	out := make([]byte, 16+len(message))
	for i := range message {
		out[16+i] = message[i] ^ stream[32+i]
	}
	copy(out[:16], poly1305Sum(stream[:32], out[16:]))
	return out
}

func secretboxOpen(key, nonce, boxed []byte) ([]byte, bool) {
	if len(boxed) < 16 {
		return nil, false
	}
	subkey := hsalsa20(key, nonce[:16])
	stream := salsa20XOR(subkey, nonce[16:], make([]byte, 32+len(boxed)-16))
	if !poly1305Verify(stream[:32], boxed[16:], boxed[:16]) {
		return nil, false
	}
	plain := make([]byte, len(boxed)-16)
	for i := range plain {
		plain[i] = boxed[16+i] ^ stream[32+i]
	}
	return plain, true
}

func hsalsa20(key, nonce []byte) []byte {
	var in [16]uint32
	in[0], in[5], in[10], in[15] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	in[1] = binary.LittleEndian.Uint32(key[0:4])
	in[2] = binary.LittleEndian.Uint32(key[4:8])
	in[3] = binary.LittleEndian.Uint32(key[8:12])
	in[4] = binary.LittleEndian.Uint32(key[12:16])
	in[11] = binary.LittleEndian.Uint32(key[16:20])
	in[12] = binary.LittleEndian.Uint32(key[20:24])
	in[13] = binary.LittleEndian.Uint32(key[24:28])
	in[14] = binary.LittleEndian.Uint32(key[28:32])
	in[6] = binary.LittleEndian.Uint32(nonce[0:4])
	in[7] = binary.LittleEndian.Uint32(nonce[4:8])
	in[8] = binary.LittleEndian.Uint32(nonce[8:12])
	in[9] = binary.LittleEndian.Uint32(nonce[12:16])
	out := salsa20Rounds(in)
	keyOut := make([]byte, 32)
	binary.LittleEndian.PutUint32(keyOut[0:4], out[0])
	binary.LittleEndian.PutUint32(keyOut[4:8], out[5])
	binary.LittleEndian.PutUint32(keyOut[8:12], out[10])
	binary.LittleEndian.PutUint32(keyOut[12:16], out[15])
	binary.LittleEndian.PutUint32(keyOut[16:20], out[6])
	binary.LittleEndian.PutUint32(keyOut[20:24], out[7])
	binary.LittleEndian.PutUint32(keyOut[24:28], out[8])
	binary.LittleEndian.PutUint32(keyOut[28:32], out[9])
	return keyOut
}

func salsa20XOR(key, nonce, message []byte) []byte {
	out := make([]byte, len(message))
	var counter uint64
	for offset := 0; offset < len(message); offset += 64 {
		block := salsa20Block(key, nonce, counter)
		counter++
		n := copy(out[offset:], block)
		for i := 0; i < n && offset+i < len(message); i++ {
			out[offset+i] = message[offset+i] ^ block[i]
		}
	}
	return out
}

func salsa20Block(key, nonce []byte, counter uint64) []byte {
	var in [16]uint32
	in[0], in[5], in[10], in[15] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	in[1] = binary.LittleEndian.Uint32(key[0:4])
	in[2] = binary.LittleEndian.Uint32(key[4:8])
	in[3] = binary.LittleEndian.Uint32(key[8:12])
	in[4] = binary.LittleEndian.Uint32(key[12:16])
	in[11] = binary.LittleEndian.Uint32(key[16:20])
	in[12] = binary.LittleEndian.Uint32(key[20:24])
	in[13] = binary.LittleEndian.Uint32(key[24:28])
	in[14] = binary.LittleEndian.Uint32(key[28:32])
	in[6] = uint32(counter)
	in[7] = uint32(counter >> 32)
	in[8] = binary.LittleEndian.Uint32(nonce[0:4])
	in[9] = binary.LittleEndian.Uint32(nonce[4:8])
	out := salsa20Rounds(in)
	block := make([]byte, 64)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(block[i*4:], out[i]+in[i])
	}
	return block
}

func salsa20Rounds(in [16]uint32) [16]uint32 {
	x := in
	for i := 0; i < 10; i++ {
		x[4] ^= rotl32(x[0]+x[12], 7)
		x[8] ^= rotl32(x[4]+x[0], 9)
		x[12] ^= rotl32(x[8]+x[4], 13)
		x[0] ^= rotl32(x[12]+x[8], 18)
		x[9] ^= rotl32(x[5]+x[1], 7)
		x[13] ^= rotl32(x[9]+x[5], 9)
		x[1] ^= rotl32(x[13]+x[9], 13)
		x[5] ^= rotl32(x[1]+x[13], 18)
		x[14] ^= rotl32(x[10]+x[6], 7)
		x[2] ^= rotl32(x[14]+x[10], 9)
		x[6] ^= rotl32(x[2]+x[14], 13)
		x[10] ^= rotl32(x[6]+x[2], 18)
		x[3] ^= rotl32(x[15]+x[11], 7)
		x[7] ^= rotl32(x[3]+x[15], 9)
		x[11] ^= rotl32(x[7]+x[3], 13)
		x[15] ^= rotl32(x[11]+x[7], 18)
		x[1] ^= rotl32(x[0]+x[3], 7)
		x[2] ^= rotl32(x[1]+x[0], 9)
		x[3] ^= rotl32(x[2]+x[1], 13)
		x[0] ^= rotl32(x[3]+x[2], 18)
		x[6] ^= rotl32(x[5]+x[4], 7)
		x[7] ^= rotl32(x[6]+x[5], 9)
		x[4] ^= rotl32(x[7]+x[6], 13)
		x[5] ^= rotl32(x[4]+x[7], 18)
		x[11] ^= rotl32(x[10]+x[9], 7)
		x[8] ^= rotl32(x[11]+x[10], 9)
		x[9] ^= rotl32(x[8]+x[11], 13)
		x[10] ^= rotl32(x[9]+x[8], 18)
		x[12] ^= rotl32(x[15]+x[14], 7)
		x[13] ^= rotl32(x[12]+x[15], 9)
		x[14] ^= rotl32(x[13]+x[12], 13)
		x[15] ^= rotl32(x[14]+x[13], 18)
	}
	return x
}

func rotl32(value uint32, n uint) uint32 {
	return value<<n | value>>(32-n)
}

func poly1305Sum(key, message []byte) []byte {
	rBytes := append([]byte(nil), key[:16]...)
	rBytes[3] &= 15
	rBytes[7] &= 15
	rBytes[11] &= 15
	rBytes[15] &= 15
	rBytes[4] &= 252
	rBytes[8] &= 252
	rBytes[12] &= 252
	r := leInt(rBytes)
	s := leInt(key[16:32])
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	h := new(big.Int)
	for offset := 0; offset < len(message); offset += 16 {
		n := 16
		if remain := len(message) - offset; remain < 16 {
			n = remain
		}
		block := make([]byte, n+1)
		copy(block, message[offset:offset+n])
		block[n] = 1
		h.Add(h, leInt(block))
		h.Mul(h, r)
		h.Mod(h, p)
	}
	h.Add(h, s)
	out := make([]byte, 16)
	hBytes := h.Bytes()
	for i := 0; i < len(hBytes) && i < 16; i++ {
		out[i] = hBytes[len(hBytes)-1-i]
	}
	return out
}

func leInt(value []byte) *big.Int {
	reversed := make([]byte, len(value))
	for i := range value {
		reversed[len(value)-1-i] = value[i]
	}
	return new(big.Int).SetBytes(reversed)
}

func poly1305Verify(key, message, tag []byte) bool {
	got := poly1305Sum(key, message)
	if len(got) != len(tag) {
		return false
	}
	var v byte
	for i := range got {
		v |= got[i] ^ tag[i]
	}
	return v == 0
}

func normalizeUpstreamEndpoint(endpoint string) (string, error) {
	spec, err := parseTransportSpec(endpoint)
	if err != nil {
		return "", err
	}
	if spec.kind != transportHTTPS {
		return "", ErrInvalidRequest
	}
	return spec.httpsURL, nil
}
