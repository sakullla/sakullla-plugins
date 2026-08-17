package shadowsocksserver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxLegacyPayload      = 0x3fff
	max2022Payload        = 0xffff
	max2022Padding        = 900
	maxUDPPacket          = 65507
	ss2022IdentitySize    = 16
	ss2022KDFContext      = "shadowsocks 2022 session subkey"
	ss2022IdentityContext = "shadowsocks 2022 identity subkey"
)

var (
	ErrUnsupportedMethod = errors.New("unsupported Shadowsocks method")
	ErrAuthentication    = errors.New("Shadowsocks authentication failed")
	ErrProtocol          = errors.New("invalid Shadowsocks wire data")
)

var supportedMethods = map[string]int{
	"aes-128-gcm":             16,
	"aes-256-gcm":             32,
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
}

func SupportedMethod(method string) bool {
	_, ok := supportedMethods[method]
	return ok
}

func MethodKeyLength(method string) int {
	return supportedMethods[method]
}

type ProxyRequest struct {
	UserID      string
	Target      string
	Payload     []byte
	ReplayToken []byte
	SessionID   uint64
	PacketID    uint64
}

type TCPServerSession struct {
	mu          sync.Mutex
	engine      *ProtocolEngine
	inbound     *streamCipher
	outbound    *streamCipher
	requestSalt []byte
	modern      bool
	closed      bool
}

// ProtocolEngine owns a single user's master key. SS2022 identity engines also
// hold the instance server PSK and require SIP022 identity headers. All wire
// parsing and AEAD authentication happen in this repository; Host adapters
// never receive a cipher name, password, PSK, or plaintext protocol frame.
type ProtocolEngine struct {
	method   string
	key      []byte
	identity []byte
	keyLen   int
	modern   bool
	mu       sync.RWMutex
	dead     bool
}

// NewProtocolEngine builds a cipher engine. SS2022 material is one canonical
// standard-Base64 PSK, or serverPSK:userPSK to enable SIP022 identity headers.
func NewProtocolEngine(method string, material []byte) (*ProtocolEngine, error) {
	keyLen, ok := supportedMethods[method]
	if !ok || len(material) == 0 {
		return nil, ErrUnsupportedMethod
	}
	if !strings.HasPrefix(method, "2022-") {
		return &ProtocolEngine{method: method, key: evpBytesToKey(material, keyLen), keyLen: keyLen}, nil
	}
	if bytes.IndexByte(material, ':') >= 0 {
		serverPSK, userPSK, ok := splitSS2022ClientPassword(material)
		if !ok {
			return nil, ErrInvalid
		}
		return newSS2022IdentityEngine(method, serverPSK, userPSK)
	}
	key, err := decodeSS2022PSK(method, string(material))
	if err != nil {
		return nil, err
	}
	return &ProtocolEngine{method: method, key: key, keyLen: keyLen, modern: true}, nil
}

// NewSS2022IdentityEngine uses the instance server PSK plus a distinct per-user
// identity PSK. The client password is serverPSK:userPSK.
func NewSS2022IdentityEngine(method string, serverPSK, userPSK []byte) (*ProtocolEngine, error) {
	if !strings.HasPrefix(method, "2022-") || !SupportedMethod(method) {
		return nil, ErrUnsupportedMethod
	}
	return newSS2022IdentityEngine(method, serverPSK, userPSK)
}

func newSS2022IdentityEngine(method string, serverPSK, userPSK []byte) (*ProtocolEngine, error) {
	identity, err := decodeSS2022PSK(method, string(serverPSK))
	if err != nil {
		return nil, err
	}
	key, err := decodeSS2022PSK(method, string(userPSK))
	if err != nil {
		clear(identity)
		return nil, err
	}
	if bytes.Equal(identity, key) {
		clear(identity)
		clear(key)
		return nil, ErrInvalid
	}
	return &ProtocolEngine{method: method, key: key, identity: identity, keyLen: len(key), modern: true}, nil
}

func splitSS2022ClientPassword(material []byte) (serverPSK, userPSK []byte, ok bool) {
	index := bytes.IndexByte(material, ':')
	if index <= 0 || index >= len(material)-1 || bytes.IndexByte(material[index+1:], ':') >= 0 {
		return nil, nil, false
	}
	return material[:index], material[index+1:], true
}

func decodeSS2022PSK(method, encoded string) ([]byte, error) {
	if !strings.HasPrefix(method, "2022-") {
		return nil, ErrUnsupportedMethod
	}
	keyLen, ok := supportedMethods[method]
	if !ok {
		return nil, ErrUnsupportedMethod
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != keyLen || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}

func sip002ShareHostPort(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", ErrInvalid
	}
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) > 2 {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", ErrInvalid
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// EncodeSIP002 builds an importable ss:// URI. SS2022 percent-encodes method
// and password and never Base64URL-encodes userinfo. QR content is this URI.
func EncodeSIP002(method, password, host string, port int) (string, error) {
	if !SupportedMethod(method) || password == "" {
		return "", ErrInvalid
	}
	hostport, err := sip002ShareHostPort(host, port)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(method, "2022-") {
		if _, _, ok := splitSS2022ClientPassword([]byte(password)); !ok {
			return "", ErrInvalid
		}
		engine, err := NewProtocolEngine(method, []byte(password))
		if err != nil {
			return "", err
		}
		engine.Destroy()
		return "ss://" + url.UserPassword(method, password).String() + "@" + hostport, nil
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return "ss://" + userinfo + "@" + hostport, nil
}

// SIP002URI is EncodeSIP002.
func SIP002URI(method, password, host string, port int) (string, error) {
	return EncodeSIP002(method, password, host, port)
}

// SIP002QRCode is the QR payload, which is exactly the SIP002 URI.
func SIP002QRCode(uri string) string {
	return uri
}

// SIP002QRContent is SIP002QRCode.
func SIP002QRContent(uri string) string {
	return SIP002QRCode(uri)
}

func (e *ProtocolEngine) Name() string {
	if e == nil {
		return ""
	}
	return e.method
}

func (e *ProtocolEngine) SaltSize() int {
	if e == nil {
		return 0
	}
	return e.keyLen
}

func (e *ProtocolEngine) HasIdentity() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return !e.dead && len(e.identity) == e.keyLen
}

func (e *ProtocolEngine) Destroy() {
	if e == nil {
		return
	}
	e.mu.Lock()
	clear(e.key)
	e.key = nil
	clear(e.identity)
	e.identity = nil
	e.dead = true
	e.mu.Unlock()
}

func (e *ProtocolEngine) keySnapshot() ([]byte, error) {
	user, identity, err := e.keysSnapshot()
	clear(identity)
	return user, err
}

func (e *ProtocolEngine) keysSnapshot() (user, identity []byte, err error) {
	if e == nil {
		return nil, nil, ErrAuthentication
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.dead || len(e.key) != e.keyLen {
		return nil, nil, ErrRevoked
	}
	if len(e.identity) != 0 && len(e.identity) != e.keyLen {
		return nil, nil, ErrRevoked
	}
	user = append([]byte(nil), e.key...)
	if len(e.identity) != 0 {
		identity = append([]byte(nil), e.identity...)
	}
	return user, identity, nil
}

func (e *ProtocolEngine) OpenTCPRequest(wire []byte, now time.Time) (ProxyRequest, error) {
	request, session, err := e.OpenTCPServerSession(wire, now)
	if session != nil {
		session.Close()
	}
	return request, err
}

func (e *ProtocolEngine) OpenTCPServerSession(wire []byte, now time.Time) (ProxyRequest, *TCPServerSession, error) {
	key, identity, err := e.keysSnapshot()
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	defer clear(key)
	defer clear(identity)
	if e.modern {
		return e.open2022TCP(key, identity, wire, now)
	}
	return e.openLegacyTCP(key, wire)
}

func (s *TCPServerSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.inbound = nil
	s.outbound = nil
	clear(s.requestSalt)
	s.requestSalt = nil
	s.mu.Unlock()
}

func (s *TCPServerSession) OpenPayloadChunk(wire []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrRevoked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.inbound == nil {
		return nil, ErrRevoked
	}
	maximum := maxLegacyPayload
	if s.modern {
		maximum = max2022Payload
	}
	return openPayloadChunk(s.inbound, wire, maximum)
}

// SealResponse starts the server-to-client stream. The caller supplies a
// unique random response salt of the method's SaltSize. SS2022 binds the
// response header to the authenticated request salt.
func (s *TCPServerSession) SealResponse(responseSalt, payload []byte, now time.Time) ([]byte, error) {
	if s == nil {
		return nil, ErrRevoked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.outbound != nil || s.engine == nil || len(responseSalt) != s.engine.SaltSize() {
		return nil, ErrProtocol
	}
	key, err := s.engine.keySnapshot()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	outbound, err := s.engine.newSession(key, responseSalt)
	if err != nil {
		return nil, err
	}
	maximum := maxLegacyPayload
	if s.modern {
		maximum = max2022Payload
	}
	if len(payload) > maximum || s.modern && len(payload) == 0 {
		return nil, ErrProtocol
	}
	wire := append([]byte(nil), responseSalt...)
	if s.modern {
		fixed := make([]byte, 1+8+len(s.requestSalt)+2)
		fixed[0] = 1
		binary.BigEndian.PutUint64(fixed[1:9], uint64(now.Unix()))
		copy(fixed[9:], s.requestSalt)
		binary.BigEndian.PutUint16(fixed[len(fixed)-2:], uint16(len(payload)))
		wire = append(wire, outbound.seal(fixed)...)
		wire = append(wire, outbound.seal(payload)...)
	} else {
		wire = append(wire, sealPayloadChunk(outbound, payload)...)
	}
	s.outbound = outbound
	return wire, nil
}

func (s *TCPServerSession) SealPayloadChunk(payload []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrRevoked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.outbound == nil {
		return nil, ErrRevoked
	}
	maximum := maxLegacyPayload
	if s.modern {
		maximum = max2022Payload
	}
	if len(payload) > maximum {
		return nil, ErrProtocol
	}
	return sealPayloadChunk(s.outbound, payload), nil
}

func sealPayloadChunk(session *streamCipher, payload []byte) []byte {
	length := []byte{byte(len(payload) >> 8), byte(len(payload))}
	wire := session.seal(length)
	return append(wire, session.seal(payload)...)
}

func openPayloadChunk(session *streamCipher, wire []byte, maximum int) ([]byte, error) {
	lengthWire := 2 + session.aead.Overhead()
	if len(wire) < lengthWire+session.aead.Overhead() {
		return nil, ErrProtocol
	}
	plainLength, err := session.open(wire[:lengthWire])
	if err != nil || len(plainLength) != 2 {
		return nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(plainLength))
	if length > maximum || len(wire)-lengthWire != length+session.aead.Overhead() {
		return nil, ErrProtocol
	}
	return session.open(wire[lengthWire:])
}

func (e *ProtocolEngine) SealTCPRequest(salt []byte, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	key, identity, err := e.keysSnapshot()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(identity)
	if len(salt) != e.keyLen {
		return nil, ErrProtocol
	}
	if e.modern {
		return e.seal2022TCP(key, identity, salt, target, payload, now, padding)
	}
	if len(padding) != 0 {
		return nil, ErrProtocol
	}
	return e.sealLegacyTCP(key, salt, target, payload)
}

func (e *ProtocolEngine) OpenUDPPacket(wire []byte, now time.Time) (ProxyRequest, error) {
	key, identity, err := e.keysSnapshot()
	if err != nil {
		return ProxyRequest{}, err
	}
	defer clear(key)
	defer clear(identity)
	if e.modern {
		return e.open2022UDP(key, identity, wire, now)
	}
	return e.openLegacyUDP(key, wire)
}

func (e *ProtocolEngine) SealUDPPacket(saltOrSession []byte, packetID uint64, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	key, identity, err := e.keysSnapshot()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(identity)
	if e.modern {
		return e.seal2022UDP(key, identity, saltOrSession, packetID, target, payload, now, padding)
	}
	if len(padding) != 0 || packetID != 0 || len(saltOrSession) != e.keyLen {
		return nil, ErrProtocol
	}
	return e.sealLegacyUDP(key, saltOrSession, target, payload)
}

// SealUDPResponse creates a server-to-client UDP packet. For legacy AEAD the
// clientSessionID is ignored and responseSalt must be SaltSize bytes. For
// SS2022 responseSalt is the server's 8-byte session ID and the authenticated
// body binds the packet to clientSessionID.
func (e *ProtocolEngine) SealUDPResponse(responseSalt []byte, packetID, clientSessionID uint64, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	key, err := e.keySnapshot()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if !e.modern {
		if len(responseSalt) != e.keyLen || packetID != 0 || clientSessionID != 0 || len(padding) != 0 {
			return nil, ErrProtocol
		}
		return e.sealLegacyUDP(key, responseSalt, target, payload)
	}
	return e.seal2022UDPResponse(key, responseSalt, packetID, clientSessionID, target, payload, now, padding)
}

func (e *ProtocolEngine) OpenUDPResponse(wire []byte, now time.Time, expectedClientSessionID uint64) (ProxyRequest, error) {
	key, err := e.keySnapshot()
	if err != nil {
		return ProxyRequest{}, err
	}
	defer clear(key)
	if !e.modern {
		return e.openLegacyUDP(key, wire)
	}
	return e.open2022UDPResponse(key, wire, now, expectedClientSessionID)
}

func (e *ProtocolEngine) newSession(master, salt []byte) (*streamCipher, error) {
	if len(salt) != e.keyLen {
		return nil, ErrProtocol
	}
	var subkey []byte
	if e.modern {
		material := make([]byte, 0, len(master)+len(salt))
		material = append(material, master...)
		material = append(material, salt...)
		derived, err := blake3DeriveKey(ss2022KDFContext, material)
		clear(material)
		if err != nil {
			return nil, err
		}
		subkey = append([]byte(nil), derived[:e.keyLen]...)
		clear(derived[:])
	} else {
		subkey = hkdfSHA1(master, salt, []byte("ss-subkey"), e.keyLen)
	}
	block, err := aes.NewCipher(subkey)
	clear(subkey)
	if err != nil {
		return nil, ErrProtocol
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrProtocol
	}
	return &streamCipher{aead: aead}, nil
}

type streamCipher struct {
	aead  cipher.AEAD
	nonce [12]byte
}

func (s *streamCipher) seal(plaintext []byte) []byte {
	out := s.aead.Seal(nil, s.nonce[:], plaintext, nil)
	incrementNonce(&s.nonce)
	return out
}

func (s *streamCipher) open(ciphertext []byte) ([]byte, error) {
	out, err := s.aead.Open(nil, s.nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	incrementNonce(&s.nonce)
	return out, nil
}

func incrementNonce(nonce *[12]byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func (e *ProtocolEngine) sealLegacyTCP(key, salt []byte, target string, payload []byte) ([]byte, error) {
	address, err := encodeAddress(target)
	if err != nil || len(address)+len(payload) > maxLegacyPayload {
		return nil, ErrProtocol
	}
	session, err := e.newSession(key, salt)
	if err != nil {
		return nil, err
	}
	body := append(address, payload...)
	length := []byte{byte(len(body) >> 8), byte(len(body))}
	wire := append([]byte(nil), salt...)
	wire = append(wire, session.seal(length)...)
	wire = append(wire, session.seal(body)...)
	clear(body)
	return wire, nil
}

func (e *ProtocolEngine) openLegacyTCP(key, wire []byte) (ProxyRequest, *TCPServerSession, error) {
	if len(wire) < e.keyLen+2+32 {
		return ProxyRequest{}, nil, ErrProtocol
	}
	salt := append([]byte(nil), wire[:e.keyLen]...)
	session, err := e.newSession(key, salt)
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	position := e.keyLen
	lengthWire := wire[position : position+2+session.aead.Overhead()]
	position += len(lengthWire)
	lengthPlain, err := session.open(lengthWire)
	if err != nil || len(lengthPlain) != 2 {
		return ProxyRequest{}, nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	if length == 0 || length > maxLegacyPayload || len(wire)-position != length+session.aead.Overhead() {
		return ProxyRequest{}, nil, ErrProtocol
	}
	body, err := session.open(wire[position:])
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	target, consumed, err := decodeAddress(body)
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	request := ProxyRequest{Target: target, Payload: append([]byte(nil), body[consumed:]...), ReplayToken: append([]byte(nil), salt...)}
	return request, &TCPServerSession{engine: e, inbound: session, requestSalt: salt}, nil
}

func (e *ProtocolEngine) sealLegacyUDP(key, salt []byte, target string, payload []byte) ([]byte, error) {
	address, err := encodeAddress(target)
	if err != nil || e.keyLen+16+len(address)+len(payload) > maxUDPPacket {
		return nil, ErrProtocol
	}
	session, err := e.newSession(key, salt)
	if err != nil {
		return nil, err
	}
	body := append(address, payload...)
	wire := append([]byte(nil), salt...)
	wire = append(wire, session.seal(body)...)
	clear(body)
	return wire, nil
}

func (e *ProtocolEngine) openLegacyUDP(key, wire []byte) (ProxyRequest, error) {
	if len(wire) < e.keyLen+1+2+16 || len(wire) > maxUDPPacket {
		return ProxyRequest{}, ErrProtocol
	}
	salt := append([]byte(nil), wire[:e.keyLen]...)
	session, err := e.newSession(key, salt)
	if err != nil {
		return ProxyRequest{}, err
	}
	body, err := session.open(wire[e.keyLen:])
	if err != nil {
		return ProxyRequest{}, err
	}
	target, consumed, err := decodeAddress(body)
	if err != nil {
		return ProxyRequest{}, err
	}
	return ProxyRequest{Target: target, Payload: append([]byte(nil), body[consumed:]...), ReplayToken: salt}, nil
}

func (e *ProtocolEngine) seal2022TCP(key, identity, salt []byte, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	if len(padding) > max2022Padding || len(payload) > max2022Payload {
		return nil, ErrProtocol
	}
	address, err := encodeAddress(target)
	if err != nil || len(address)+2+len(padding)+len(payload) > max2022Payload || len(padding)+len(payload) == 0 {
		return nil, ErrProtocol
	}
	variable := make([]byte, 0, len(address)+2+len(padding)+len(payload))
	variable = append(variable, address...)
	variable = binary.BigEndian.AppendUint16(variable, uint16(len(padding)))
	variable = append(variable, padding...)
	variable = append(variable, payload...)
	fixed := make([]byte, 11)
	fixed[0] = 0
	binary.BigEndian.PutUint64(fixed[1:9], uint64(now.Unix()))
	binary.BigEndian.PutUint16(fixed[9:11], uint16(len(variable)))
	session, err := e.newSession(key, salt)
	if err != nil {
		return nil, err
	}
	wire := append([]byte(nil), salt...)
	if header, err := seal2022Identity(identity, key, salt); err != nil {
		return nil, err
	} else if len(header) != 0 {
		wire = append(wire, header...)
	}
	wire = append(wire, session.seal(fixed)...)
	wire = append(wire, session.seal(variable)...)
	clear(variable)
	return wire, nil
}

func (e *ProtocolEngine) open2022TCP(key, identity, wire []byte, now time.Time) (ProxyRequest, *TCPServerSession, error) {
	fixedWireLength := 11 + 16
	overhead := ss2022IdentityOverhead(identity)
	if len(wire) < e.keyLen+overhead+fixedWireLength+16 {
		return ProxyRequest{}, nil, ErrProtocol
	}
	salt := append([]byte(nil), wire[:e.keyLen]...)
	position := e.keyLen
	if overhead != 0 {
		if err := open2022Identity(identity, key, salt, wire[position:position+ss2022IdentitySize]); err != nil {
			return ProxyRequest{}, nil, err
		}
		position += ss2022IdentitySize
	}
	session, err := e.newSession(key, salt)
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	fixed, err := session.open(wire[position : position+fixedWireLength])
	if err != nil || len(fixed) != 11 {
		return ProxyRequest{}, nil, ErrAuthentication
	}
	if fixed[0] != 0 || !timestampValid(binary.BigEndian.Uint64(fixed[1:9]), now) {
		return ProxyRequest{}, nil, ErrReplay
	}
	variableLength := int(binary.BigEndian.Uint16(fixed[9:11]))
	position += fixedWireLength
	if variableLength == 0 || len(wire)-position != variableLength+16 {
		return ProxyRequest{}, nil, ErrProtocol
	}
	variable, err := session.open(wire[position:])
	if err != nil {
		return ProxyRequest{}, nil, err
	}
	target, consumed, err := decodeAddress(variable)
	if err != nil || len(variable)-consumed < 2 {
		return ProxyRequest{}, nil, ErrProtocol
	}
	paddingLength := int(binary.BigEndian.Uint16(variable[consumed : consumed+2]))
	consumed += 2
	if paddingLength > max2022Padding || len(variable)-consumed < paddingLength {
		return ProxyRequest{}, nil, ErrProtocol
	}
	consumed += paddingLength
	if paddingLength == 0 && consumed == len(variable) {
		return ProxyRequest{}, nil, ErrProtocol
	}
	request := ProxyRequest{Target: target, Payload: append([]byte(nil), variable[consumed:]...), ReplayToken: append([]byte(nil), salt...)}
	return request, &TCPServerSession{engine: e, inbound: session, requestSalt: salt, modern: true}, nil
}

func (e *ProtocolEngine) seal2022UDP(key, identity, sessionID []byte, packetID uint64, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	if len(sessionID) != 8 || len(padding) > max2022Padding {
		return nil, ErrProtocol
	}
	address, err := encodeAddress(target)
	if err != nil || 16+16+11+len(padding)+len(address)+len(payload)+ss2022IdentityOverhead(identity) > maxUDPPacket {
		return nil, ErrProtocol
	}
	separate := make([]byte, 16)
	copy(separate[:8], sessionID)
	binary.BigEndian.PutUint64(separate[8:], packetID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrProtocol
	}
	encryptedSeparate := make([]byte, 16)
	block.Encrypt(encryptedSeparate, separate)
	material := append(append(make([]byte, 0, len(key)+8), key...), sessionID...)
	derived, err := blake3DeriveKey(ss2022KDFContext, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	subkey := append([]byte(nil), derived[:e.keyLen]...)
	clear(derived[:])
	bodyBlock, err := aes.NewCipher(subkey)
	clear(subkey)
	if err != nil {
		return nil, ErrProtocol
	}
	aead, err := cipher.NewGCM(bodyBlock)
	if err != nil {
		return nil, ErrProtocol
	}
	body := []byte{0}
	body = binary.BigEndian.AppendUint64(body, uint64(now.Unix()))
	body = binary.BigEndian.AppendUint16(body, uint16(len(padding)))
	body = append(body, padding...)
	body = append(body, address...)
	body = append(body, payload...)
	header, err := seal2022Identity(identity, key, separate)
	if err != nil {
		return nil, err
	}
	wire := append(encryptedSeparate, header...)
	wire = append(wire, aead.Seal(nil, separate[4:16], body, nil)...)
	clear(body)
	return wire, nil
}

func (e *ProtocolEngine) open2022UDP(key, identity, wire []byte, now time.Time) (ProxyRequest, error) {
	overhead := ss2022IdentityOverhead(identity)
	if len(wire) < overhead+16+1+8+2+1+2+16 || len(wire) > maxUDPPacket {
		return ProxyRequest{}, ErrProtocol
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	separate := make([]byte, 16)
	block.Decrypt(separate, wire[:16])
	position := 16
	if overhead != 0 {
		if err := open2022Identity(identity, key, separate, wire[ss2022IdentitySize:2*ss2022IdentitySize]); err != nil {
			return ProxyRequest{}, err
		}
		position = 2 * ss2022IdentitySize
	}
	sessionID := binary.BigEndian.Uint64(separate[:8])
	packetID := binary.BigEndian.Uint64(separate[8:])
	material := append(append(make([]byte, 0, len(key)+8), key...), separate[:8]...)
	derived, err := blake3DeriveKey(ss2022KDFContext, material)
	clear(material)
	if err != nil {
		return ProxyRequest{}, err
	}
	subkey := append([]byte(nil), derived[:e.keyLen]...)
	clear(derived[:])
	bodyBlock, err := aes.NewCipher(subkey)
	clear(subkey)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	aead, err := cipher.NewGCM(bodyBlock)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	body, err := aead.Open(nil, separate[4:16], wire[position:], nil)
	if err != nil {
		return ProxyRequest{}, ErrAuthentication
	}
	if len(body) < 11 || body[0] != 0 || !timestampValid(binary.BigEndian.Uint64(body[1:9]), now) {
		return ProxyRequest{}, ErrReplay
	}
	paddingLength := int(binary.BigEndian.Uint16(body[9:11]))
	if paddingLength > max2022Padding || len(body) < 11+paddingLength {
		return ProxyRequest{}, ErrProtocol
	}
	target, consumed, err := decodeAddress(body[11+paddingLength:])
	if err != nil {
		return ProxyRequest{}, err
	}
	payloadStart := 11 + paddingLength + consumed
	replay := append([]byte(nil), separate...)
	return ProxyRequest{Target: target, Payload: append([]byte(nil), body[payloadStart:]...), ReplayToken: replay, SessionID: sessionID, PacketID: packetID}, nil
}

func (e *ProtocolEngine) seal2022UDPResponse(key, serverSessionID []byte, packetID, clientSessionID uint64, target string, payload []byte, now time.Time, padding []byte) ([]byte, error) {
	if len(serverSessionID) != 8 || len(padding) > max2022Padding {
		return nil, ErrProtocol
	}
	address, err := encodeAddress(target)
	if err != nil || 16+16+19+len(padding)+len(address)+len(payload) > maxUDPPacket {
		return nil, ErrProtocol
	}
	separate := make([]byte, 16)
	copy(separate[:8], serverSessionID)
	binary.BigEndian.PutUint64(separate[8:], packetID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrProtocol
	}
	encryptedSeparate := make([]byte, 16)
	block.Encrypt(encryptedSeparate, separate)
	material := append(append(make([]byte, 0, len(key)+8), key...), serverSessionID...)
	derived, err := blake3DeriveKey(ss2022KDFContext, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	subkey := append([]byte(nil), derived[:e.keyLen]...)
	clear(derived[:])
	bodyBlock, err := aes.NewCipher(subkey)
	clear(subkey)
	if err != nil {
		return nil, ErrProtocol
	}
	aead, err := cipher.NewGCM(bodyBlock)
	if err != nil {
		return nil, ErrProtocol
	}
	body := []byte{1}
	body = binary.BigEndian.AppendUint64(body, uint64(now.Unix()))
	body = binary.BigEndian.AppendUint64(body, clientSessionID)
	body = binary.BigEndian.AppendUint16(body, uint16(len(padding)))
	body = append(body, padding...)
	body = append(body, address...)
	body = append(body, payload...)
	wire := append(encryptedSeparate, aead.Seal(nil, separate[4:16], body, nil)...)
	clear(body)
	return wire, nil
}

func (e *ProtocolEngine) open2022UDPResponse(key, wire []byte, now time.Time, expectedClientSessionID uint64) (ProxyRequest, error) {
	if len(wire) < 16+1+8+8+2+1+2+16 || len(wire) > maxUDPPacket {
		return ProxyRequest{}, ErrProtocol
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	separate := make([]byte, 16)
	block.Decrypt(separate, wire[:16])
	serverSessionID := binary.BigEndian.Uint64(separate[:8])
	packetID := binary.BigEndian.Uint64(separate[8:])
	material := append(append(make([]byte, 0, len(key)+8), key...), separate[:8]...)
	derived, err := blake3DeriveKey(ss2022KDFContext, material)
	clear(material)
	if err != nil {
		return ProxyRequest{}, err
	}
	subkey := append([]byte(nil), derived[:e.keyLen]...)
	clear(derived[:])
	bodyBlock, err := aes.NewCipher(subkey)
	clear(subkey)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	aead, err := cipher.NewGCM(bodyBlock)
	if err != nil {
		return ProxyRequest{}, ErrProtocol
	}
	body, err := aead.Open(nil, separate[4:16], wire[16:], nil)
	if err != nil {
		return ProxyRequest{}, ErrAuthentication
	}
	if len(body) < 19 || body[0] != 1 || !timestampValid(binary.BigEndian.Uint64(body[1:9]), now) || binary.BigEndian.Uint64(body[9:17]) != expectedClientSessionID {
		return ProxyRequest{}, ErrReplay
	}
	paddingLength := int(binary.BigEndian.Uint16(body[17:19]))
	if paddingLength > max2022Padding || len(body) < 19+paddingLength {
		return ProxyRequest{}, ErrProtocol
	}
	target, consumed, err := decodeAddress(body[19+paddingLength:])
	if err != nil {
		return ProxyRequest{}, err
	}
	payloadStart := 19 + paddingLength + consumed
	return ProxyRequest{Target: target, Payload: append([]byte(nil), body[payloadStart:]...), ReplayToken: append([]byte(nil), separate...), SessionID: serverSessionID, PacketID: packetID}, nil
}

func ss2022IdentityOverhead(identity []byte) int {
	if len(identity) == 0 {
		return 0
	}
	return ss2022IdentitySize
}

// seal2022Identity writes SIP022 EIH: AES-ECB(identity_subkey(iPSK)[:16], uPSK[:16] XOR mask).
// TCP mask is salt[0:16]; UDP mask is the plaintext session header.
func seal2022Identity(ipsk, nextPSK, mask []byte) ([]byte, error) {
	if len(ipsk) == 0 {
		return nil, nil
	}
	plain, key, err := ss2022IdentityMaterial(ipsk, nextPSK, mask)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrProtocol
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, plain)
	return out, nil
}

func open2022Identity(ipsk, nextPSK, mask, header []byte) error {
	if len(header) != ss2022IdentitySize {
		return ErrProtocol
	}
	plain, key, err := ss2022IdentityMaterial(ipsk, nextPSK, mask)
	if err != nil {
		return err
	}
	defer clear(plain)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return ErrProtocol
	}
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, plain)
	if !bytes.Equal(out, header) {
		return ErrAuthentication
	}
	return nil
}

func ss2022IdentityMaterial(ipsk, nextPSK, mask []byte) (plain, aesKey []byte, err error) {
	if len(nextPSK) < ss2022IdentitySize || len(mask) < ss2022IdentitySize {
		return nil, nil, ErrProtocol
	}
	derived, err := blake3DeriveKey(ss2022IdentityContext, ipsk)
	if err != nil {
		return nil, nil, err
	}
	aesKey = append([]byte(nil), derived[:ss2022IdentitySize]...)
	clear(derived[:])
	plain = make([]byte, ss2022IdentitySize)
	for i := range plain {
		plain[i] = nextPSK[i] ^ mask[i]
	}
	return plain, aesKey, nil
}

func timestampValid(value uint64, now time.Time) bool {
	if value > math.MaxInt64 {
		return false
	}
	timestamp := int64(value)
	current := now.Unix()
	return timestamp >= current-30 && timestamp <= current+30
}

func evpBytesToKey(password []byte, keyLen int) []byte {
	key := make([]byte, 0, keyLen)
	var previous []byte
	for len(key) < keyLen {
		digest := md5.New()
		digest.Write(previous)
		digest.Write(password)
		previous = digest.Sum(previous[:0])
		key = append(key, previous...)
	}
	clear(previous)
	return key[:keyLen]
}

func hkdfSHA1(key, salt, info []byte, length int) []byte {
	extract := hmac.New(sha1.New, salt)
	extract.Write(key)
	prk := extract.Sum(nil)
	defer clear(prk)
	result := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		expand := hmac.New(sha1.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(previous[:0])
		result = append(result, previous...)
	}
	clear(previous)
	return result[:length]
}

func encodeAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, ErrProtocol
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, ErrProtocol
	}
	var encoded []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			encoded = append([]byte{1}, ipv4...)
		} else {
			encoded = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, "\x00\r\n") {
			return nil, ErrProtocol
		}
		encoded = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(encoded, uint16(port)), nil
}

func decodeAddress(wire []byte) (string, int, error) {
	if len(wire) < 1 {
		return "", 0, ErrProtocol
	}
	position := 1
	var host string
	switch wire[0] {
	case 1:
		if len(wire) < position+4+2 {
			return "", 0, ErrProtocol
		}
		host = net.IP(wire[position : position+4]).String()
		position += 4
	case 4:
		if len(wire) < position+16+2 {
			return "", 0, ErrProtocol
		}
		host = net.IP(wire[position : position+16]).String()
		position += 16
	case 3:
		if len(wire) < position+1 {
			return "", 0, ErrProtocol
		}
		length := int(wire[position])
		position++
		if length == 0 || len(wire) < position+length+2 {
			return "", 0, ErrProtocol
		}
		host = string(wire[position : position+length])
		if strings.ContainsAny(host, "\x00\r\n") {
			return "", 0, ErrProtocol
		}
		position += length
	default:
		return "", 0, ErrProtocol
	}
	port := binary.BigEndian.Uint16(wire[position : position+2])
	if port == 0 {
		return "", 0, ErrProtocol
	}
	position += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), position, nil
}

const (
	blake3ChunkStart     = uint32(1)
	blake3ChunkEnd       = uint32(2)
	blake3Root           = uint32(8)
	blake3DeriveContext  = uint32(32)
	blake3DeriveMaterial = uint32(64)
)

var blake3IV = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
var blake3Permutation = [16]uint8{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

// blake3DeriveKey implements the BLAKE3 derive-key mode needed by SIP022.
// SIP022's context and key+salt material fit in one 64-byte BLAKE3 block; the
// explicit bound keeps this security-critical implementation small enough to
// review and rejects accidental reuse as a general-purpose hash.
func blake3DeriveKey(context string, material []byte) ([32]byte, error) {
	if len(context) > 64 || len(material) > 64 {
		return [32]byte{}, ErrProtocol
	}
	contextKey := blake3OneBlock(blake3IV, []byte(context), blake3DeriveContext)
	var contextWords [8]uint32
	for i := range contextWords {
		contextWords[i] = binary.LittleEndian.Uint32(contextKey[i*4 : i*4+4])
	}
	return blake3OneBlock(contextWords, material, blake3DeriveMaterial), nil
}

func blake3OneBlock(cv [8]uint32, input []byte, mode uint32) [32]byte {
	var block [16]uint32
	var padded [64]byte
	copy(padded[:], input)
	for i := range block {
		block[i] = binary.LittleEndian.Uint32(padded[i*4 : i*4+4])
	}
	words := blake3Compress(cv, block, uint32(len(input)), mode|blake3ChunkStart|blake3ChunkEnd|blake3Root)
	var output [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(output[i*4:i*4+4], words[i])
	}
	return output
}

func blake3Compress(cv [8]uint32, block [16]uint32, blockLen, flags uint32) [16]uint32 {
	state := [16]uint32{cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3], 0, 0, blockLen, flags}
	message := block
	for round := 0; round < 7; round++ {
		blake3G(&state, 0, 4, 8, 12, message[0], message[1])
		blake3G(&state, 1, 5, 9, 13, message[2], message[3])
		blake3G(&state, 2, 6, 10, 14, message[4], message[5])
		blake3G(&state, 3, 7, 11, 15, message[6], message[7])
		blake3G(&state, 0, 5, 10, 15, message[8], message[9])
		blake3G(&state, 1, 6, 11, 12, message[10], message[11])
		blake3G(&state, 2, 7, 8, 13, message[12], message[13])
		blake3G(&state, 3, 4, 9, 14, message[14], message[15])
		var permuted [16]uint32
		for i, source := range blake3Permutation {
			permuted[i] = message[source]
		}
		message = permuted
	}
	var output [16]uint32
	for i := 0; i < 8; i++ {
		output[i] = state[i] ^ state[i+8]
		output[i+8] = state[i+8] ^ cv[i]
	}
	return output
}

func blake3G(state *[16]uint32, a, b, c, d int, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = rotateRight(state[d]^state[a], 16)
	state[c] += state[d]
	state[b] = rotateRight(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = rotateRight(state[d]^state[a], 8)
	state[c] += state[d]
	state[b] = rotateRight(state[b]^state[c], 7)
}

func rotateRight(value uint32, count uint) uint32 {
	return value>>count | value<<(32-count)
}
