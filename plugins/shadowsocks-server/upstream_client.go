package shadowsocksserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// TCPClientSession owns one outbound Shadowsocks request stream and validates
// that the first server response is bound to that request salt.
type TCPClientSession struct {
	mu          sync.Mutex
	engine      *ProtocolEngine
	key         []byte
	requestSalt []byte
	outbound    *streamCipher
	inbound     *streamCipher
	modern      bool
	started     bool
	closed      bool
}

func newTCPClientSession(engine *ProtocolEngine, requestSalt []byte) (*TCPClientSession, error) {
	key, _, err := engine.keysSnapshot()
	if err != nil || len(requestSalt) != engine.SaltSize() {
		clear(key)
		return nil, ErrProtocol
	}
	outbound, err := engine.newSession(key, requestSalt)
	if err != nil {
		clear(key)
		return nil, err
	}
	// The initial request always seals two records.
	incrementNonce(&outbound.nonce)
	incrementNonce(&outbound.nonce)
	return &TCPClientSession{engine: engine, key: key, requestSalt: append([]byte(nil), requestSalt...), outbound: outbound, modern: engine.modern}, nil
}

func (session *TCPClientSession) SealPayload(payload []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.outbound == nil {
		return nil, ErrRevoked
	}
	maximum := maxLegacyPayload
	if session.modern {
		maximum = max2022Payload
	}
	if len(payload) == 0 || len(payload) > maximum {
		return nil, ErrProtocol
	}
	return sealPayloadChunk(session.outbound, payload), nil
}

func (session *TCPClientSession) openFirstResponse(reader io.Reader, now time.Time) ([]byte, error) {
	salt := make([]byte, len(session.key))
	if _, err := io.ReadFull(reader, salt); err != nil {
		return nil, err
	}
	inbound, err := session.engine.newSession(session.key, salt)
	clear(salt)
	if err != nil {
		return nil, err
	}
	if !session.modern {
		session.inbound = inbound
		return readEncryptedPayload(reader, inbound, maxLegacyPayload)
	}
	fixedLength := 1 + 8 + len(session.requestSalt) + 2
	fixedWire := make([]byte, fixedLength+inbound.aead.Overhead())
	if _, err := io.ReadFull(reader, fixedWire); err != nil {
		return nil, err
	}
	fixed, err := inbound.open(fixedWire)
	if err != nil || len(fixed) != fixedLength || fixed[0] != 1 || !timestampValid(binary.BigEndian.Uint64(fixed[1:9]), now) ||
		subtle.ConstantTimeCompare(fixed[9:9+len(session.requestSalt)], session.requestSalt) != 1 {
		return nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(fixed[len(fixed)-2:]))
	if length < 1 || length > max2022Payload {
		return nil, ErrProtocol
	}
	body := make([]byte, length+inbound.aead.Overhead())
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	payload, err := inbound.open(body)
	if err != nil {
		return nil, ErrAuthentication
	}
	session.inbound = inbound
	return payload, nil
}

func (session *TCPClientSession) OpenPayload(reader io.Reader, now time.Time) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, ErrRevoked
	}
	if !session.started {
		payload, err := session.openFirstResponse(reader, now)
		if err == nil {
			session.started = true
		}
		return payload, err
	}
	maximum := maxLegacyPayload
	if session.modern {
		maximum = max2022Payload
	}
	return readEncryptedPayload(reader, session.inbound, maximum)
}

func readEncryptedPayload(reader io.Reader, cipher *streamCipher, maximum int) ([]byte, error) {
	header := make([]byte, 2+cipher.aead.Overhead())
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	plain, err := cipher.open(header)
	if err != nil || len(plain) != 2 {
		return nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(plain))
	if length < 1 || length > maximum {
		return nil, ErrProtocol
	}
	body := make([]byte, length+cipher.aead.Overhead())
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	payload, err := cipher.open(body)
	if err != nil {
		return nil, ErrAuthentication
	}
	return payload, nil
}

func (session *TCPClientSession) Close() {
	if session == nil {
		return
	}
	session.mu.Lock()
	session.closed = true
	session.inbound, session.outbound = nil, nil
	clear(session.key)
	clear(session.requestSalt)
	session.key, session.requestSalt = nil, nil
	engine := session.engine
	session.engine = nil
	session.mu.Unlock()
	if engine != nil {
		engine.Destroy()
	}
}

type upstreamTCPConn struct {
	net.Conn
	session *TCPClientSession
	mu      sync.Mutex
	pending bytes.Reader
}

func (connection *upstreamTCPConn) Read(value []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.pending.Len() == 0 {
		payload, err := connection.session.OpenPayload(connection.Conn, time.Now())
		if err != nil {
			return 0, err
		}
		connection.pending.Reset(payload)
	}
	return connection.pending.Read(value)
}

func (connection *upstreamTCPConn) Write(value []byte) (int, error) {
	total := 0
	for total < len(value) {
		maximum := maxLegacyPayload
		if connection.session.modern {
			maximum = max2022Payload
		}
		chunk := value[total:]
		if len(chunk) > maximum {
			chunk = chunk[:maximum]
		}
		wire, err := connection.session.SealPayload(chunk)
		if err != nil {
			return total, err
		}
		if _, err := connection.Conn.Write(wire); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func (connection *upstreamTCPConn) Close() error {
	connection.session.Close()
	return connection.Conn.Close()
}

func (b *boundListen) upstreamEngine(ctx context.Context, upstream Upstream) (*ProtocolEngine, error) {
	if b.secrets == nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	material, err := b.secrets.Resolve(ctx, upstream.SecretRef, upstream.SecretVersion)
	if err != nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	engine, err := NewProtocolEngine(upstream.Method, material)
	clear(material)
	if err != nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	return engine, nil
}

func (b *boundListen) wrapUpstreamTCP(ctx context.Context, connection net.Conn, upstream Upstream, request ProxyRequest) (net.Conn, error) {
	engine, err := b.upstreamEngine(ctx, upstream)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, engine.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		engine.Destroy()
		return nil, err
	}
	wire, err := engine.SealTCPRequest(salt, request.Target, request.Payload, time.Now(), nil)
	if err != nil {
		clear(salt)
		engine.Destroy()
		return nil, err
	}
	session, err := newTCPClientSession(engine, salt)
	clear(salt)
	if err != nil {
		engine.Destroy()
		return nil, err
	}
	if _, err := connection.Write(wire); err != nil {
		session.Close()
		return nil, err
	}
	return &upstreamTCPConn{Conn: connection, session: session}, nil
}

func (b *boundListen) roundTripUpstreamUDP(ctx context.Context, connection net.Conn, upstream Upstream, request ProxyRequest) ([]byte, error) {
	responses, err := b.roundTripUpstreamUDPResponses(ctx, connection, upstream, request)
	if err != nil || len(responses) == 0 {
		return nil, err
	}
	return responses[0], nil
}

func (b *boundListen) roundTripUpstreamUDPResponses(ctx context.Context, connection net.Conn, upstream Upstream, request ProxyRequest) ([][]byte, error) {
	engine, err := b.upstreamEngine(ctx, upstream)
	if err != nil {
		return nil, err
	}
	defer engine.Destroy()
	session := make([]byte, engine.SaltSize())
	if engine.modern {
		session = make([]byte, 8)
	}
	if _, err := rand.Read(session); err != nil {
		return nil, err
	}
	wire, err := engine.SealUDPPacket(session, 0, request.Target, request.Payload, time.Now(), nil)
	if err != nil {
		clear(session)
		return nil, err
	}
	if _, err := connection.Write(wire); err != nil {
		clear(session)
		return nil, err
	}
	expected := uint64(0)
	if engine.modern {
		expected = binary.BigEndian.Uint64(session)
	}
	clear(session)
	return collectUDPAssociationResponses(connection, func(wire []byte) ([]byte, error) {
		response, openErr := engine.OpenUDPResponse(wire, time.Now(), expected)
		if openErr != nil {
			return nil, openErr
		}
		return response.Payload, nil
	})
}

func collectUDPAssociationResponses(connection net.Conn, decode func([]byte) ([]byte, error)) ([][]byte, error) {
	if connection == nil || decode == nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	responses := make([][]byte, 0, maxUDPAssociationResponses)
	total := 0
	buffer := make([]byte, maxUDPPacket)
	for len(responses) < maxUDPAssociationResponses {
		n, readErr := connection.Read(buffer)
		if n > 0 {
			payload, err := decode(buffer[:n])
			if err != nil {
				return nil, err
			}
			if len(payload) > maxUDPAssociationBytes-total {
				return nil, ErrRouteUpstreamUnavailable
			}
			total += len(payload)
			responses = append(responses, append([]byte(nil), payload...))
		}
		if readErr != nil {
			break
		}
	}
	if len(responses) == 0 {
		return nil, ErrRouteUpstreamUnavailable
	}
	return responses, nil
}
