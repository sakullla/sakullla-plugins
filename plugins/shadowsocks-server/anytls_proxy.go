package shadowsocksserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func handshakeAnyTLSClient(ctx context.Context, conn net.Conn, serverName string, roots *x509.CertPool) (*tls.Conn, error) {
	if strings.TrimSpace(serverName) == "" {
		_ = conn.Close()
		return nil, ErrInvalid
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (exec *listenExecutor) paddingForUpstream(upstream Upstream) string {
	if exec != nil {
		exec.paddingMu.Lock()
		if exec.upstreamPadding != nil {
			if scheme := exec.upstreamPadding[upstream.ID]; validatePaddingScheme(scheme) == nil {
				exec.paddingMu.Unlock()
				return scheme
			}
		}
		exec.paddingMu.Unlock()
	}
	if validatePaddingScheme(upstream.PaddingScheme) == nil {
		return upstream.PaddingScheme
	}
	return defaultAnyTLSPaddingScheme
}

func (exec *listenExecutor) rememberUpstreamPadding(id, scheme string) {
	if exec == nil || id == "" || validatePaddingScheme(scheme) != nil {
		return
	}
	exec.paddingMu.Lock()
	defer exec.paddingMu.Unlock()
	if exec.upstreamPadding == nil {
		exec.upstreamPadding = map[string]string{}
	}
	exec.upstreamPadding[id] = scheme
}

func (b *boundListen) handleAnyTLS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if !b.certificateReady(ctx) {
		return
	}
	tlsConn, err := b.terminateAnyTLS(ctx, conn)
	if err != nil || tlsConn == nil {
		return
	}
	if tlsConn != conn {
		defer tlsConn.Close()
	}
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := readAnyTLSClientHello(tlsConn, b.anytlsIdentities(ctx)); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	session := newServerAnyTLSSession(tlsConn, b.snapshotPadding(), func(stream *anytlsStream) {
		b.serveAnyTLSStream(ctx, stream)
	})
	session.recvLoop()
}

func (b *boundListen) certificateReady(ctx context.Context) bool {
	if b == nil || b.certificateID <= 0 {
		return false
	}
	if b.exec != nil && b.exec.certReady != nil {
		return b.exec.certReady(ctx, b.agentID, b.certificateID)
	}
	if b.exec != nil && b.exec.managed != nil {
		return b.exec.managed.certificateUsable(ctx, b.agentID, b.certificateID)
	}
	return false
}

func (b *boundListen) terminateAnyTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if b != nil && b.exec != nil && b.exec.tlsTerminate != nil {
		return b.exec.tlsTerminate(ctx, b.certificateID, conn)
	}
	if b != nil && b.exec != nil && b.exec.managed != nil {
		return b.exec.managed.terminateCertificate(ctx, b.certificateID, conn)
	}
	return nil, ErrTypedHandlesUnavailable
}

func (b *boundListen) snapshotPadding() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if validatePaddingScheme(b.paddingScheme) == nil {
		return b.paddingScheme
	}
	return defaultAnyTLSPaddingScheme
}

func (b *boundListen) anytlsIdentities(ctx context.Context) []anytlsIdentity {
	b.mu.Lock()
	users := append([]ListenApplyUser(nil), b.anytlsUsers...)
	resolver := b.secrets
	b.mu.Unlock()
	identities := make([]anytlsIdentity, 0, len(users))
	for _, user := range users {
		if !user.Enabled || user.ID == "" || resolver == nil {
			continue
		}
		material, err := resolver.Resolve(ctx, user.SecretRef, user.SecretVersion)
		if err != nil || len(material) == 0 {
			clear(material)
			continue
		}
		identities = append(identities, anytlsIdentity{id: user.ID, hash: anytlsPasswordHash(material)})
		clear(material)
	}
	return identities
}

func (b *boundListen) serveAnyTLSStream(ctx context.Context, stream *anytlsStream) {
	defer stream.Close()
	target, err := readSocksAddr(stream)
	if err != nil {
		return
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	if isUoTv2Target(host) {
		b.serveAnyTLSUoT(ctx, stream)
		return
	}
	b.serveAnyTLSTCP(ctx, stream, target)
}

func (b *boundListen) serveAnyTLSTCP(ctx context.Context, stream *anytlsStream, target string) {
	decision, err := b.snapshotRoutes().decide(ctx, "tcp", target)
	if err != nil || decision.Action == RouteReject || b.dialer == nil {
		failure := "route-rejected"
		if err != nil {
			failure = "dataset-or-upstream-unavailable"
		}
		if b.dialer == nil && err == nil && decision.Action != RouteReject {
			failure = "dial-failed"
		}
		b.recordRouteFailure(decision, failure)
		_ = stream.sess.handshakeFailure(stream, "closed")
		return
	}
	dialTarget := target
	if decision.Action == RouteUpstream {
		dialTarget = net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port))
	}
	remote, err := b.dialer.DialContext(ctx, "tcp", dialTarget)
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		_ = stream.sess.handshakeFailure(stream, "closed")
		return
	}
	defer remote.Close()
	if decision.Action == RouteUpstream {
		if decision.Upstream.AnyTLS() {
			remote, err = b.wrapAnyTLSUpstream(ctx, remote, *decision.Upstream, target, nil)
		} else {
			remote, err = b.wrapUpstreamTCP(ctx, remote, *decision.Upstream, ProxyRequest{Target: target})
		}
		if err != nil {
			b.recordRouteFailure(decision, upstreamFailureReason(err))
			_ = stream.sess.handshakeFailure(stream, "closed")
			return
		}
	}
	if err := stream.sess.handshakeSuccess(stream); err != nil {
		return
	}
	b.recordRouteFailure(decision, "")
	relayBidirectional(stream, remote)
}

func (b *boundListen) serveAnyTLSUoT(ctx context.Context, stream *anytlsStream) {
	request, err := readUoTRequest(stream)
	if err != nil {
		return
	}
	if request.isConnect {
		b.serveAnyTLSUoTConnect(ctx, stream, request)
		return
	}
	if err := stream.sess.handshakeSuccess(stream); err != nil {
		return
	}
	for {
		destination, payload, err := readUoTPacket(stream, request)
		if err != nil {
			return
		}
		response, ok := b.forwardUDPDatagram(ctx, destination, payload)
		if !ok {
			continue
		}
		if err := writeUoTPacket(stream, false, destination, response); err != nil {
			return
		}
	}
}

func (b *boundListen) serveAnyTLSUoTConnect(ctx context.Context, stream *anytlsStream, request uotRequest) {
	decision, err := b.snapshotRoutes().decide(ctx, "udp", request.destination)
	if err != nil || decision.Action == RouteReject || b.dialer == nil {
		_ = stream.sess.handshakeFailure(stream, "closed")
		failure := "route-rejected"
		if err != nil {
			failure = "dataset-or-upstream-unavailable"
		}
		b.recordRouteFailure(decision, failure)
		return
	}
	if decision.Action == RouteUpstream && decision.Upstream.AnyTLS() {
		raw, dialErr := b.dialer.DialContext(ctx, "tcp", net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port)))
		if dialErr != nil {
			b.recordRouteFailure(decision, "dial-failed")
			_ = stream.sess.handshakeFailure(stream, "closed")
			return
		}
		defer raw.Close()
		remote, wrapErr := b.wrapAnyTLSUpstream(ctx, raw, *decision.Upstream, net.JoinHostPort(uotMagicV2, "443"), nil)
		if wrapErr != nil {
			b.recordRouteFailure(decision, upstreamFailureReason(wrapErr))
			_ = stream.sess.handshakeFailure(stream, "closed")
			return
		}
		defer remote.Close()
		if err := writeUoTRequest(remote, true, request.destination); err != nil {
			b.recordRouteFailure(decision, upstreamFailureReason(err))
			return
		}
		if err := stream.sess.handshakeSuccess(stream); err != nil {
			return
		}
		b.recordRouteFailure(decision, "")
		relayBidirectional(stream, remote)
		return
	}
	dialTarget := request.destination
	if decision.Action == RouteUpstream {
		dialTarget = net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port))
	}
	remote, err := b.dialer.DialContext(ctx, "udp", dialTarget)
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		_ = stream.sess.handshakeFailure(stream, "closed")
		return
	}
	defer remote.Close()
	if err := stream.sess.handshakeSuccess(stream); err != nil {
		return
	}
	b.recordRouteFailure(decision, "")
	if decision.Action == RouteUpstream {
		// Match handleUDP: bound the association read so a received datagram is written back on this UoT stream.
		_ = remote.SetDeadline(time.Now().Add(500 * time.Millisecond))
		b.relayUoTToShadowsocks(ctx, stream, request, remote, *decision.Upstream)
		return
	}
	relayUoTToUDP(stream, request, remote)
}

func (b *boundListen) forwardUDPDatagram(ctx context.Context, destination string, payload []byte) ([]byte, bool) {
	decision, err := b.snapshotRoutes().decide(ctx, "udp", destination)
	if err != nil || decision.Action == RouteReject || b.dialer == nil {
		failure := "route-rejected"
		if err != nil {
			failure = "dataset-or-upstream-unavailable"
		}
		b.recordRouteFailure(decision, failure)
		return nil, false
	}
	if decision.Action == RouteUpstream && decision.Upstream.AnyTLS() {
		raw, dialErr := b.dialer.DialContext(ctx, "tcp", net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port)))
		if dialErr != nil {
			b.recordRouteFailure(decision, "dial-failed")
			return nil, false
		}
		defer raw.Close()
		remote, wrapErr := b.wrapAnyTLSUpstream(ctx, raw, *decision.Upstream, net.JoinHostPort(uotMagicV2, "443"), nil)
		if wrapErr != nil {
			b.recordRouteFailure(decision, upstreamFailureReason(wrapErr))
			return nil, false
		}
		defer remote.Close()
		if err := writeUoTRequest(remote, true, destination); err != nil {
			return nil, false
		}
		if err := writeUoTPacket(remote, true, destination, payload); err != nil {
			return nil, false
		}
		_ = remote.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, response, err := readUoTPacket(remote, uotRequest{isConnect: true, destination: destination})
		if err != nil {
			return nil, false
		}
		b.recordRouteFailure(decision, "")
		return response, true
	}
	dialTarget := destination
	network := "udp"
	if decision.Action == RouteUpstream {
		dialTarget = net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port))
	}
	remote, err := b.dialer.DialContext(ctx, network, dialTarget)
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		return nil, false
	}
	defer remote.Close()
	if decision.Action == RouteUpstream {
		_ = remote.SetDeadline(time.Now().Add(500 * time.Millisecond))
		responses, err := b.roundTripUpstreamUDPResponses(ctx, remote, *decision.Upstream, ProxyRequest{Target: destination, Payload: payload})
		if err != nil || len(responses) == 0 {
			b.recordRouteFailure(decision, upstreamFailureReason(err))
			return nil, false
		}
		b.recordRouteFailure(decision, "")
		return responses[0], true
	}
	_ = remote.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if len(payload) > 0 {
		if _, err := remote.Write(payload); err != nil {
			return nil, false
		}
	}
	buffer := make([]byte, maxUDPPacket)
	n, err := remote.Read(buffer)
	if err != nil || n == 0 {
		return nil, false
	}
	b.recordRouteFailure(decision, "")
	return append([]byte(nil), buffer[:n]...), true
}

func (b *boundListen) relayUoTToShadowsocks(ctx context.Context, stream *anytlsStream, request uotRequest, remote net.Conn, upstream Upstream) {
	for {
		_, payload, err := readUoTPacket(stream, request)
		if err != nil {
			return
		}
		// Each datagram gets a fresh 500ms read deadline. Replies already received are written back on this UoT stream.
		_ = remote.SetDeadline(time.Now().Add(500 * time.Millisecond))
		responses, err := b.roundTripUpstreamUDPResponses(ctx, remote, upstream, ProxyRequest{Target: request.destination, Payload: payload})
		if err != nil || len(responses) == 0 {
			b.recordRouteFailure(routeDecision{Action: RouteUpstream, Upstream: &upstream}, upstreamFailureReason(err))
			return
		}
		for _, response := range responses {
			if err := writeUoTPacket(stream, true, request.destination, response); err != nil {
				return
			}
		}
	}
}

func relayUoTToUDP(stream *anytlsStream, request uotRequest, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxUDPPacket)
		for {
			n, err := remote.Read(buffer)
			if n > 0 {
				if writeErr := writeUoTPacket(stream, true, request.destination, buffer[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		_, payload, err := readUoTPacket(stream, request)
		if len(payload) > 0 {
			if _, writeErr := remote.Write(payload); writeErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	_ = remote.Close()
	<-done
}

func relayBidirectional(left, right net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(right, left)
		_ = closeWrite(right)
	}()
	_, _ = io.Copy(left, right)
	_ = closeWrite(left)
	<-done
}

func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type anytlsClientConn struct {
	net.Conn
	session *anytlsSession
}

func (c *anytlsClientConn) Close() error {
	err := c.Conn.Close()
	if c.session != nil {
		if sessionErr := c.session.Close(); err == nil {
			err = sessionErr
		}
	}
	return err
}

func (b *boundListen) wrapAnyTLSUpstream(ctx context.Context, raw net.Conn, upstream Upstream, target string, initial []byte) (net.Conn, error) {
	password, err := b.upstreamPassword(ctx, upstream)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer clear(password)
	scheme := defaultAnyTLSPaddingScheme
	if b != nil {
		scheme = b.paddingForUpstream(upstream)
	}
	tlsConn, err := handshakeAnyTLSClient(ctx, raw, upstream.tlsServerName(), nil)
	if err != nil {
		clear(password)
		return nil, err
	}
	session, err := startClientAnyTLSSession(tlsConn, password, scheme, func(updated string) {
		if b != nil && b.exec != nil {
			b.exec.rememberUpstreamPadding(upstream.ID, updated)
		}
	})
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	stream, err := session.openStream()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	address, err := encodeSocksAddr(target)
	if err != nil {
		_ = session.Close()
		return nil, ErrProtocol
	}
	if _, err := stream.Write(address); err != nil {
		_ = session.Close()
		return nil, err
	}
	if len(initial) > 0 {
		if _, err := stream.Write(initial); err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	return &anytlsClientConn{Conn: stream, session: session}, nil
}

func (b *boundListen) paddingForUpstream(upstream Upstream) string {
	if b != nil && b.exec != nil {
		return b.exec.paddingForUpstream(upstream)
	}
	if validatePaddingScheme(upstream.PaddingScheme) == nil {
		return upstream.PaddingScheme
	}
	return defaultAnyTLSPaddingScheme
}

func (b *boundListen) upstreamPassword(ctx context.Context, upstream Upstream) ([]byte, error) {
	if b == nil || b.secrets == nil {
		return nil, ErrRouteUpstreamUnavailable
	}
	material, err := b.secrets.Resolve(ctx, upstream.SecretRef, upstream.SecretVersion)
	if err != nil || len(material) == 0 {
		clear(material)
		return nil, ErrRouteUpstreamUnavailable
	}
	return material, nil
}

func (exec *listenExecutor) probeAnyTLSUpstream(ctx context.Context, upstream Upstream, result *upstreamTestResult) {
	if !upstream.TCP {
		result.Failure = "tcp-unsupported"
		return
	}
	exec.mu.Lock()
	resolver, managed := exec.secrets, exec.managed
	exec.mu.Unlock()
	var dialer networkDialer = &nativeNetworkDialer{net.Dialer{Timeout: upstreamProbeDialTimeout}}
	if managed != nil {
		resolver = managed
		dialer = managedNetworkDialer{runtime: managed}
	}
	if resolver == nil || !refPattern.MatchString(upstream.ID) || !refPattern.MatchString(upstream.SecretRef) || !refPattern.MatchString(upstream.SecretVersion) || strings.TrimSpace(upstream.tlsServerName()) == "" {
		result.Failure = "upstream-unavailable"
		return
	}
	material, err := resolver.Resolve(ctx, upstream.SecretRef, upstream.SecretVersion)
	if err != nil || len(material) == 0 {
		clear(material)
		result.Failure = "upstream-unavailable"
		return
	}
	defer clear(material)
	started := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, upstreamProbeDialTimeout)
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(upstream.Host, strconv.Itoa(upstream.Port)))
	cancel()
	if err != nil {
		result.Failure = upstreamFailureReason(err)
		return
	}
	defer conn.Close()
	result.RTTMillis = time.Since(started).Milliseconds()
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, upstreamProbeStreamTimeout)
	tlsConn, err := handshakeAnyTLSClient(handshakeCtx, conn, upstream.tlsServerName(), exec.clientRoots)
	handshakeCancel()
	if err != nil {
		result.Failure = "upstream-connection-failed"
		return
	}
	defer tlsConn.Close()
	if err = writeAnyTLSClientHello(tlsConn, material, exec.paddingForUpstream(upstream)); err != nil {
		result.Failure = upstreamFailureReason(err)
		return
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(upstreamProbeStreamTimeout))
	var probeByte [1]byte
	_, err = tlsConn.Read(probeByte[:])
	if err != nil {
		if upstreamProbeHeld(err) {
			result.Reachable = true
			result.RTTMillis = time.Since(started).Milliseconds()
			return
		}
		result.Failure = upstreamProbeFailure(err)
		return
	}
	result.Reachable = true
	result.RTTMillis = time.Since(started).Milliseconds()
}

func (b *boundListen) handleShadowsocksUDPOverAnyTLS(ctx context.Context, matched *ProtocolEngine, request ProxyRequest, clientAddr net.Addr, decision routeDecision) {
	if matched == nil || decision.Upstream == nil || b.dialer == nil {
		return
	}
	raw, err := b.dialer.DialContext(ctx, "tcp", net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port)))
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		return
	}
	defer raw.Close()
	remote, err := b.wrapAnyTLSUpstream(ctx, raw, *decision.Upstream, net.JoinHostPort(uotMagicV2, "443"), nil)
	if err != nil {
		b.recordRouteFailure(decision, upstreamFailureReason(err))
		return
	}
	defer remote.Close()
	if err = writeUoTRequest(remote, true, request.Target); err != nil {
		b.recordRouteFailure(decision, upstreamFailureReason(err))
		return
	}
	if err = writeUoTPacket(remote, true, request.Target, request.Payload); err != nil {
		b.recordRouteFailure(decision, upstreamFailureReason(err))
		return
	}
	_ = remote.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, payload, err := readUoTPacket(remote, uotRequest{isConnect: true, destination: request.Target})
	if err != nil || len(payload) == 0 {
		b.recordRouteFailure(decision, upstreamFailureReason(err))
		return
	}
	b.recordRouteFailure(decision, "")
	saltSize := 8
	if !matched.modern {
		saltSize = matched.SaltSize()
	}
	responseSalt := make([]byte, saltSize)
	if _, err = rand.Read(responseSalt); err != nil {
		return
	}
	packetID := uint64(0)
	if matched.modern {
		packetID = b.nextUDPPacketID()
	}
	sealed, err := matched.SealUDPResponse(responseSalt, packetID, request.SessionID, request.Target, payload, time.Now(), nil)
	if err != nil {
		return
	}
	udp := b.packetConn()
	if udp == nil {
		return
	}
	_, _ = udp.WriteTo(sealed, clientAddr)
}
