package shadowsocksserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	pluginCallListenReport = "listen.report"
	pluginCallListenApply  = "listen.apply"
	pluginCallListenStop   = "listen.stop"
)

var _ pluginsdk.RPCPluginCaller = (*Controller)(nil)

type listenBinder interface {
	Listen(network, address string) (net.Listener, error)
	ListenPacket(network, address string) (net.PacketConn, error)
}

type netListenBinder struct{}

func (netListenBinder) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (netListenBinder) ListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

// ListenReport is the execution-face presence plus bound port summary.
// It never includes secret material.
type ListenReport struct {
	AgentID string             `json:"agent_id"`
	Online  bool               `json:"online"`
	Listens []ListenPortStatus `json:"listens"`
}

// ListenPortStatus is one bound TCP+UDP port without keys or passwords.
type ListenPortStatus struct {
	ID   string `json:"id"`
	Port int    `json:"port"`
	TCP  bool   `json:"tcp"`
	UDP  bool   `json:"udp"`
}

// ListenApplyUser is the one-time secret envelope for one enabled user.
type ListenApplyUser struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Password string `json:"password,omitempty"`
}

// ListenApplyItem is the desired listen on one Agent, including engine material.
type ListenApplyItem struct {
	ID        string            `json:"id"`
	Port      int               `json:"port"`
	Method    string            `json:"method"`
	ServerPSK string            `json:"server_psk,omitempty"`
	Users     []ListenApplyUser `json:"users"`
}

type listenApplyRequest struct {
	AgentID string            `json:"agent_id"`
	Listens []ListenApplyItem `json:"listens"`
}

type listenStopRequest struct {
	AgentID   string   `json:"agent_id"`
	ListenIDs []string `json:"listen_ids"`
}

type listenApplyResult struct {
	Accepted bool               `json:"accepted"`
	AgentID  string             `json:"agent_id"`
	Listens  []ListenPortStatus `json:"listens"`
}

type listenExecutor struct {
	mu     sync.Mutex
	binder listenBinder
	bound  map[string]*boundListen
}

type boundListen struct {
	mu      sync.Mutex
	closed  bool
	id      string
	port    int
	tcp     net.Listener
	udp     net.PacketConn
	engines []*ProtocolEngine
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newListenExecutor(binder listenBinder) *listenExecutor {
	if binder == nil {
		binder = netListenBinder{}
	}
	return &listenExecutor{binder: binder, bound: map[string]*boundListen{}}
}

func (c *Controller) Call(ctx context.Context, generation, name string, payload []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = generation
	exec := c.listenExec
	if exec == nil {
		return nil, ErrTypedHandlesUnavailable
	}
	switch strings.TrimSpace(name) {
	case pluginCallListenReport:
		return exec.report(payload)
	case pluginCallListenApply:
		return exec.apply(ctx, payload)
	case pluginCallListenStop:
		return exec.stop(payload)
	default:
		return nil, fmt.Errorf("%w: plugin call name %q is unknown", ErrTypedHandlesUnavailable, name)
	}
}

func (exec *listenExecutor) report(payload []byte) ([]byte, error) {
	agentID, err := agentIDFromListenPayload(payload)
	if err != nil {
		return nil, err
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	return json.Marshal(ListenReport{AgentID: agentID, Online: true, Listens: exec.viewsLocked()})
}

func (exec *listenExecutor) apply(ctx context.Context, payload []byte) ([]byte, error) {
	agentID, err := agentIDFromListenPayload(payload)
	if err != nil {
		return nil, err
	}
	var request listenApplyRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, errors.New("listen payload is invalid")
	}
	desired := make(map[string]struct{}, len(request.Listens))
	for _, item := range request.Listens {
		if strings.TrimSpace(item.ID) == "" {
			return nil, ErrInvalid
		}
		desired[item.ID] = struct{}{}
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for id := range exec.bound {
		if _, ok := desired[id]; !ok {
			exec.unbindLocked(id)
		}
	}
	var applyErr error
	for _, item := range request.Listens {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := exec.bindOneLocked(item); err != nil {
			if applyErr == nil {
				applyErr = err
			}
		}
	}
	if applyErr != nil {
		return nil, applyErr
	}
	return json.Marshal(listenApplyResult{Accepted: true, AgentID: agentID, Listens: exec.viewsLocked()})
}

func (exec *listenExecutor) stop(payload []byte) ([]byte, error) {
	agentID, err := agentIDFromListenPayload(payload)
	if err != nil {
		return nil, err
	}
	var request listenStopRequest
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, errors.New("listen payload is invalid")
		}
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if len(request.ListenIDs) == 0 {
		exec.stopAllLocked()
	} else {
		for _, id := range request.ListenIDs {
			exec.unbindLocked(id)
		}
	}
	return json.Marshal(listenApplyResult{Accepted: true, AgentID: agentID, Listens: exec.viewsLocked()})
}

func (exec *listenExecutor) stopAll() {
	if exec == nil {
		return
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	exec.stopAllLocked()
}

func (exec *listenExecutor) stopAllLocked() {
	for id := range exec.bound {
		exec.unbindLocked(id)
	}
}

func (exec *listenExecutor) viewsLocked() []ListenPortStatus {
	out := make([]ListenPortStatus, 0, len(exec.bound))
	for _, item := range exec.bound {
		out = append(out, ListenPortStatus{ID: item.id, Port: item.port, TCP: true, UDP: true})
	}
	return out
}

func (exec *listenExecutor) bindOneLocked(item ListenApplyItem) error {
	if !refPattern.MatchString(item.ID) || item.Port < 1 || item.Port > 65535 || !SupportedMethod(item.Method) {
		return ErrInvalid
	}
	engines := make([]*ProtocolEngine, 0, len(item.Users))
	for _, user := range item.Users {
		if !user.Enabled || strings.TrimSpace(user.Password) == "" {
			continue
		}
		engine, err := engineFromMaterial(item.Method, []byte(user.Password), item.ServerPSK)
		if err != nil {
			destroyListenEngines(engines)
			return err
		}
		engines = append(engines, engine)
	}
	existing := exec.bound[item.ID]
	if existing != nil && existing.port == item.Port {
		existing.replaceEngines(engines)
		return nil
	}
	address := net.JoinHostPort("0.0.0.0", strconv.Itoa(item.Port))
	tcp, err := exec.binder.Listen("tcp", address)
	if err != nil {
		destroyListenEngines(engines)
		return ErrListenBind
	}
	udp, err := exec.binder.ListenPacket("udp", address)
	if err != nil {
		_ = tcp.Close()
		destroyListenEngines(engines)
		return ErrListenBind
	}
	if existing != nil {
		exec.unbindLocked(item.ID)
	}
	ctx, cancel := context.WithCancel(context.Background())
	bound := &boundListen{id: item.ID, port: item.Port, tcp: tcp, udp: udp, engines: engines, cancel: cancel}
	bound.wg.Add(2)
	go func() {
		defer bound.wg.Done()
		bound.serveTCP(ctx)
	}()
	go func() {
		defer bound.wg.Done()
		bound.serveUDP(ctx)
	}()
	exec.bound[item.ID] = bound
	return nil
}

func (exec *listenExecutor) unbindLocked(id string) {
	bound := exec.bound[id]
	if bound == nil {
		return
	}
	delete(exec.bound, id)
	bound.close()
}

func (b *boundListen) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	if b.tcp != nil {
		_ = b.tcp.Close()
	}
	if b.udp != nil {
		_ = b.udp.Close()
	}
	b.wg.Wait()
	b.mu.Lock()
	engines := b.engines
	b.engines = nil
	b.mu.Unlock()
	destroyListenEngines(engines)
}

func (b *boundListen) goHandle(fn func()) bool {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return false
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		fn()
	}()
	return true
}

func (b *boundListen) serveTCP(ctx context.Context) {
	for {
		conn, err := b.tcp.Accept()
		if err != nil {
			return
		}
		if ctx.Err() != nil || !b.goHandle(func() { b.handleTCP(ctx, conn) }) {
			_ = conn.Close()
			return
		}
	}
}

func (b *boundListen) snapshotEngines() []*ProtocolEngine {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*ProtocolEngine(nil), b.engines...)
}

func (b *boundListen) replaceEngines(engines []*ProtocolEngine) {
	if b == nil {
		destroyListenEngines(engines)
		return
	}
	b.mu.Lock()
	old := b.engines
	b.engines = engines
	b.mu.Unlock()
	destroyListenEngines(old)
}

func (b *boundListen) packetConn() net.PacketConn {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	return b.udp
}

func (b *boundListen) serveUDP(ctx context.Context) {
	buf := make([]byte, maxUDPPacket)
	for {
		n, addr, err := b.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		clientAddr := clonePacketAddr(addr)
		if !b.goHandle(func() { b.handleUDP(ctx, packet, clientAddr) }) {
			return
		}
	}
}

func (b *boundListen) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request, session, err := readTCPHandshake(conn, b.snapshotEngines())
	if session != nil {
		defer session.Close()
	}
	if err != nil {
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	target, err := dialer.DialContext(ctx, "tcp", request.Target)
	if err != nil {
		return
	}
	defer target.Close()
	if len(request.Payload) > 0 {
		if _, err := target.Write(request.Payload); err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})
	_ = target.SetDeadline(time.Time{})

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			_ = conn.Close()
			_ = target.Close()
		})
	}
	defer shutdown()

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTCPClientToTarget(conn, target, session)
	}()
	relayTCPTargetToClient(conn, target, session)
	shutdown()
	<-done
}

func (b *boundListen) handleUDP(ctx context.Context, wire []byte, clientAddr net.Addr) {
	if clientAddr == nil {
		return
	}
	now := time.Now()
	var request ProxyRequest
	var matched *ProtocolEngine
	for _, engine := range b.snapshotEngines() {
		req, err := engine.OpenUDPPacket(wire, now)
		if err != nil {
			if errors.Is(err, ErrReplay) {
				return
			}
			continue
		}
		request = req
		matched = engine
		break
	}
	if matched == nil {
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", request.Target)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if len(request.Payload) > 0 {
		if _, err := conn.Write(request.Payload); err != nil {
			return
		}
	}
	buf := make([]byte, maxUDPPacket)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	saltSize := 8
	if !matched.modern {
		saltSize = matched.SaltSize()
	}
	responseSalt := make([]byte, saltSize)
	if _, err := rand.Read(responseSalt); err != nil {
		return
	}
	sealed, err := matched.SealUDPResponse(responseSalt, 0, request.SessionID, request.Target, buf[:n], time.Now(), nil)
	if err != nil {
		return
	}
	udp := b.packetConn()
	if udp == nil {
		return
	}
	_, _ = udp.WriteTo(sealed, clientAddr)
}

func relayTCPClientToTarget(conn, target net.Conn, session *TCPServerSession) {
	for {
		payload, err := readTCPPayloadChunk(conn, session)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			continue
		}
		if _, err := target.Write(payload); err != nil {
			return
		}
	}
}

func relayTCPTargetToClient(conn, target net.Conn, session *TCPServerSession) {
	buf := make([]byte, 32*1024)
	startResponse := true
	for {
		n, err := target.Read(buf)
		if n > 0 {
			var writeErr error
			startResponse, writeErr = writeTCPClientChunks(conn, session, buf[:n], startResponse)
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeTCPClientChunks(conn net.Conn, session *TCPServerSession, payload []byte, startResponse bool) (bool, error) {
	maximum := maxLegacyPayload
	if session != nil && session.modern {
		maximum = max2022Payload
	}
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maximum {
			chunk = chunk[:maximum]
		}
		var wire []byte
		var err error
		if startResponse {
			saltSize := 0
			if session != nil && session.engine != nil {
				saltSize = session.engine.SaltSize()
			}
			salt := make([]byte, saltSize)
			if _, err := rand.Read(salt); err != nil {
				return startResponse, err
			}
			wire, err = session.SealResponse(salt, chunk, time.Now())
			startResponse = false
		} else {
			wire, err = session.SealPayloadChunk(chunk)
		}
		if err != nil {
			return startResponse, err
		}
		if _, err := conn.Write(wire); err != nil {
			return startResponse, err
		}
		payload = payload[len(chunk):]
	}
	return startResponse, nil
}

func readTCPPayloadChunk(conn net.Conn, session *TCPServerSession) ([]byte, error) {
	if session == nil {
		return nil, ErrRevoked
	}
	session.mu.Lock()
	inbound := session.inbound
	modern := session.modern
	closed := session.closed
	session.mu.Unlock()
	if closed || inbound == nil {
		return nil, ErrRevoked
	}
	headerSize := 2 + inbound.aead.Overhead()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	session.mu.Lock()
	lengthPlain, err := inbound.aead.Open(nil, inbound.nonce[:], header, nil)
	session.mu.Unlock()
	if err != nil || len(lengthPlain) != 2 {
		return nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	maximum := maxLegacyPayload
	if modern {
		maximum = max2022Payload
	}
	if length > maximum {
		return nil, ErrProtocol
	}
	rest := make([]byte, length+inbound.aead.Overhead())
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	return session.OpenPayloadChunk(append(header, rest...))
}

func clonePacketAddr(addr net.Addr) net.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return addr
	}
	out := *udpAddr
	if udpAddr.IP != nil {
		out.IP = append(net.IP(nil), udpAddr.IP...)
	}
	return &out
}

func readTCPHandshake(conn net.Conn, engines []*ProtocolEngine) (ProxyRequest, *TCPServerSession, error) {
	now := time.Now()
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 2048)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			complete := false
			for _, engine := range engines {
				request, session, openErr := engine.OpenTCPServerSession(buf, now)
				if openErr == nil {
					return request, session, nil
				}
				if errors.Is(openErr, ErrReplay) {
					return ProxyRequest{}, nil, openErr
				}
				if !errors.Is(openErr, ErrProtocol) {
					complete = true
				}
			}
			if complete {
				return ProxyRequest{}, nil, ErrAuthentication
			}
		}
		if err != nil {
			if len(buf) == 0 {
				return ProxyRequest{}, nil, err
			}
			return ProxyRequest{}, nil, ErrProtocol
		}
		if len(buf) > maxUDPPacket {
			return ProxyRequest{}, nil, ErrProtocol
		}
	}
}

func destroyListenEngines(engines []*ProtocolEngine) {
	for _, engine := range engines {
		if engine != nil {
			engine.Destroy()
		}
	}
}

func agentIDFromListenPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", ErrAgentOffline
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return "", errors.New("listen payload is invalid")
	}
	agentID := stringField(raw, "agent_id")
	if !validAgentID(agentID) {
		return "", ErrAgentOffline
	}
	return agentID, nil
}

func stringField(raw map[string]any, key string) string {
	value, _ := raw[key].(string)
	return strings.TrimSpace(value)
}
