package shadowsocksserver

import (
	"bytes"
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

type networkDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type nativeNetworkDialer struct{ net.Dialer }

// ListenReport is the execution-face presence plus bound port summary.
// It never includes secret material.
type ListenReport struct {
	AgentID string             `json:"agent_id"`
	Online  bool               `json:"online"`
	Listens []ListenPortStatus `json:"listens"`
	DDNS    string             `json:"ddns_domain,omitempty"`
	IPv4    string             `json:"ipv4,omitempty"`
	IPv6    string             `json:"ipv6,omitempty"`
	Routes  []RouteStatus      `json:"routes,omitempty"`
}

// ListenPortStatus is one bound TCP+UDP port without keys or passwords.
type ListenPortStatus struct {
	ID   string `json:"id"`
	Port int    `json:"port"`
	TCP  bool   `json:"tcp"`
	UDP  bool   `json:"udp"`
}

// ListenApplyUser carries only a scoped Host secret reference.
type ListenApplyUser struct {
	ID            string `json:"id"`
	Enabled       bool   `json:"enabled"`
	SecretRef     string `json:"secret_ref,omitempty"`
	SecretVersion string `json:"secret_version,omitempty"`
}

// ListenApplyItem is the desired managed listen on one Agent.
type ListenApplyItem struct {
	ID                  string            `json:"id"`
	Port                int               `json:"port"`
	Method              string            `json:"method"`
	ServerSecretRef     string            `json:"server_secret_ref,omitempty"`
	ServerSecretVersion string            `json:"server_secret_version,omitempty"`
	Users               []ListenApplyUser `json:"users"`
}

type listenApplyRequest struct {
	AgentID string               `json:"agent_id"`
	Listens []ListenApplyItem    `json:"listens"`
	Routing RoutingConfiguration `json:"routing"`
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
	mu       sync.Mutex
	binder   listenBinder
	managed  *hostCapabilityRuntime
	secrets  SecretVerifier
	bound    map[string]*boundListen
	bindHost string
}

type boundUserEngine struct {
	id     string
	engine *ProtocolEngine
}

type boundListen struct {
	mu            sync.Mutex
	closed        bool
	id            string
	port          int
	tcp           net.Listener
	udp           net.PacketConn
	engines       []*boundUserEngine
	dialer        networkDialer
	secrets       SecretVerifier
	routes        *routeSnapshot
	udpPacketID   uint64
	routeFailures map[string]string
	flowRoutes    map[string]*routeSnapshot
	flowOrder     []string
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

type preparedListen struct {
	item     ListenApplyItem
	existing *boundListen
	bound    *boundListen
	engines  []*boundUserEngine
	ctx      context.Context
	routes   *routeSnapshot
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if n := copy(p, c.prefix); n > 0 {
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func newListenExecutor(binder listenBinder) *listenExecutor {
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
		raw, err := exec.report(payload)
		if err != nil {
			return nil, err
		}
		return c.attachReportNode(ctx, raw)
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
	return json.Marshal(ListenReport{AgentID: agentID, Online: true, Listens: exec.viewsLocked(), Routes: exec.routeStatusesLocked()})
}

func (exec *listenExecutor) routeStatusesLocked() []RouteStatus {
	for _, listener := range exec.bound {
		return listener.routeStatuses()
	}
	return []RouteStatus{}
}

func (exec *listenExecutor) apply(ctx context.Context, payload []byte) ([]byte, error) {
	agentID, err := agentIDFromListenPayload(payload)
	if err != nil {
		return nil, err
	}
	var request listenApplyRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, errors.New("listen payload is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("listen payload is invalid")
	}
	var route *routeSnapshot
	var routeClient datasetRoutingClient
	if exec.managed != nil {
		routeClient = exec.managed.datasets
	}
	route, err = prepareRouteSnapshot(ctx, request.Routing, routeClient)
	if err != nil {
		return nil, err
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
	prepared := make([]preparedListen, 0, len(request.Listens))
	for _, item := range request.Listens {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidate, err := exec.prepareOneLocked(ctx, item, route)
		if err != nil {
			exec.abortPrepared(prepared)
			return nil, err
		}
		prepared = append(prepared, candidate)
	}
	for id := range exec.bound {
		if _, ok := desired[id]; !ok {
			exec.unbindLocked(id)
		}
	}
	for _, candidate := range prepared {
		exec.commitPrepared(candidate)
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

func (exec *listenExecutor) prepareOneLocked(ctx context.Context, item ListenApplyItem, routes *routeSnapshot) (preparedListen, error) {
	if !refPattern.MatchString(item.ID) || item.Port < 1 || item.Port > 65535 || !SupportedMethod(item.Method) {
		return preparedListen{}, ErrInvalid
	}
	existing := exec.bound[item.ID]
	var current []*boundUserEngine
	if existing != nil && existing.port == item.Port {
		current = existing.snapshotUserEngines()
	}
	resolver := exec.secrets
	if exec.managed != nil {
		resolver = exec.managed
	}
	engines, err := assembleUserEngines(ctx, item, current, resolver)
	if err != nil {
		return preparedListen{}, err
	}
	if existing != nil && existing.port == item.Port {
		return preparedListen{item: item, existing: existing, engines: engines, routes: routes}, nil
	}
	host := exec.bindHost
	if host == "" {
		host = "0.0.0.0"
	}
	address := net.JoinHostPort(host, strconv.Itoa(item.Port))
	var tcp net.Listener
	var udp net.PacketConn
	var dialer networkDialer
	if exec.managed != nil {
		tcp, err = exec.managed.listenTCP(ctx, item.Port)
		dialer = managedNetworkDialer{runtime: exec.managed}
	} else if exec.binder != nil {
		tcp, err = exec.binder.Listen("tcp", address)
		dialer = &nativeNetworkDialer{net.Dialer{Timeout: 5 * time.Second}}
	} else {
		err = ErrTypedHandlesUnavailable
	}
	if err != nil {
		destroyUserEngines(engines, nil)
		return preparedListen{}, ErrListenBind
	}
	if exec.managed != nil {
		udp, err = exec.managed.listenUDP(ctx, item.Port)
	} else {
		udp, err = exec.binder.ListenPacket("udp", address)
	}
	if err != nil {
		_ = tcp.Close()
		destroyUserEngines(engines, nil)
		return preparedListen{}, ErrListenBind
	}
	ctx, cancel := context.WithCancel(context.Background())
	bound := &boundListen{id: item.ID, port: item.Port, tcp: tcp, udp: udp, engines: engines, dialer: dialer, secrets: resolver, routes: routes, routeFailures: map[string]string{}, flowRoutes: map[string]*routeSnapshot{}, cancel: cancel}
	return preparedListen{item: item, existing: existing, bound: bound, ctx: ctx, routes: routes}, nil
}

func (exec *listenExecutor) commitPrepared(candidate preparedListen) {
	if candidate.bound == nil {
		candidate.existing.replaceUserEngines(candidate.engines)
		candidate.existing.replaceRoutes(candidate.routes)
		return
	}
	if candidate.existing != nil {
		exec.unbindLocked(candidate.item.ID)
	}
	bound := candidate.bound
	bound.wg.Add(2)
	go func() {
		defer bound.wg.Done()
		bound.serveTCP(candidate.ctx)
	}()
	go func() {
		defer bound.wg.Done()
		bound.serveUDP(candidate.ctx)
	}()
	exec.bound[candidate.item.ID] = bound
}

func (b *boundListen) replaceRoutes(routes *routeSnapshot) {
	b.mu.Lock()
	b.routes = routes
	b.routeFailures = map[string]string{}
	b.mu.Unlock()
}

func (b *boundListen) snapshotRoutes() *routeSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.routes
}

func (b *boundListen) snapshotRoutesForFlow(address net.Addr) *routeSnapshot {
	if address == nil {
		return b.snapshotRoutes()
	}
	key := address.Network() + "\x00" + address.String()
	b.mu.Lock()
	if routes := b.flowRoutes[key]; routes != nil {
		b.mu.Unlock()
		return routes
	}
	if b.flowRoutes == nil {
		b.flowRoutes = map[string]*routeSnapshot{}
	}
	if managed, ok := b.udp.(*managedPacketConn); ok {
		kept := b.flowOrder[:0]
		for _, candidate := range b.flowOrder {
			token := strings.TrimPrefix(candidate, "udp\x00")
			if managed.hasFlow(token) {
				kept = append(kept, candidate)
			} else {
				delete(b.flowRoutes, candidate)
			}
		}
		b.flowOrder = kept
	}
	for len(b.flowOrder) >= 256 {
		oldest := b.flowOrder[0]
		b.flowOrder = b.flowOrder[1:]
		delete(b.flowRoutes, oldest)
	}
	routes := b.routes
	b.flowRoutes[key] = routes
	b.flowOrder = append(b.flowOrder, key)
	b.mu.Unlock()
	return routes
}

func (b *boundListen) recordRouteFailure(decision routeDecision, failure string) {
	if decision.RuleID == "" {
		return
	}
	b.mu.Lock()
	if b.routeFailures == nil {
		b.routeFailures = map[string]string{}
	}
	if failure == "" {
		delete(b.routeFailures, decision.RuleID)
	} else {
		b.routeFailures[decision.RuleID] = failure
	}
	b.mu.Unlock()
}

func (b *boundListen) routeStatuses() []RouteStatus {
	b.mu.Lock()
	routes := b.routes
	failures := make(map[string]string, len(b.routeFailures))
	for id, failure := range b.routeFailures {
		failures[id] = failure
	}
	b.mu.Unlock()
	statuses := routes.statuses()
	for index := range statuses {
		if failures[statuses[index].RuleID] != "" {
			statuses[index].Failure = failures[statuses[index].RuleID]
		}
	}
	return statuses
}

func (exec *listenExecutor) abortPrepared(prepared []preparedListen) {
	keep := map[*ProtocolEngine]struct{}{}
	for _, listener := range exec.bound {
		for _, engine := range listener.snapshotEngines() {
			keep[engine] = struct{}{}
		}
	}
	for _, candidate := range prepared {
		if candidate.bound != nil {
			candidate.bound.close()
			continue
		}
		destroyUserEngines(candidate.engines, keep)
	}
}

func assembleUserEngines(ctx context.Context, item ListenApplyItem, current []*boundUserEngine, resolver SecretVerifier) ([]*boundUserEngine, error) {
	byID := make(map[string]*ProtocolEngine, len(current))
	for _, existing := range current {
		if existing == nil || existing.engine == nil || existing.id == "" {
			continue
		}
		byID[existing.id] = existing.engine
	}
	next := make([]*boundUserEngine, 0, len(item.Users))
	created := make([]*ProtocolEngine, 0, len(item.Users))
	serverPSK := ""
	if item.ServerSecretRef != "" {
		if resolver == nil {
			return nil, ErrTypedHandlesUnavailable
		}
		material, err := resolver.Resolve(ctx, item.ServerSecretRef, item.ServerSecretVersion)
		if err != nil {
			return nil, err
		}
		serverPSK = string(material)
		clear(material)
	}
	for _, user := range item.Users {
		if !user.Enabled {
			continue
		}
		if user.SecretRef == "" || user.SecretVersion == "" || resolver == nil {
			destroyListenEngines(created)
			return nil, ErrInvalid
		}
		password, err := resolver.Resolve(ctx, user.SecretRef, user.SecretVersion)
		if err != nil {
			destroyListenEngines(created)
			return nil, err
		}
		if len(password) == 0 {
			clear(password)
			destroyListenEngines(created)
			return nil, ErrInvalid
		}
		engine, err := engineFromMaterial(item.Method, password, serverPSK)
		clear(password)
		if err != nil {
			destroyListenEngines(created)
			return nil, err
		}
		if old := byID[user.ID]; user.ID != "" && old != nil && old.sameSecrets(engine) {
			engine.Destroy()
			next = append(next, &boundUserEngine{id: user.ID, engine: old})
			continue
		}
		created = append(created, engine)
		next = append(next, &boundUserEngine{id: user.ID, engine: engine})
	}
	return next, nil
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
	b.flowRoutes = nil
	b.flowOrder = nil
	b.mu.Unlock()
	destroyUserEngines(engines, nil)
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

func (b *boundListen) snapshotUserEngines() []*boundUserEngine {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*boundUserEngine(nil), b.engines...)
}

func (b *boundListen) snapshotEngines() []*ProtocolEngine {
	users := b.snapshotUserEngines()
	out := make([]*ProtocolEngine, 0, len(users))
	for _, item := range users {
		if item != nil && item.engine != nil {
			out = append(out, item.engine)
		}
	}
	return out
}

func (b *boundListen) replaceUserEngines(engines []*boundUserEngine) {
	if b == nil {
		destroyUserEngines(engines, nil)
		return
	}
	keep := make(map[*ProtocolEngine]struct{}, len(engines))
	for _, item := range engines {
		if item != nil && item.engine != nil {
			keep[item.engine] = struct{}{}
		}
	}
	b.mu.Lock()
	old := b.engines
	b.engines = engines
	b.mu.Unlock()
	destroyUserEngines(old, keep)
}

func (b *boundListen) engineByUser(userID string) *ProtocolEngine {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, item := range b.engines {
		if item != nil && item.id == userID {
			return item.engine
		}
	}
	return nil
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
		if leftover := session.takeLeftover(); len(leftover) > 0 {
			conn = &prefixConn{Conn: conn, prefix: leftover}
		}
	}
	if err != nil {
		return
	}
	routes := b.snapshotRoutes()
	decision, err := routes.decide(ctx, "tcp", request.Target)
	if err != nil || decision.Action == RouteReject {
		failure := "route-rejected"
		if err != nil {
			failure = "dataset-or-upstream-unavailable"
		}
		b.recordRouteFailure(decision, failure)
		return
	}
	if b.dialer == nil {
		return
	}
	dialTarget := request.Target
	if decision.Action == RouteUpstream {
		dialTarget = net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port))
	}
	target, err := b.dialer.DialContext(ctx, "tcp", dialTarget)
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		return
	}
	defer target.Close()
	if decision.Action == RouteUpstream {
		target, err = b.wrapUpstreamTCP(ctx, target, *decision.Upstream, request)
		if err != nil {
			b.recordRouteFailure(decision, "upstream-auth-failed")
			return
		}
	} else if len(request.Payload) > 0 {
		if _, err := target.Write(request.Payload); err != nil {
			return
		}
	}
	b.recordRouteFailure(decision, "")
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
	decision, err := b.snapshotRoutesForFlow(clientAddr).decide(ctx, "udp", request.Target)
	if err != nil || decision.Action == RouteReject {
		failure := "route-rejected"
		if err != nil {
			failure = "dataset-or-upstream-unavailable"
		}
		b.recordRouteFailure(decision, failure)
		return
	}
	if b.dialer == nil {
		return
	}
	dialTarget := request.Target
	if decision.Action == RouteUpstream {
		dialTarget = net.JoinHostPort(decision.Upstream.Host, strconv.Itoa(decision.Upstream.Port))
	}
	conn, err := b.dialer.DialContext(ctx, "udp", dialTarget)
	if err != nil {
		b.recordRouteFailure(decision, "dial-failed")
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	var responses [][]byte
	if decision.Action == RouteUpstream {
		var upstreamErr error
		responses, upstreamErr = b.roundTripUpstreamUDPResponses(ctx, conn, *decision.Upstream, request)
		if upstreamErr != nil {
			b.recordRouteFailure(decision, "upstream-auth-failed")
			return
		}
	} else if len(request.Payload) > 0 {
		if _, err := conn.Write(request.Payload); err != nil {
			return
		}
		responses, err = collectUDPAssociationResponses(conn, func(payload []byte) ([]byte, error) { return payload, nil })
		if err != nil {
			b.recordRouteFailure(decision, "response-budget")
			return
		}
	}
	if len(responses) == 0 {
		b.recordRouteFailure(decision, "no-response")
		return
	}
	b.recordRouteFailure(decision, "")
	saltSize := 8
	if !matched.modern {
		saltSize = matched.SaltSize()
	}
	responseSalt := make([]byte, saltSize)
	if _, err := rand.Read(responseSalt); err != nil {
		return
	}
	udp := b.packetConn()
	if udp == nil {
		return
	}
	for _, response := range responses {
		if _, err := rand.Read(responseSalt); err != nil {
			return
		}
		packetID := uint64(0)
		if matched.modern {
			packetID = b.nextUDPPacketID()
		}
		sealed, err := matched.SealUDPResponse(responseSalt, packetID, request.SessionID, request.Target, response, time.Now(), nil)
		if err != nil {
			return
		}
		if _, err := udp.WriteTo(sealed, clientAddr); err != nil {
			return
		}
	}
}

func (b *boundListen) nextUDPPacketID() uint64 {
	b.mu.Lock()
	b.udpPacketID++
	value := b.udpPacketID
	b.mu.Unlock()
	return value
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

func destroyUserEngines(engines []*boundUserEngine, keep map[*ProtocolEngine]struct{}) {
	for _, item := range engines {
		if item == nil || item.engine == nil {
			continue
		}
		if _, ok := keep[item.engine]; ok {
			continue
		}
		item.engine.Destroy()
	}
}

func (c *Controller) attachReportNode(ctx context.Context, raw []byte) ([]byte, error) {
	var report ListenReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return raw, nil
	}
	if nodeHasAddr(nodeFromReport(report)) {
		return raw, nil
	}
	if c == nil || c.listenHost == nil {
		return raw, nil
	}
	node := c.listenHost.CatalogNode(ctx, report.AgentID)
	if !nodeHasAddr(node) {
		return raw, nil
	}
	report.DDNS, report.IPv4, report.IPv6 = node.DDNS, node.IPv4, node.IPv6
	encoded, err := json.Marshal(report)
	if err != nil {
		return raw, nil
	}
	return encoded, nil
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
