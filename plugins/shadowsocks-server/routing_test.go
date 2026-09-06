package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type routeDatasetFake struct {
	matches map[string]bool
	status  pluginsdk.DatasetQueryStatus
	queries []pluginsdk.DatasetQueryRequest
}

type rawSecretResolver map[string]string

func (resolver rawSecretResolver) Resolve(_ context.Context, ref, version string) ([]byte, error) {
	value, ok := resolver[issuedSecretKey(ref, version)]
	if !ok {
		return nil, ErrDenied
	}
	return []byte(value), nil
}

func (resolver rawSecretResolver) Verify(ctx context.Context, ref, version string, material []byte) error {
	value, err := resolver.Resolve(ctx, ref, version)
	if err != nil {
		return err
	}
	defer clear(value)
	if !bytes.Equal(value, material) {
		return ErrDenied
	}
	return nil
}

func (fake *routeDatasetFake) ResolveDataset(_ context.Context, request pluginsdk.DatasetResolveRequest) (pluginsdk.DatasetReference, error) {
	return pluginsdk.DatasetReference{Handle: strings.Repeat("a", 43), InstanceID: "instance-a", Generation: "generation-a", SourceID: request.SourceID, VersionDigest: "sha256:" + strings.Repeat("1", 64)}, nil
}

func (fake *routeDatasetFake) QueryDatasets(_ context.Context, request pluginsdk.DatasetQueryRequest) (pluginsdk.DatasetQueryResponse, error) {
	fake.queries = append(fake.queries, request)
	status := fake.status
	if status == "" {
		status = pluginsdk.DatasetQueryOK
	}
	response := pluginsdk.DatasetQueryResponse{Reference: request.Reference, Status: status}
	if status == pluginsdk.DatasetQueryOK {
		response.Matches = []pluginsdk.DatasetMatch{{Index: 0, Matched: fake.matches[request.Classifications[0].Name], Coverage: pluginsdk.DatasetCovered}}
	}
	return response, nil
}

func routeFixture() RoutingConfiguration {
	attribute := true
	return RoutingConfiguration{
		Upstreams: []Upstream{{ID: "ai-upstream", Host: "192.0.2.20", Port: 8388, Method: "aes-256-gcm", SecretRef: "secret/upstream", SecretVersion: "secret-version-000000000001", Enabled: true, TCP: true, UDP: true}},
		Rules: []RouteRule{
			{ID: "first-direct", SourceID: "geosite", Classification: pluginsdk.DatasetClassification{Name: "category-ai-cn", Kind: pluginsdk.DatasetClassificationDomain}, Action: RouteDirect},
			{ID: "ai-not-cn", SourceID: "geosite", Classification: pluginsdk.DatasetClassification{Name: "category-ai", Kind: pluginsdk.DatasetClassificationDomain, Attributes: []pluginsdk.DatasetAttribute{{Name: "!cn", Boolean: &attribute}}}, Action: RouteUpstream, UpstreamID: "ai-upstream"},
		},
		DefaultAction: RouteReject,
	}
}

func TestRouteSnapshotUsesFirstMatchAndDistinguishesDatasetFailure(t *testing.T) {
	fake := &routeDatasetFake{matches: map[string]bool{"category-ai-cn": true, "category-ai": true}}
	snapshot, err := prepareRouteSnapshot(t.Context(), routeFixture(), fake)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := snapshot.decide(t.Context(), "tcp", "chat.example.com:443")
	if err != nil || decision.Action != RouteDirect || decision.RuleID != "first-direct" || len(fake.queries) != 1 {
		t.Fatalf("decision=%+v queries=%d err=%v", decision, len(fake.queries), err)
	}
	reordered := routeFixture()
	reordered.Rules[0], reordered.Rules[1] = reordered.Rules[1], reordered.Rules[0]
	reorderedSnapshot, err := prepareRouteSnapshot(t.Context(), reordered, fake)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = reorderedSnapshot.decide(t.Context(), "tcp", "chat.example.com:443")
	if err != nil || decision.Action != RouteUpstream || decision.RuleID != "ai-not-cn" {
		t.Fatalf("reordered decision=%+v err=%v", decision, err)
	}

	fake.matches["category-ai-cn"] = false
	fake.queries = nil
	decision, err = snapshot.decide(t.Context(), "udp", "chat.example.com:53")
	if err != nil || decision.Action != RouteUpstream || decision.RuleID != "ai-not-cn" || decision.Upstream == nil || len(fake.queries) != 2 {
		t.Fatalf("upstream decision=%+v queries=%d err=%v", decision, len(fake.queries), err)
	}

	fake.status = pluginsdk.DatasetQueryMissingClassification
	if _, err := snapshot.decide(t.Context(), "tcp", "chat.example.com:443"); err != ErrRouteDatasetUnavailable {
		t.Fatalf("missing classification err=%v", err)
	}
	fake.status = pluginsdk.DatasetQueryOK
	fake.matches = map[string]bool{}
	outside := routeFixture()
	outside.DefaultAction = RouteDirect
	outsideSnapshot, err := prepareRouteSnapshot(t.Context(), outside, fake)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = outsideSnapshot.decide(t.Context(), "tcp", "outside.example.com:443")
	if err != nil || decision.Action != RouteDirect {
		t.Fatalf("outside decision=%+v err=%v", decision, err)
	}
}

func TestRouteSnapshotIPAndExplicitDefault(t *testing.T) {
	routing := routeFixture()
	routing.Rules = []RouteRule{{ID: "private", SourceID: "geoip", Classification: pluginsdk.DatasetClassification{Name: "private", Kind: pluginsdk.DatasetClassificationCIDR}, Action: RouteReject}}
	routing.DefaultAction = RouteDirect
	fake := &routeDatasetFake{matches: map[string]bool{"private": false}}
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, fake)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := snapshot.decide(t.Context(), "tcp", "198.51.100.7:443")
	if err != nil || decision.Action != RouteDirect || len(fake.queries) != 1 || fake.queries[0].Address != "198.51.100.7" {
		t.Fatalf("decision=%+v query=%+v err=%v", decision, fake.queries, err)
	}
	fake.matches["private"] = true
	decision, err = snapshot.decide(t.Context(), "tcp", "198.51.100.7:443")
	if err != nil || decision.Action != RouteReject {
		t.Fatalf("reject decision=%+v err=%v", decision, err)
	}
}

func TestTCPClientSessionValidatesLegacyAndSS2022Responses(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			material := "legacy-password"
			if SS2022Method(method) {
				server, user, err := GenerateSS2022Identity(method)
				if err != nil {
					t.Fatal(err)
				}
				material = server + ":" + user
			}
			clientEngine, err := NewProtocolEngine(method, []byte(material))
			if err != nil {
				t.Fatal(err)
			}
			serverEngine, err := NewProtocolEngine(method, []byte(material))
			if err != nil {
				t.Fatal(err)
			}
			defer serverEngine.Destroy()
			now := time.Unix(100, 0)
			requestSalt := bytes.Repeat([]byte{1}, clientEngine.SaltSize())
			requestWire, err := clientEngine.SealTCPRequest(requestSalt, "example.com:443", []byte("hello"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			clientSession, err := newTCPClientSession(clientEngine, requestSalt)
			if err != nil {
				t.Fatal(err)
			}
			defer clientSession.Close()
			request, serverSession, err := serverEngine.OpenTCPServerSession(requestWire, now)
			if err != nil || request.Target != "example.com:443" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			defer serverSession.Close()
			responseSalt := bytes.Repeat([]byte{2}, serverEngine.SaltSize())
			responseWire, err := serverSession.SealResponse(responseSalt, []byte("world"), now)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := clientSession.OpenPayload(bytes.NewReader(responseWire), now)
			if err != nil || string(payload) != "world" {
				t.Fatalf("first response=%q err=%v", payload, err)
			}
			serverChunk, _ := serverSession.SealPayloadChunk([]byte("again"))
			payload, err = clientSession.OpenPayload(bytes.NewReader(serverChunk), now)
			if err != nil || string(payload) != "again" {
				t.Fatalf("next response=%q err=%v", payload, err)
			}
			clientChunk, _ := clientSession.SealPayload([]byte("request-two"))
			payload, err = serverSession.OpenPayloadChunk(clientChunk)
			if err != nil || string(payload) != "request-two" {
				t.Fatalf("client chunk=%q err=%v", payload, err)
			}
		})
	}
}

func TestSS2022UpstreamPasswordIsCanonical(t *testing.T) {
	server := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	user := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	if _, err := NewProtocolEngine("2022-blake3-aes-128-gcm", []byte(server+":"+user)); err != nil {
		t.Fatal(err)
	}
}

type recordingDialer struct {
	mu      sync.Mutex
	address string
	open    func() net.Conn
	err     error
}

type messageConn struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   sync.Once
}

func messageConnPair() (*messageConn, *messageConn) {
	leftToRight, rightToLeft := make(chan []byte, 8), make(chan []byte, 8)
	closed := make(chan struct{})
	return &messageConn{in: rightToLeft, out: leftToRight, closed: closed}, &messageConn{in: leftToRight, out: rightToLeft, closed: closed}
}
func (conn *messageConn) Read(value []byte) (int, error) {
	select {
	case message := <-conn.in:
		if message == nil {
			return 0, io.EOF
		}
		return copy(value, message), nil
	case <-conn.closed:
		return 0, io.EOF
	}
}
func (conn *messageConn) Write(value []byte) (int, error) {
	copyValue := append([]byte(nil), value...)
	select {
	case conn.out <- copyValue:
		return len(value), nil
	case <-conn.closed:
		return 0, io.ErrClosedPipe
	}
}
func (conn *messageConn) Close() error                { conn.once.Do(func() { close(conn.closed) }); return nil }
func (*messageConn) LocalAddr() net.Addr              { return managedAddr{network: "udp", value: "local"} }
func (*messageConn) RemoteAddr() net.Addr             { return managedAddr{network: "udp", value: "remote"} }
func (*messageConn) SetDeadline(time.Time) error      { return nil }
func (*messageConn) SetReadDeadline(time.Time) error  { return nil }
func (*messageConn) SetWriteDeadline(time.Time) error { return nil }

func (dialer *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.address = address
	dialer.mu.Unlock()
	if dialer.err != nil {
		return nil, dialer.err
	}
	return dialer.open(), nil
}

func TestTCPHandlerRoutesCategoryAIToAuthenticatedUpstream(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			password := "upstream-password"
			if SS2022Method(method) {
				server, user, err := GenerateSS2022Identity(method)
				if err != nil {
					t.Fatal(err)
				}
				password = server + ":" + user
			}
			runTCPHandlerRoutesCategoryAI(t, method, password)
		})
	}
}

func runTCPHandlerRoutesCategoryAI(t *testing.T, upstreamMethod, upstreamPassword string) {
	t.Helper()
	const inboundPassword = "inbound-password"
	inboundServer, _ := NewProtocolEngine("aes-256-gcm", []byte(inboundPassword))
	inboundClient, _ := NewProtocolEngine("aes-256-gcm", []byte(inboundPassword))
	defer inboundServer.Destroy()
	requestSalt := bytes.Repeat([]byte{3}, inboundClient.SaltSize())
	inboundWire, err := inboundClient.SealTCPRequest(requestSalt, "chat.example.com:443", []byte("hello"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	inboundSession, err := newTCPClientSession(inboundClient, requestSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer inboundSession.Close()

	dataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	routing := routeFixture()
	routing.Rules = routing.Rules[1:]
	routing.Upstreams[0].Method = upstreamMethod
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, dataset)
	if err != nil {
		t.Fatal(err)
	}
	secrets := rawSecretResolver{issuedSecretKey("secret/upstream", "secret-version-000000000001"): upstreamPassword}
	served := make(chan ProxyRequest, 1)
	dialer := &recordingDialer{open: func() net.Conn {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			upstream, _ := NewProtocolEngine(upstreamMethod, []byte(upstreamPassword))
			defer upstream.Destroy()
			request, session, err := readTCPHandshake(server, []*ProtocolEngine{upstream})
			if err != nil {
				return
			}
			defer session.Close()
			served <- request
			wire, _ := session.SealResponse(bytes.Repeat([]byte{4}, upstream.SaltSize()), []byte("world"), time.Now())
			_, _ = server.Write(wire)
		}()
		return client
	}}
	bound := &boundListen{engines: []*boundUserEngine{{id: "inbound", engine: inboundServer}}, dialer: dialer, secrets: secrets, routes: snapshot}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { bound.handleTCP(context.Background(), server); close(done) }()
	if _, err := client.Write(inboundWire); err != nil {
		t.Fatal(err)
	}
	response, err := inboundSession.OpenPayload(client, time.Now())
	if err != nil || string(response) != "world" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
	request := <-served
	if request.Target != "chat.example.com:443" || string(request.Payload) != "hello" {
		t.Fatalf("upstream request=%+v", request)
	}
	if dialer.address != "192.0.2.20:8388" || len(dataset.queries) != 1 {
		t.Fatalf("dial=%q queries=%d", dialer.address, len(dataset.queries))
	}
}

func TestUpstreamFailureNeverDialsOriginalTarget(t *testing.T) {
	dataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	routing := routeFixture()
	routing.Rules = routing.Rules[1:]
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, dataset)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{err: errors.New("upstream offline")}
	decision, err := snapshot.decide(t.Context(), "tcp", "chat.example.com:443")
	if err != nil || decision.Upstream == nil {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if _, err := dialer.DialContext(t.Context(), "tcp", net.JoinHostPort(decision.Upstream.Host, "8388")); err == nil {
		t.Fatal("offline upstream succeeded")
	}
	if dialer.address != "192.0.2.20:8388" {
		t.Fatalf("fallback dial=%q", dialer.address)
	}
}

func TestWrongUpstreamSecretFailsWithoutDirectFallback(t *testing.T) {
	const configured = "configured-password"
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		wrong, _ := NewProtocolEngine("aes-256-gcm", []byte("wrong-password"))
		defer wrong.Destroy()
		_, _, _ = readTCPHandshake(server, []*ProtocolEngine{wrong})
	}()
	bound := &boundListen{secrets: rawSecretResolver{issuedSecretKey("secret/upstream", "secret-version-000000000001"): configured}}
	upstream := routeFixture().Upstreams[0]
	wrapped, err := bound.wrapUpstreamTCP(t.Context(), client, upstream, ProxyRequest{Target: "example.com:443", Payload: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if _, err = wrapped.Read(buffer); err == nil {
		t.Fatal("wrong upstream secret produced a response")
	}
}

func TestRoutingAPIManagesUpstreamOrderDefaultAndDiagnostics(t *testing.T) {
	fake := &managedRuntimeFake{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm"}`); response.Code != 200 {
		t.Fatalf("listen=%d %s", response.Code, response.Body.String())
	}
	upstream := uiJSON(t, controller, "POST", "/api/upstreams", `{"id":"ai-upstream","host":"192.0.2.20","port":8388,"method":"aes-256-gcm","password":"upstream-password","tcp":true,"udp":true}`)
	if upstream.Code != 200 {
		t.Fatalf("upstream=%d %s", upstream.Code, upstream.Body.String())
	}
	rules := `{"rules":[{"id":"ai-not-cn","source_id":"geosite","classification":{"name":"category-ai","kind":"domain","attributes":[{"name":"!cn","boolean":true}]},"action":"upstream","upstream_id":"ai-upstream"}],"default_action":"direct"}`
	if response := uiJSON(t, controller, "POST", "/api/routing", rules); response.Code != 200 {
		t.Fatalf("rules=%d %s", response.Code, response.Body.String())
	}
	if !state.routingFound || len(state.routing.Rules) != 1 || len(state.routing.Upstreams) != 1 {
		t.Fatalf("persisted routing=%+v", state.routing)
	}
	get := uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-1", "")
	var payload listenAPIResponse
	if err := json.Unmarshal(get.Body.Bytes(), &payload); err != nil || payload.Routing == nil || len(payload.Routing.Rules) != 1 || len(payload.RouteSources) != 1 || payload.RouteSources[0].VersionDigest == "" || len(payload.RouteStatus) != 1 {
		t.Fatalf("routing=%s err=%v", get.Body.String(), err)
	}
	if bytes.Contains(get.Body.Bytes(), []byte("upstream-password")) || payload.RouteStatus[0].Exit != "ai-upstream" {
		t.Fatalf("routing diagnostics leaked secret or omitted exit: %s", get.Body.String())
	}
	if payload.Routing.Rules[0].Classification.Attributes[0].Name != "!cn" {
		t.Fatalf("classification=%+v", payload.Routing.Rules[0])
	}
	disabled := uiJSON(t, controller, "POST", "/api/upstreams/ai-upstream/disable", `{}`)
	if disabled.Code != 200 {
		t.Fatalf("disable=%d %s", disabled.Code, disabled.Body.String())
	}
	get = uiJSON(t, controller, "GET", "/api/routing?agent_id=agent-1", "")
	payload = listenAPIResponse{}
	_ = json.Unmarshal(get.Body.Bytes(), &payload)
	if payload.Routing.Upstreams[0].Enabled || len(payload.RouteStatus) != 1 || payload.RouteStatus[0].Failure != "upstream-disabled" {
		t.Fatalf("disabled routing=%s", get.Body.String())
	}
	snapshot, err := prepareRouteSnapshot(t.Context(), *payload.Routing, &routeDatasetFake{matches: map[string]bool{"category-ai": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.decide(t.Context(), "tcp", "chat.example.com:443"); err != ErrRouteUpstreamUnavailable {
		t.Fatalf("disabled decision=%v", err)
	}
	fake.datasetError = true
	get = uiJSON(t, controller, "GET", "/api/routing", "")
	payload = listenAPIResponse{}
	_ = json.Unmarshal(get.Body.Bytes(), &payload)
	if len(payload.RouteSources) != 1 || payload.RouteSources[0].Error != "dataset-unavailable" || payload.RouteStatus[0].Failure != "upstream-disabled" {
		t.Fatalf("dataset diagnostics=%s", get.Body.String())
	}
	if response := uiJSON(t, controller, "POST", "/api/upstreams/ai-upstream/enable", `{}`); response.Code != 200 {
		t.Fatalf("enable=%d %s", response.Code, response.Body.String())
	}
	if response := uiJSON(t, controller, "POST", "/api/routing", `{"rules":[],"default_action":"direct"}`); response.Code != 200 {
		t.Fatalf("clear rules=%d %s", response.Code, response.Body.String())
	}
	ref := payload.Routing.Upstreams[0]
	if response := uiJSON(t, controller, "POST", "/api/upstreams/ai-upstream/delete", `{}`); response.Code != 200 {
		t.Fatalf("delete=%d %s", response.Code, response.Body.String())
	}
	if _, err := managed.Resolve(t.Context(), ref.SecretRef, ref.SecretVersion); err == nil {
		t.Fatal("deleted upstream secret remained readable")
	}
}

func TestSS2022TCPClientRejectsResponseBoundToAnotherRequest(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	serverPSK, userPSK, err := GenerateSS2022Identity(method)
	if err != nil {
		t.Fatal(err)
	}
	material := []byte(serverPSK + ":" + userPSK)
	clientEngine, _ := NewProtocolEngine(method, material)
	serverEngine, _ := NewProtocolEngine(method, material)
	defer serverEngine.Destroy()
	now := time.Now()
	firstSalt := bytes.Repeat([]byte{1}, clientEngine.SaltSize())
	clientSession, err := newTCPClientSession(clientEngine, firstSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	secondSalt := bytes.Repeat([]byte{2}, serverEngine.SaltSize())
	secondWire, err := serverEngine.SealTCPRequest(secondSalt, "example.com:443", []byte("other"), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, serverSession, err := serverEngine.OpenTCPServerSession(secondWire, now)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	responseWire, err := serverSession.SealResponse(bytes.Repeat([]byte{3}, serverEngine.SaltSize()), []byte("wrong-flow"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clientSession.OpenPayload(bytes.NewReader(responseWire), now); err == nil {
		t.Fatal("response bound to another request was accepted")
	}
}

func TestUDPUpstreamRoundTripAuthenticatesResponse(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			password := "upstream-password"
			if SS2022Method(method) {
				server, user, err := GenerateSS2022Identity(method)
				if err != nil {
					t.Fatal(err)
				}
				password = server + ":" + user
			}
			runUDPUpstreamRoundTrip(t, method, password)
		})
	}
}

func TestUDPAssociationCollectorBoundsCountAndBytes(t *testing.T) {
	client, server := messageConnPair()
	go func() {
		for index := 0; index < maxUDPAssociationResponses+1; index++ {
			server.out <- []byte{byte(index)}
		}
	}()
	responses, err := collectUDPAssociationResponses(client, func(value []byte) ([]byte, error) { return value, nil })
	if err != nil || len(responses) != maxUDPAssociationResponses {
		t.Fatalf("count responses=%d err=%v", len(responses), err)
	}

	client, server = messageConnPair()
	packet := bytes.Repeat([]byte{'x'}, maxUDPPacket)
	for index := 0; index < 5; index++ {
		server.out <- packet
	}
	if responses, err = collectUDPAssociationResponses(client, func(value []byte) ([]byte, error) { return value, nil }); err != ErrRouteUpstreamUnavailable || responses != nil {
		t.Fatalf("byte overflow responses=%d err=%v", len(responses), err)
	}
}

func TestUDPFlowKeepsRouteSnapshotAcrossUpdatesAndPrunes(t *testing.T) {
	oldDataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	oldRouting := routeFixture()
	oldRouting.Rules = oldRouting.Rules[1:]
	oldSnapshot, err := prepareRouteSnapshot(t.Context(), oldRouting, oldDataset)
	if err != nil {
		t.Fatal(err)
	}
	newRouting := cloneRouting(oldRouting)
	newRouting.Rules[0].Action = RouteDirect
	newRouting.Rules[0].UpstreamID = ""
	newSnapshot, err := prepareRouteSnapshot(t.Context(), newRouting, oldDataset)
	if err != nil {
		t.Fatal(err)
	}
	flowConn := &managedPacketConn{flows: map[string]*managedConn{"flow-old": {}}, packets: make(chan managedPacket, 1)}
	bound := &boundListen{udp: flowConn, routes: oldSnapshot, flowRoutes: map[string]*routeSnapshot{}}
	oldAddress := managedAddr{network: "udp", value: "flow-old"}
	if got := bound.snapshotRoutesForFlow(oldAddress); got != oldSnapshot {
		t.Fatal("first flow did not bind old snapshot")
	}
	bound.replaceRoutes(newSnapshot)
	if got := bound.snapshotRoutesForFlow(oldAddress); got != oldSnapshot {
		t.Fatal("existing flow switched route snapshot")
	}
	flowConn.mu.Lock()
	flowConn.flows["flow-new"] = &managedConn{}
	delete(flowConn.flows, "flow-old")
	flowConn.mu.Unlock()
	newAddress := managedAddr{network: "udp", value: "flow-new"}
	if got := bound.snapshotRoutesForFlow(newAddress); got != newSnapshot {
		t.Fatal("new flow did not bind new snapshot")
	}
	bound.mu.Lock()
	_, oldKept := bound.flowRoutes["udp\x00flow-old"]
	bound.mu.Unlock()
	if oldKept {
		t.Fatal("inactive managed flow route was not pruned")
	}

	native := &boundListen{routes: newSnapshot, flowRoutes: map[string]*routeSnapshot{}}
	for index := 0; index < 300; index++ {
		native.snapshotRoutesForFlow(managedAddr{network: "native", value: fmt.Sprintf("peer-%d", index)})
	}
	native.mu.Lock()
	size := len(native.flowRoutes)
	native.mu.Unlock()
	if size > 256 {
		t.Fatalf("native flow route cache=%d", size)
	}
}

func runUDPUpstreamRoundTrip(t *testing.T, method, password string) {
	t.Helper()
	client, server := messageConnPair()
	serverResult := make(chan error, 1)
	go func() {
		defer func() { server.out <- nil }()
		engine, _ := NewProtocolEngine(method, []byte(password))
		defer engine.Destroy()
		buffer := make([]byte, maxUDPPacket)
		n, _ := server.Read(buffer)
		request, err := engine.OpenUDPPacket(buffer[:n], time.Now())
		if err != nil {
			serverResult <- fmt.Errorf("open n=%d prefix=%x: %w", n, buffer[:min(n, 8)], err)
			return
		}
		for packetID, payload := range [][]byte{[]byte("answer-one"), []byte("answer-two")} {
			responsePacketID := uint64(0)
			responseSaltSize := engine.SaltSize()
			if SS2022Method(method) {
				responsePacketID = uint64(packetID + 1)
				responseSaltSize = 8
			}
			wire, sealErr := engine.SealUDPResponse(bytes.Repeat([]byte{byte(5 + packetID)}, responseSaltSize), responsePacketID, request.SessionID, request.Target, payload, time.Now(), nil)
			if sealErr != nil {
				serverResult <- sealErr
				return
			}
			if _, writeErr := server.Write(wire); writeErr != nil {
				serverResult <- writeErr
				return
			}
		}
		serverResult <- nil
	}()
	bound := &boundListen{secrets: rawSecretResolver{issuedSecretKey("secret/upstream", "secret-version-000000000001"): password}}
	upstream := routeFixture().Upstreams[0]
	upstream.Method = method
	responses, err := bound.roundTripUpstreamUDPResponses(t.Context(), client, upstream, ProxyRequest{Target: "example.org:53", Payload: []byte("query")})
	if err != nil || len(responses) != 2 || string(responses[0]) != "answer-one" || string(responses[1]) != "answer-two" {
		t.Fatalf("responses=%q err=%v server=%v", responses, err, <-serverResult)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
