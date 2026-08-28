package shadowsocksserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countingListenBinder struct {
	tcp atomic.Int32
	udp atomic.Int32
}

func (b *countingListenBinder) Listen(network, address string) (net.Listener, error) {
	b.tcp.Add(1)
	return net.Listen(network, address)
}

func (b *countingListenBinder) ListenPacket(network, address string) (net.PacketConn, error) {
	b.udp.Add(1)
	return net.ListenPacket(network, address)
}

type failListenBinder struct {
	err error
	tcp atomic.Int32
	udp atomic.Int32
}

func (b *failListenBinder) Listen(string, string) (net.Listener, error) {
	b.tcp.Add(1)
	return nil, b.err
}

func (b *failListenBinder) ListenPacket(string, string) (net.PacketConn, error) {
	b.udp.Add(1)
	return nil, b.err
}

func newCallController(t *testing.T, binder listenBinder) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ListenBinder: binder,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if controller.listenExec != nil {
			controller.listenExec.stopAll()
		}
	})
	return controller
}

func callListen(t *testing.T, controller *Controller, name string, payload map[string]any) ([]byte, error) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return controller.Call(context.Background(), "generation-1", name, raw)
}

func freeTCPUDPPort(t *testing.T) int {
	t.Helper()
	tcp, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenPacket("udp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestPluginCallListenApplySuccessBindsTCPUDPAndHandshakes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		method string
	}{
		{name: "legacy", method: "aes-256-gcm"},
		{name: "ss2022", method: "2022-blake3-aes-128-gcm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertListenApplyHandshakeAndUDPReply(t, test.method)
		})
	}
}

func assertListenApplyHandshakeAndUDPReply(t *testing.T, method string) {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	got := make(chan []byte, 2)
	go echoTCPHandshake(target, got)

	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go echoUDPQuery(udpTarget)

	port := freeTCPUDPPort(t)
	password := "alice-password"
	serverPSK := ""
	listen := map[string]any{
		"id": "listen-1", "port": port, "method": method,
		"users": []map[string]any{{"id": "alice", "enabled": true, "password": password}},
	}
	if strings.HasPrefix(method, "2022-") {
		var identityPSK string
		var genErr error
		serverPSK, identityPSK, genErr = GenerateSS2022Identity(method)
		if genErr != nil {
			t.Fatal(genErr)
		}
		password = identityPSK
		listen["server_psk"] = serverPSK
		listen["users"] = []map[string]any{{"id": "alice", "enabled": true, "password": identityPSK}}
	}
	controller := newCallController(t, nil)
	raw, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens":  []map[string]any{listen},
	})
	if err != nil {
		t.Fatal(err)
	}
	var applied listenApplyResult
	if err := json.Unmarshal(raw, &applied); err != nil {
		t.Fatal(err)
	}
	if !applied.Accepted || applied.AgentID != "agent-1" || len(applied.Listens) != 1 || applied.Listens[0].Port != port || !applied.Listens[0].TCP || !applied.Listens[0].UDP {
		t.Fatalf("apply result=%#v", applied)
	}

	material := []byte(password)
	if serverPSK != "" {
		material = []byte(serverPSK + ":" + password)
	}
	client, err := NewProtocolEngine(method, material)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	completeTCPHandshake(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), target.Addr().String(), got)
	completeUDPReply(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), udpTarget.LocalAddr().String())

	report, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), password) || serverPSK != "" && strings.Contains(string(report), serverPSK) {
		t.Fatalf("report leaked secrets: %s", report)
	}
	decoded, err := decodeListenReport(report)
	if err != nil || decoded.AgentID != "agent-1" || !decoded.Online || len(decoded.Listens) != 1 || decoded.Listens[0].Port != port {
		t.Fatalf("report=%#v err=%v", decoded, err)
	}

	if _, err := callListen(t, controller, pluginCallListenStop, map[string]any{"agent_id": "agent-1", "listen_ids": []string{"listen-1"}}); err != nil {
		t.Fatal(err)
	}
	stopped, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := decodeListenReport(stopped)
	if err != nil || len(after.Listens) != 0 {
		t.Fatalf("stop left listens=%#v err=%v", after, err)
	}
}

func completeTCPHandshake(t *testing.T, client *ProtocolEngine, listenAddr, targetAddr string, got <-chan []byte) {
	t.Helper()
	salt := make([]byte, client.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tcpWire, err := client.SealTCPRequest(salt, targetAddr, []byte("hello"), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(tcpWire); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got:
		if string(payload) != "hello" {
			t.Fatalf("tcp handshake payload=%q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tcp handshake did not reach target")
	}
	first, response := readTCPClientResponse(t, conn, client, salt)
	if string(first) != "world" {
		t.Fatalf("tcp handshake response=%q", first)
	}
	key, err := client.keySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	requestSession, err := client.newSession(key, salt)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	requestSession.nonce[0] = 2
	if _, err := conn.Write(sealPayloadChunk(requestSession, []byte("next!"))); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got:
		if string(payload) != "next!" {
			t.Fatalf("tcp follow payload=%q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tcp follow chunk did not reach target")
	}
	follow, err := readOpenedTCPChunk(conn, response, max2022Payload)
	if err != nil || string(follow) != "again" {
		t.Fatalf("tcp follow response=%q err=%v", follow, err)
	}
}

func completeUDPReply(t *testing.T, client *ProtocolEngine, listenAddr, targetAddr string) {
	t.Helper()
	sessionID := make([]byte, client.SaltSize())
	packetID := uint64(0)
	clientSession := uint64(0)
	if client.modern {
		sessionID = []byte{1, 2, 3, 4, 5, 6, 7, 8}
		packetID = 9
		clientSession = 0x0102030405060708
	} else if _, err := rand.Read(sessionID); err != nil {
		t.Fatal(err)
	}
	udpWire, err := client.SealUDPPacket(sessionID, packetID, targetAddr, []byte("query"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)
	var opened ProxyRequest
	for {
		if _, err := udpConn.Write(udpWire); err != nil {
			t.Fatal(err)
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, readErr := udpConn.Read(buf)
		if readErr == nil {
			opened, err = client.OpenUDPResponse(buf[:n], time.Now(), clientSession)
			if err == nil && string(opened.Payload) == "answer" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("udp reply payload=%q err=%v", opened.Payload, err)
		}
	}
}

func readTCPClientResponse(t *testing.T, conn net.Conn, engine *ProtocolEngine, requestSalt []byte) ([]byte, *streamCipher) {
	t.Helper()
	salt := make([]byte, engine.SaltSize())
	if _, err := io.ReadFull(conn, salt); err != nil {
		t.Fatalf("tcp response salt: %v", err)
	}
	key, err := engine.keySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	session, err := engine.newSession(key, salt)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	if engine.modern {
		fixedWireLength := 1 + 8 + engine.SaltSize() + 2 + session.aead.Overhead()
		fixedWire := make([]byte, fixedWireLength)
		if _, err := io.ReadFull(conn, fixedWire); err != nil {
			t.Fatalf("tcp response header: %v", err)
		}
		fixed, err := session.open(fixedWire)
		if err != nil || len(fixed) < 11 || fixed[0] != 1 || !bytes.Equal(fixed[9:9+engine.SaltSize()], requestSalt) {
			t.Fatalf("tcp response header=%x err=%v", fixed, err)
		}
		payloadLen := int(binary.BigEndian.Uint16(fixed[len(fixed)-2:]))
		payloadWire := make([]byte, payloadLen+session.aead.Overhead())
		if _, err := io.ReadFull(conn, payloadWire); err != nil {
			t.Fatalf("tcp response payload: %v", err)
		}
		payload, err := session.open(payloadWire)
		if err != nil {
			t.Fatal(err)
		}
		return payload, session
	}
	payload, err := readOpenedTCPChunk(conn, session, maxLegacyPayload)
	if err != nil {
		t.Fatal(err)
	}
	return payload, session
}

func readOpenedTCPChunk(conn net.Conn, session *streamCipher, maximum int) ([]byte, error) {
	headerSize := 2 + session.aead.Overhead()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	lengthPlain, err := session.open(header)
	if err != nil || len(lengthPlain) != 2 {
		return nil, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(lengthPlain))
	if length > maximum {
		return nil, ErrProtocol
	}
	rest := make([]byte, length+session.aead.Overhead())
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	return session.open(rest)
}

func echoTCPHandshake(target net.Listener, got chan<- []byte) {
	conn, acceptErr := target.Accept()
	if acceptErr != nil {
		got <- nil
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 5)
	if _, readErr := io.ReadFull(conn, buf); readErr != nil {
		got <- nil
		return
	}
	got <- append([]byte(nil), buf...)
	if _, writeErr := conn.Write([]byte("world")); writeErr != nil {
		return
	}
	if _, readErr := io.ReadFull(conn, buf); readErr != nil {
		return
	}
	got <- append([]byte(nil), buf...)
	_, _ = conn.Write([]byte("again"))
}

func echoUDPQuery(udpTarget net.PacketConn) {
	_ = udpTarget.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	_, addr, readErr := udpTarget.ReadFrom(buf)
	if readErr != nil {
		return
	}
	_, _ = udpTarget.WriteTo([]byte("answer"), addr)
}

func TestPluginCallListenApplyKeepsPreviousSocketsOnReplacementBindFailure(t *testing.T) {
	t.Parallel()
	port := freeTCPUDPPort(t)
	blocked := freeTCPUDPPort(t)
	blocker, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(blocked)))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	controller := newCallController(t, nil)
	if _, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens": []map[string]any{{
			"id": "listen-1", "port": port, "method": "aes-256-gcm",
			"users": []map[string]any{{"id": "alice", "enabled": true, "password": "alice-password"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens": []map[string]any{{
			"id": "listen-1", "port": blocked, "method": "aes-256-gcm",
			"users": []map[string]any{{"id": "alice", "enabled": true, "password": "alice-password"}},
		}},
	}); !errors.Is(err, ErrListenBind) {
		t.Fatalf("replacement apply err=%v", err)
	}
	report, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeListenReport(report)
	if err != nil || len(decoded.Listens) != 1 || decoded.Listens[0].Port != port {
		t.Fatalf("replacement bind failure dropped previous listen: %#v err=%v", decoded, err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	got := make(chan []byte, 2)
	go echoTCPHandshake(target, got)
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go echoUDPQuery(udpTarget)
	client, err := NewProtocolEngine("aes-256-gcm", []byte("alice-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	completeTCPHandshake(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), target.Addr().String(), got)
	completeUDPReply(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), udpTarget.LocalAddr().String())
}

func TestPluginCallListenApplyBindFailureDoesNotMarkLive(t *testing.T) {
	t.Parallel()
	binder := &failListenBinder{err: errors.New("bind: address already in use")}
	controller := newCallController(t, binder)
	_, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens": []map[string]any{{
			"id": "listen-1", "port": 8388, "method": "aes-256-gcm",
			"users": []map[string]any{{"id": "alice", "enabled": true, "password": "secret-must-not-leak"}},
		}},
	})
	if !errors.Is(err, ErrListenBind) {
		t.Fatalf("apply err=%v", err)
	}
	if binder.tcp.Load() == 0 {
		t.Fatal("bind was not attempted")
	}
	report, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), "secret-must-not-leak") {
		t.Fatalf("report leaked password: %s", report)
	}
	decoded, err := decodeListenReport(report)
	if err != nil || !decoded.Online || len(decoded.Listens) != 0 {
		t.Fatalf("failed apply still live: %#v err=%v", decoded, err)
	}
}

func TestPluginCallListenMissingAgentIDDoesNotBind(t *testing.T) {
	t.Parallel()
	binder := &countingListenBinder{}
	controller := newCallController(t, binder)
	for _, payload := range []map[string]any{
		{"listens": []map[string]any{{"id": "listen-1", "port": 8388, "method": "aes-256-gcm"}}},
		{"agent_id": "", "listens": []map[string]any{{"id": "listen-1", "port": 8388, "method": "aes-256-gcm"}}},
		nil,
	} {
		_, err := callListen(t, controller, pluginCallListenApply, payload)
		if !errors.Is(err, ErrAgentOffline) {
			t.Fatalf("payload=%#v err=%v", payload, err)
		}
	}
	if _, err := controller.Call(context.Background(), "generation-1", pluginCallListenApply, nil); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("empty payload err=%v", err)
	}
	if binder.tcp.Load() != 0 || binder.udp.Load() != 0 {
		t.Fatalf("missing agent id still bound tcp=%d udp=%d", binder.tcp.Load(), binder.udp.Load())
	}
}

func TestPluginCallListenUnknownNameFailsClosed(t *testing.T) {
	t.Parallel()
	binder := &countingListenBinder{}
	controller := newCallController(t, binder)
	if _, err := controller.Call(context.Background(), "generation-1", "listen.bind", []byte(`{"agent_id":"agent-1"}`)); err == nil || !errors.Is(err, ErrTypedHandlesUnavailable) {
		t.Fatalf("unknown name err=%v", err)
	}
	if binder.tcp.Load() != 0 {
		t.Fatal("unknown name invoked local bind")
	}
}

func TestPluginCallListenStopAllUnbinds(t *testing.T) {
	t.Parallel()
	port := freeTCPUDPPort(t)
	controller := newCallController(t, nil)
	if _, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens":  []map[string]any{{"id": "listen-1", "port": port, "method": "aes-256-gcm"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := callListen(t, controller, pluginCallListenStop, map[string]any{"agent_id": "agent-1"}); err != nil {
		t.Fatal(err)
	}
	report, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeListenReport(report)
	if err != nil || len(decoded.Listens) != 0 {
		t.Fatalf("stop all left listens=%#v err=%v", decoded, err)
	}
}

func decodeListenReport(raw []byte) (ListenReport, error) {
	var report ListenReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return ListenReport{}, err
	}
	return report, nil
}
