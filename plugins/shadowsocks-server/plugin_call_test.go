package shadowsocksserver

import (
	"context"
	"crypto/rand"
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
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			got <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 5)
		n, _ := io.ReadFull(conn, buf)
		got <- append([]byte(nil), buf[:n]...)
	}()

	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	udpGot := make(chan []byte, 1)
	go func() {
		_ = udpTarget.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _, readErr := udpTarget.ReadFrom(buf)
		if readErr != nil {
			udpGot <- nil
			return
		}
		udpGot <- append([]byte(nil), buf[:n]...)
	}()

	port := freeTCPUDPPort(t)
	password := "alice-password"
	controller := newCallController(t, nil)
	raw, err := callListen(t, controller, pluginCallListenApply, map[string]any{
		"agent_id": "agent-1",
		"listens": []map[string]any{{
			"id": "listen-1", "port": port, "method": "aes-256-gcm",
			"users": []map[string]any{{"id": "alice", "enabled": true, "password": password}},
		}},
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

	client, err := NewProtocolEngine("aes-256-gcm", []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	salt := make([]byte, client.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	tcpWire, err := client.SealTCPRequest(salt, target.Addr().String(), []byte("hello"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
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
	_ = conn.Close()

	udpSalt := make([]byte, client.SaltSize())
	if _, err := rand.Read(udpSalt); err != nil {
		t.Fatal(err)
	}
	udpWire, err := client.SealUDPPacket(udpSalt, 0, udpTarget.LocalAddr().String(), []byte("query"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := udpConn.Write(udpWire); err != nil {
			t.Fatal(err)
		}
		select {
		case payload := <-udpGot:
			if string(payload) != "query" {
				t.Fatalf("udp handshake payload=%q", payload)
			}
			deadline = time.Time{}
		case <-time.After(100 * time.Millisecond):
		}
		if deadline.IsZero() || time.Now().After(deadline) {
			break
		}
	}
	_ = udpConn.Close()
	if !deadline.IsZero() {
		t.Fatal("udp handshake did not reach target")
	}

	report, err := callListen(t, controller, pluginCallListenReport, map[string]any{"agent_id": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), password) || strings.Contains(string(report), "server_psk") {
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
