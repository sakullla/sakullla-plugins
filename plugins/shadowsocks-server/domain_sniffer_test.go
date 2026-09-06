package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

type deadlineRecordingConn struct {
	net.Conn
	mu    sync.Mutex
	reads []time.Time
}

func (conn *deadlineRecordingConn) SetReadDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.reads = append(conn.reads, value)
	conn.mu.Unlock()
	return conn.Conn.SetReadDeadline(value)
}

func TestSniffHTTPHostAndFallbacks(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		domain  string
		state   sniffState
	}{
		{"http11", "GET / HTTP/1.1\r\nHost: AI.Example.com:443\r\n\r\n", "ai.example.com", sniffDone},
		{"http10", "GET / HTTP/1.0\r\nhost: ai.example.com\r\n\r\n", "ai.example.com", sniffDone},
		{"fragment", "GET / HTTP/1.1\r\nHo", "", sniffNeedMore},
		{"conflict", "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n", "", sniffDone},
		{"http2", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "", sniffDone},
		{"malformed", "GET / HTTP/1.1\r\nHost ai.example\r\n\r\n", "", sniffDone},
		{"absolute-conflict", "GET http://a.example/path HTTP/1.1\r\nHost: b.example\r\n\r\n", "", sniffDone},
		{"absolute", "GET https://ai.example/path HTTP/1.1\r\nHost: ai.example\r\n\r\n", "ai.example", sniffDone},
		{"obs-fold", "GET / HTTP/1.1\r\nHost: ai.example\r\n folded\r\n\r\n", "", sniffDone},
		{"bare-lf", "GET / HTTP/1.1\nHost: ai.example\n\n", "", sniffDone},
		{"control", "GET / HTTP/1.1\r\nHost: ai.example\x01\r\n\r\n", "", sniffDone},
		{"binary-body", "POST / HTTP/1.1\r\nHost: ai.example\r\nContent-Length: 3\r\n\r\n\x00\nx", "ai.example", sniffDone},
		{"bare-lf-body", "POST / HTTP/1.1\r\nHost: ai.example\r\n\r\nline-one\nline-two", "ai.example", sniffDone},
	} {
		t.Run(test.name, func(t *testing.T) {
			domain, state := sniffTCPDomain([]byte(test.payload))
			if domain != test.domain || state != test.state {
				t.Fatalf("domain=%q state=%d", domain, state)
			}
		})
	}
}

func sniffSessionFixture(t *testing.T) (*TCPServerSession, *TCPClientSession) {
	t.Helper()
	engine, _ := NewProtocolEngine("aes-256-gcm", []byte("password"))
	client, _ := NewProtocolEngine("aes-256-gcm", []byte("password"))
	t.Cleanup(engine.Destroy)
	salt := bytes.Repeat([]byte{1}, client.SaltSize())
	wire, err := client.SealTCPRequest(salt, "198.51.100.1:443", []byte("x"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := newTCPClientSession(client, salt)
	if err != nil {
		t.Fatal(err)
	}
	_, serverSession, err := engine.OpenTCPServerSession(wire, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return serverSession, clientSession
}

func TestTransactionalSniffChunkReplaysPartialCiphertextWithoutAdvancingNonce(t *testing.T) {
	serverSession, clientSession := sniffSessionFixture(t)
	defer serverSession.Close()
	defer clientSession.Close()
	wire, err := clientSession.SealPayload([]byte("Host: ai.example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	go func() {
		_, _ = client.Write(wire[:len(wire)/2])
		time.Sleep(30 * time.Millisecond)
		_, _ = client.Write(wire[len(wire)/2:])
	}()
	payload, prefix, err := transactionalSniffChunk(server, serverSession, maxSniffBytes)
	if err == nil || len(payload) != 0 || len(prefix) == 0 {
		t.Fatalf("payload=%q prefix=%d err=%v", payload, len(prefix), err)
	}
	_ = server.SetReadDeadline(time.Time{})
	replayed := &prefixConn{Conn: server, prefix: prefix}
	payload, err = readTCPPayloadChunk(replayed, serverSession)
	if err != nil || string(payload) != "Host: ai.example.com\r\n\r\n" {
		t.Fatalf("replayed=%q err=%v", payload, err)
	}
}

func TestTransactionalSniffChunkLeavesOverLimitChunkForRelay(t *testing.T) {
	serverSession, clientSession := sniffSessionFixture(t)
	defer serverSession.Close()
	defer clientSession.Close()
	wire, err := clientSession.SealPayload(bytes.Repeat([]byte{'z'}, 64))
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() { _, _ = client.Write(wire); close(done) }()
	payload, prefix, err := transactionalSniffChunk(server, serverSession, 8)
	if err != errSniffLimit || len(payload) != 0 || len(prefix) == 0 {
		t.Fatalf("payload=%d prefix=%d err=%v", len(payload), len(prefix), err)
	}
	replayed := &prefixConn{Conn: server, prefix: prefix}
	payload, err = readTCPPayloadChunk(replayed, serverSession)
	if err != nil || !bytes.Equal(payload, bytes.Repeat([]byte{'z'}, 64)) {
		t.Fatalf("replayed=%d err=%v", len(payload), err)
	}
	<-done
}

func TestSniffDeadlineUsesEarlierContextAndRestoresOuterDeadline(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	recording := &deadlineRecordingConn{Conn: right}
	outer := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(50*time.Millisecond))
	defer cancel()
	_, domain, _ := sniffTargetDomain(ctx, recording, nil, []byte("GET / HTTP/1.1\r\nHost: ai.example\r\n\r\n"), outer)
	if domain != "ai.example" {
		t.Fatalf("domain=%q", domain)
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	if len(recording.reads) != 2 || recording.reads[0].After(outer) || !recording.reads[1].Equal(outer) {
		t.Fatalf("deadlines=%v outer=%v", recording.reads, outer)
	}
}

func tlsClientHello(host string, ech bool, split int) []byte {
	sniName := []byte{0, byte(len(host) >> 8), byte(len(host))}
	sniName = append(sniName, []byte(host)...)
	sni := []byte{byte(len(sniName) >> 8), byte(len(sniName))}
	sni = append(sni, sniName...)
	extensions := append([]byte{0, 0, byte(len(sni) >> 8), byte(len(sni))}, sni...)
	if ech {
		extensions = append(extensions, 0xfe, 0x0d, 0, 1, 1)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	if split <= 0 || split >= len(handshake) {
		split = len(handshake)
	}
	var result []byte
	for len(handshake) > 0 {
		size := split
		if size > len(handshake) {
			size = len(handshake)
		}
		record := []byte{0x16, 3, 3, byte(size >> 8), byte(size)}
		result = append(result, record...)
		result = append(result, handshake[:size]...)
		handshake = handshake[size:]
	}
	return result
}

func TestSniffTLSClientHelloAcrossRecordsAndRejectsECH(t *testing.T) {
	for _, split := range []int{0, 7, 31} {
		payload := tlsClientHello("ai.example.com", false, split)
		domain, state := sniffTCPDomain(payload)
		if domain != "ai.example.com" || state != sniffDone {
			t.Fatalf("split=%d domain=%q state=%d", split, domain, state)
		}
	}
	if domain, state := sniffTCPDomain(tlsClientHello("public.example.com", true, 13)); domain != "" || state != sniffDone {
		t.Fatalf("ECH domain=%q state=%d", domain, state)
	}
	partial := tlsClientHello("ai.example.com", false, 0)
	partial = partial[:len(partial)-3]
	if domain, state := sniffTCPDomain(partial); domain != "" || state != sniffNeedMore {
		t.Fatalf("partial domain=%q state=%d", domain, state)
	}
	oversized := bytes.Repeat([]byte{'x'}, maxSniffBytes+1)
	if domain, state := sniffTCPDomain(oversized); domain != "" || state != sniffDone {
		t.Fatalf("oversized domain=%q state=%d", domain, state)
	}
	legacyTLS := tlsClientHello("ai.example.com", false, 0)
	legacyTLS[10] = 1
	if domain, state := sniffTCPDomain(legacyTLS); domain != "" || state != sniffDone {
		t.Fatalf("TLS1.0 domain=%q state=%d", domain, state)
	}
}
