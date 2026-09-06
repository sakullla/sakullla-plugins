package shadowsocksserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPHandlerSniffsHTTPAndTLSAcrossSSChunksWithoutChangingTarget(t *testing.T) {
	for _, application := range [][]byte{
		[]byte("GET /v1/chat HTTP/1.1\r\nHost: ai.example.com\r\n\r\nbody"),
		[]byte("POST /v1/chat HTTP/1.1\r\nHost: ai.example.com\r\nContent-Length: 3\r\n\r\n\x00\nx"),
		tlsClientHello("ai.example.com", false, 17),
	} {
		source := "sniffed-http-host"
		if application[0] == 0x16 {
			source = "sniffed-tls-sni"
		}
		runSniffedUpstreamHandler(t, application, len(application)/2, "198.51.100.8:443", "ai.example.com", source)
	}
}

func runSniffedUpstreamHandler(t *testing.T, application []byte, split int, originalTarget, expectedDomain, expectedSource string) {
	t.Helper()
	const inboundPassword = "inbound-password"
	const upstreamPassword = "upstream-password"
	inboundServer, _ := NewProtocolEngine("aes-256-gcm", []byte(inboundPassword))
	inboundClient, _ := NewProtocolEngine("aes-256-gcm", []byte(inboundPassword))
	defer inboundServer.Destroy()
	requestSalt := bytes.Repeat([]byte{7}, inboundClient.SaltSize())
	requestWire, err := inboundClient.SealTCPRequest(requestSalt, originalTarget, application[:split], time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := newTCPClientSession(inboundClient, requestSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	var remaining []byte
	if split < len(application) {
		remaining, err = clientSession.SealPayload(application[split:])
		if err != nil {
			t.Fatal(err)
		}
	}
	dataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	routing := routeFixture()
	routing.Rules = routing.Rules[1:]
	routing.Rules[0].Classification.Attributes = nil
	routing.DefaultAction = RouteDirect
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, dataset)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan ProxyRequest, 1)
	dialer := &recordingDialer{open: func() net.Conn {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			engine, _ := NewProtocolEngine("aes-256-gcm", []byte(upstreamPassword))
			defer engine.Destroy()
			request, session, err := readTCPHandshake(server, []*ProtocolEngine{engine})
			if err != nil {
				return
			}
			defer session.Close()
			served <- request
			wire, _ := session.SealResponse(bytes.Repeat([]byte{8}, engine.SaltSize()), []byte("world"), time.Now())
			_, _ = server.Write(wire)
		}()
		return client
	}}
	bound := &boundListen{engines: []*boundUserEngine{{id: "inbound", engine: inboundServer}}, dialer: dialer, secrets: rawSecretResolver{issuedSecretKey("secret/upstream", "secret-version-000000000001"): upstreamPassword}, routes: snapshot, routeFailures: map[string]string{}}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { bound.handleTCP(context.Background(), server); close(done) }()
	if _, err := client.Write(requestWire); err != nil {
		t.Fatal(err)
	}
	if len(remaining) > 0 {
		if _, err := client.Write(remaining); err != nil {
			t.Fatal(err)
		}
	}
	response, err := clientSession.OpenPayload(client, time.Now())
	if err != nil || string(response) != "world" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
	request := <-served
	if request.Target != originalTarget || !bytes.Equal(request.Payload, application) {
		t.Fatalf("target=%q payloadEqual=%v", request.Target, bytes.Equal(request.Payload, application))
	}
	if len(dataset.queries) != 1 || dataset.queries[0].Domain != expectedDomain || dialer.address != "192.0.2.20:8388" {
		t.Fatalf("query=%+v dial=%q", dataset.queries, dialer.address)
	}
	statuses := bound.routeStatuses()
	if len(statuses) != 1 || statuses[0].DomainSource != expectedSource {
		t.Fatalf("route statuses=%+v", statuses)
	}
}

func TestTCPHandlerOriginalDomainTakesPriorityOverHTTPHost(t *testing.T) {
	application := []byte("GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
	runSniffedUpstreamHandler(t, application, len(application), "original.example.com:443", "original.example.com", "target-domain")
}

func TestTCPHandlerServerFirstFallsBackAfterBoundedSniffTimeout(t *testing.T) {
	const password = "inbound-password"
	targetAddress := "198.51.100.10:25"
	serverEngine, _ := NewProtocolEngine("aes-256-gcm", []byte(password))
	clientEngine, _ := NewProtocolEngine("aes-256-gcm", []byte(password))
	defer serverEngine.Destroy()
	salt := bytes.Repeat([]byte{10}, clientEngine.SaltSize())
	wire, err := clientEngine.SealTCPRequest(salt, targetAddress, nil, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := newTCPClientSession(clientEngine, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	dataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	routing := routeFixture()
	routing.Rules = routing.Rules[1:]
	routing.Rules[0].Classification.Attributes = nil
	routing.DefaultAction = RouteDirect
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, dataset)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{open: func() net.Conn {
		client, server := net.Pipe()
		go func() { defer server.Close(); _, _ = server.Write([]byte("banner")) }()
		return client
	}}
	bound := &boundListen{engines: []*boundUserEngine{{id: "inbound", engine: serverEngine}}, dialer: dialer, routes: snapshot, routeFailures: map[string]string{}}
	client, server := net.Pipe()
	done := make(chan struct{})
	started := time.Now()
	go func() { bound.handleTCP(context.Background(), server); close(done) }()
	_, _ = client.Write(wire)
	response, err := clientSession.OpenPayload(client, time.Now())
	elapsed := time.Since(started)
	if err != nil || string(response) != "banner" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
	if elapsed < 150*time.Millisecond || elapsed > time.Second || dialer.address != targetAddress || len(dataset.queries) != 0 {
		t.Fatalf("elapsed=%s dial=%q queries=%d", elapsed, dialer.address, len(dataset.queries))
	}
}

func TestTCPHandlerFallsBackToOriginalIPForHTTP2AndECHWithExactReplay(t *testing.T) {
	for _, application := range [][]byte{[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), tlsClientHello("outer.example.com", true, 19)} {
		runSniffFallbackHandler(t, application)
	}
}

func runSniffFallbackHandler(t *testing.T, application []byte) {
	t.Helper()
	const password = "inbound-password"
	targetAddress := "198.51.100.9:443"
	serverEngine, _ := NewProtocolEngine("aes-256-gcm", []byte(password))
	clientEngine, _ := NewProtocolEngine("aes-256-gcm", []byte(password))
	defer serverEngine.Destroy()
	salt := bytes.Repeat([]byte{9}, clientEngine.SaltSize())
	wire, err := clientEngine.SealTCPRequest(salt, targetAddress, application, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := newTCPClientSession(clientEngine, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	dataset := &routeDatasetFake{matches: map[string]bool{"category-ai": true}}
	routing := routeFixture()
	routing.Rules = routing.Rules[1:]
	routing.Rules[0].Classification.Attributes = nil
	routing.DefaultAction = RouteDirect
	snapshot, err := prepareRouteSnapshot(t.Context(), routing, dataset)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	dialer := &recordingDialer{open: func() net.Conn {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			payload := make([]byte, len(application))
			_, _ = io.ReadFull(server, payload)
			received <- payload
			_, _ = server.Write([]byte("world"))
		}()
		return client
	}}
	bound := &boundListen{engines: []*boundUserEngine{{id: "inbound", engine: serverEngine}}, dialer: dialer, routes: snapshot, routeFailures: map[string]string{}}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { bound.handleTCP(context.Background(), server); close(done) }()
	_, _ = client.Write(wire)
	response, err := clientSession.OpenPayload(client, time.Now())
	if err != nil || string(response) != "world" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	_ = client.Close()
	<-done
	if !bytes.Equal(<-received, application) || dialer.address != targetAddress || len(dataset.queries) != 0 {
		t.Fatalf("fallback dial=%q queries=%d", dialer.address, len(dataset.queries))
	}
}
