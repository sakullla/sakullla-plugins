package shadowsocksserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientHalfCloseReachesTargetAndPreservesFinalResponse(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			targetDone <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		body, e := io.ReadAll(c)
		if e == nil && !bytes.Equal(body, []byte("request")) {
			e = ErrProtocol
		}
		if e == nil {
			_, e = c.Write([]byte("after-eof"))
		}
		targetDone <- e
	}()
	inbound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	serverEngine, _ := NewProtocolEngine("aes-256-gcm", []byte("fixture-password"))
	defer serverEngine.Destroy()
	clientEngine, _ := NewProtocolEngine("aes-256-gcm", []byte("fixture-password"))
	routes, err := prepareRouteSnapshot(t.Context(), RoutingConfiguration{DefaultAction: RouteDirect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound := &boundListen{engines: []*boundUserEngine{{id: "user", engine: serverEngine}}, dialer: &net.Dialer{}, routes: routes, routeFailures: map[string]string{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := inbound.Accept()
		if e == nil {
			bound.handleTCP(context.Background(), c)
		}
	}()
	client, err := net.Dial("tcp", inbound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	salt := bytes.Repeat([]byte{9}, clientEngine.SaltSize())
	session, err := newTCPClientSession(clientEngine, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	wire, err := clientEngine.SealTCPRequest(salt, target.Addr().String(), []byte("request"), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err = client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := session.OpenPayload(client, time.Now())
	if err != nil || string(body) != "after-eof" {
		t.Fatalf("final response %q: %v", body, err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("completed connection leaked its handler")
	}
}
