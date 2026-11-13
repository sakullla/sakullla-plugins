package shadowsocksserver

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestUpstreamFailureReasonDistinguishesAuthentication(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", ErrAuthentication), "upstream-auth-failed"},
		{ErrProtocol, "upstream-protocol-error"},
		{context.DeadlineExceeded, "upstream-timeout"},
		{ErrRouteUpstreamUnavailable, "upstream-unavailable"},
		{net.ErrClosed, "upstream-connection-failed"},
	} {
		if got := upstreamFailureReason(test.err); got != test.want {
			t.Errorf("%v: got %s, want %s", test.err, got, test.want)
		}
	}
}

func TestUpstreamTCPAcceptsAddressBeforeApplicationPayload(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			password := "upstream-password"
			if SS2022Method(method) {
				server, user, err := GenerateSS2022Identity(method)
				if err != nil {
					t.Fatal(err)
				}
				password = server + ":" + user
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			serverResult := make(chan error, 1)
			go func() {
				engine, err := NewProtocolEngine(method, []byte(password))
				if err != nil {
					serverResult <- err
					return
				}
				defer engine.Destroy()
				request, session, err := readTCPHandshake(server, []*ProtocolEngine{engine})
				if err != nil {
					serverResult <- err
					return
				}
				defer session.Close()
				if request.Target != "chatgpt.com:443" || len(request.Payload) != 0 {
					serverResult <- fmt.Errorf("initial request changed: %+v", request)
					return
				}
				payload, err := readTCPPayloadChunk(server, session)
				if err != nil || string(payload) != "later TLS payload" {
					serverResult <- fmt.Errorf("later payload=%q err=%v", payload, err)
					return
				}
				wire, err := session.SealResponse(bytes.Repeat([]byte{7}, engine.SaltSize()), []byte("response"), time.Now())
				if err == nil {
					_, err = server.Write(wire)
				}
				serverResult <- err
			}()
			upstream := routeFixture().Upstreams[0]
			upstream.Method = method
			bound := &boundListen{secrets: rawSecretResolver{issuedSecretKey(upstream.SecretRef, upstream.SecretVersion): password}}
			wrapped, err := bound.wrapUpstreamTCP(t.Context(), client, upstream, ProxyRequest{Target: "chatgpt.com:443"})
			if err != nil {
				t.Fatal(err)
			}
			defer wrapped.Close()
			if _, err := wrapped.Write([]byte("later TLS payload")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 32)
			n, err := wrapped.Read(response)
			if err != nil || string(response[:n]) != "response" {
				t.Fatalf("response=%q err=%v", response[:n], err)
			}
			if err := <-serverResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}
