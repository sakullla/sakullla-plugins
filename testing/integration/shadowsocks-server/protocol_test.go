package shadowsocksserver_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

func TestShadowsocksProtocolConstructorsLegacyAnd2022(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm"} {
		engine, err := ss.NewProtocolEngine(method, []byte("legacy-password"))
		if err != nil || engine.Name() != method {
			t.Fatalf("%s engine=%v err=%v", method, engine, err)
		}
	}
	for method, size := range map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32} {
		encoded := []byte(base64.StdEncoding.EncodeToString(make([]byte, size)))
		engine, err := ss.NewProtocolEngine(method, encoded)
		if err != nil || engine.Name() != method {
			t.Fatalf("%s engine=%v err=%v", method, engine, err)
		}
	}
	if ss.SupportedMethod("chacha20-ietf-poly1305") {
		t.Fatal("undeclared dependency-backed cipher is exposed")
	}
}

func TestShadowsocks2022RejectsNonCanonicalOrWrongLengthPSK(t *testing.T) {
	for _, material := range [][]byte{
		[]byte("not-base64"),
		[]byte(base64.RawStdEncoding.EncodeToString(make([]byte, 16))),
		[]byte(base64.StdEncoding.EncodeToString(make([]byte, 15))),
	} {
		if _, err := ss.NewProtocolEngine("2022-blake3-aes-128-gcm", material); err == nil {
			t.Fatalf("accepted %q", material)
		}
	}
}

func TestShadowsocksLegacyTCPUDPWireAndAuthentication(t *testing.T) {
	engine, err := ss.NewProtocolEngine("aes-128-gcm", []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ss.NewProtocolEngine("aes-128-gcm", []byte("wrong password"))
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x31}, engine.SaltSize())
	tcpWire, err := engine.SealTCPRequest(salt, "example.com:443", []byte("client-first"), time.Unix(100, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := engine.OpenTCPRequest(tcpWire, time.Unix(100, 0))
	if err != nil || request.Target != "example.com:443" || string(request.Payload) != "client-first" || !bytes.Equal(request.ReplayToken, salt) {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	if _, err = wrong.OpenTCPRequest(tcpWire, time.Unix(100, 0)); !errors.Is(err, ss.ErrAuthentication) {
		t.Fatalf("wrong key=%v", err)
	}
	udpWire, err := engine.SealUDPPacket(salt, 0, "1.1.1.1:53", []byte("dns"), time.Unix(100, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err = engine.OpenUDPPacket(udpWire, time.Unix(100, 0))
	if err != nil || request.Target != "1.1.1.1:53" || string(request.Payload) != "dns" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestShadowsocks2022TCPUDPWireAuthenticationReplayAndTamper(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	engine, err := ss.NewProtocolEngine("2022-blake3-aes-128-gcm", []byte(base64.StdEncoding.EncodeToString(key)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	salt := bytes.Repeat([]byte{0xa5}, engine.SaltSize())
	tcpWire, err := engine.SealTCPRequest(salt, "[2001:db8::1]:8443", []byte("hello"), now, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	request, err := engine.OpenTCPRequest(tcpWire, now)
	if err != nil || request.Target != "[2001:db8::1]:8443" || string(request.Payload) != "hello" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	if _, err = engine.OpenTCPRequest(tcpWire, now.Add(31*time.Second)); !errors.Is(err, ss.ErrReplay) {
		t.Fatalf("stale timestamp=%v", err)
	}
	tcpWire[len(tcpWire)-1] ^= 1
	if _, err = engine.OpenTCPRequest(tcpWire, now); !errors.Is(err, ss.ErrAuthentication) {
		t.Fatalf("tamper=%v", err)
	}
	sessionID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	udpWire, err := engine.SealUDPPacket(sessionID, 9, "example.org:53", []byte("query"), now, []byte{7, 8})
	if err != nil {
		t.Fatal(err)
	}
	request, err = engine.OpenUDPPacket(udpWire, now)
	if err != nil || request.Target != "example.org:53" || request.SessionID != 0x0102030405060708 || request.PacketID != 9 || string(request.Payload) != "query" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	udpWire[len(udpWire)-1] ^= 1
	if _, err = engine.OpenUDPPacket(udpWire, now); !errors.Is(err, ss.ErrAuthentication) {
		t.Fatalf("tamper=%v", err)
	}
	serverSession := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	responseWire, err := engine.SealUDPResponse(serverSession, 10, request.SessionID, "example.org:53", []byte("answer"), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := engine.OpenUDPResponse(responseWire, now, request.SessionID)
	if err != nil || response.SessionID != 0x0807060504030201 || response.PacketID != 10 || response.Target != "example.org:53" || string(response.Payload) != "answer" {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	if _, err = engine.OpenUDPResponse(responseWire, now, request.SessionID+1); !errors.Is(err, ss.ErrReplay) {
		t.Fatalf("client session binding=%v", err)
	}
}

func TestShadowsocksDestroyedEngineRejectsNewWire(t *testing.T) {
	engine, err := ss.NewProtocolEngine("aes-128-gcm", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	engine.Destroy()
	if _, err = engine.SealTCPRequest(make([]byte, 16), "example.com:443", []byte("x"), time.Now(), nil); !errors.Is(err, ss.ErrRevoked) {
		t.Fatalf("destroyed engine=%v", err)
	}
}
