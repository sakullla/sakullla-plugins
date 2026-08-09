package shadowsocksserver_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	ss "github.com/sakullla/sakullla-plugins/plugins/shadowsocks-server"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestShadowsocksOfficialRustTCPUDPFixtures(t *testing.T) {
	// Generated from the official shadowsocks-rust repository at commit
	// e543d9bc8caf88ae69411f452f10e3e37094bbbe using the public
	// ProxyClientStream and encrypt_client_payload APIs. The generator lived
	// outside this repository; these fixed frames add no production dependency.
	fixtures := []struct {
		method    string
		material  string
		tcp       string
		udp       string
		sessionID uint64
		packetID  uint64
	}{
		{
			method:   "aes-128-gcm",
			material: "fixture-password",
			tcp:      "271076a102502df3e154d6c5d03a2cfcb8a89dfc68b510029d57d8393554a152841967220073d46dbe58934dc96f2b6f2512bc9d3d5ff0b6d6d3d50bf3a3d5208884a54f21b1dbfb0261f9ff4ebc7ccb",
			udp:      "0b7526a8678ff8f909c6e9d5818821bab0de20219f822bd5b325e260bf818a359340bc544cbb8962ceb815af98360bc62fe93a9c78ab64aa01868568d4ba",
		},
		{
			method:   "aes-256-gcm",
			material: "fixture-password",
			tcp:      "69a96f2018b063e3346367d39f2514561daf2c3cd58b6b9a8f14b3c098d1e4034122bbd431c21b1e060cebfa1393f17c2296a4b7c0fe0f7c4b820c9723accb750ce9911ebf16741c00959ba7295ceaaf06c74d796d157ad32f6b500408b5c17f",
			udp:      "a02214fb43c9645d7389bed321b173f4166aedb5be58dec1d8653c9ce15d74b9c4222b1cd342e17edb830fd74313186a0328e375f2bf6706ac5e9d7f75bd145c04b32616c8310c191caf2ae75874",
		},
		{
			method:    "2022-blake3-aes-128-gcm",
			material:  "AAECAwQFBgcICQoLDA0ODw==",
			tcp:       "164cfbda39dd97b819d6c400d85d730729030e13b25c8618f347558c79f9357713c496ed0e5a36c9ec905035b40d610e7a82edf6454c71e4247c048307cb6474d47971526fab75bb6744638c17aa3b0a8e4eaabaa280a685e73a55",
			udp:       "fad3db1e8b256c40f71bd52298c06e3c36e221e39c4b2277c5657727451b823eeb4936b288f8a9569482979e87e70925ebe161894a7f2bf8d3e21a50171dd058c03e694945a4133a6d",
			sessionID: 0x0102030405060708,
			packetID:  9,
		},
		{
			method:    "2022-blake3-aes-256-gcm",
			material:  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			tcp:       "59ff97d481d16b447b4317258950e7e104c635a3ae47d771ac82626139beeb8d62e8cf966c09a3ae3dafba7b4c343629257208f8e02a8bce62367abff533f11472e5a204f94154a85c0d0ce8071e08fddac2ca4b8d32fca4643669879d876290ebe211df2d9d444630fb31",
			udp:       "bd960a980e1a308bc15bc6d18ab7c62214bbadf9cd5c0f1dd611b9f785a9011344516cc9112ac42debac69e2a96bf82aa16c943622c8a82ad59d99da415d2be85f4a94ac3956746d8b",
			sessionID: 0x1112131415161718,
			packetID:  10,
		},
	}
	now := time.Unix(1786292808, 0)
	for _, fixture := range fixtures {
		t.Run(fixture.method, func(t *testing.T) {
			engine, err := ss.NewProtocolEngine(fixture.method, []byte(fixture.material))
			if err != nil {
				t.Fatal(err)
			}
			for protocol, wire := range map[string][]byte{"tcp": mustHex(t, fixture.tcp), "udp": mustHex(t, fixture.udp)} {
				var request ss.ProxyRequest
				if protocol == "tcp" {
					request, err = engine.OpenTCPRequest(wire, now)
				} else {
					request, err = engine.OpenUDPPacket(wire, now)
				}
				if err != nil || request.Target != "example.org:53" || string(request.Payload) != "fixture-payload" {
					t.Fatalf("%s request=%+v err=%v", protocol, request, err)
				}
				if fixture.sessionID != 0 && protocol == "udp" && (request.SessionID != fixture.sessionID || request.PacketID != fixture.packetID) {
					t.Fatalf("udp identity=%x/%d", request.SessionID, request.PacketID)
				}
				tampered := append([]byte(nil), wire...)
				tampered[len(tampered)-1] ^= 1
				if protocol == "tcp" {
					_, err = engine.OpenTCPRequest(tampered, now)
				} else {
					_, err = engine.OpenUDPPacket(tampered, now)
				}
				if !errors.Is(err, ss.ErrAuthentication) {
					t.Fatalf("%s tamper=%v", protocol, err)
				}
			}
			if fixture.sessionID != 0 {
				if _, err = engine.OpenTCPRequest(mustHex(t, fixture.tcp), now.Add(31*time.Second)); !errors.Is(err, ss.ErrReplay) {
					t.Fatalf("stale tcp=%v", err)
				}
				if _, err = engine.OpenUDPPacket(mustHex(t, fixture.udp), now.Add(31*time.Second)); !errors.Is(err, ss.ErrReplay) {
					t.Fatalf("stale udp=%v", err)
				}
			}
		})
	}
}

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
