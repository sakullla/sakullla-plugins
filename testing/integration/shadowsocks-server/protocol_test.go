package shadowsocksserver_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
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
	// ProxyClientStream, ProxyServerStream, encrypt_client_payload, and
	// encrypt_server_payload APIs. The generator lived outside this repository;
	// these fixed frames add no production dependency.
	fixtures := []struct {
		method, material, wrongMaterial string
		tcp, udp, tcpResponse           string
		udpResponse                     string
		sessionID, packetID             uint64
		serverSessionID, responsePacket uint64
	}{
		{
			method:        "aes-128-gcm",
			material:      "fixture-password",
			wrongMaterial: "wrong-password",
			tcp:           "c6bd18e3d16622a9456fd52517097624b5e094c5b92080b31110672fa38e53a4e5d5c84d0bc90d27008ea895a175a9a0422bf1d7a0fe67c139c9db5e2f8bea586cec46697ff04db3ce24704307ec16e1",
			udp:           "0dfb1250ff4e9bb8cf2ac771e292d2db2f7566b4536df864151d2fc5dbea6672288b9781e1902c98fce9223c440e83f9ee1c140d57c81b8174e4d4f323f1",
			tcpResponse:   "2971ed17d7050e230d613c6f17aca3bd1313919dab4b43b5ca5f91f74f687b5f022569bb9737b86128b5dba3f7823e92f920e03574379a86bfa9e09d9f74bdd75a11",
			udpResponse:   "e4692995d85c22bc5bda5f2d7bf2dc1e944c4ac83edd4b7690d787a8c44a83423bbee7d40e485ab0cf635d18e4cdcaa4b46e0b85dba949994c12ef0cb2a5e9",
		},
		{
			method:        "aes-256-gcm",
			material:      "fixture-password",
			wrongMaterial: "wrong-password",
			tcp:           "78bf76f8dca025ab40ca2092f01098202a37edc84d20e8f1313c1902db371684c8bbbe2982678fd6c89037bf4cb0622d5fe96fb4a07137f4d12e5c72a21e71a5cb179df6546f7092c8d150c5b34be6f2539c3d7afa715c9cde90c2dd671bcf41",
			udp:           "126f2b19b35d538ed51dacb6b051598a0f3619d3f681033ee58c717e30d0f56a4c4c991ea1e1fc5afbae23a1af9aa0bf71fee8792a6ed9b2fb6a490a70bdc685aaf450b0d26799678f0c8cc60cf9",
			tcpResponse:   "b3138e4f74771ce4214a4f169ec310c35276b355a7dc66b33fc779f328c4ca9988a2b86d1f32c6a1bfdbf9490ec5c91958baa3ae82b1c381a32a7c18a2eda20fc564dc9dbc609e983471ea3caabc674e4f5b",
			udpResponse:   "1a4353f10223ed023498928cf9fd1c889ccc0c00441629e1f6865305815b8244a772b7929069a4e21e44c6176b34ace04af2acec38cfafa49168ce37f8b57bc45013b6d0bd297bb1f810d2f0667173",
		},
		{
			method:          "2022-blake3-aes-128-gcm",
			material:        "AAECAwQFBgcICQoLDA0ODw==",
			wrongMaterial:   "AQEBAQEBAQEBAQEBAQEBAQ==",
			tcp:             "ca26d70ef9f29fa78c9b75b2e721d29e6fd936495d162b7147e23668162e0bbc77f2533a919d2ab13bb8d7b9d2268f03c7f71df1d98fc977d6be61ca577e566dcc044baa90daa7a1f4f1594e657124e9eb2259c5b40d8bd3d674fa",
			udp:             "fad3db1e8b256c40f71bd52298c06e3c36e221e39c4b227023657727451b823eeb4936b288f8a9569482979e87e70925ebe161894a7f2bf8d3580ff6b8e2ac019a561b95195ad0fef4",
			tcpResponse:     "71c792a296affd0ce5ccf59b01a7884958ff7b6ab11495267e66b6e0147d688e98dfdae36e7f7c7db4090bad61da70a8d6fcb0a123d6cdc0ea166a77119548c744249fc8d5d4d4bb267c443a9655f748632c1ac83471bf739c60cc",
			udpResponse:     "513455c0e57c9e01ae34fabc4a5cb4d817308c7ffdba069956bee468245a7cebfdd03291bf5a3cff677523e8771891d7a32ca6182d92cf9b6f2f21a6293c866e1a981b1fbb7fee0b0c6a93b99652faa3f6f2",
			sessionID:       0x0102030405060708,
			packetID:        9,
			serverSessionID: 0x2122232425262728,
			responsePacket:  19,
		},
		{
			method:          "2022-blake3-aes-256-gcm",
			material:        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			wrongMaterial:   "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
			tcp:             "11c1de3559e24abab76fca8358c6b68fc05072d4ed43ac88c2db9c6672a2b05c7a27d873e95193912c68bc0d013c72ff9f2075ccdf0d95845418285ca17c6b20de9ed7709f8b9c5bb195e6271ddede570ea05faf29bda5b47db2612fdbd1f8a044098af29e17013ab6943c",
			udp:             "bd960a980e1a308bc15bc6d18ab7c62214bbadf9cd5c0f1a3011b9f785a9011344516cc9112ac42debac69e2a96bf82aa16c943622c8a82ad518e4dd6a658a6063cae709e634183ec4",
			tcpResponse:     "f10dd115243915a605b475631c0a344a96bb46f37f16a25008d79b7f080509226b5fffafd725a3001fcfddb68981fe7740af710e40bae169946d2e1ce01543c647499e805c0880f6799871ecca966ae84d828e82f2e36c4561f7b9bf02644fca1cea2319c5e72605ccdb2405a9d79393307ec8fa215a54b26e9929",
			udpResponse:     "2d5eeff0e2a4b94e198314dae3832b8cb7375c0c481a3293c3add7246b15dc8c080f25fc71a8b6a69e91c474c8e37821907bac482297548988fb64ec2745a0cc89979b4431441bfd63f2115566f0462e23c7",
			sessionID:       0x1112131415161718,
			packetID:        10,
			serverSessionID: 0x3132333435363738,
			responsePacket:  20,
		},
	}
	now := time.Unix(1786293678, 0)
	for _, fixture := range fixtures {
		t.Run(fixture.method, func(t *testing.T) {
			engine, err := ss.NewProtocolEngine(fixture.method, []byte(fixture.material))
			if err != nil {
				t.Fatal(err)
			}
			tcpWire := mustHex(t, fixture.tcp)
			request, session, err := engine.OpenTCPServerSession(tcpWire, now)
			if err != nil || request.Target != "example.org:53" || string(request.Payload) != "fixture-payload" {
				t.Fatalf("tcp request=%+v err=%v", request, err)
			}
			tcpResponse := mustHex(t, fixture.tcpResponse)
			sealed, err := session.SealResponse(tcpResponse[:engine.SaltSize()], []byte("fixture-response"), now)
			if err != nil || !bytes.Equal(sealed, tcpResponse) {
				t.Fatalf("tcp response match=%v err=%v", bytes.Equal(sealed, tcpResponse), err)
			}
			session.Close()
			udpResponse, err := engine.OpenUDPResponse(mustHex(t, fixture.udpResponse), now, fixture.sessionID)
			if err != nil || udpResponse.Target != "example.org:53" || string(udpResponse.Payload) != "fixture-response" || udpResponse.SessionID != fixture.serverSessionID || udpResponse.PacketID != fixture.responsePacket {
				t.Fatalf("udp response=%+v err=%v", udpResponse, err)
			}
			tamperedResponse := mustHex(t, fixture.udpResponse)
			tamperedResponse[len(tamperedResponse)-1] ^= 1
			if _, err = engine.OpenUDPResponse(tamperedResponse, now, fixture.sessionID); !errors.Is(err, ss.ErrAuthentication) {
				t.Fatalf("udp response tamper=%v", err)
			}
			if fixture.sessionID != 0 {
				if _, err = engine.OpenUDPResponse(mustHex(t, fixture.udpResponse), now, fixture.sessionID+1); !errors.Is(err, ss.ErrReplay) {
					t.Fatalf("udp response binding=%v", err)
				}
			}
			responseSalt := mustHex(t, fixture.udpResponse)[:engine.SaltSize()]
			if fixture.serverSessionID != 0 {
				responseSalt = make([]byte, 8)
				binary.BigEndian.PutUint64(responseSalt, fixture.serverSessionID)
			}
			sealedUDP, err := engine.SealUDPResponse(responseSalt, fixture.responsePacket, fixture.sessionID, "example.org:53", []byte("fixture-response"), now, nil)
			if err != nil || !bytes.Equal(sealedUDP, mustHex(t, fixture.udpResponse)) {
				t.Fatalf("udp response match=%v err=%v", bytes.Equal(sealedUDP, mustHex(t, fixture.udpResponse)), err)
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

			runtime := &runtime{now: uint64(now.Unix()), secrets: map[string]string{"secret/a-wrong": fixture.wrongMaterial, "secret/z-correct": fixture.material}}
			service, serviceErr := ss.NewService(ss.Configuration{
				Generation: "generation-1", ListenerRef: "listener/1", Cipher: fixture.method, MaxSessions: 2,
				Users: []ss.User{{ID: "a-wrong", SecretRef: "secret/a-wrong", SecretVersion: "v1", Enabled: true, QuotaBytes: 1024}, {ID: "z-correct", SecretRef: "secret/z-correct", SecretVersion: "v1", Enabled: true, QuotaBytes: 1024}},
			}, runtime.adapters())
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			if serviceErr = service.Initialize(context.Background()); serviceErr != nil {
				t.Fatal(serviceErr)
			}
			flow, selected, serviceErr := service.OpenTCP(context.Background(), mustHex(t, fixture.tcp))
			if serviceErr != nil || selected.UserID != "z-correct" {
				t.Fatalf("service tcp user=%q err=%v", selected.UserID, serviceErr)
			}
			_ = flow.Close()
			flow, selected, serviceErr = service.OpenUDP(context.Background(), mustHex(t, fixture.udp))
			if serviceErr != nil || selected.UserID != "z-correct" {
				t.Fatalf("service udp user=%q err=%v", selected.UserID, serviceErr)
			}
			_ = flow.Close()
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

func canonicalPSK(size int, fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, size))
}

func assertCanonicalPSK(t *testing.T, method, psk string) {
	t.Helper()
	size := 16
	if strings.Contains(method, "256") {
		size = 32
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(psk)
	if err != nil || len(decoded) != size || base64.StdEncoding.EncodeToString(decoded) != psk {
		t.Fatalf("method=%s psk=%q", method, psk)
	}
}

func TestShadowsocksProtocol2022IdentityPSKClientPasswordAndWire(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		method string
		size   int
	}{
		{method: "2022-blake3-aes-128-gcm", size: 16},
		{method: "2022-blake3-aes-256-gcm", size: 32},
	} {
		t.Run(test.method, func(t *testing.T) {
			generatedServer, generatedUser, err := ss.GenerateSS2022Identity(test.method)
			if err != nil {
				t.Fatal(err)
			}
			assertCanonicalPSK(t, test.method, generatedServer)
			assertCanonicalPSK(t, test.method, generatedUser)
			if generatedServer == generatedUser {
				t.Fatal("generated server and user PSK must differ")
			}
			if _, err = ss.NewProtocolEngine(test.method, []byte(generatedServer+":"+generatedUser)); err != nil {
				t.Fatal(err)
			}

			serverPSK := canonicalPSK(test.size, 0x11)
			userPSK := canonicalPSK(test.size, 0x22)
			assertCanonicalPSK(t, test.method, serverPSK)
			assertCanonicalPSK(t, test.method, userPSK)
			if serverPSK == userPSK {
				t.Fatal("server and user PSK must differ")
			}
			clientPassword := serverPSK + ":" + userPSK
			engine, err := ss.NewProtocolEngine(test.method, []byte(clientPassword))
			if err != nil || engine.Name() != test.method || engine.SaltSize() != test.size || !engine.HasIdentity() {
				t.Fatalf("identity engine=%v salt=%d identity=%v err=%v", engine, engine.SaltSize(), engine != nil && engine.HasIdentity(), err)
			}
			single, err := ss.NewProtocolEngine(test.method, []byte(userPSK))
			if err != nil || single.HasIdentity() {
				t.Fatalf("single engine identity=%v err=%v", single != nil && single.HasIdentity(), err)
			}
			salt := bytes.Repeat([]byte{0xa5}, engine.SaltSize())
			identityTCP, err := engine.SealTCPRequest(salt, "example.org:53", []byte("identity-payload"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			singleTCP, err := single.SealTCPRequest(salt, "example.org:53", []byte("identity-payload"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(identityTCP) != len(singleTCP)+16 {
				t.Fatalf("tcp eih=%d single=%d", len(identityTCP), len(singleTCP))
			}
			request, err := engine.OpenTCPRequest(identityTCP, now)
			if err != nil || request.Target != "example.org:53" || string(request.Payload) != "identity-payload" {
				t.Fatalf("tcp request=%+v err=%v", request, err)
			}
			if _, err = single.OpenTCPRequest(identityTCP, now); !errors.Is(err, ss.ErrAuthentication) {
				t.Fatalf("user-only tcp=%v", err)
			}
			wrong, err := ss.NewProtocolEngine(test.method, []byte(serverPSK+":"+canonicalPSK(test.size, 0x33)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = wrong.OpenTCPRequest(identityTCP, now); !errors.Is(err, ss.ErrAuthentication) {
				t.Fatalf("wrong identity tcp=%v", err)
			}
			sessionID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			identityUDP, err := engine.SealUDPPacket(sessionID, 9, "example.org:53", []byte("identity-query"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			singleUDP, err := single.SealUDPPacket(sessionID, 9, "example.org:53", []byte("identity-query"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(identityUDP) != len(singleUDP)+16 {
				t.Fatalf("udp eih=%d single=%d", len(identityUDP), len(singleUDP))
			}
			request, err = engine.OpenUDPPacket(identityUDP, now)
			if err != nil || request.Target != "example.org:53" || request.SessionID != 0x0102030405060708 || request.PacketID != 9 || string(request.Payload) != "identity-query" {
				t.Fatalf("udp request=%+v err=%v", request, err)
			}
			if _, err = single.OpenUDPPacket(identityUDP, now); !errors.Is(err, ss.ErrAuthentication) {
				t.Fatalf("user-only udp=%v", err)
			}

			runtime := &runtime{now: uint64(now.Unix()), secrets: map[string]string{"secret/identity": clientPassword}}
			service, serviceErr := ss.NewService(ss.Configuration{
				Generation: "generation-1", ListenerRef: "listener/1", Cipher: test.method, MaxSessions: 2,
				Users: []ss.User{{ID: "identity-user", SecretRef: "secret/identity", SecretVersion: "v1", Enabled: true, QuotaBytes: 1024}},
			}, runtime.adapters())
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			if serviceErr = service.Initialize(context.Background()); serviceErr != nil {
				t.Fatal(serviceErr)
			}
			flow, selected, serviceErr := service.OpenTCP(context.Background(), identityTCP)
			if serviceErr != nil || selected.UserID != "identity-user" {
				t.Fatalf("service tcp user=%q err=%v", selected.UserID, serviceErr)
			}
			_ = flow.Close()
			flow, selected, serviceErr = service.OpenUDP(context.Background(), identityUDP)
			if serviceErr != nil || selected.UserID != "identity-user" {
				t.Fatalf("service udp user=%q err=%v", selected.UserID, serviceErr)
			}
			_ = flow.Close()
		})
	}
}

func TestShadowsocksProtocolSIP002URIAndQRCode(t *testing.T) {
	for _, test := range []struct {
		method string
		modern bool
	}{
		{method: "aes-128-gcm"},
		{method: "aes-256-gcm"},
		{method: "2022-blake3-aes-128-gcm", modern: true},
		{method: "2022-blake3-aes-256-gcm", modern: true},
	} {
		t.Run(test.method, func(t *testing.T) {
			const host = "example.com"
			const port = 8388
			account := ss.SIP002Account{Method: test.method, Host: host, Port: port}
			password := "only-one-password"
			if test.modern {
				serverPSK, identityPSK, err := ss.GenerateSS2022Identity(test.method)
				if err != nil {
					t.Fatal(err)
				}
				assertCanonicalPSK(t, test.method, serverPSK)
				assertCanonicalPSK(t, test.method, identityPSK)
				if serverPSK == identityPSK {
					t.Fatal("server and user PSK must differ")
				}
				password = serverPSK + ":" + identityPSK
				account.ServerPSK = serverPSK
				account.IdentityPSK = identityPSK
			} else {
				account.Password = password
			}
			share, err := ss.BuildSIP002(account)
			if err != nil {
				t.Fatal(err)
			}
			if share.Password != password || share.URI == "" || share.QR.Content != share.URI {
				t.Fatalf("share password=%q uri=%q qr=%q", share.Password, share.URI, share.QR.Content)
			}
			uri, err := ss.SIP002URI(test.method, password, host, port)
			if err != nil {
				t.Fatal(err)
			}
			if qr := ss.SIP002QRContent(uri); qr != uri {
				t.Fatalf("qr=%q uri=%q", qr, uri)
			}
			assertImportableSIP002(t, share.URI, test.method, password, host, port, test.modern)
			assertImportableSIP002(t, uri, test.method, password, host, port, test.modern)
		})
	}
}

func assertImportableSIP002(t *testing.T, uri, method, password, host string, port int, modern bool) {
	t.Helper()
	if !strings.HasPrefix(uri, "ss://") || strings.Contains(uri, "plugin=") {
		t.Fatalf("uri=%q", uri)
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "ss" {
		t.Fatalf("uri=%q err=%v", uri, err)
	}
	if parsed.Hostname() != host || parsed.Port() != strconv.Itoa(port) {
		t.Fatalf("hostport=%s:%s", parsed.Hostname(), parsed.Port())
	}
	userinfo := uri[len("ss://"):]
	if at := strings.Index(userinfo, "@"); at >= 0 {
		userinfo = userinfo[:at]
	}
	gotMethod, gotPassword, ok := sip002Credentials(parsed, userinfo)
	if !ok || gotMethod != method || gotPassword != password {
		t.Fatalf("parsed method=%q password=%q userinfo=%q", gotMethod, gotPassword, userinfo)
	}
	if modern {
		if strings.Count(userinfo, ":") != 1 || !strings.Contains(userinfo, "%") {
			t.Fatalf("ss2022 userinfo=%q", userinfo)
		}
		if sip002UserinfoIsBase64URL(userinfo, method, password) {
			t.Fatalf("ss2022 userinfo is Base64URL: %q", userinfo)
		}
		return
	}
	if strings.Contains(gotPassword, ":") {
		t.Fatalf("legacy password must be a single secret: %q", gotPassword)
	}
}

func sip002Credentials(parsed *url.URL, userinfo string) (method, password string, ok bool) {
	if parsed.User != nil {
		if secret, has := parsed.User.Password(); has {
			return parsed.User.Username(), secret, parsed.User.Username() != "" && secret != ""
		}
	}
	decoded, err := decodeSIP002Userinfo(userinfo)
	if err != nil {
		return "", "", false
	}
	method, password, ok = strings.Cut(string(decoded), ":")
	return method, password, ok && method != "" && password != ""
}

func sip002UserinfoIsBase64URL(userinfo, method, password string) bool {
	want := method + ":" + password
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := encoding.DecodeString(userinfo)
		if err == nil && string(decoded) == want {
			return true
		}
	}
	return false
}

func decodeSIP002Userinfo(userinfo string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err := encoding.DecodeString(userinfo)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("userinfo is not importable SIP002")
}
