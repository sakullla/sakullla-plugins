package shadowsocksserver

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestShadowsocksBLAKE3OfficialDeriveKeyVectors(t *testing.T) {
	const context = "BLAKE3 2019-12-27 16:29:52 test vectors context"
	tests := []struct {
		input []byte
		want  string
	}{
		{input: nil, want: "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
		{input: func() []byte {
			value := make([]byte, 64)
			for i := range value {
				value[i] = byte(i)
			}
			return value
		}(), want: "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"},
	}
	for _, test := range tests {
		got, err := blake3DeriveKey(context, test.input)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != test.want {
			t.Fatalf("input=%d got=%x want=%s", len(test.input), got, test.want)
		}
	}
}

func TestShadowsocksTCPServerSessionRequestAndResponseChunks(t *testing.T) {
	for _, test := range []struct {
		method   string
		material []byte
	}{
		{method: "aes-128-gcm", material: []byte("password")},
		{method: "2022-blake3-aes-128-gcm", material: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)))},
	} {
		t.Run(test.method, func(t *testing.T) {
			engine, err := NewProtocolEngine(test.method, test.material)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0)
			requestSalt := bytes.Repeat([]byte{1}, engine.SaltSize())
			first, err := engine.SealTCPRequest(requestSalt, "example.com:443", []byte("first"), now, []byte{9})
			if !engine.modern {
				first, err = engine.SealTCPRequest(requestSalt, "example.com:443", []byte("first"), now, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			request, server, err := engine.OpenTCPServerSession(first, now)
			if err != nil || string(request.Payload) != "first" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			key, err := engine.keySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			clientRequest, err := engine.newSession(key, requestSalt)
			if err != nil {
				t.Fatal(err)
			}
			clientRequest.nonce[0] = 2
			nextWire := sealPayloadChunk(clientRequest, []byte("next"))
			next, err := server.OpenPayloadChunk(nextWire)
			if err != nil || string(next) != "next" {
				t.Fatalf("next=%q err=%v", next, err)
			}
			responseSalt := bytes.Repeat([]byte{2}, engine.SaltSize())
			responseWire, err := server.SealResponse(responseSalt, []byte("response-first"), now)
			if err != nil {
				t.Fatal(err)
			}
			clientResponse, err := engine.newSession(key, responseSalt)
			clear(key)
			if err != nil {
				t.Fatal(err)
			}
			if engine.modern {
				fixedWireLength := 1 + 8 + engine.SaltSize() + 2 + clientResponse.aead.Overhead()
				fixed, openErr := clientResponse.open(responseWire[engine.SaltSize() : engine.SaltSize()+fixedWireLength])
				if openErr != nil || fixed[0] != 1 || !bytes.Equal(fixed[9:9+engine.SaltSize()], requestSalt) || binary.BigEndian.Uint16(fixed[len(fixed)-2:]) != uint16(len("response-first")) {
					t.Fatalf("fixed=%x err=%v", fixed, openErr)
				}
				plain, openErr := clientResponse.open(responseWire[engine.SaltSize()+fixedWireLength:])
				if openErr != nil || string(plain) != "response-first" {
					t.Fatalf("response=%q err=%v", plain, openErr)
				}
			} else {
				plain, openErr := openPayloadChunk(clientResponse, responseWire[engine.SaltSize():], maxLegacyPayload)
				if openErr != nil || string(plain) != "response-first" {
					t.Fatalf("response=%q err=%v", plain, openErr)
				}
			}
			followWire, err := server.SealPayloadChunk([]byte("response-next"))
			if err != nil {
				t.Fatal(err)
			}
			follow, err := openPayloadChunk(clientResponse, followWire, max2022Payload)
			if err != nil || string(follow) != "response-next" {
				t.Fatalf("follow=%q err=%v", follow, err)
			}
			server.Close()
		})
	}
}

func TestTCPServerSessionSealResponseSurvivesEngineDestroy(t *testing.T) {
	for _, test := range []struct {
		method   string
		material []byte
	}{
		{method: "aes-128-gcm", material: []byte("password")},
		{method: "2022-blake3-aes-128-gcm", material: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)))},
	} {
		t.Run(test.method, func(t *testing.T) {
			engine, err := NewProtocolEngine(test.method, test.material)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0)
			requestSalt := bytes.Repeat([]byte{1}, engine.SaltSize())
			padding := []byte{9}
			if !strings.HasPrefix(test.method, "2022-") {
				padding = nil
			}
			first, err := engine.SealTCPRequest(requestSalt, "example.com:443", []byte("first"), now, padding)
			if err != nil {
				t.Fatal(err)
			}
			request, server, err := engine.OpenTCPServerSession(first, now)
			if err != nil || string(request.Payload) != "first" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			engine.Destroy()
			responseSalt := bytes.Repeat([]byte{2}, engine.SaltSize())
			if _, err := server.SealResponse(responseSalt, []byte("response-first"), now); err != nil {
				t.Fatalf("live session lost key material after Destroy: %v", err)
			}
			server.Close()
		})
	}
}

func TestOpenTCPServerSessionKeepsCoalescedLeftover(t *testing.T) {
	for _, test := range []struct {
		method   string
		material []byte
	}{
		{method: "aes-128-gcm", material: []byte("password")},
		{method: "2022-blake3-aes-128-gcm", material: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)))},
	} {
		t.Run(test.method, func(t *testing.T) {
			engine, err := NewProtocolEngine(test.method, test.material)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Destroy()
			now := time.Unix(1_700_000_000, 0)
			requestSalt := bytes.Repeat([]byte{1}, engine.SaltSize())
			padding := []byte{9}
			if !strings.HasPrefix(test.method, "2022-") {
				padding = nil
			}
			first, err := engine.SealTCPRequest(requestSalt, "example.com:443", []byte("first"), now, padding)
			if err != nil {
				t.Fatal(err)
			}
			key, err := engine.keySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			clientRequest, err := engine.newSession(key, requestSalt)
			clear(key)
			if err != nil {
				t.Fatal(err)
			}
			clientRequest.nonce[0] = 2
			nextWire := sealPayloadChunk(clientRequest, []byte("next"))
			combined := append(append([]byte{}, first...), nextWire...)
			request, server, err := engine.OpenTCPServerSession(combined, now)
			if err != nil || string(request.Payload) != "first" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			leftover := server.takeLeftover()
			if !bytes.Equal(leftover, nextWire) {
				t.Fatalf("leftover=%x want=%x", leftover, nextWire)
			}
			next, err := server.OpenPayloadChunk(leftover)
			if err != nil || string(next) != "next" {
				t.Fatalf("next=%q err=%v", next, err)
			}
			server.Close()
		})
	}
}

func TestShadowsocks2022IdentityPSKsAreCanonicalDistinctAndFormClientPassword(t *testing.T) {
	for _, test := range []struct {
		method string
		keyLen int
	}{
		{method: "2022-blake3-aes-128-gcm", keyLen: 16},
		{method: "2022-blake3-aes-256-gcm", keyLen: 32},
	} {
		t.Run(test.method, func(t *testing.T) {
			serverPSK := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x11}, test.keyLen))
			userPSK := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x22}, test.keyLen))
			if serverPSK == userPSK {
				t.Fatal("server PSK and user identity PSK must differ")
			}
			password := serverPSK + ":" + userPSK
			if strings.ContainsAny(password, " \t") || strings.Count(password, ":") != 1 {
				t.Fatalf("client password=%q", password)
			}
			engine, err := NewProtocolEngine(test.method, []byte(password))
			if err != nil || engine == nil || engine.Name() != test.method || !engine.HasIdentity() {
				t.Fatalf("engine=%v identity=%v err=%v", engine, engine != nil && engine.HasIdentity(), err)
			}
			named, err := NewSS2022IdentityEngine(test.method, []byte(serverPSK), []byte(userPSK))
			if err != nil || named == nil || !named.HasIdentity() {
				t.Fatalf("named identity engine=%v err=%v", named, err)
			}
			solo, err := NewProtocolEngine(test.method, []byte(serverPSK))
			if err != nil || solo.HasIdentity() {
				t.Fatalf("single psk identity=%v err=%v", solo != nil && solo.HasIdentity(), err)
			}
			solo.Destroy()
			named.Destroy()
			engine.Destroy()
		})
	}
}

func TestShadowsocks2022IdentityTCPUDPWireUsesSIP022Header(t *testing.T) {
	for _, test := range []struct {
		method string
		keyLen int
	}{
		{method: "2022-blake3-aes-128-gcm", keyLen: 16},
		{method: "2022-blake3-aes-256-gcm", keyLen: 32},
	} {
		t.Run(test.method, func(t *testing.T) {
			serverKey := bytes.Repeat([]byte{0x11}, test.keyLen)
			userKey := bytes.Repeat([]byte{0x22}, test.keyLen)
			serverPSK := canonicalSS2022PSK(t, serverKey)
			userPSK := canonicalSS2022PSK(t, userKey)
			password := serverPSK + ":" + userPSK
			client, err := NewProtocolEngine(test.method, []byte(password))
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewSS2022IdentityEngine(test.method, []byte(serverPSK), []byte(userPSK))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1_700_000_000, 0)
			salt := bytes.Repeat([]byte{0xa5}, client.SaltSize())
			tcpWire, err := client.SealTCPRequest(salt, "example.com:443", []byte("first"), now, []byte{9})
			if err != nil {
				t.Fatal(err)
			}
			wantHeader, err := seal2022Identity(serverKey, userKey, salt)
			if err != nil {
				t.Fatal(err)
			}
			if len(tcpWire) < client.SaltSize()+ss2022IdentitySize || !bytes.Equal(tcpWire[client.SaltSize():client.SaltSize()+ss2022IdentitySize], wantHeader) {
				t.Fatalf("tcp identity header=%x want=%x", identityPrefix(tcpWire, client.SaltSize()+ss2022IdentitySize), wantHeader)
			}
			request, session, err := server.OpenTCPServerSession(tcpWire, now)
			if err != nil || request.Target != "example.com:443" || string(request.Payload) != "first" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			key, err := server.keySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(key, userKey) {
				t.Fatalf("session key is not the user PSK")
			}
			clientRequest, err := client.newSession(key, salt)
			if err != nil {
				t.Fatal(err)
			}
			clientRequest.nonce[0] = 2
			next, err := session.OpenPayloadChunk(sealPayloadChunk(clientRequest, []byte("next")))
			if err != nil || string(next) != "next" {
				t.Fatalf("next=%q err=%v", next, err)
			}
			responseSalt := bytes.Repeat([]byte{0x5a}, server.SaltSize())
			responseWire, err := session.SealResponse(responseSalt, []byte("response-first"), now)
			if err != nil {
				t.Fatal(err)
			}
			responseIdentity, err := seal2022Identity(serverKey, userKey, responseSalt)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(responseWire, responseSalt) || len(responseWire) >= server.SaltSize()+ss2022IdentitySize && bytes.Equal(responseWire[server.SaltSize():server.SaltSize()+ss2022IdentitySize], responseIdentity) {
				t.Fatalf("tcp response must bind request salt without an identity header")
			}
			session.Close()

			sessionID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			udpWire, err := client.SealUDPPacket(sessionID, 9, "example.org:53", []byte("query"), now, []byte{7})
			if err != nil {
				t.Fatal(err)
			}
			separate := make([]byte, ss2022IdentitySize)
			copy(separate[:8], sessionID)
			binary.BigEndian.PutUint64(separate[8:], 9)
			wantUDP, err := seal2022Identity(serverKey, userKey, separate)
			if err != nil {
				t.Fatal(err)
			}
			if len(udpWire) < 2*ss2022IdentitySize || !bytes.Equal(udpWire[ss2022IdentitySize:2*ss2022IdentitySize], wantUDP) {
				t.Fatalf("udp identity header=%x want=%x", identityPrefix(udpWire, 2*ss2022IdentitySize), wantUDP)
			}
			udpRequest, err := server.OpenUDPPacket(udpWire, now)
			if err != nil || udpRequest.Target != "example.org:53" || string(udpRequest.Payload) != "query" || udpRequest.SessionID != 0x0102030405060708 || udpRequest.PacketID != 9 {
				t.Fatalf("udp request=%+v err=%v", udpRequest, err)
			}
			serverSession := []byte{8, 7, 6, 5, 4, 3, 2, 1}
			udpResponse, err := server.SealUDPResponse(serverSession, 10, udpRequest.SessionID, "example.org:53", []byte("answer"), now, nil)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := client.OpenUDPResponse(udpResponse, now, udpRequest.SessionID)
			if err != nil || opened.Target != "example.org:53" || string(opened.Payload) != "answer" {
				t.Fatalf("udp response=%+v err=%v", opened, err)
			}

			wrongServer := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x33}, test.keyLen)) + ":" + userPSK
			wrongUser := serverPSK + ":" + canonicalSS2022PSK(t, bytes.Repeat([]byte{0x44}, test.keyLen))
			for _, material := range []string{wrongServer, wrongUser, userPSK} {
				peer, peerErr := NewProtocolEngine(test.method, []byte(material))
				if peerErr != nil {
					t.Fatal(peerErr)
				}
				if _, _, openErr := peer.OpenTCPServerSession(tcpWire, now); !errors.Is(openErr, ErrAuthentication) {
					t.Fatalf("material=%q tcp=%v", material, openErr)
				}
				if _, openErr := peer.OpenUDPPacket(udpWire, now); !errors.Is(openErr, ErrAuthentication) {
					t.Fatalf("material=%q udp=%v", material, openErr)
				}
				peer.Destroy()
			}
			solo, err := NewProtocolEngine(test.method, []byte(userPSK))
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := solo.SealTCPRequest(salt, "example.com:443", []byte("first"), now, []byte{9})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, openErr := server.OpenTCPServerSession(legacy, now); !errors.Is(openErr, ErrAuthentication) {
				t.Fatalf("single-psk into identity=%v", openErr)
			}
			solo.Destroy()
			clear(key)
			client.Destroy()
			server.Destroy()
		})
	}
}

func TestShadowsocks2022IdentityRejectsNonCanonicalOrWrongLengthPSK(t *testing.T) {
	serverPSK := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x11}, 16))
	userPSK := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x22}, 16))
	padded32 := canonicalSS2022PSK(t, bytes.Repeat([]byte{0x22}, 32))
	for _, material := range [][]byte{
		[]byte(serverPSK + ":" + serverPSK),
		[]byte(serverPSK + ":" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 16))),
		[]byte(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 16)) + ":" + userPSK),
		[]byte(serverPSK + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 15))),
		[]byte(serverPSK + ":" + padded32),
		[]byte(serverPSK + ":"),
		[]byte(":" + userPSK),
		[]byte(serverPSK + " :" + userPSK),
		[]byte(serverPSK + ": " + userPSK),
		[]byte("not-base64:" + userPSK),
	} {
		if _, err := NewProtocolEngine("2022-blake3-aes-128-gcm", material); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q err=%v", material, err)
		}
	}
}

func canonicalSS2022PSK(t *testing.T, key []byte) string {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(key)
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || !bytes.Equal(decoded, key) || base64.StdEncoding.EncodeToString(decoded) != encoded {
		t.Fatalf("psk is not canonical standard Base64 of %d bytes", len(key))
	}
	return encoded
}

func identityPrefix(wire []byte, n int) []byte {
	if len(wire) < n {
		return wire
	}
	return wire[:n]
}
