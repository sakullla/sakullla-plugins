package shadowsocksserver

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
