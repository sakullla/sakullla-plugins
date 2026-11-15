package shadowsocksserver

import (
	"bytes"
	"io"
	"net"
	"testing"
)

type discardStreamConn struct{ net.Conn }

func (discardStreamConn) Write(p []byte) (int, error) { return len(p), nil }

type streamWriterOnly struct{ io.Writer }

func BenchmarkAnyTLSWriteFrame(b *testing.B) {
	session := newServerAnyTLSSession(discardStreamConn{}, defaultAnyTLSPaddingScheme, nil)
	payload := make([]byte, 32<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := session.writeData(1, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnyTLSReceiveRelay(b *testing.B) {
	payload := bytes.Repeat([]byte{1}, 32<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		stream := &anytlsStream{incoming: make(chan []byte, 1)}
		stream.deliver(bytes.Clone(payload))
		close(stream.incoming)
		if n, err := io.Copy(streamWriterOnly{io.Discard}, stream); err != nil || n != int64(len(payload)) {
			b.Fatalf("relay = %d, %v", n, err)
		}
	}
}

func BenchmarkShadowsocksResponseWrite(b *testing.B) {
	engine, err := NewProtocolEngine("2022-blake3-aes-128-gcm", []byte("AAAAAAAAAAAAAAAAAAAAAA=="))
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Destroy()
	cipher, err := engine.newSession(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	if err != nil {
		b.Fatal(err)
	}
	session := &TCPServerSession{outbound: cipher, modern: true}
	payload := make([]byte, 32<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := writeTCPClientChunks(discardStreamConn{}, session, payload, false); err != nil {
			b.Fatal(err)
		}
	}
}
