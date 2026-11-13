package shadowsocksserver

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type upstreamReadSignal struct {
	io.Reader
	entered chan struct{}
}

func (r upstreamReadSignal) Read(p []byte) (int, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}
	return r.Reader.Read(p)
}

func TestUpstreamResponseWaitAllowsRequestWrites(t *testing.T) {
	engine, err := NewProtocolEngine("aes-256-gcm", []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := newTCPClientSession(engine, bytes.Repeat([]byte{1}, engine.SaltSize()))
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	entered := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = session.OpenPayload(upstreamReadSignal{reader, entered}, time.Now())
	}()
	<-entered
	writeDone := make(chan error, 1)
	go func() {
		_, err := session.SealPayload([]byte("request body while waiting for response"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("blocked response read prevented request encryption")
	}
	reader.Close()
	<-readDone
	session.Close()
}

func TestUpstreamCloseUnblocksResponseRead(t *testing.T) {
	engine, _ := NewProtocolEngine("aes-256-gcm", []byte("test-password"))
	session, _ := newTCPClientSession(engine, bytes.Repeat([]byte{1}, engine.SaltSize()))
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	connection := &upstreamTCPConn{Conn: client, session: session}
	entered := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = session.OpenPayload(upstreamReadSignal{client, entered}, time.Now())
	}()
	<-entered
	closed := make(chan struct{})
	go func() { connection.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		client.Close()
		t.Fatal("close waited for response instead of closing socket")
	}
	<-readDone
}

func TestStreamingPayloadRecordsPreserveBoundariesAndEmptyFrames(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			engine, err := NewProtocolEngine(method, []byte("AAAAAAAAAAAAAAAAAAAAAA=="))
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Destroy()
			key := bytes.Repeat([]byte{1}, engine.SaltSize())
			salt := bytes.Repeat([]byte{2}, engine.SaltSize())
			outbound, _ := engine.newSession(key, salt)
			inbound, _ := engine.newSession(key, salt)
			maximum := maxLegacyPayload
			if engine.modern {
				maximum = max2022Payload
			}
			var wire bytes.Buffer
			for _, size := range []int{0, 1, maximum, 9} {
				wire.Write(sealPayloadChunk(outbound, bytes.Repeat([]byte{42}, size)))
			}
			for _, size := range []int{0, 1, maximum, 9} {
				payload, err := readEncryptedPayloadRecord(&wire, inbound, maximum, true)
				if err != nil || !bytes.Equal(payload, bytes.Repeat([]byte{42}, size)) {
					t.Fatalf("size %d: len=%d err=%v", size, len(payload), err)
				}
			}
			if wire.Len() != 0 {
				t.Fatal("stream reader left bytes behind")
			}
		})
	}
}
