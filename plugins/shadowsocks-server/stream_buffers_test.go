package shadowsocksserver

import (
	"bytes"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

type recordStreamConn struct {
	net.Conn
	bytes.Buffer
}

func (c *recordStreamConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *recordStreamConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }

func TestAnyTLSConcurrentCloseUnblocksDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session := newServerAnyTLSSession(discardStreamConn{}, defaultAnyTLSPaddingScheme, nil)
		stream, err := session.openStream()
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < cap(stream.incoming); j++ {
			stream.deliver([]byte("queued"))
		}
		done := make(chan struct{})
		go func() {
			stream.deliver([]byte("blocked"))
			close(done)
		}()
		synctest.Wait()
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("closed stream retained blocked frame delivery")
		}
	})
}

type shortStreamWriter struct{}

func (shortStreamWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type frameInputConn struct {
	discardStreamConn
	input *bytes.Reader
	reads int
}

func (c *frameInputConn) Read(p []byte) (int, error) {
	c.reads++
	return c.input.Read(p)
}
func (*frameInputConn) Close() error { return nil }

func TestAnyTLSBufferedMultiplexedRelay(t *testing.T) {
	wire := &recordStreamConn{}
	writer := newServerAnyTLSSession(wire, defaultAnyTLSPaddingScheme, nil)
	if err := writer.writeFrame(anytlsCmdSettings, 0, []byte("v=2\npadding-md5="+paddingMD5(defaultAnyTLSPaddingScheme))); err != nil {
		t.Fatal(err)
	}
	for id := uint32(1); id <= 3; id++ {
		if err := writer.writeFrame(anytlsCmdSYN, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	want := map[uint32][]byte{}
	for i := 0; i < 20; i++ {
		for id := uint32(1); id <= 3; id++ {
			payload := bytes.Repeat([]byte{byte(i + int(id))}, 100)
			want[id] = append(want[id], payload...)
			if err := writer.writeData(id, payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	for id := uint32(1); id <= 3; id++ {
		if err := writer.writeFrame(anytlsCmdFIN, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	input := &frameInputConn{input: bytes.NewReader(wire.Bytes())}
	type result struct {
		id   uint32
		data []byte
		err  error
	}
	results := make(chan result, 3)
	reader := newServerAnyTLSSession(input, defaultAnyTLSPaddingScheme, func(stream *anytlsStream) {
		var output bytes.Buffer
		_, err := io.Copy(&output, stream)
		results <- result{stream.id, output.Bytes(), err}
	})
	reader.recvLoop()
	for i := 0; i < 3; i++ {
		select {
		case got := <-results:
			if got.err != nil || !bytes.Equal(got.data, want[got.id]) {
				t.Fatalf("stream %d lost data: %v", got.id, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("multiplexed stream did not finish")
		}
	}
	if input.reads >= 60 {
		t.Fatalf("small frames still require individual underlying reads: %d", input.reads)
	}
}

func TestAnyTLSRelayPreservesPartialFrameAndShortWrite(t *testing.T) {
	payload := bytes.Repeat([]byte("payload"), 5000)
	stream := &anytlsStream{incoming: make(chan []byte, 2)}
	stream.deliver(bytes.Clone(payload))
	stream.deliver([]byte("tail"))
	close(stream.incoming)
	if n, err := stream.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	prefix := make([]byte, 7)
	if _, err := io.ReadFull(stream, prefix); err != nil || !bytes.Equal(prefix, payload[:7]) {
		t.Fatalf("prefix = %q, %v", prefix, err)
	}
	n, err := io.Copy(shortStreamWriter{}, stream)
	if err != io.ErrShortWrite || n != int64((len(payload)-7)/2) {
		t.Fatalf("short write = %d, %v", n, err)
	}
	var output bytes.Buffer
	if _, err := io.Copy(&output, stream); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(payload[7+int(n):]), []byte("tail")...)
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatal("relay lost or reordered unread data")
	}
}

func TestPooledAnyTLSFramesPreserveWireAndPadding(t *testing.T) {
	for _, client := range []bool{false, true} {
		conn := &recordStreamConn{}
		session := newServerAnyTLSSession(conn, "stop=2\n0=30-30\n1=400-400", nil)
		session.sendPadding, session.buffering = client, client
		if err := session.writeFrame(anytlsCmdSYN, 7, nil); err != nil {
			t.Fatal(err)
		}
		session.buffering = false
		for _, size := range []int{1, 4096, 16384, 65535, 2} {
			payload := bytes.Repeat([]byte{byte(size)}, size)
			if err := session.writeData(7, payload); err != nil {
				t.Fatal(err)
			}
		}
		cmd, id, _, err := readAnyTLSFrame(&conn.Buffer)
		if err != nil || cmd != anytlsCmdSYN || id != 7 {
			t.Fatalf("SYN = %d, %d, %v", cmd, id, err)
		}
		for _, size := range []int{1, 4096, 16384, 65535, 2} {
			var payload []byte
			for {
				cmd, id, payload, err = readAnyTLSFrame(&conn.Buffer)
				if err != nil {
					t.Fatal(err)
				}
				if cmd != anytlsCmdWaste {
					break
				}
			}
			if cmd != anytlsCmdPSH || id != 7 || !bytes.Equal(payload, bytes.Repeat([]byte{byte(size)}, size)) {
				t.Fatalf("corrupted frame of size %d", size)
			}
		}
	}
}

func TestPooledShadowsocksWritesRoundTrip(t *testing.T) {
	for method := range supportedMethods {
		t.Run(method, func(t *testing.T) {
			material := []byte("fixture-password")
			if method == "2022-blake3-aes-128-gcm" {
				material = []byte("AAAAAAAAAAAAAAAAAAAAAA==")
			} else if method == "2022-blake3-aes-256-gcm" {
				material = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			}
			engine, err := NewProtocolEngine(method, material)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Destroy()
			salt := bytes.Repeat([]byte{3}, engine.SaltSize())
			request, err := engine.SealTCPRequest(salt, "example.com:443", []byte("hello"), time.Now(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, server, err := engine.OpenTCPServerSession(request, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := newTCPClientSession(engine, salt)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			conn := &recordStreamConn{}
			payload := bytes.Repeat([]byte("response"), 20000)
			if _, err := writeTCPClientChunks(conn, server, payload, true); err != nil {
				t.Fatal(err)
			}
			var decoded []byte
			for conn.Len() > 0 {
				chunk, err := client.OpenPayload(&conn.Buffer, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				decoded = append(decoded, chunk...)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatal("response corrupted across pooled records")
			}
			upstream := &upstreamTCPConn{Conn: conn, session: client}
			if _, err := upstream.Write(payload); err != nil {
				t.Fatal(err)
			}
			decoded = nil
			for conn.Len() > 0 {
				chunk, err := readEncryptedPayload(&conn.Buffer, server.inbound, max2022Payload)
				if err != nil {
					t.Fatal(err)
				}
				decoded = append(decoded, chunk...)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatal("upstream request corrupted across pooled records")
			}
		})
	}
}
