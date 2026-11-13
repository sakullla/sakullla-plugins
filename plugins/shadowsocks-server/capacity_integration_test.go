//go:build capacity

package shadowsocksserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// The host process integration harness supplies synthetic credentials and an
// isolated listener. This opt-in test never discovers or uses a production node.
func TestManagedShadowsocksCapacity(t *testing.T) {
	var config struct {
		Endpoint, Password string
		Connections        int
	}
	if err := json.Unmarshal([]byte(os.Getenv("NRE_SS_CAPACITY_CONFIG")), &config); err != nil {
		t.Fatal("isolated capacity fixture config required")
	}
	if config.Connections < 3000 || config.Connections > 4096 {
		t.Fatal("capacity fixture requires 3000..4096 connections")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var echoMu sync.Mutex
	var echoes []net.Conn
	defer func() {
		echoMu.Lock()
		defer echoMu.Unlock()
		for _, c := range echoes {
			c.Close()
		}
	}()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			echoMu.Lock()
			echoes = append(echoes, c)
			echoMu.Unlock()
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dial := func() net.Conn {
		engine, e := NewProtocolEngine("2022-blake3-aes-128-gcm", []byte(config.Password))
		if e != nil {
			t.Fatal(e)
		}
		salt := make([]byte, engine.SaltSize())
		if _, e = rand.Read(salt); e != nil {
			t.Fatal(e)
		}
		session, e := newTCPClientSession(engine, salt)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := net.DialTimeout("tcp", config.Endpoint, 5*time.Second)
		if e != nil {
			session.Close()
			t.Fatal(e)
		}
		conn := &upstreamTCPConn{Conn: raw, session: session}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		wire, e := engine.SealTCPRequest(salt, echo.Addr().String(), []byte{0}, time.Now(), nil)
		if e == nil {
			_, e = raw.Write(wire)
		}
		if e == nil {
			var reply [1]byte
			_, e = io.ReadFull(conn, reply[:])
			if e == nil && reply[0] != 0 {
				e = ErrProtocol
			}
		}
		if e != nil {
			conn.Close()
			t.Fatal(e)
		}
		conn.SetDeadline(time.Time{})
		return conn
	}
	held := make([]net.Conn, 0, config.Connections)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < config.Connections; i++ {
		held = append(held, dial())
		if len(held)%500 == 0 {
			t.Logf("established=%d", len(held))
		}
	}
	for round := 0; round < 3; round++ {
		for i, c := range held {
			payload := bytes.Repeat([]byte{byte(i), byte(round), 0x80, 0x42}, 16)
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err = c.Write(payload); err != nil {
				t.Fatalf("round=%d connection=%d write: %v", round, i, err)
			}
			reply := make([]byte, len(payload))
			if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, payload) {
				t.Fatalf("round=%d connection=%d echo: %v", round, i, err)
			}
			c.SetDeadline(time.Time{})
		}
		t.Logf("round=%d all=%d bidirectional echoes verified", round, len(held))
		if round == 0 {
			time.Sleep(31 * time.Second)
		} // cross the host's real idle poll rollover
	}
	bulk := bytes.Repeat([]byte("capacity-hash-fixture"), 1<<19)
	c := held[0]
	c.SetDeadline(time.Now().Add(30 * time.Second))
	written := make(chan error, 1)
	go func() { _, e := c.Write(bulk); written <- e }()
	reply := make([]byte, len(bulk))
	if _, err = io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(reply) != sha256.Sum256(bulk) {
		t.Fatal("bulk echo hash mismatch")
	}
	t.Logf("bulk_bytes=%d sha256 matched with %d connections held", len(bulk), len(held))
	for _, c := range held {
		c.Close()
	}
	held = nil
	for i := 0; i < 16; i++ {
		dial().Close()
	}
	t.Log("post-close new connections verified")
}
