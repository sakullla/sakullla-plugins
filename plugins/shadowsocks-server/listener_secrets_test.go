package shadowsocksserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type faultListenStore struct {
	uiMemoryListenState
	beforeStore func()
	afterStore  func()
	deny        bool
	lostReply   bool
	denyRead    bool
}

func (s *faultListenStore) StoreListens(ctx context.Context, listens []ListenRule) error {
	if s.beforeStore != nil {
		s.beforeStore()
	}
	if s.deny {
		return ErrDenied
	}
	if err := s.uiMemoryListenState.StoreListens(ctx, listens); err != nil {
		return err
	}
	if s.afterStore != nil {
		s.afterStore()
	}
	if s.lostReply {
		return ErrTypedHandlesUnavailable
	}
	return nil
}

func (s *faultListenStore) LoadListens(ctx context.Context) ([]ListenRule, bool, error) {
	if s.denyRead {
		return nil, false, ErrTypedHandlesUnavailable
	}
	return s.uiMemoryListenState.LoadListens(ctx)
}

func TestManagedListenCreateAndAppendReadBackBeforeRetiringSecrets(t *testing.T) {
	for _, path := range []string{"create", "append"} {
		for _, mode := range []string{"rejected", "lost reply", "read unavailable"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				fake := &managedRuntimeFake{}
				state := &faultListenStore{}
				host := &uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.5"}}
				c := newAnyTLSUIController(t, newHostCapabilityRuntime(fake), host, state)
				target, original := "/api/listens", 0
				body := `{"agent_id":"agent-1","name":"new","method":"2022-blake3-aes-128-gcm"}`
				added := 2
				if path == "append" {
					row := decodeListenAPI(t, uiJSON(t, c, "POST", target, body)).Listen
					if row == nil {
						t.Fatal("missing original listener")
					}
					target += "/" + row.ID + "/users"
					body = `{"agent_id":"agent-1","name":"extra"}`
					original, added = len(fake.secrets), 1
				}
				state.deny = mode == "rejected"
				state.lostReply = !state.deny
				state.denyRead = mode == "read unavailable"
				reply := uiJSON(t, c, "POST", target, body)
				switch mode {
				case "rejected":
					if fake.revokes != 0 {
						t.Fatal("request started revocation")
					}
					if err := c.recoverListenerSecrets(t.Context()); err != nil {
						t.Fatal(err)
					}
					if reply.Code == http.StatusOK || len(fake.secrets) != original || fake.revokes != added {
						t.Fatalf("code=%d remaining=%d retired=%d", reply.Code, len(fake.secrets), fake.revokes)
					}
				case "lost reply":
					if reply.Code != http.StatusOK || len(fake.secrets) != original+added || fake.revokes != 0 {
						t.Fatalf("code=%d remaining=%d retired=%d", reply.Code, len(fake.secrets), fake.revokes)
					}
				case "read unavailable":
					if reply.Code == http.StatusOK || fake.revokes != 0 || len(fake.secrets) != original+added {
						t.Fatalf("uncertain write code=%d remaining=%d retired=%d", reply.Code, len(fake.secrets), fake.revokes)
					}
					if other := uiJSON(t, c, "POST", target, body); other.Code != http.StatusServiceUnavailable || len(fake.secrets) != original+added {
						t.Fatalf("a second write proceeded while the directory was unconfirmed: %d", other.Code)
					}
					state.denyRead = false
					if err := c.recoverListenerSecrets(t.Context()); err != nil {
						t.Fatal(err)
					}
					listens := c.directory().Listeners
					if len(listens) != 1 || len(fake.secrets) != original+added || fake.revokes != 0 {
						t.Fatal("recovery lost the committed state")
					}
				}
				if cache := c.secrets().snapshot(); len(cache) != 0 {
					t.Fatalf("managed password copies=%d", len(cache))
				}
				pending, err := c.loadListenerSecretIntents(t.Context())
				if err != nil || len(pending) != 0 {
					t.Fatalf("remaining intents=%d err=%v", len(pending), err)
				}
			})
		}
	}
}

type interruptedSecretHost struct {
	managedRuntimeFake
	interrupt string
	offline   bool
}

func (h *interruptedSecretHost) ScopedSecret(ctx context.Context, req pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error) {
	if h.offline {
		return pluginsdk.ScopedSecretResponse{}, context.Canceled
	}
	res, err := h.managedRuntimeFake.ScopedSecret(ctx, req)
	if err == nil && req.Action == h.interrupt {
		h.offline = true
		return pluginsdk.ScopedSecretResponse{}, context.Canceled
	}
	return res, err
}

func (h *interruptedSecretHost) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, dst any) error {
	if h.offline {
		return context.Canceled
	}
	return h.managedRuntimeFake.Call(ctx, call, dst)
}

func TestManagedListenerCleanupAfterGenerationStops(t *testing.T) {
	for _, action := range []string{pluginsdk.ScopedSecretRevoke, pluginsdk.ScopedSecretCreate} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fake := &interruptedSecretHost{}
				state := &uiMemoryListenState{}
				host := &uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.4"}}
				current := newAnyTLSUIController(t, newHostCapabilityRuntime(fake), host, state)
				post := func(path, body string) *listenAPIView {
					t.Helper()
					reply := uiJSON(t, current, "POST", path, body)
					if reply.Code != 200 {
						t.Fatalf("setup request returned %d", reply.Code)
					}
					return decodeListenAPI(t, reply).Listen
				}
				keep := post("/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm","name":"stay","port":9000}`)
				path := "/api/listens"
				body := `{"agent_id":"agent-1","method":"aes-256-gcm","name":"interrupted","password":"test-secret-no-plaintext"}`
				wantIntents := 1
				if action == pluginsdk.ScopedSecretRevoke {
					fake.certificates = []pluginsdk.PublicCertificateProjection{{ID: 7, Domain: "node.example", Enabled: true, MaterialAvailable: true}}
					removed := post(path, `{"agent_id":"agent-1","protocol":"anytls","certificate_id":7,"name":"one","password":"test-secret-no-plaintext"}`)
					post("/api/listens/"+removed.ID+"/users", `{"agent_id":"agent-1","name":"two","password":"two-secret"}`)
					path = "/api/listens/" + removed.ID + "/delete"
					body = `{"agent_id":"agent-1"}`
					wantIntents = 2
				}
				fake.interrupt = action
				reply := uiJSON(t, current, "POST", path, body)
				if action == pluginsdk.ScopedSecretRevoke {
					if reply.Code != http.StatusOK || fake.offline || fake.revokes != 0 || len(host.live) != 1 || host.live[0].ID != keep.ID {
						t.Fatalf("delete response=%d, stopped=%v, revokes=%d, listeners=%v", reply.Code, fake.offline, fake.revokes, host.live)
					}
					time.Sleep(listenReconcileInterval + time.Second)
					synctest.Wait()
				} else if reply.Code == http.StatusOK {
					t.Fatal("interrupted create reported success")
				}
				if !fake.offline {
					t.Fatal("host did not interrupt the generation")
				}
				var pending []listenerSecretIntent
				if err := json.Unmarshal(fake.listenerIntents, &pending); err != nil || len(pending) != wantIntents || strings.Contains(string(fake.listenerIntents), "test-secret-no-plaintext") {
					t.Fatalf("saved intent count=%d err=%v", len(pending), err)
				}
				current.stopListenReconciler()
				synctest.Wait()
				fake.offline, fake.interrupt = false, ""
				successor := startManagedUIController(t, newHostCapabilityRuntime(fake), host, state, "generation-b")
				defer successor.stopListenReconciler()
				time.Sleep(listenReconcileInterval + time.Second)
				synctest.Wait()
				pending, err := successor.loadListenerSecretIntents(t.Context())
				listens := successor.directory().Listeners
				if err != nil || len(pending) != 0 || len(fake.secrets) != 1 || len(listens) != 1 || listens[0].ID != keep.ID || len(host.live) != 1 || host.live[0].ID != keep.ID {
					t.Fatalf("remaining intents=%d secrets=%d listens=%d active=%d err=%v", len(pending), len(fake.secrets), len(listens), len(host.live), err)
				}
				user := listens[0].Users[0]
				if _, err := successor.managedRuntime.Resolve(t.Context(), user.SecretRef, user.SecretVersion); err != nil {
					t.Fatal("surviving credential unavailable")
				}
			})
		})
	}
}

func TestUIConcurrentAppendPersistsBothUsers(t *testing.T) {
	fake := &managedRuntimeFake{}
	state := &faultListenStore{}
	c := newAnyTLSUIController(t, newHostCapabilityRuntime(fake), &uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.4"}}, state)
	listen := decodeListenAPI(t, uiJSON(t, c, "POST", "/api/listens", `{"agent_id":"agent-1","method":"2022-blake3-aes-128-gcm","name":"owner"}`)).Listen
	if listen == nil {
		t.Fatal("missing initial listener")
	}
	path := "/api/listens/" + listen.ID + "/users"
	entered, release := make(chan struct{}), make(chan struct{})
	state.beforeStore = func() {
		select {
		case <-entered:
			return
		default:
			close(entered)
		}
		<-release
	}
	result := make(chan int, 2)
	go func() { result <- uiJSON(t, c, "POST", path, `{"agent_id":"agent-1","name":"first"}`).Code }()
	<-entered
	// The first writer must still own the mutation until its store and Agent apply complete.
	if c.directoryMu.TryLock() {
		c.directoryMu.Unlock()
		close(release)
		t.Fatal("directory read/modify/write was not serialized")
	}
	started := make(chan struct{})
	go func() {
		close(started)
		result <- uiJSON(t, c, "POST", path, `{"agent_id":"agent-1","name":"second"}`).Code
	}()
	<-started
	close(release)
	if <-result != 200 || <-result != 200 {
		t.Fatal("concurrent append failed")
	}
	saved, _, err := state.LoadListens(t.Context())
	if err != nil || len(saved) != 1 || len(saved[0].Users) != 3 || len(c.directory().Listeners[0].Users) != 3 {
		t.Errorf("concurrent append lost a user: %v", err)
	}
}

type executorListenHost struct {
	*uiListenHost
	exec *listenExecutor
}

func (h *executorListenHost) Call(ctx context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	if err := h.uiListenHost.Call(ctx, call, target); err != nil {
		return err
	}
	request := decodePluginCallRequestFromCall(call)
	if request.Name == pluginCallListenApply {
		_, err := h.exec.apply(ctx, request.Payload)
		return err
	}
	return nil
}

func TestAnyTLSCommittedUserChangeRetriesFullApplyOnSamePort(t *testing.T) {
	for _, action := range []string{"append", "delete", "disable"} {
		t.Run(action, func(t *testing.T) {
			cert, roots := testAnyTLSCertificate(t)
			store := &faultListenStore{}
			fake := &interruptedSecretHost{}
			fake.certificates = []pluginsdk.PublicCertificateProjection{{ID: 7, Domain: "anytls.example", Enabled: true, MaterialAvailable: true}}
			managed := newHostCapabilityRuntime(fake)
			exec := newListenExecutor(netListenBinder{})
			exec.bindHost, exec.secrets = "127.0.0.1", managed
			exec.tlsTerminate = func(_ context.Context, _ int, conn net.Conn) (net.Conn, error) {
				return tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
			}
			t.Cleanup(exec.stopAll)
			host := &executorListenHost{&uiListenHost{online: true, node: NodeAddresses{IPv4: "203.0.113.5"}}, exec}
			current := startManagedUIController(t, managed, host, store, "generation-a")
			port := freePort(t)
			create := fmt.Sprintf(`{"agent_id":"agent-1","port":%d,"protocol":"anytls","certificate_id":7,"name":"owner","password":"owner-pass"}`, port)
			listen := decodeListenAPI(t, uiJSON(t, current, "POST", "/api/listens", create)).Listen
			if listen == nil {
				t.Fatal("original listener failed")
			}
			target := "/api/listens/" + listen.ID + "/users"
			body := `{"agent_id":"agent-1","name":"second","password":"second-pass"}`
			if action != "append" {
				updated := decodeListenAPI(t, uiJSON(t, current, "POST", target, body)).Listen
				if updated == nil || len(updated.Users) != 2 {
					t.Fatal("missing original second user")
				}
				target = "/api/users/" + updated.Users[1].ID + "/" + action
				body = `{"agent_id":"agent-1"}`
			}
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			auth := func(password string, want bool) {
				t.Helper()
				err := dialAnyTLS(t, roots, port, password, echo.Addr().String(), func(conn net.Conn) error {
					if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
						return err
					}
					if _, err := conn.Write([]byte("x")); err != nil {
						return err
					}
					var buf [1]byte
					if _, err := io.ReadFull(conn, buf[:]); err != nil {
						return err
					}
					if buf[0] != 'x' {
						return errors.New("unexpected echo")
					}
					return nil
				})
				if (err == nil) != want || isTimeout(err) {
					t.Fatalf("login should succeed=%v, err=%v", want, err)
				}
			}
			auth("owner-pass", true)
			auth("second-pass", action != "append")

			// Stop precisely after the durable directory commit, before Agent apply
			// or retirement. No calls to the old generation's host can complete.
			stopAfterCommit := errors.New("generation stopped after state.put")
			store.afterStore = func() { host.online = false; fake.offline = true; panic(stopAfterCommit) }
			func() {
				defer func() {
					if got := recover(); got != stopAfterCommit {
						t.Fatalf("missed crash window: %v", got)
					}
				}()
				uiJSON(t, current, "POST", target, body)
			}()
			current.stopListenReconciler()
			store.afterStore = nil
			fake.offline = false
			successor := startManagedUIController(t, newHostCapabilityRuntime(fake), host, store, "generation-b")
			defer successor.stopListenReconciler()
			checkPending := func(want int) {
				t.Helper()
				pending, err := successor.loadListenerSecretIntents(t.Context())
				if err != nil || len(pending) != want {
					t.Fatalf("pending=%d want=%d err=%v", len(pending), want, err)
				}
			}
			checkPending(1)
			if err := successor.recoverListenerSecrets(t.Context()); !errors.Is(err, ErrAgentOffline) {
				t.Fatalf("offline retry = %v", err)
			}
			checkPending(1)
			auth("second-pass", action != "append")
			host.online = true
			host.applyErr = ErrExecutionUnavailable
			if err := successor.recoverListenerSecrets(t.Context()); err == nil {
				t.Fatal("failed Agent apply was acknowledged")
			}
			checkPending(1)
			host.applyErr = nil
			if err := successor.recoverListenerSecrets(t.Context()); err != nil {
				t.Fatal(err)
			}
			checkPending(0)
			auth("owner-pass", true)
			auth("second-pass", action == "append")
			wantSecrets := 2
			if action == "delete" {
				wantSecrets = 1
			}
			if len(fake.secrets) != wantSecrets {
				t.Fatalf("live secrets=%d want=%d", len(fake.secrets), wantSecrets)
			}
		})
	}
}
