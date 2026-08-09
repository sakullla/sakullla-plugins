package shadowsocksserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testRuntime struct {
	mu           sync.Mutex
	now          uint64
	used         map[string]uint64
	pending      map[string]bool
	refs         map[string]string
	replay       map[string]bool
	blockClock   chan struct{}
	clockStarted chan struct{}
	vaultVersion string
	rotations    int
	listeners    int
}
type testReservation struct {
	runtime *testRuntime
	id      string
	limit   uint64
	once    sync.Once
}

func (r *testReservation) Commit(_ context.Context, n uint64) error {
	var result error
	r.once.Do(func() {
		r.runtime.mu.Lock()
		defer r.runtime.mu.Unlock()
		if r.runtime.used[r.id]+n > r.limit {
			result = ErrQuota
		} else {
			r.runtime.used[r.id] += n
		}
		delete(r.runtime.pending, r.id)
	})
	return result
}
func (r *testReservation) Release(context.Context) error {
	r.runtime.mu.Lock()
	delete(r.runtime.pending, r.id)
	r.runtime.mu.Unlock()
	return nil
}
func (r *testRuntime) Verify(_ context.Context, ref, version string, material []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refs[ref] != string(material) {
		return ErrDenied
	}
	return nil
}
func (r *testRuntime) Resolve(_ context.Context, ref, version string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	material, ok := r.refs[ref]
	if !ok {
		return nil, ErrDenied
	}
	return []byte(material), nil
}
func (r *testRuntime) Reserve(_ context.Context, id string, limit uint64, _ string) (TrafficReservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string]bool{}
	}
	if r.used[id] >= limit || r.pending[id] {
		return nil, ErrQuota
	}
	r.pending[id] = true
	return &testReservation{runtime: r, id: id, limit: limit}, nil
}
func (r *testRuntime) Now(context.Context) (uint64, error) {
	if r.clockStarted != nil {
		select {
		case r.clockStarted <- struct{}{}:
		default:
		}
	}
	if r.blockClock != nil {
		<-r.blockClock
	}
	return r.now, nil
}
func (r *testRuntime) Admit(_ context.Context, id string, token []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := id + string(token)
	if r.replay[key] {
		return ErrReplay
	}
	r.replay[key] = true
	return nil
}
func (r *testRuntime) Register(context.Context, string, *Service) error { r.listeners++; return nil }
func (r *testRuntime) Rotate(_ context.Context, id, currentRef, currentVersion, op string) (*SecretOnce, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.vaultVersion != "" && r.vaultVersion != currentVersion {
		return nil, ErrRevoked
	}
	r.vaultVersion = "v2"
	r.rotations++
	if r.refs == nil {
		r.refs = map[string]string{}
	}
	r.refs["secret/rotated"] = "rotated-value"
	return NewSecretOnce("secret/rotated", "v2", []byte("rotated-value")), nil
}
func (r *testRuntime) Audit(context.Context, AuditRecord) error { return nil }
func adapters(r *testRuntime) RuntimeAdapters {
	return RuntimeAdapters{Secrets: r, Traffic: r, Clock: r, Replay: r, Listener: r, Vault: r, Auditor: r}
}
func testConfig() Configuration {
	return Configuration{Generation: "gen-1", ListenerRef: "listener/1", Cipher: "aes-256-gcm", MaxSessions: 2, Users: []User{{ID: "alice", SecretRef: "secret/alice", SecretVersion: "v1", Enabled: true, ExpiresAt: 20, QuotaBytes: 100}, {ID: "bob", SecretRef: "secret/bob", SecretVersion: "v1", Enabled: true, QuotaBytes: 100}}}
}

func TestShadowsocksTCPUDPAndMultiUser(t *testing.T) {
	r := &testRuntime{now: 10, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "a", "secret/bob": "b"}, replay: map[string]bool{}}
	s, err := NewService(testConfig(), adapters(r))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p       Protocol
		u, c, k string
	}{{TCP, "alice", "a", "1"}, {UDP, "bob", "b", "2"}} {
		flow, err := s.Admit(context.Background(), AdmissionRequest{Protocol: tc.p, UserID: tc.u, Credential: []byte(tc.c), ReplayToken: []byte(tc.k)})
		if err != nil {
			t.Fatal(err)
		}
		alias := flow
		if err := flow.Close(7); err != nil {
			t.Fatal(err)
		}
		if err := alias.Close(9); err != nil {
			t.Fatal(err)
		}
	}
	if r.used["alice"] != 7 || r.used["bob"] != 7 {
		t.Fatalf("traffic=%v", r.used)
	}
}

func TestShadowsocksLocalWireAuthenticationAndMultiUser(t *testing.T) {
	r := &testRuntime{now: 10, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "alice-password", "secret/bob": "bob-password"}, replay: map[string]bool{}}
	s, err := NewService(testConfig(), adapters(r))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	bobClient, err := NewProtocolEngine("aes-256-gcm", []byte("bob-password"))
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, bobClient.SaltSize())
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	tcpWire, err := bobClient.SealTCPRequest(salt, "example.com:443", []byte("hello"), time.Unix(10, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	flow, request, err := s.OpenTCP(context.Background(), tcpWire)
	if err != nil || request.Target != "example.com:443" || string(request.Payload) != "hello" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	if err = flow.Close(5); err != nil {
		t.Fatal(err)
	}
	if r.used["bob"] != 5 || r.used["alice"] != 0 {
		t.Fatalf("traffic=%v", r.used)
	}
	aliceClient, err := NewProtocolEngine("aes-256-gcm", []byte("wrong-password"))
	if err != nil {
		t.Fatal(err)
	}
	badWire, err := aliceClient.SealUDPPacket(salt, 0, "1.1.1.1:53", []byte("query"), time.Unix(10, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.OpenUDP(context.Background(), badWire); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong user key=%v", err)
	}
	s.Disable()
	if _, err = bobClient.OpenTCPRequest(tcpWire, time.Unix(10, 0)); err != nil {
		t.Fatalf("client engine unexpectedly revoked: %v", err)
	}
	if engine, ok := s.Engine("bob"); ok || engine != nil {
		t.Fatalf("revoked engine=%v ok=%v", engine, ok)
	}
}
func TestExpiryQuotaReplayAndNoEgress(t *testing.T) {
	r := &testRuntime{now: 20, used: map[string]uint64{"bob": 100}, refs: map[string]string{"secret/alice": "a", "secret/bob": "b"}, replay: map[string]bool{}}
	s, _ := NewService(testConfig(), adapters(r))
	if _, err := s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("x")}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry=%v", err)
	}
	r.now = 1
	if _, err := s.Admit(context.Background(), AdmissionRequest{Protocol: UDP, UserID: "bob", Credential: []byte("b"), ReplayToken: []byte("x")}); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota=%v", err)
	}
	r.used["bob"] = 0
	flow, err := s.Admit(context.Background(), AdmissionRequest{Protocol: UDP, UserID: "bob", Credential: []byte("b"), ReplayToken: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	_ = flow.Close(0)
	if _, err = s.Admit(context.Background(), AdmissionRequest{Protocol: UDP, UserID: "bob", Credential: []byte("b"), ReplayToken: []byte("x")}); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay=%v", err)
	}
	if got := s.EgressProviders(); len(got) != 0 {
		t.Fatalf("egress=%v", got)
	}
}
func TestRotateOneTimeSecretAndSnapshotRedact(t *testing.T) {
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "alice-value", "secret/bob": "bob-value"}, replay: map[string]bool{}}
	s, _ := NewService(testConfig(), adapters(r))
	if err := s.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	secret, err := s.Rotate(context.Background(), "alice", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secret.RevealOnce()); got != "rotated-value" {
		t.Fatalf("material=%q", got)
	}
	if got := secret.RevealOnce(); got != nil {
		t.Fatal("material revealed twice")
	}
	snapshot := s.Snapshot()
	if snapshot.Users[0].SecretRef != "secret/rotated" || snapshot.Users[0].SecretVersion != "v2" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestRotateImmediatelyInvalidatesOldWireKey(t *testing.T) {
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "old-value", "secret/bob": "bob-value"}, replay: map[string]bool{}, vaultVersion: "v1"}
	s, err := NewService(testConfig(), adapters(r))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldClient, _ := NewProtocolEngine("aes-256-gcm", []byte("old-value"))
	salt := make([]byte, oldClient.SaltSize())
	oldWire, _ := oldClient.SealTCPRequest(salt, "example.com:443", []byte("old"), time.Unix(1, 0), nil)
	secret, err := s.Rotate(context.Background(), "alice", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.OpenTCP(context.Background(), oldWire); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old wire=%v", err)
	}
	newClient, _ := NewProtocolEngine("aes-256-gcm", secret.RevealOnce())
	newSalt := make([]byte, newClient.SaltSize())
	newSalt[0] = 1
	newWire, _ := newClient.SealTCPRequest(newSalt, "example.com:443", []byte("new"), time.Unix(1, 0), nil)
	flow, request, err := s.OpenTCP(context.Background(), newWire)
	if err != nil || request.UserID != "alice" || string(request.Payload) != "new" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	_ = flow.Close(1)
}
func TestDrainRejectsNewAndWaitsForSession(t *testing.T) {
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "a"}, replay: map[string]bool{}}
	s, _ := NewService(testConfig(), adapters(r))
	flow, err := s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain=%v", err)
	}
	if _, err = s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("y")}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("new=%v", err)
	}
	_ = flow.Close(1)
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRotateRevokeDestroysUnrevealedSecretAndStaleCAS(t *testing.T) {
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{}, replay: map[string]bool{}, vaultVersion: "v1"}
	s, _ := NewService(testConfig(), adapters(r))
	results := make(chan *SecretOnce, 2)
	for range 2 {
		go func() { secret, _ := s.Rotate(context.Background(), "alice", "v1"); results <- secret }()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) || r.rotations != 1 {
		t.Fatalf("a=%v b=%v rotations=%d", a, b, r.rotations)
	}
	secret := a
	if secret == nil {
		secret = b
	}
	s.Disable()
	if got := secret.RevealOnce(); got != nil {
		t.Fatalf("revoked material=%q", got)
	}
}

func TestQuotaAtomicReservationAndFlowAliasSharesError(t *testing.T) {
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "a"}, replay: map[string]bool{}}
	s, _ := NewService(testConfig(), adapters(r))
	flow, err := s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("1")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("2")}); !errors.Is(err, ErrQuota) {
		t.Fatalf("parallel quota=%v", err)
	}
	alias := flow
	if err = flow.Close(101); !errors.Is(err, ErrQuota) {
		t.Fatalf("commit=%v", err)
	}
	if err = alias.Close(1); !errors.Is(err, ErrQuota) {
		t.Fatalf("alias=%v", err)
	}
}

func TestDrainTracksLateHostCall(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{}, 1)
	r := &testRuntime{now: 1, used: map[string]uint64{}, refs: map[string]string{"secret/alice": "a"}, replay: map[string]bool{}, blockClock: block, clockStarted: started}
	s, _ := NewService(testConfig(), adapters(r))
	result := make(chan error, 1)
	go func() {
		_, err := s.Admit(context.Background(), AdmissionRequest{Protocol: TCP, UserID: "alice", Credential: []byte("a"), ReplayToken: []byte("1")})
		result <- err
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain=%v", err)
	}
	if err := <-result; err == nil {
		t.Fatal("late admission succeeded")
	}
	close(block)
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}
