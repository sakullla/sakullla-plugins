package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type managedRuntimeFake struct {
	mu              sync.Mutex
	network         []pluginsdk.ManagedNetworkRequest
	secrets         map[string][]byte
	version         int
	createCalls     int
	failCreateAt    int
	revokes         int
	failRevokeID    string
	onRevokeFailure func()
	accepts         map[string]int
	reads           map[string][]byte
	writes          map[string][]byte
	nextRead        []byte
}

func (*managedRuntimeFake) Call(context.Context, pluginsdk.HostRuntimeCall, any) error { return nil }

func (fake *managedRuntimeFake) ManagedNetwork(ctx context.Context, request pluginsdk.ManagedNetworkRequest) (pluginsdk.ManagedNetworkResponse, error) {
	fake.mu.Lock()
	fake.network = append(fake.network, request)
	if fake.accepts == nil {
		fake.accepts = map[string]int{}
	}
	if fake.reads == nil {
		fake.reads = map[string][]byte{}
	}
	if fake.writes == nil {
		fake.writes = map[string][]byte{}
	}
	switch request.Action {
	case pluginsdk.ManagedNetworkListen:
		response := pluginsdk.ManagedNetworkResponse{Handle: &pluginsdk.ManagedNetworkHandle{Binding: request.Binding, Token: fmt.Sprintf("listener-token-%012d", len(fake.network)), Kind: "listener", Protocol: request.Protocol}}
		fake.mu.Unlock()
		return response, nil
	case pluginsdk.ManagedNetworkAccept:
		key := request.Handle.Token
		if fake.accepts[key] > 0 {
			fake.mu.Unlock()
			<-ctx.Done()
			return pluginsdk.ManagedNetworkResponse{}, ctx.Err()
		}
		fake.accepts[key]++
		token := fmt.Sprintf("inbound-token-%012d", len(fake.network))
		fake.reads[token] = append([]byte(nil), fake.nextRead...)
		response := pluginsdk.ManagedNetworkResponse{Handle: &pluginsdk.ManagedNetworkHandle{Binding: request.Binding, Token: token, Kind: map[string]string{"tcp": "stream", "udp": "datagram"}[request.Handle.Protocol], Protocol: request.Handle.Protocol}, Source: &pluginsdk.ManagedSourceMetadata{Peer: pluginsdk.ManagedNetworkEndpoint{Host: "192.0.2.10", Port: 50000}, Source: pluginsdk.ManagedNetworkEndpoint{Host: "192.0.2.10", Port: 50000}, Authority: "socket"}}
		fake.mu.Unlock()
		return response, nil
	case pluginsdk.ManagedNetworkDial:
		kind := "stream"
		if request.Protocol == "udp" {
			kind = "datagram"
		}
		token := fmt.Sprintf("outbound-token-%012d", len(fake.network))
		fake.reads[token] = append([]byte(nil), fake.nextRead...)
		response := pluginsdk.ManagedNetworkResponse{Handle: &pluginsdk.ManagedNetworkHandle{Binding: request.Binding, Token: token, Kind: kind, Protocol: request.Protocol}}
		fake.mu.Unlock()
		return response, nil
	case pluginsdk.ManagedNetworkRead, pluginsdk.ManagedNetworkReceive:
		data := append([]byte(nil), fake.reads[request.Handle.Token]...)
		delete(fake.reads, request.Handle.Token)
		fake.mu.Unlock()
		if request.Action == pluginsdk.ManagedNetworkRead && len(data) == 0 {
			return pluginsdk.ManagedNetworkResponse{EOF: true}, nil
		}
		return pluginsdk.ManagedNetworkResponse{Data: data}, nil
	case pluginsdk.ManagedNetworkWrite, pluginsdk.ManagedNetworkSend:
		fake.writes[request.Handle.Token] = append(fake.writes[request.Handle.Token], request.Data...)
		fake.mu.Unlock()
		return pluginsdk.ManagedNetworkResponse{Written: len(request.Data)}, nil
	case pluginsdk.ManagedNetworkClose:
		fake.mu.Unlock()
		return pluginsdk.ManagedNetworkResponse{Done: true}, nil
	default:
		fake.mu.Unlock()
		return pluginsdk.ManagedNetworkResponse{}, errors.New("unsupported fake network action")
	}
}

func (fake *managedRuntimeFake) ScopedSecret(_ context.Context, request pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.secrets == nil {
		fake.secrets = map[string][]byte{}
	}
	key := request.Reference.ID + "\x00" + request.Reference.Version
	switch request.Action {
	case pluginsdk.ScopedSecretCreate, pluginsdk.ScopedSecretRotate:
		if request.Action == pluginsdk.ScopedSecretCreate {
			fake.createCalls++
			if fake.failCreateAt > 0 && fake.createCalls == fake.failCreateAt {
				return pluginsdk.ScopedSecretResponse{}, ErrDenied
			}
		}
		var value []byte
		if err := request.Material.WithBytes(func(material []byte) error {
			value = append([]byte(nil), material...)
			return nil
		}); err != nil {
			return pluginsdk.ScopedSecretResponse{}, err
		}
		if request.Action == pluginsdk.ScopedSecretRotate {
			delete(fake.secrets, key)
		}
		fake.version++
		reference := request.Reference
		reference.Version = fmt.Sprintf("secret-version-%012d", fake.version)
		fake.secrets[reference.ID+"\x00"+reference.Version] = value
		return pluginsdk.ScopedSecretResponse{Reference: reference}, nil
	case pluginsdk.ScopedSecretRead:
		value, ok := fake.secrets[key]
		if !ok {
			return pluginsdk.ScopedSecretResponse{}, ErrDenied
		}
		material, _ := pluginsdk.NewManagedSecretMaterial(value)
		return pluginsdk.ScopedSecretResponse{Reference: request.Reference, Material: material}, nil
	case pluginsdk.ScopedSecretRevoke:
		if request.Reference.ID == fake.failRevokeID {
			if fake.onRevokeFailure != nil {
				fake.onRevokeFailure()
			}
			return pluginsdk.ScopedSecretResponse{}, ErrDenied
		}
		delete(fake.secrets, key)
		fake.revokes++
		return pluginsdk.ScopedSecretResponse{Reference: request.Reference, Revoked: true}, nil
	default:
		return pluginsdk.ScopedSecretResponse{}, ErrDenied
	}
}

func TestLegacyMigrationCreateFailureRevokesPartialAndRetriesWithOpaqueIDs(t *testing.T) {
	fake := &managedRuntimeFake{failCreateAt: 2}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	configuration := Configuration{Generation: "generation-a", Listeners: []ListenRule{
		{ID: "listen-a", AgentID: "agent-a", Port: 8388, Method: "aes-256-gcm", Users: []User{{ID: "account-a", SecretRef: "legacy/account-a", SecretVersion: "v1", Enabled: true}}},
		{ID: "listen-b", AgentID: "agent-a", Port: 8389, Method: "aes-256-gcm", Users: []User{{ID: "account-b", SecretRef: "legacy/account-b", SecretVersion: "v1", Enabled: true}}},
	}}
	legacy := map[string]string{issuedSecretKey("legacy/account-a", "v1"): "one", issuedSecretKey("legacy/account-b", "v1"): "two"}
	if _, _, err := runtime.migrateLegacySecrets(t.Context(), configuration, legacy); err == nil {
		t.Fatal("partial create failure was accepted")
	}
	if len(fake.secrets) != 0 || fake.revokes != 1 {
		t.Fatalf("partial migration secrets=%d revokes=%d", len(fake.secrets), fake.revokes)
	}
	fake.failCreateAt = 0
	migrated, _, err := runtime.migrateLegacySecrets(t.Context(), configuration, legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, listener := range migrated.Listeners {
		for _, user := range listener.Users {
			if !strings.HasPrefix(user.SecretRef, "ss-migrated-") || user.SecretVersion == "v1" {
				t.Fatalf("migrated user=%+v", user)
			}
		}
	}
}

func TestManagedRuntimeUsesExactIdentityForScopedSecretsAndNetwork(t *testing.T) {
	fake := &managedRuntimeFake{}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	reference, err := runtime.importSecret(t.Context(), "secret/account-a", []byte("account-secret"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := runtime.Resolve(t.Context(), reference.ID, reference.Version)
	if err != nil || string(resolved) != "account-secret" {
		t.Fatalf("resolved=%q err=%v", resolved, err)
	}
	clear(resolved)
	if err := runtime.Verify(t.Context(), reference.ID, reference.Version, []byte("wrong")); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong material err=%v", err)
	}
	rotated, err := runtime.Rotate(t.Context(), "account-a", reference.ID, reference.Version, "operation")
	if err != nil || rotated.SecretVersion == reference.Version || len(rotated.RevealOnce()) == 0 {
		t.Fatalf("rotated=%+v err=%v", rotated, err)
	}

	listener, err := runtime.listenTCP(t.Context(), 8388)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := (managedNetworkDialer{runtime: runtime}).DialContext(t.Context(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("managed-request")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	udp, err := (managedNetworkDialer{runtime: runtime}).DialContext(t.Context(), "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write([]byte("dns-query")); err != nil {
		t.Fatal(err)
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	for _, request := range fake.network {
		if request.Binding != (pluginsdk.ManagedBinding{InstanceID: "instance-a", Generation: "generation-a", EntryID: "instance-a"}) {
			t.Fatalf("managed binding=%+v", request.Binding)
		}
	}
}

func TestManagedScopedReferencesBuildAllSupportedMethodEngines(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			fake := &managedRuntimeFake{}
			runtime := newHostCapabilityRuntime(fake)
			if err := runtime.bind("instance-a", "generation-a"); err != nil {
				t.Fatal(err)
			}
			user, err := runtime.importSecret(t.Context(), "secret/user-a", []byte("user-material"))
			if err != nil {
				t.Fatal(err)
			}
			item := ListenApplyItem{ID: "listen-a", Port: 8388, Method: method, Users: []ListenApplyUser{{ID: "user-a", Enabled: true, SecretRef: user.ID, SecretVersion: user.Version}}}
			if SS2022Method(method) {
				server, err := runtime.importSecret(t.Context(), "secret/server-a", []byte("server-material"))
				if err != nil {
					t.Fatal(err)
				}
				item.ServerSecretRef, item.ServerSecretVersion = server.ID, server.Version
			}
			engines, err := assembleUserEngines(t.Context(), item, nil, runtime)
			if err != nil || len(engines) != 1 || engines[0].engine.Name() != method {
				t.Fatalf("engines=%+v err=%v", engines, err)
			}
			destroyUserEngines(engines, nil)
		})
	}
}

func TestManagedTCPAndUDPAcceptedFlowsCarryOpaqueBytes(t *testing.T) {
	fake := &managedRuntimeFake{nextRead: []byte("encrypted-client-frame")}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	tcpListener, err := runtime.listenTCP(t.Context(), 8388)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := tcpListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := tcp.Read(buffer)
	if err != nil || string(buffer[:n]) != "encrypted-client-frame" {
		t.Fatalf("tcp read=%q err=%v", buffer[:n], err)
	}
	if _, err := tcp.Write([]byte("encrypted-server-frame")); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	_ = tcpListener.Close()

	fake.nextRead = []byte("encrypted-udp-packet")
	udp, err := runtime.listenUDP(t.Context(), 8388)
	if err != nil {
		t.Fatal(err)
	}
	n, address, err := udp.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "encrypted-udp-packet" {
		t.Fatalf("udp read=%q err=%v", buffer[:n], err)
	}
	if _, err := udp.WriteTo([]byte("encrypted-udp-response"), address); err != nil {
		t.Fatal(err)
	}
	_ = udp.Close()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	joined := []byte{}
	for _, value := range fake.writes {
		joined = append(joined, value...)
	}
	if !bytes.Contains(joined, []byte("encrypted-server-frame")) || !bytes.Contains(joined, []byte("encrypted-udp-response")) {
		t.Fatalf("managed writes=%q", joined)
	}
}

func TestManagedAcceptDenialExposesNoPayloadOrDial(t *testing.T) {
	fake := &deniedManagedRuntime{}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.listenTCP(t.Context(), 8388)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); err == nil {
		t.Fatal("denied source was accepted")
	}
	_ = listener.Close()
	if fake.reads != 0 || fake.dials != 0 {
		t.Fatalf("denied source reads=%d dials=%d", fake.reads, fake.dials)
	}
}

type deniedManagedRuntime struct{ reads, dials int }

func (*deniedManagedRuntime) Call(context.Context, pluginsdk.HostRuntimeCall, any) error { return nil }
func (fake *deniedManagedRuntime) ScopedSecret(context.Context, pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error) {
	return pluginsdk.ScopedSecretResponse{}, ErrDenied
}
func (fake *deniedManagedRuntime) ManagedNetwork(_ context.Context, request pluginsdk.ManagedNetworkRequest) (pluginsdk.ManagedNetworkResponse, error) {
	switch request.Action {
	case pluginsdk.ManagedNetworkListen:
		return pluginsdk.ManagedNetworkResponse{Handle: &pluginsdk.ManagedNetworkHandle{Binding: request.Binding, Token: "listener-token-000000000001", Kind: "listener", Protocol: request.Protocol}}, nil
	case pluginsdk.ManagedNetworkAccept:
		return pluginsdk.ManagedNetworkResponse{}, &pluginsdk.RuntimeError{Code: pluginsdk.ErrorPermissionDenied, Message: "source denied"}
	case pluginsdk.ManagedNetworkRead:
		fake.reads++
	case pluginsdk.ManagedNetworkDial:
		fake.dials++
	case pluginsdk.ManagedNetworkClose:
		return pluginsdk.ManagedNetworkResponse{Done: true}, nil
	}
	return pluginsdk.ManagedNetworkResponse{}, ErrDenied
}

func TestManagedRuntimeMigratesLegacyStateWithoutSerializingMaterial(t *testing.T) {
	fake := &managedRuntimeFake{}
	runtime := newHostCapabilityRuntime(fake)
	if err := runtime.bind("instance-a", "generation-a"); err != nil {
		t.Fatal(err)
	}
	configuration := Configuration{Generation: "generation-a", Listeners: []ListenRule{{
		ID: "listen-a", AgentID: "agent-a", Port: 8388, Method: "aes-256-gcm",
		Users: []User{{ID: "account-a", SecretRef: "secret/account-a", SecretVersion: "v1", Enabled: true}},
	}}}
	migrated, _, err := runtime.migrateLegacySecrets(t.Context(), configuration, map[string]string{issuedSecretKey("secret/account-a", "v1"): "legacy-material"})
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Listeners[0].Users[0].SecretVersion == "v1" {
		t.Fatal("legacy version was retained")
	}
	encoded, err := json.Marshal(migrated)
	if err != nil || string(encoded) == "" || containsSecret(encoded, "legacy-material") {
		t.Fatalf("migrated state=%s err=%v", encoded, err)
	}
}

func TestControllerPrepareMigratesLegacySecretStateThenClearsIt(t *testing.T) {
	fake := &managedRuntimeFake{}
	runtime := newHostCapabilityRuntime(fake)
	configuration := Configuration{Generation: "provider-generation", Listeners: []ListenRule{{
		ID: "listen-a", AgentID: "agent-a", Port: 8388, Method: "aes-256-gcm",
		Users: []User{{ID: "account-a", SecretRef: "secret/account-a", SecretVersion: "v1", Enabled: true}},
	}}}
	state := &uiMemoryListenState{found: true, listens: cloneListeners(configuration.Listeners), secrets: map[string]string{issuedSecretKey("secret/account-a", "v1"): "legacy-material"}}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: runtime, ListenState: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(configuration)
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.secrets) != 0 || state.listens[0].Users[0].SecretVersion == "v1" {
		t.Fatalf("migrated listens=%+v secrets=%+v", state.listens, state.secrets)
	}
	encoded, _ := json.Marshal(state.listens)
	if containsSecret(encoded, "legacy-material") {
		t.Fatalf("ordinary state retained material: %s", encoded)
	}
}

type flakyMigrationState struct {
	listens     []ListenRule
	secrets     map[string]string
	failListens bool
	failClear   bool
}

func (state *flakyMigrationState) LoadListens(context.Context) ([]ListenRule, bool, error) {
	return cloneListeners(state.listens), true, nil
}
func (state *flakyMigrationState) StoreListens(_ context.Context, listeners []ListenRule) error {
	if state.failListens {
		state.failListens = false
		return errors.New("store listens failed")
	}
	state.listens = cloneListeners(listeners)
	return nil
}
func (state *flakyMigrationState) LoadSecrets(context.Context) (map[string]string, bool, error) {
	return cloneSecretMap(state.secrets), true, nil
}
func (state *flakyMigrationState) StoreSecrets(_ context.Context, secrets map[string]string) error {
	if len(secrets) == 0 && state.failClear {
		state.failClear = false
		return errors.New("clear secrets failed")
	}
	state.secrets = cloneSecretMap(secrets)
	return nil
}
func (*flakyMigrationState) LoadNodes(context.Context) (map[string]NodeAddresses, bool, error) {
	return nil, false, nil
}
func (*flakyMigrationState) StoreNodes(context.Context, map[string]NodeAddresses) error { return nil }

func TestControllerLegacyMigrationRetriesAfterEachStateBoundaryFailure(t *testing.T) {
	for _, boundary := range []string{"store-listens", "clear-secrets"} {
		t.Run(boundary, func(t *testing.T) {
			original := ListenRule{ID: "listen-a", AgentID: "agent-a", Port: 8388, Method: "aes-256-gcm", Users: []User{{ID: "account-a", SecretRef: "legacy/account-a", SecretVersion: "v1", Enabled: true}}}
			state := &flakyMigrationState{listens: []ListenRule{original}, secrets: map[string]string{issuedSecretKey("legacy/account-a", "v1"): "legacy-material"}, failListens: boundary == "store-listens", failClear: boundary == "clear-secrets"}
			fake := &managedRuntimeFake{}
			run := func(generation string) error {
				runtime := newHostCapabilityRuntime(fake)
				controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: runtime, ListenState: state})
				if err != nil {
					return err
				}
				if _, err = controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: generation, RequiredFeatures: supportedFeatures()}); err != nil {
					return err
				}
				wire, _ := json.Marshal(Configuration{Generation: "provider", Listeners: []ListenRule{original}})
				response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: generation, Config: wire})
				if response.Error == nil {
					return nil
				}
				return response.Error
			}
			if err := run("generation-a"); err == nil {
				t.Fatal("boundary failure was accepted")
			}
			if state.listens[0].Users[0].SecretRef != "legacy/account-a" || len(state.secrets) != 1 || len(fake.secrets) != 0 {
				t.Fatalf("failed boundary changed state: listens=%+v legacy=%+v scoped=%+v", state.listens, state.secrets, fake.secrets)
			}
			if err := run("generation-b"); err != nil {
				t.Fatalf("retry error=%#v", err)
			}
			if !strings.HasPrefix(state.listens[0].Users[0].SecretRef, "ss-migrated-") || len(state.secrets) != 0 || len(fake.secrets) != 1 {
				t.Fatalf("retry state: listens=%+v legacy=%+v scoped=%+v", state.listens, state.secrets, fake.secrets)
			}
		})
	}
}

func TestManagedUIRotatesPersistedUserAndServerThenRevokesOldVersions(t *testing.T) {
	fake := &managedRuntimeFake{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	created := decodeListenAPI(t, uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"agent-1"}`)).Listen
	if created == nil || len(created.Users) != 1 {
		t.Fatalf("created=%+v", created)
	}
	before := controller.directory()
	listener, user, ok := before.userListener(created.Users[0].ID)
	if !ok {
		t.Fatal("created user missing")
	}
	oldUserRef, oldUserVersion := user.SecretRef, user.SecretVersion
	oldServerRef, oldServerVersion := listener.ServerSecretRef, listener.ServerSecretVersion
	host.applyErr = errors.New("agent apply failed")
	failed := uiJSON(t, controller, "POST", "/api/users/"+user.ID+"/rotate", `{"agent_id":"agent-1"}`)
	if failed.Code == 200 {
		t.Fatalf("failed rotation=%s", failed.Body.String())
	}
	_, preserved, _ := controller.directory().userListener(user.ID)
	if preserved.SecretRef != oldUserRef || preserved.SecretVersion != oldUserVersion {
		t.Fatalf("failed rotation changed directory=%+v", preserved)
	}
	if _, err := managed.Resolve(t.Context(), oldUserRef, oldUserVersion); err != nil {
		t.Fatalf("failed rotation revoked old secret: %v", err)
	}
	host.applyErr = nil
	rotatedUser := uiJSON(t, controller, "POST", "/api/users/"+user.ID+"/rotate", `{"agent_id":"agent-1"}`)
	if rotatedUser.Code != 200 {
		t.Fatalf("rotate user=%d %s", rotatedUser.Code, rotatedUser.Body.String())
	}
	afterUser := controller.directory()
	_, nextUser, _ := afterUser.userListener(user.ID)
	if nextUser.SecretRef == oldUserRef || nextUser.SecretVersion == oldUserVersion {
		t.Fatalf("user ref unchanged=%+v", nextUser)
	}
	if _, err := managed.Resolve(t.Context(), oldUserRef, oldUserVersion); err == nil {
		t.Fatal("old user version still readable")
	}
	rotatedServer := uiJSON(t, controller, "POST", "/api/listens/"+listener.ID+"/rotate-server", `{"agent_id":"agent-1"}`)
	if rotatedServer.Code != 200 {
		t.Fatalf("rotate server=%d %s", rotatedServer.Code, rotatedServer.Body.String())
	}
	afterServer, _ := controller.directory().Listen(listener.ID)
	if afterServer.ServerSecretRef == oldServerRef || afterServer.ServerSecretVersion == oldServerVersion {
		t.Fatalf("server ref unchanged=%+v", afterServer)
	}
	if _, err := managed.Resolve(t.Context(), oldServerRef, oldServerVersion); err == nil {
		t.Fatal("old server version still readable")
	}
	if len(host.apply) < 3 {
		t.Fatalf("listen apply count=%d", len(host.apply))
	}
	if err := controller.Use(t.Context(), func(context.Context, *Service) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatalf("managed production published legacy Service: %v", err)
	}
}

func TestManagedUIRotatesBothSS2022MethodsIntoRealAgentEngines(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			fake := &managedRuntimeFake{}
			managed := newHostCapabilityRuntime(fake)
			host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
			controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: &uiMemoryListenState{}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(Configuration{Generation: "provider"})
			if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
				t.Fatal(response.Error)
			}
			if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
				t.Fatal(response.Error)
			}
			created := decodeListenAPI(t, uiJSON(t, controller, "POST", "/api/listens", fmt.Sprintf(`{"agent_id":"agent-1","method":%q}`, method))).Listen
			if created == nil || len(created.Users) != 1 {
				t.Fatalf("created=%+v", created)
			}
			if response := uiJSON(t, controller, "POST", "/api/users/"+created.Users[0].ID+"/rotate", `{"agent_id":"agent-1"}`); response.Code != 200 {
				t.Fatalf("user rotate=%d %s", response.Code, response.Body.String())
			}
			if response := uiJSON(t, controller, "POST", "/api/listens/"+created.ID+"/rotate-server", `{"agent_id":"agent-1"}`); response.Code != 200 {
				t.Fatalf("server rotate=%d %s", response.Code, response.Body.String())
			}
			items, err := controller.listenApplyItems(t.Context(), "agent-1")
			if err != nil || len(items) != 1 {
				t.Fatalf("items=%+v err=%v", items, err)
			}
			userMaterial, err := managed.Resolve(t.Context(), items[0].Users[0].SecretRef, items[0].Users[0].SecretVersion)
			if err != nil {
				t.Fatal(err)
			}
			serverMaterial, err := managed.Resolve(t.Context(), items[0].ServerSecretRef, items[0].ServerSecretVersion)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCanonicalPSK(method, string(userMaterial)); err != nil {
				t.Fatalf("user PSK=%q err=%v", userMaterial, err)
			}
			if _, err := decodeCanonicalPSK(method, string(serverMaterial)); err != nil {
				t.Fatalf("server PSK=%q err=%v", serverMaterial, err)
			}
			clear(userMaterial)
			clear(serverMaterial)
			engines, err := assembleUserEngines(t.Context(), items[0], nil, managed)
			if err != nil || len(engines) != 1 || engines[0].engine.Name() != method || !engines[0].engine.HasIdentity() {
				t.Fatalf("rotated agent engines=%+v err=%v", engines, err)
			}
			destroyUserEngines(engines, nil)
		})
	}
}

func TestManagedUILegacyUserRotationRemainsProtocolCompatible(t *testing.T) {
	fake := &managedRuntimeFake{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: &uiMemoryListenState{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	created := decodeListenAPI(t, uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm"}`)).Listen
	if response := uiJSON(t, controller, "POST", "/api/users/"+created.Users[0].ID+"/rotate", `{"agent_id":"agent-1"}`); response.Code != 200 {
		t.Fatalf("rotate=%d %s", response.Code, response.Body.String())
	}
	items, _ := controller.listenApplyItems(t.Context(), "agent-1")
	engines, err := assembleUserEngines(t.Context(), items[0], nil, managed)
	if err != nil || len(engines) != 1 || engines[0].engine.Name() != "aes-256-gcm" {
		t.Fatalf("legacy engines=%+v err=%v", engines, err)
	}
	destroyUserEngines(engines, nil)
}

func managedRotationFixture(t *testing.T) (*Controller, *managedRuntimeFake, *uiListenHost, *listenAPIView) {
	t.Helper()
	fake := &managedRuntimeFake{}
	managed := newHostCapabilityRuntime(fake)
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: &uiMemoryListenState{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-a", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "provider"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); response.Error != nil {
		t.Fatal(response.Error)
	}
	created := decodeListenAPI(t, uiJSON(t, controller, "POST", "/api/listens", `{"agent_id":"agent-1"}`)).Listen
	if created == nil || len(created.Users) != 1 {
		t.Fatalf("created=%+v", created)
	}
	return controller, fake, host, created
}

func TestManagedUIRevokeFailureCompensatesUserAndServerRotation(t *testing.T) {
	for _, target := range []string{"user", "server"} {
		t.Run(target, func(t *testing.T) {
			controller, fake, host, created := managedRotationFixture(t)
			before := controller.directory()
			listener, user, _ := before.userListener(created.Users[0].ID)
			oldRef, oldVersion, path := user.SecretRef, user.SecretVersion, "/api/users/"+user.ID+"/rotate"
			if target == "server" {
				oldRef, oldVersion, path = listener.ServerSecretRef, listener.ServerSecretVersion, "/api/listens/"+listener.ID+"/rotate-server"
			}
			fake.failRevokeID = oldRef
			activeBefore := len(fake.secrets)
			response := uiJSON(t, controller, "POST", path, `{"agent_id":"agent-1"}`)
			if response.Code == 200 {
				t.Fatalf("revoke failure reported success: %s", response.Body.String())
			}
			after := controller.directory()
			afterListener, afterUser, _ := after.userListener(user.ID)
			if target == "user" && (afterUser.SecretRef != oldRef || afterUser.SecretVersion != oldVersion) {
				t.Fatalf("user compensation=%+v", afterUser)
			}
			if target == "server" && (afterListener.ServerSecretRef != oldRef || afterListener.ServerSecretVersion != oldVersion) {
				t.Fatalf("server compensation=%+v", afterListener)
			}
			if _, err := controller.managedRuntime.Resolve(t.Context(), oldRef, oldVersion); err != nil {
				t.Fatalf("old ref unavailable: %v", err)
			}
			if len(fake.secrets) != activeBefore {
				t.Fatalf("new ref retained after compensation: before=%d after=%d", activeBefore, len(fake.secrets))
			}
			last := host.apply[len(host.apply)-1].Listens[0]
			if target == "user" && (last.Users[0].SecretRef != oldRef || last.Users[0].SecretVersion != oldVersion) {
				t.Fatalf("Agent user ref=%+v", last.Users[0])
			}
			if target == "server" && (last.ServerSecretRef != oldRef || last.ServerSecretVersion != oldVersion) {
				t.Fatalf("Agent server ref=%+v", last)
			}
		})
	}
}

func TestManagedUIRevokeFailureWithRollbackApplyFailureKeepsActualNewState(t *testing.T) {
	controller, fake, host, created := managedRotationFixture(t)
	before := controller.directory()
	_, user, _ := before.userListener(created.Users[0].ID)
	fake.failRevokeID = user.SecretRef
	fake.onRevokeFailure = func() { host.applyErr = errors.New("rollback apply failed") }
	response := uiJSON(t, controller, "POST", "/api/users/"+user.ID+"/rotate", `{"agent_id":"agent-1"}`)
	if response.Code == 200 {
		t.Fatalf("rollback failure reported success: %s", response.Body.String())
	}
	after := controller.directory()
	_, current, _ := after.userListener(user.ID)
	if current.SecretRef == user.SecretRef || current.SecretVersion == user.SecretVersion {
		t.Fatalf("directory lied about actual new Agent state: %+v", current)
	}
	lastSuccessful := host.apply[len(host.apply)-1].Listens[0].Users[0]
	if lastSuccessful.SecretRef != current.SecretRef || lastSuccessful.SecretVersion != current.SecretVersion {
		t.Fatalf("directory=%+v Agent=%+v", current, lastSuccessful)
	}
	if _, err := controller.managedRuntime.Resolve(t.Context(), user.SecretRef, user.SecretVersion); err != nil {
		t.Fatalf("old ref should remain readable: %v", err)
	}
	if _, err := controller.managedRuntime.Resolve(t.Context(), current.SecretRef, current.SecretVersion); err != nil {
		t.Fatalf("actual new ref should remain readable: %v", err)
	}
}

func TestProductionExecutorHasNoNativeSocketFallback(t *testing.T) {
	executor := newListenExecutor(nil)
	payload := []byte(`{"agent_id":"agent-a","listens":[{"id":"listen-a","port":8388,"method":"aes-256-gcm","users":[{"id":"account-a","enabled":true,"secret_ref":"secret/account-a","secret_version":"secret-version-000000000001"}]}]}`)
	if _, err := executor.apply(t.Context(), payload); !errors.Is(err, ErrInvalid) {
		t.Fatalf("native fallback err=%v", err)
	}
}

func containsSecret(value []byte, secret string) bool {
	return len(secret) > 0 && string(value) != "" && json.Valid(value) && len(value) >= len(secret) && func() bool {
		for index := 0; index+len(secret) <= len(value); index++ {
			if string(value[index:index+len(secret)]) == secret {
				return true
			}
		}
		return false
	}()
}
