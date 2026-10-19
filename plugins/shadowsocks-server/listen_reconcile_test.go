package shadowsocksserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestActivateRestoresPersistedListensWithoutPanelView(t *testing.T) {
	previous := listenReconcileInterval
	listenReconcileInterval = time.Hour
	t.Cleanup(func() { listenReconcileInterval = previous })

	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{found: true, listens: []ListenRule{{
		ID: "listen-1", AgentID: "agent-1", Port: 43816, Method: "aes-256-gcm",
		Users: []User{{ID: "user-1", SecretRef: "user-secret", SecretVersion: "v1", Enabled: true}},
	}}}
	controller := startManagedListenController(t, host, state)
	t.Cleanup(func() {
		_ = controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"})
	})

	host.mu.Lock()
	applied := append([]listenApplyRequest(nil), host.apply...)
	host.mu.Unlock()
	if len(applied) != 1 || len(applied[0].Listens) != 1 || applied[0].Listens[0].Port != 43816 {
		t.Fatalf("activate apply = %+v", applied)
	}
}

func TestReconcilerReappliesAfterAgentDropsListens(t *testing.T) {
	previous := listenReconcileInterval
	listenReconcileInterval = 20 * time.Millisecond
	t.Cleanup(func() { listenReconcileInterval = previous })

	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{found: true, listens: []ListenRule{{
		ID: "listen-1", AgentID: "agent-1", Port: 43816, Method: "aes-256-gcm",
		Users: []User{{ID: "user-1", SecretRef: "user-secret", SecretVersion: "v1", Enabled: true}},
	}}}
	controller := startManagedListenController(t, host, state)
	t.Cleanup(func() {
		_ = controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"})
	})

	host.mu.Lock()
	host.live = nil
	host.apply = nil
	host.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		host.mu.Lock()
		applied := len(host.apply)
		host.mu.Unlock()
		if applied >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconciler did not reapply the dropped listen")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if result := controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	host.mu.Lock()
	host.live = nil
	stopped := len(host.apply)
	host.mu.Unlock()
	time.Sleep(80 * time.Millisecond)
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.apply) != stopped {
		t.Fatalf("reconciler kept applying after stop: %d -> %d", stopped, len(host.apply))
	}
}

func startManagedListenController(t *testing.T, host *uiListenHost, state ListenCatalogStore) *Controller {
	t.Helper()
	managed := newHostCapabilityRuntime(&managedRuntimeFake{})
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a",
		ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: state,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(),
		Generation: "generation-a", RequiredFeatures: supportedFeatures(),
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(Configuration{Generation: "provider"})
	if err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-a"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	return controller
}
