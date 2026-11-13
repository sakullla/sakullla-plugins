//go:build !windows

package shadowsocksserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestManagedAcceptSurvivesHTTPAdmissionOverload(t *testing.T) {
	directory := t.TempDir()
	endpoint := filepath.Join(directory, "host.sock")
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	binding := pluginsdk.ManagedBinding{InstanceID: "instance-a", Generation: "generation-a", EntryID: "instance-a"}
	handle := pluginsdk.ManagedNetworkHandle{Binding: binding, Token: "listener-token-000000000001", Kind: "listener", Protocol: "tcp"}
	flow := handle
	flow.Kind = "stream"
	flow.Token = "inbound-token-000000000001"
	source := pluginsdk.ManagedSourceMetadata{Peer: pluginsdk.ManagedNetworkEndpoint{Host: "192.0.2.10", Port: 50000}, Source: pluginsdk.ManagedNetworkEndpoint{Host: "192.0.2.10", Port: 50000}, Authority: "socket"}
	var calls atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		payload, _ := json.Marshal(pluginsdk.ManagedNetworkResponse{Handle: &flow, Source: &source})
		_ = json.NewEncoder(w).Encode(pluginsdk.HostRuntimeResponse{Payload: payload})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	cookie := filepath.Join(directory, "cookie")
	if err := os.WriteFile(cookie, []byte("test-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(pluginsdk.EnvPluginHostEndpoint, "unix:"+endpoint)
	t.Setenv("NRE_PLUGIN_COOKIE_FILE", cookie)
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	response, err := managedAccept(ctx, func() (pluginsdk.ManagedNetworkResponse, error) {
		return client.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkAccept, Binding: binding, RequestID: managedRequestID("accept"), Handle: &handle, WaitMS: 1000})
	})
	if err != nil || response.Handle == nil || calls.Load() != 2 {
		t.Fatalf("accept after busy: calls=%d handle=%v err=%v", calls.Load(), response.Handle, err)
	}
}
