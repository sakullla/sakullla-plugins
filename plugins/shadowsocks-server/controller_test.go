package shadowsocksserver

import (
	"context"
	"encoding/json"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestListenControllerCreateTwoSS2022MethodsDoesNotPoisonFirstResolve(t *testing.T) {
	runtime := &testRuntime{now: 10, used: map[string]uint64{}, refs: map[string]string{}, replay: map[string]bool{}, accountVault: true}
	controller, err := NewController(ControllerConfig{
		PackageDigest:  "package",
		ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return adapters(runtime), nil
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Configuration{
		Generation: "generation-1",
		Listeners: []ListenRule{
			{ID: "a-ss2022-128", AgentID: "agent-1", Port: 8488, Method: DefaultSS2022Method},
			{ID: "b-ss2022-256", AgentID: "agent-1", Port: 8588, Method: "2022-blake3-aes-256-gcm"},
		},
	}
	wire, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{"audit", "listener", "monotonic-clock", "replay", "secret", "traffic"}
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: grants, Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}

	user128, secret128, err := controller.CreateAccount(context.Background(), AccountSpec{ID: "ss2022-128", Method: DefaultSS2022Method})
	if err != nil {
		t.Fatal(err)
	}
	pass128 := secret128.RevealOnce()
	server128, _, ok := splitSS2022ClientPassword(pass128)
	if !ok {
		t.Fatalf("128 password=%q", pass128)
	}

	user256, secret256, err := controller.CreateAccount(context.Background(), AccountSpec{ID: "ss2022-256", Method: "2022-blake3-aes-256-gcm"})
	if err != nil {
		t.Fatal(err)
	}
	pass256 := secret256.RevealOnce()
	server256, _, ok := splitSS2022ClientPassword(pass256)
	if !ok {
		t.Fatalf("256 password=%q", pass256)
	}
	if string(server128) == string(server256) {
		t.Fatalf("ss2022 methods shared server psk: 128=%q 256=%q", server128, server256)
	}

	var listen128, listen256 ListenRule
	var got128, got256 []byte
	err = controller.Use(context.Background(), func(ctx context.Context, s *Service) error {
		snapshot := s.Snapshot()
		var found bool
		listen128, _, found = snapshot.userListener(user128.ID)
		if !found {
			return ErrInvalid
		}
		listen256, _, found = snapshot.userListener(user256.ID)
		if !found {
			return ErrInvalid
		}
		var resolveErr error
		got128, resolveErr = s.runtime.Secrets.Resolve(ctx, listen128.ServerSecretRef, listen128.ServerSecretVersion)
		if resolveErr != nil {
			return resolveErr
		}
		got256, resolveErr = s.runtime.Secrets.Resolve(ctx, listen256.ServerSecretRef, listen256.ServerSecretVersion)
		return resolveErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if listen128.ServerSecretRef == "" || listen128.ServerSecretVersion == "" {
		t.Fatalf("128-gcm server psk missing: %+v", listen128)
	}
	if listen256.ServerSecretRef == "" || listen256.ServerSecretVersion == "" {
		t.Fatalf("256-gcm server psk missing: %+v", listen256)
	}
	if listen256.ServerSecretRef == listen128.ServerSecretRef || listen256.ServerSecretVersion == listen128.ServerSecretVersion {
		t.Fatalf("ss2022 methods shared server secret: 128=%s/%s 256=%s/%s", listen128.ServerSecretRef, listen128.ServerSecretVersion, listen256.ServerSecretRef, listen256.ServerSecretVersion)
	}
	if string(got128) != string(server128) {
		t.Fatalf("first listen Resolve poisoned: got %q want %q (second=%q)", got128, server128, server256)
	}
	if string(got256) != string(server256) {
		t.Fatalf("second listen Resolve=%q want %q", got256, server256)
	}
}
