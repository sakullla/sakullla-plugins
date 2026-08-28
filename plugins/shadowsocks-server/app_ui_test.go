package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type uiListenHost struct {
	mu       sync.Mutex
	online   bool
	apply    []listenApplyRequest
	applyErr error
	node     NodeAddresses
}

func (h *uiListenHost) Call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	request := decodePluginCallRequestFromCall(call)
	h.mu.Lock()
	defer h.mu.Unlock()
	switch request.Name {
	case pluginCallListenReport:
		if !h.online {
			return copyHostResult(ListenReport{AgentID: request.AgentID, Online: false, DDNS: h.node.DDNS, IPv4: h.node.IPv4, IPv6: h.node.IPv6}, target)
		}
		return copyHostResult(ListenReport{AgentID: request.AgentID, Online: true, DDNS: h.node.DDNS, IPv4: h.node.IPv4, IPv6: h.node.IPv6}, target)
	case pluginCallListenApply:
		if h.applyErr != nil {
			return h.applyErr
		}
		var body listenApplyRequest
		_ = json.Unmarshal(request.Payload, &body)
		h.apply = append(h.apply, body)
		listens := make([]ListenPortStatus, 0, len(body.Listens))
		for _, item := range body.Listens {
			listens = append(listens, ListenPortStatus{ID: item.ID, Port: item.Port, TCP: true, UDP: true})
		}
		return copyHostResult(listenApplyResult{Accepted: true, AgentID: request.AgentID, Listens: listens}, target)
	case pluginCallListenStop:
		return copyHostResult(listenApplyResult{Accepted: true, AgentID: request.AgentID}, target)
	default:
		return ErrTypedHandlesUnavailable
	}
}

func decodePluginCallRequestFromCall(call pluginsdk.HostRuntimeCall) pluginsdk.PluginCallRequest {
	var request pluginsdk.PluginCallRequest
	_ = json.Unmarshal(call.Payload, &request)
	return request
}

func newUITestController(t *testing.T, host *uiListenHost, node NodeAddresses) *Controller {
	t.Helper()
	if host == nil {
		host = &uiListenHost{online: true, node: node}
	}
	if host.node == (NodeAddresses{}) {
		host.node = node
	}
	runtime := &testRuntime{now: 10, refs: map[string]string{}, replay: map[string]bool{}, accountVault: true}
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ListenRuntime: newHostCapabilityRuntime(host),
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return adapters(runtime), nil
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(Configuration{Generation: "generation-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	return controller
}

func uiJSON(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set(pluginsdk.HeaderPluginActor, "panel/admin")
	request.Header.Set(pluginsdk.HeaderPluginOperationKey, "operation/ui-test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeListenAPI(t *testing.T, recorder *httptest.ResponseRecorder) listenAPIResponse {
	t.Helper()
	var payload listenAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json=%s err=%v", recorder.Body.String(), err)
	}
	return payload
}

func TestControlAPIDefaultCreateAppendDisableDelete(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := newUITestController(t, host, NodeAddresses{DDNS: "ss.example.com"})

	denied := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"method":"2022-blake3-aes-128-gcm"}`)
	if denied.Code != http.StatusConflict {
		t.Fatalf("unselected create=%d %s", denied.Code, denied.Body.String())
	}

	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("default create=%d %s", created.Code, created.Body.String())
	}
	first := decodeListenAPI(t, created).Listen
	if first == nil || first.Method != DefaultSS2022Method || first.Port < 1 || len(first.Users) != 1 {
		t.Fatalf("default listen=%#v", first)
	}
	userA := first.Users[0]
	if !userA.ShareAvailable || userA.URI == "" || userA.QRContent != userA.URI || !strings.HasPrefix(userA.URI, "ss://") || strings.Contains(userA.URI, "ss2022://") || strings.Contains(userA.URI, "plugin=") {
		t.Fatalf("share=%#v", userA)
	}

	dup := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","port":`+strconv.Itoa(first.Port)+`}`)
	if dup.Code != http.StatusConflict || !strings.Contains(dup.Body.String(), duplicatePortText) {
		t.Fatalf("duplicate port=%d %s", dup.Code, dup.Body.String())
	}

	appended := uiJSON(t, controller, http.MethodPost, "/api/listens/"+first.ID+"/users", `{"agent_id":"agent-1"}`)
	if appended.Code != http.StatusOK {
		t.Fatalf("append=%d %s", appended.Code, appended.Body.String())
	}
	two := decodeListenAPI(t, appended).Listen
	if two == nil || len(two.Users) != 2 {
		t.Fatalf("append listen=%#v", two)
	}
	userB := two.Users[0]
	if userB.ID == userA.ID {
		userB = two.Users[1]
	}
	if !userB.ShareAvailable || userB.URI == "" || userB.QRContent != userB.URI {
		t.Fatalf("user B share=%#v", userB)
	}

	disabled := uiJSON(t, controller, http.MethodPost, "/api/users/"+userA.ID+"/disable", `{"agent_id":"agent-1"}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", disabled.Code, disabled.Body.String())
	}
	listed := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || len(listed.Listens[0].Users) != 2 {
		t.Fatalf("after disable=%#v", listed.Listens)
	}
	var disabledView, enabledView listenUserView
	for _, user := range listed.Listens[0].Users {
		if user.ID == userA.ID {
			disabledView = user
			continue
		}
		enabledView = user
	}
	if disabledView.Enabled || disabledView.ShareAvailable || disabledView.URI != "" {
		t.Fatalf("disabled=%#v", disabledView)
	}
	if !enabledView.Enabled || !enabledView.ShareAvailable || enabledView.URI == "" || enabledView.QRContent != enabledView.URI {
		t.Fatalf("enabled peer=%#v", enabledView)
	}

	pngB64 := enabledView.QRPNGBase64
	pngBytes, err := base64.StdEncoding.DecodeString(pngB64)
	if err != nil || len(pngBytes) == 0 {
		t.Fatalf("qr png=%v", err)
	}
	if _, err = png.Decode(bytes.NewReader(pngBytes)); err != nil {
		t.Fatalf("qr decode=%v", err)
	}

	deletedUser := uiJSON(t, controller, http.MethodPost, "/api/users/"+userA.ID+"/delete", `{"agent_id":"agent-1"}`)
	if deletedUser.Code != http.StatusOK {
		t.Fatalf("delete user=%d %s", deletedUser.Code, deletedUser.Body.String())
	}
	afterDeleteUser := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(afterDeleteUser.Listens) != 1 || len(afterDeleteUser.Listens[0].Users) != 1 || afterDeleteUser.Listens[0].Users[0].ID == userA.ID {
		t.Fatalf("after delete user=%#v", afterDeleteUser.Listens)
	}

	deletedListen := uiJSON(t, controller, http.MethodPost, "/api/listens/"+first.ID+"/delete", `{"agent_id":"agent-1"}`)
	if deletedListen.Code != http.StatusOK {
		t.Fatalf("delete listen=%d %s", deletedListen.Code, deletedListen.Body.String())
	}
	empty := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(empty.Listens) != 0 {
		t.Fatalf("after delete listen=%#v", empty.Listens)
	}
	host.mu.Lock()
	if len(host.apply) == 0 {
		host.mu.Unlock()
		t.Fatal("create/update did not call listen.apply")
	}
	last := host.apply[len(host.apply)-1]
	host.mu.Unlock()
	if last.AgentID != "agent-1" {
		t.Fatalf("apply agent=%#v", last)
	}
}

func TestControlAPIRejectsOfflineAndTraditionalSecondUser(t *testing.T) {
	host := &uiListenHost{online: false, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := newUITestController(t, host, NodeAddresses{DDNS: "ss.example.com"})
	offline := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if offline.Code != http.StatusConflict || !strings.Contains(offline.Body.String(), offlineText) {
		t.Fatalf("offline create=%d %s", offline.Code, offline.Body.String())
	}

	host.mu.Lock()
	host.online = true
	host.mu.Unlock()
	legacy := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm"}`)
	if legacy.Code != http.StatusOK {
		t.Fatalf("legacy create=%d %s", legacy.Code, legacy.Body.String())
	}
	listen := decodeListenAPI(t, legacy).Listen
	second := uiJSON(t, controller, http.MethodPost, "/api/listens/"+listen.ID+"/users", `{"agent_id":"agent-1"}`)
	if second.Code != http.StatusBadRequest || !strings.Contains(second.Body.String(), ErrTraditionalMultiUser.Error()) {
		t.Fatalf("traditional second user=%d %s", second.Code, second.Body.String())
	}
}

func TestControlAPICreateApplyBindsAndHandshakes(t *testing.T) {
	t.Parallel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	got := make(chan []byte, 1)
	go echoTCPHandshake(target, got)

	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return RuntimeAdapters{}, nil
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller.BindLoopbackListenHost()
	t.Cleanup(func() {
		if controller.listenExec != nil {
			controller.listenExec.stopAll()
		}
	})
	if _, err = controller.Handshake(context.Background(), pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1",
	}); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(Configuration{Generation: "generation-1"})
	if err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); result.Error != nil {
		t.Fatal(result.Error)
	}

	port := freeTCPUDPPort(t)
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","port":`+strconv.Itoa(port)+`}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	view := decodeListenAPI(t, created).Listen
	if view == nil || !view.Bound || len(view.Users) != 1 {
		t.Fatalf("created=%#v", view)
	}
	items, err := controller.listenApplyItems(context.Background(), "agent-1")
	if err != nil || len(items) != 1 || len(items[0].Users) != 1 {
		t.Fatalf("apply items=%#v err=%v", items, err)
	}
	client, err := engineFromMaterial(view.Method, []byte(items[0].Users[0].Password), items[0].ServerPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	completeTCPHandshake(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), target.Addr().String(), got)
}
