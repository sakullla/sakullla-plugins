package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	mu             sync.Mutex
	online         bool
	apply          []listenApplyRequest
	live           []ListenPortStatus
	applyErr       error
	node           NodeAddresses
	hideReportNode bool
}

func (h *uiListenHost) Call(_ context.Context, call pluginsdk.HostRuntimeCall, target any) error {
	if call.Operation == pluginNodeAddressesOp {
		h.mu.Lock()
		defer h.mu.Unlock()
		return copyHostResult(h.node, target)
	}
	request := decodePluginCallRequestFromCall(call)
	h.mu.Lock()
	defer h.mu.Unlock()
	switch request.Name {
	case pluginCallListenReport:
		report := ListenReport{AgentID: request.AgentID, Online: h.online, Listens: append([]ListenPortStatus(nil), h.live...)}
		if !h.hideReportNode {
			report.DDNS, report.IPv4, report.IPv6 = h.node.DDNS, h.node.IPv4, h.node.IPv6
		}
		return copyHostResult(report, target)
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
		h.live = append([]ListenPortStatus(nil), listens...)
		return copyHostResult(listenApplyResult{Accepted: true, AgentID: request.AgentID, Listens: listens}, target)
	case pluginCallListenStop:
		var body listenStopRequest
		_ = json.Unmarshal(request.Payload, &body)
		if len(body.ListenIDs) == 0 {
			h.live = nil
		} else {
			stopped := make(map[string]struct{}, len(body.ListenIDs))
			for _, id := range body.ListenIDs {
				stopped[id] = struct{}{}
			}
			kept := h.live[:0]
			for _, item := range h.live {
				if _, ok := stopped[item.ID]; !ok {
					kept = append(kept, item)
				}
			}
			h.live = kept
		}
		return copyHostResult(listenApplyResult{Accepted: true, AgentID: request.AgentID, Listens: append([]ListenPortStatus(nil), h.live...)}, target)
	default:
		return ErrTypedHandlesUnavailable
	}
}

func decodePluginCallRequestFromCall(call pluginsdk.HostRuntimeCall) pluginsdk.PluginCallRequest {
	var request pluginsdk.PluginCallRequest
	_ = json.Unmarshal(call.Payload, &request)
	return request
}

type uiTestSetup struct {
	host           *uiListenHost
	node           NodeAddresses
	state          ListenCatalogStore
	publishService bool
}

func newUITestController(t *testing.T, host *uiListenHost, node NodeAddresses) *Controller {
	t.Helper()
	return startUITestController(t, uiTestSetup{host: host, node: node, publishService: true})
}

func startUITestController(t *testing.T, setup uiTestSetup) *Controller {
	t.Helper()
	host := setup.host
	if host == nil {
		host = &uiListenHost{online: true, node: setup.node}
	}
	if host.node == (NodeAddresses{}) {
		host.node = setup.node
	}
	admission := TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
		return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
			return RuntimeAdapters{}, nil
		}}, nil
	})
	if setup.publishService {
		runtime := &testRuntime{now: 10, refs: map[string]string{}, replay: map[string]bool{}, accountVault: true}
		admission = TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
			return PreparedAdmissionFuncs{CommitFunc: func(context.Context) (RuntimeAdapters, error) {
				return adapters(runtime), nil
			}}, nil
		})
	}
	controller, err := NewController(ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		ListenRuntime: newHostCapabilityRuntime(host),
		ListenState:   setup.state,
		Admission:     admission,
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

type uiMemoryListenState struct {
	mu      sync.Mutex
	listens []ListenRule
	secrets map[string]string
	nodes   map[string]NodeAddresses
	found   bool
}

func (state *uiMemoryListenState) LoadListens(context.Context) ([]ListenRule, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return cloneListeners(state.listens), state.found, nil
}

func (state *uiMemoryListenState) StoreListens(_ context.Context, listeners []ListenRule) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.listens = cloneListeners(listeners)
	state.found = true
	return nil
}

func (state *uiMemoryListenState) LoadSecrets(context.Context) (map[string]string, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return cloneSecretMap(state.secrets), state.found, nil
}

func (state *uiMemoryListenState) StoreSecrets(_ context.Context, secrets map[string]string) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.secrets = cloneSecretMap(secrets)
	state.found = true
	return nil
}

func (state *uiMemoryListenState) LoadNodes(context.Context) (map[string]NodeAddresses, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return cloneAgentNodes(state.nodes), state.found, nil
}

func (state *uiMemoryListenState) StoreNodes(_ context.Context, nodes map[string]NodeAddresses) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.nodes = cloneAgentNodes(nodes)
	state.found = true
	return nil
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

func TestControlAPIShareURIPercentEncodesChineseName(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := newUITestController(t, host, NodeAddresses{DDNS: "ss.example.com"})
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","name":"手机"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	listen := decodeListenAPI(t, created).Listen
	if listen == nil || len(listen.Users) != 1 {
		t.Fatalf("listen=%#v", listen)
	}
	user := listen.Users[0]
	if user.Name != "手机" || !strings.HasSuffix(user.URI, "#%E6%89%8B%E6%9C%BA") || strings.Contains(user.URI, "手机") {
		t.Fatalf("chinese share=%#v", user)
	}
	if user.QRContent != user.URI {
		t.Fatalf("qr=%q uri=%q", user.QRContent, user.URI)
	}
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
	if !strings.HasPrefix(userA.HostPort, "ss.example.com:") || first.HostPort != userA.HostPort {
		t.Fatalf("host_port listen=%q user=%q", first.HostPort, userA.HostPort)
	}

	dup := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","port":`+strconv.Itoa(first.Port)+`}`)
	if dup.Code != http.StatusConflict || !strings.Contains(dup.Body.String(), duplicatePortText) {
		t.Fatalf("duplicate port=%d %s", dup.Code, dup.Body.String())
	}

	appended := uiJSON(t, controller, http.MethodPost, "/api/listens/"+first.ID+"/users", `{"agent_id":"agent-1","name":"手机"}`)
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
	if userB.Name != "手机" || !userB.ShareAvailable || userB.URI == "" || userB.QRContent != userB.URI || !strings.HasSuffix(userB.URI, "#%E6%89%8B%E6%9C%BA") || strings.Contains(userB.URI, "手机") {
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

func TestControlAPIShareAvailableWithoutPublishedService(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com", IPv4: "203.0.113.10"}}
	controller := startUITestController(t, uiTestSetup{host: host, node: host.node})
	if err := controller.Use(context.Background(), func(context.Context, *Service) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatalf("published Service still present: %v", err)
	}
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	view := decodeListenAPI(t, created).Listen
	if view == nil || len(view.Users) != 1 || !view.Users[0].ShareAvailable || view.Users[0].URI == "" || view.Users[0].QRContent != view.Users[0].URI || !strings.HasPrefix(view.Users[0].URI, "ss://") {
		t.Fatalf("share without published Service=%#v", view)
	}
	listed := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || !listed.Listens[0].Users[0].ShareAvailable || listed.Listens[0].Users[0].QRContent != listed.Listens[0].Users[0].URI {
		t.Fatalf("get share without published Service=%#v", listed.Listens)
	}
}

func TestControlAPIShareHostOverrideUpdatesURIs(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := newUITestController(t, host, host.node)
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	original := decodeListenAPI(t, created).Listen
	if original == nil || len(original.Users) != 1 || !strings.Contains(original.Users[0].URI, "ss.example.com") {
		t.Fatalf("created=%#v", original)
	}
	updated := uiJSON(t, controller, http.MethodPost, "/api/share-host", `{"agent_id":"agent-1","host":"share.example.com"}`)
	if updated.Code != http.StatusOK {
		t.Fatalf("share-host=%d %s", updated.Code, updated.Body.String())
	}
	payload := decodeListenAPI(t, updated)
	if payload.Execution == nil || payload.Execution.ShareHost != "share.example.com" || len(payload.Listens) != 1 {
		t.Fatalf("payload=%#v", payload)
	}
	if payload.Execution.ShareHostSource != "override" || payload.Execution.ShareHostAuto != "ss.example.com" {
		t.Fatalf("override source=%#v", payload.Execution)
	}
	if !strings.Contains(payload.Listens[0].Users[0].URI, "share.example.com") || strings.Contains(payload.Listens[0].Users[0].URI, "ss.example.com") {
		t.Fatalf("uri=%q", payload.Listens[0].Users[0].URI)
	}
	listed := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || !strings.Contains(listed.Listens[0].Users[0].URI, "share.example.com") {
		t.Fatalf("listed=%#v", listed.Listens)
	}
	bad := uiJSON(t, controller, http.MethodPost, "/api/share-host", `{"agent_id":"agent-1","host":"127.0.0.1"}`)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), shareHostText) {
		t.Fatalf("loopback=%d %s", bad.Code, bad.Body.String())
	}
	appended := uiJSON(t, controller, http.MethodPost, "/api/listens/"+original.ID+"/users", `{"agent_id":"agent-1","name":"bob"}`)
	if appended.Code != http.StatusOK {
		t.Fatalf("append=%d %s", appended.Code, appended.Body.String())
	}
	after := decodeListenAPI(t, appended).Listen
	if after == nil || len(after.Users) != 2 {
		t.Fatalf("append listen=%#v", after)
	}
	for _, user := range after.Users {
		if !strings.Contains(user.URI, "share.example.com") || strings.Contains(user.URI, "ss.example.com") {
			t.Fatalf("append overwrote share host=%#v", user)
		}
	}
}

func TestControlAPIShareUsesRequestCatalogIdentity(t *testing.T) {
	host := &uiListenHost{online: true}
	controller := startUITestController(t, uiTestSetup{host: host})
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","ddns_domain":"panel.example.com","ipv4":"203.0.113.20"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	view := decodeListenAPI(t, created).Listen
	if view == nil || len(view.Users) != 1 || !view.Users[0].ShareAvailable || !strings.Contains(view.Users[0].URI, "panel.example.com") || view.Users[0].QRContent != view.Users[0].URI {
		t.Fatalf("request catalog share=%#v", view)
	}
}

func TestControlAPIShareUsesCatalogNodeWhenReportOmitsIdentity(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "edge.example.com"}, hideReportNode: true}
	controller := startUITestController(t, uiTestSetup{host: host})
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	view := decodeListenAPI(t, created).Listen
	if view == nil || len(view.Users) != 1 || !view.Users[0].ShareAvailable || !strings.Contains(view.Users[0].URI, "edge.example.com") || view.Users[0].QRContent != view.Users[0].URI {
		t.Fatalf("catalog share=%#v", view)
	}
}

func TestControlAPIShareFollowsCatalogUntilOverride(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "first.example.com"}}
	controller := newUITestController(t, host, host.node)
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	first := decodeListenAPI(t, created)
	if first.Listen == nil || !strings.Contains(first.Listen.Users[0].URI, "first.example.com") {
		t.Fatalf("created=%#v", first.Listen)
	}
	execution := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/execution?agent_id=agent-1", ""))
	if execution.Execution == nil || execution.Execution.ShareHost != "first.example.com" || execution.Execution.ShareHostSource != ShareHostSourceDDNS {
		t.Fatalf("auto execution=%#v", execution.Execution)
	}

	host.mu.Lock()
	host.node = NodeAddresses{DDNS: "second.example.com"}
	host.mu.Unlock()
	listed := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || !strings.Contains(listed.Listens[0].Users[0].URI, "second.example.com") || strings.Contains(listed.Listens[0].Users[0].URI, "first.example.com") {
		t.Fatalf("catalog follow=%#v", listed.Listens)
	}

	overridden := uiJSON(t, controller, http.MethodPost, "/api/share-host", `{"agent_id":"agent-1","host":"fixed.example.com"}`)
	if overridden.Code != http.StatusOK {
		t.Fatalf("override=%d %s", overridden.Code, overridden.Body.String())
	}
	host.mu.Lock()
	host.node = NodeAddresses{DDNS: "third.example.com"}
	host.mu.Unlock()
	frozen := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(frozen.Listens) != 1 || !strings.Contains(frozen.Listens[0].Users[0].URI, "fixed.example.com") || strings.Contains(frozen.Listens[0].Users[0].URI, "third.example.com") {
		t.Fatalf("override froze=%#v", frozen.Listens)
	}

	restored := uiJSON(t, controller, http.MethodPost, "/api/share-host", `{"agent_id":"agent-1","host":""}`)
	if restored.Code != http.StatusOK {
		t.Fatalf("restore=%d %s", restored.Code, restored.Body.String())
	}
	payload := decodeListenAPI(t, restored)
	if payload.Execution == nil || payload.Execution.ShareHost != "third.example.com" || payload.Execution.ShareHostSource != ShareHostSourceDDNS {
		t.Fatalf("restored execution=%#v", payload.Execution)
	}
	if len(payload.Listens) != 1 || !strings.Contains(payload.Listens[0].Users[0].URI, "third.example.com") {
		t.Fatalf("restored uri=%#v", payload.Listens)
	}
}

func TestControlAPIRestoresPersistedListensAfterRestart(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{}
	first := startUITestController(t, uiTestSetup{host: host, node: host.node, state: state})
	created := uiJSON(t, first, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	original := decodeListenAPI(t, created).Listen
	if original == nil || original.ID == "" || len(original.Users) != 1 || !original.Users[0].ShareAvailable {
		t.Fatalf("created=%#v", original)
	}
	if !state.found || len(state.listens) != 1 || len(state.secrets) == 0 {
		t.Fatalf("persist listens=%#v secrets=%d", state.listens, len(state.secrets))
	}
	host.mu.Lock()
	applyBefore := len(host.apply)
	host.mu.Unlock()

	restarted := startUITestController(t, uiTestSetup{host: host, node: host.node, state: state})
	listed := decodeListenAPI(t, uiJSON(t, restarted, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || listed.Listens[0].ID != original.ID || listed.Listens[0].Port != original.Port || !listed.Listens[0].Bound || len(listed.Listens[0].Users) != 1 {
		t.Fatalf("restored list=%#v", listed.Listens)
	}
	user := listed.Listens[0].Users[0]
	if !user.ShareAvailable || user.URI == "" || user.QRContent != user.URI || user.URI != original.Users[0].URI {
		t.Fatalf("restored share=%#v want %q", user, original.Users[0].URI)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.apply) != applyBefore {
		t.Fatalf("live restart reapplied %d times", len(host.apply)-applyBefore)
	}
}

func TestControlAPIReappliesPersistedListensAfterAgentUpgrade(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{}
	first := startUITestController(t, uiTestSetup{host: host, node: host.node, state: state})
	created := decodeListenAPI(t, uiJSON(t, first, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)).Listen
	if created == nil || !created.Bound {
		t.Fatalf("created=%#v", created)
	}

	host.mu.Lock()
	host.live = nil
	applyBefore := len(host.apply)
	host.mu.Unlock()

	restarted := startUITestController(t, uiTestSetup{host: host, node: host.node, state: state})
	listed := decodeListenAPI(t, uiJSON(t, restarted, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || listed.Listens[0].ID != created.ID || !listed.Listens[0].Bound {
		t.Fatalf("reapplied list=%#v", listed.Listens)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.apply) != applyBefore+1 {
		t.Fatalf("upgrade reconcile applies=%d want=%d", len(host.apply), applyBefore+1)
	}
}

func TestControlAPIRestoresShareFromPersistedCatalogNode(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "catalog.example.com"}}
	state := &uiMemoryListenState{}
	first := startUITestController(t, uiTestSetup{host: host, state: state})
	created := uiJSON(t, first, http.MethodPost, "/api/listens", `{"agent_id":"agent-1"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	saved := uiJSON(t, first, http.MethodPost, "/api/share-host", `{"agent_id":"agent-1","host":"persist.example.com"}`)
	if saved.Code != http.StatusOK {
		t.Fatalf("share-host=%d %s", saved.Code, saved.Body.String())
	}
	original := decodeListenAPI(t, saved)
	if len(original.Listens) != 1 || !strings.Contains(original.Listens[0].Users[0].URI, "persist.example.com") {
		t.Fatalf("saved=%#v", original.Listens)
	}
	host.node = NodeAddresses{DDNS: "other.example.com"}
	restarted := startUITestController(t, uiTestSetup{host: host, state: state})
	listed := decodeListenAPI(t, uiJSON(t, restarted, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || len(listed.Listens[0].Users) != 1 {
		t.Fatalf("restored list=%#v", listed.Listens)
	}
	user := listed.Listens[0].Users[0]
	if !user.ShareAvailable || !strings.Contains(user.URI, "persist.example.com") || strings.Contains(user.URI, "other.example.com") || user.QRContent != user.URI {
		t.Fatalf("restored override share=%#v", user)
	}
}
