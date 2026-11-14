package shadowsocksserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	routingDigest  string
	routes         []RouteStatus
	tests          []upstreamTestRequest
	testResult     upstreamTestResult
	testErr        error
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
		report := ListenReport{AgentID: request.AgentID, Online: h.online, Listens: append([]ListenPortStatus(nil), h.live...), RoutingDigest: h.routingDigest, Routes: append([]RouteStatus(nil), h.routes...)}
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
		h.routingDigest = routingDigest(body.Routing)
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
	case pluginCallUpstreamTest:
		var body upstreamTestRequest
		_ = json.Unmarshal(request.Payload, &body)
		h.tests = append(h.tests, body)
		if h.testErr != nil {
			return h.testErr
		}
		result := h.testResult
		if result.AgentID == "" {
			result.AgentID = request.AgentID
		}
		if result.UpstreamID == "" {
			result.UpstreamID = body.Upstream.ID
		}
		return copyHostResult(result, target)
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
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1", RequiredFeatures: supportedFeatures(),
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
	mu           sync.Mutex
	listens      []ListenRule
	secrets      map[string]string
	nodes        map[string]NodeAddresses
	found        bool
	routing      RoutingConfiguration
	routingFound bool
	sources      []remoteSourceRecord
	sourcesFound bool
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

func (state *uiMemoryListenState) LoadRouting(context.Context) (RoutingConfiguration, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return cloneRouting(state.routing), state.routingFound, nil
}

func (state *uiMemoryListenState) StoreRouting(_ context.Context, routing RoutingConfiguration) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.routing = cloneRouting(routing)
	state.routingFound = true
	return nil
}

func (state *uiMemoryListenState) LoadRemoteSources(context.Context) ([]remoteSourceRecord, bool, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return append([]remoteSourceRecord(nil), state.sources...), state.sourcesFound, nil
}

func (state *uiMemoryListenState) StoreRemoteSources(_ context.Context, records []remoteSourceRecord) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.sources = append([]remoteSourceRecord(nil), records...)
	state.sourcesFound = true
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
	if two == nil || len(two.Users) != 2 || two.Users[0].ID != userA.ID {
		t.Fatalf("append listen=%#v", two)
	}
	userB := two.Users[1]
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

func TestControlAPIListenProjectionKeepsCreatorFirst(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := newUITestController(t, host, NodeAddresses{DDNS: "ss.example.com"})
	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","name":"alice"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	first := decodeListenAPI(t, created).Listen
	if first == nil || len(first.Users) != 1 || first.Users[0].Name != "alice" {
		t.Fatalf("create listen=%#v", first)
	}
	appended := uiJSON(t, controller, http.MethodPost, "/api/listens/"+first.ID+"/users", `{"agent_id":"agent-1","name":"bob"}`)
	if appended.Code != http.StatusOK {
		t.Fatalf("append=%d %s", appended.Code, appended.Body.String())
	}
	two := decodeListenAPI(t, appended).Listen
	if two == nil || len(two.Users) != 2 || two.Users[0].Name != "alice" || two.Users[1].Name != "bob" {
		t.Fatalf("append title source drifted: %#v", two)
	}
	listed := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(listed.Listens) != 1 || len(listed.Listens[0].Users) != 2 || listed.Listens[0].Users[0].Name != "alice" || listed.Listens[0].Users[1].Name != "bob" {
		t.Fatalf("list title source drifted: %#v", listed.Listens)
	}
	deleted := uiJSON(t, controller, http.MethodPost, "/api/users/"+first.Users[0].ID+"/delete", `{"agent_id":"agent-1"}`)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete creator=%d %s", deleted.Code, deleted.Body.String())
	}
	afterDelete := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/listens?agent_id=agent-1", ""))
	if len(afterDelete.Listens) != 1 || len(afterDelete.Listens[0].Users) != 1 || afterDelete.Listens[0].Users[0].Name != "bob" {
		t.Fatalf("after deleting creator: %#v", afterDelete.Listens)
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
		PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1", RequiredFeatures: supportedFeatures(),
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
	userMaterial, ok := controller.secrets().lookup(items[0].Users[0].SecretRef, items[0].Users[0].SecretVersion)
	if !ok {
		t.Fatal("user scoped reference did not resolve")
	}
	serverMaterial := ""
	if items[0].ServerSecretRef != "" {
		serverMaterial, ok = controller.secrets().lookup(items[0].ServerSecretRef, items[0].ServerSecretVersion)
		if !ok {
			t.Fatal("server scoped reference did not resolve")
		}
	}
	client, err := engineFromMaterial(view.Method, []byte(userMaterial), serverMaterial)
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

// TestUpstreamSIP002ImportCreatesEquivalentUpstream covers the dialog flow's
// server-visible half: ParseSIP002 yields the fields the paste box prefills,
// and posting them through the normal create endpoint yields that upstream.
// A URI that fails parsing never reaches the endpoint, so nothing is created.
func TestUpstreamSIP002ImportCreatesEquivalentUpstream(t *testing.T) {
	managed := newHostCapabilityRuntime(&managedRuntimeFake{})
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	state := &uiMemoryListenState{}
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", InstanceID: "instance-a", ManagedRuntime: managed, ListenRuntime: newHostCapabilityRuntime(host), ListenState: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Handshake(t.Context(), pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: requiredGrants(), Generation: "generation-1", RequiredFeatures: supportedFeatures()}); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(Configuration{Generation: "generation-1"})
	if response := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: wire}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}

	uri := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:imported-secret@203.0.113.55:8488")) + "#relay"
	method, password, parsedHost, port, err := ParseSIP002(uri)
	if err != nil {
		t.Fatalf("ParseSIP002 err=%v", err)
	}
	body := fmt.Sprintf(`{"id":"imported","host":%q,"port":%d,"method":%q,"password":%q,"tcp":true,"udp":true}`, parsedHost, port, method, password)
	created := uiJSON(t, controller, http.MethodPost, "/api/upstreams", body)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	if bytes.Contains(created.Body.Bytes(), []byte("imported-secret")) {
		t.Fatalf("create response echoed the upstream password: %s", created.Body.String())
	}
	payload := decodeListenAPI(t, created)
	if payload.Routing == nil || len(payload.Routing.Upstreams) != 1 {
		t.Fatalf("routing=%#v", payload.Routing)
	}
	upstream := payload.Routing.Upstreams[0]
	if upstream.ID != "imported" || upstream.Host != "203.0.113.55" || upstream.Port != 8488 || upstream.Method != "aes-256-gcm" || !upstream.TCP || !upstream.UDP || !upstream.Enabled {
		t.Fatalf("upstream=%+v", upstream)
	}
	if _, _, _, _, err := ParseSIP002("ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:imported-secret@203.0.113.55"))); err == nil {
		t.Fatal("incomplete ss:// URI parsed; the dialog must refuse it before create")
	}
}

// TestUpstreamDialogSIP002ImportWiring asserts the create-upstream dialog
// keeps the paste field, the in-dialog hint, and the client-side parser that
// prefills without persisting anything.
func TestUpstreamDialogSIP002ImportWiring(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("assets", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("assets", "ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(page)
	source := string(script)
	dialogStart := strings.Index(markup, `id="upstream-dialog"`)
	if dialogStart < 0 {
		t.Fatal("upstream dialog missing from index.html")
	}
	dialog := markup[dialogStart:]
	for _, want := range []string{`id="upstream-import"`, `id="upstream-import-hint"`, "ss://"} {
		if !strings.Contains(dialog, want) {
			t.Fatalf("upstream dialog missing %q", want)
		}
	}
	for _, want := range []string{
		"parseSIP002URI",
		"applySIP002Paste",
		"fillUpstreamFromSIP002",
		`params.has("plugin")`,
		"METHOD_LABELS",
		`upstreamImportInput.addEventListener("change"`,
		"markFieldError(upstreamImportInput",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}
	if !strings.Contains(source, "method: parsed.method") || !strings.Contains(source, "password: parsed.password") {
		t.Fatal("prefill must cover method/password alongside host/port")
	}
}

// upstreamTestFixture mirrors routingRefreshFixture: the control plane needs
// the managed runtime to mint opaque upstream references.
func upstreamTestFixture(t *testing.T, host *uiListenHost) *Controller {
	t.Helper()
	if host == nil {
		host = &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	}
	managed := newHostCapabilityRuntime(&managedRuntimeFake{})
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
	return controller
}

func TestControlAPIUpstreamTestRoutesProbeWithoutSecrets(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := upstreamTestFixture(t, host)
	created := uiJSON(t, controller, http.MethodPost, "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-secret-material","tcp":true,"udp":true}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	upstream := decodeListenAPI(t, created).Routing.Upstreams[0]
	if upstream.SecretRef == "" || strings.Contains(upstream.SecretRef, "edge-secret-material") {
		t.Fatalf("upstream=%+v", upstream)
	}
	host.mu.Lock()
	host.testResult = upstreamTestResult{Reachable: true, RTTMillis: 12}
	host.mu.Unlock()

	response := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{"agent_id":"agent-1"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("test=%d %s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("edge-secret-material")) {
		t.Fatalf("test response echoed secret material: %s", response.Body.String())
	}
	payload := decodeListenAPI(t, response)
	if payload.Test == nil || !payload.Test.Reachable || payload.Test.RTTMillis != 12 || payload.Test.AgentID != "agent-1" || payload.Test.UpstreamID != "edge" || payload.Test.Failure != "" {
		t.Fatalf("test=%+v", payload.Test)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.tests) != 1 {
		t.Fatalf("probe calls=%d", len(host.tests))
	}
	sent, err := json.Marshal(host.tests[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sent, []byte("edge-secret-material")) || !bytes.Contains(sent, []byte(upstream.SecretRef)) {
		t.Fatalf("probe request=%s", sent)
	}
	if host.tests[0].Upstream.ID != "edge" || !host.tests[0].Upstream.Enabled {
		t.Fatalf("probe upstream=%+v", host.tests[0].Upstream)
	}
}

func TestControlAPIUpstreamTestClassifiesOfflineAndStaysReadOnly(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := upstreamTestFixture(t, host)
	created := uiJSON(t, controller, http.MethodPost, "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"edge-secret-material","tcp":true,"udp":true}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	host.mu.Lock()
	host.testErr = ErrAgentOffline
	host.mu.Unlock()
	offline := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{"agent_id":"agent-1"}`)
	if offline.Code != http.StatusOK {
		t.Fatalf("offline=%d %s", offline.Code, offline.Body.String())
	}
	payload := decodeListenAPI(t, offline)
	if payload.Test == nil || payload.Test.Reachable || payload.Test.Failure != "agent-offline" {
		t.Fatalf("offline test=%+v", payload.Test)
	}
	host.mu.Lock()
	host.testErr = errors.New("plugin.call transport lost")
	host.mu.Unlock()
	failed := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{"agent_id":"agent-1"}`)
	payload = decodeListenAPI(t, failed)
	if payload.Test == nil || payload.Test.Failure != "probe-failed" {
		t.Fatalf("call failure test=%+v", payload.Test)
	}
	host.mu.Lock()
	host.testErr = nil
	host.testResult = upstreamTestResult{Reachable: true, RTTMillis: 4}
	host.mu.Unlock()
	// A disabled upstream stays testable and the probe does not re-enable it.
	if disabled := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/disable", `{}`); disabled.Code != http.StatusOK {
		t.Fatalf("disable=%d %s", disabled.Code, disabled.Body.String())
	}
	retested := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{"agent_id":"agent-1"}`)
	payload = decodeListenAPI(t, retested)
	if payload.Test == nil || !payload.Test.Reachable {
		t.Fatalf("disabled test=%+v", payload.Test)
	}
	get := decodeListenAPI(t, uiJSON(t, controller, http.MethodGet, "/api/routing", ""))
	if get.Routing == nil || len(get.Routing.Upstreams) != 1 || get.Routing.Upstreams[0].Enabled {
		t.Fatalf("test mutated routing=%+v", get.Routing)
	}
	host.mu.Lock()
	probes := len(host.tests)
	host.mu.Unlock()
	if probes != 3 {
		t.Fatalf("probe calls=%d", probes)
	}
	for _, rejected := range []*httptest.ResponseRecorder{
		uiJSON(t, controller, http.MethodGet, "/api/upstreams/edge/test", ""),
		uiJSON(t, controller, http.MethodPost, "/api/upstreams/ghost/test", `{"agent_id":"agent-1"}`),
		uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{}`),
		uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test", `{"agent_id":`),
	} {
		if rejected.Code == http.StatusOK {
			t.Fatalf("rejected request returned 200: %s", rejected.Body.String())
		}
	}
	// The query-parameter fallback carries the same target node.
	query := uiJSON(t, controller, http.MethodPost, "/api/upstreams/edge/test?agent_id=agent-2", "")
	payload = decodeListenAPI(t, query)
	if payload.Test == nil || payload.Test.AgentID != "agent-2" {
		t.Fatalf("query fallback=%+v", payload.Test)
	}
}

// TestDetailPanelBatchUserOpsWiring asserts the account list keeps the
// multi-select controls and that batch operations loop the existing per-user
// endpoints with a per-account summary — there is no bulk aggregate backend
// route (R8/R10).
func TestDetailPanelBatchUserOpsWiring(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("assets", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("assets", "ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	markup := string(page)
	source := string(script)
	detailStart := strings.Index(markup, `id="listen-detail"`)
	if detailStart < 0 {
		t.Fatal("listen detail dialog missing from index.html")
	}
	detail := markup[detailStart:]
	for _, want := range []string{
		`id="detail-batch"`,
		`id="detail-select-all"`,
		`id="detail-batch-count"`,
		`id="detail-batch-enable"`,
		`id="detail-batch-disable"`,
		`id="detail-batch-delete"`,
		"全选",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail dialog missing batch control %q", want)
		}
	}
	batch := jsConstFunction(source, "batchMutateUsers")
	if batch == "" {
		t.Fatal("batchMutateUsers is missing")
	}
	for _, want := range []string{
		"for (const user of targets)",
		"api/users/${encodeURIComponent(user.id)}/${action}",
		"sendPluginJSON",
		"selectedUserIDs",
		"askConfirm",
		"reportBatchResult",
	} {
		if !strings.Contains(batch, want) {
			t.Fatalf("batchMutateUsers missing %q", want)
		}
	}
	// Batch stays on the per-account primitives: no aggregate or bulk route.
	for _, banned := range []string{"api/users/batch", "api/batch", "api/users\",", `"api/users"`} {
		if strings.Contains(batch, banned) {
			t.Fatalf("batchMutateUsers calls an aggregate endpoint %q", banned)
		}
	}
	summary := jsConstFunction(source, "reportBatchResult")
	if summary == "" || !strings.Contains(summary, "个失败") {
		t.Fatal("reportBatchResult does not summarize per-account failures")
	}
	render := jsConstFunction(source, "renderUser")
	if !strings.Contains(render, "selectedUserIDs") || !strings.Contains(render, `type = "checkbox"`) {
		t.Fatal("renderUser does not render the per-account selection checkbox")
	}
	for _, want := range []string{"detailSelectAll", "syncBatchActions", "account-select", "已选"} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}
}

// TestControlAPIBoundariesNoAggregateSubscriptionOrSecretEcho enforces the
// R9/R10 static guards: no public multi-account aggregate endpoint in the
// route table or backend offers, no subscription/share-aggregate UI surface,
// no SIP003 plugin= field in share URIs, and no secret material echoed in
// API responses.
func TestControlAPIBoundariesNoAggregateSubscriptionOrSecretEcho(t *testing.T) {
	host := &uiListenHost{online: true, node: NodeAddresses{DDNS: "ss.example.com"}}
	controller := upstreamTestFixture(t, host)

	created := uiJSON(t, controller, http.MethodPost, "/api/listens", `{"agent_id":"agent-1","method":"aes-256-gcm","password":"listen-secret-material"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	if bytes.Contains(created.Body.Bytes(), []byte("listen-secret-material")) {
		t.Fatalf("create response echoed the account secret: %s", created.Body.String())
	}
	listen := decodeListenAPI(t, created).Listen
	if listen == nil || len(listen.Users) != 1 {
		t.Fatalf("listen=%#v", listen)
	}
	user := listen.Users[0]
	for _, banned := range []string{"plugin=", "plugin%3D", "ss2022://"} {
		if strings.Contains(user.URI, banned) || strings.Contains(user.QRContent, banned) {
			t.Fatalf("share URI carries a forbidden field %q: %q", banned, user.URI)
		}
	}
	upstream := uiJSON(t, controller, http.MethodPost, "/api/upstreams", `{"id":"edge","host":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"upstream-secret-material","tcp":true,"udp":true}`)
	if upstream.Code != http.StatusOK {
		t.Fatalf("upstream create=%d %s", upstream.Code, upstream.Body.String())
	}
	if bytes.Contains(upstream.Body.Bytes(), []byte("upstream-secret-material")) {
		t.Fatalf("upstream create response echoed the secret: %s", upstream.Body.String())
	}

	// Read surfaces never echo raw secret material.
	for _, path := range []string{
		"/api/listens?agent_id=agent-1",
		"/api/routing",
		"/api/routing/export",
		"/api/execution?agent_id=agent-1",
		"/api/defaults?agent_id=agent-1",
		"/api/users/" + user.ID,
	} {
		response := uiJSON(t, controller, http.MethodGet, path, "")
		for _, secret := range []string{"listen-secret-material", "upstream-secret-material"} {
			if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
				t.Fatalf("%s echoed secret material: %s", path, response.Body.String())
			}
		}
	}

	// No public multi-account aggregate endpoint: collection-shaped and
	// subscription-shaped paths stay unserved by the control API.
	for _, path := range []string{
		"/api/users",
		"/api/users/",
		"/api/accounts",
		"/api/subscription",
		"/api/subscribe",
		"/api/share",
		"/api/export",
	} {
		response := uiJSON(t, controller, http.MethodGet, path, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("aggregate path %s served: %d %s", path, response.Code, response.Body.String())
		}
	}

	// Every control endpoint still requires the panel actor identity; nothing
	// account-shaped can be pulled without it.
	for _, path := range []string{
		"/api/listens?agent_id=agent-1",
		"/api/routing",
		"/api/routing/export",
		"/api/users/" + user.ID,
		"/api/users/" + user.ID + "/qr.png",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		controller.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated %s = %d %s", path, response.Code, response.Body.String())
		}
	}

	// The plugin offers no HTTP/L4 egress or backend provider surface.
	services := runtimeServices()
	if len(services.HTTPBackendProviderIDs) != 0 || len(services.HTTPBackendHandlers) != 0 || len(services.UnavailableHTTPBackendProviders) != 0 {
		t.Fatalf("runtime services offer a backend provider surface: %+v", services)
	}
	manifest, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"http.backend-provider", "http_backend_providers", "http.rule", "l4.accept"} {
		if strings.Contains(string(manifest), banned) {
			t.Fatalf("plugin.yaml declares forbidden surface %q", banned)
		}
	}

	// The panel exposes no subscription or aggregate-share toggle.
	page, err := os.ReadFile(filepath.Join("assets", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("assets", "ui", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"订阅", "subscription", "api/subscription"} {
		if strings.Contains(string(page), banned) || strings.Contains(string(script), banned) {
			t.Fatalf("panel exposes a subscription/share-aggregate surface %q", banned)
		}
	}
}
