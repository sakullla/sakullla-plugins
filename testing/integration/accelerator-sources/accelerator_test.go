package acceleratorsources_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	acceleratorsources "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources"
)

type fakeService struct {
	body       string
	metrics    acceleratorsources.Metrics
	closed     atomic.Int32
	started    chan struct{}
	release    chan struct{}
	streamSize int
}

func (service *fakeService) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	if service.started != nil {
		close(service.started)
	}
	if service.streamSize > 0 {
		chunk := strings.Repeat("x", 32<<10)
		for written := 0; written < service.streamSize; written += len(chunk) {
			_, _ = io.WriteString(writer, chunk)
		}
	}
	if service.release != nil {
		<-service.release
	}
	_, _ = io.WriteString(writer, service.body)
}

func (service *fakeService) Close() error                        { service.closed.Add(1); return nil }
func (service *fakeService) Metrics() acceleratorsources.Metrics { return service.metrics }

func TestGenerationLifecycleIsZeroConfigAndGenerationOwned(t *testing.T) {
	expectedMetrics := acceleratorsources.Metrics{DNSQueries: 1, DNSHits: 2, DNSMisses: 3, DNSEvictions: 4, CacheHits: 5, CacheMisses: 6, CacheEvictions: 7, NewConnections: 8, ReusedConnections: 9, TLSHandshakes: 10, PoolWaitNanos: 11, UpstreamCalls: 12, FirstResponseBytes: 13, TransferredBytes: 14, HTTP2Requests: 15}
	instance := &fakeService{body: "generation-one", metrics: expectedMetrics}
	rejected := newController(t, func() (acceleratorsources.GenerationService, error) { return &fakeService{}, nil })
	rejectedRequest := handshakeRequest("rejected-generation")
	if _, err := rejected.Handshake(t.Context(), rejectedRequest); err != nil {
		t.Fatal(err)
	}
	if result := rejected.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: rejectedRequest.Generation, Config: []byte(`{"legacy":true}`)}); result.Error == nil {
		t.Fatal("non-empty configuration was accepted")
	}

	controller := newController(t, func() (acceleratorsources.GenerationService, error) { return instance, nil })

	request := handshakeRequest("generation-one")
	response, err := controller.Handshake(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Features) != 1 || response.Features[0] != pluginsdk.RPCFeatureHTTPBackendProviderV1 || len(response.Capabilities) != 1 || response.Capabilities[0] != pluginsdk.PermissionHTTPOutbound {
		t.Fatalf("handshake response = %+v", response)
	}
	if result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: request.Generation, Config: []byte(`{}`)}); result.Error != nil {
		t.Fatalf("prepare: %+v", result.Error)
	}
	assertProviderStatus(t, controller, http.StatusServiceUnavailable, "")
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: request.Generation}); result.Error != nil {
		t.Fatalf("activate: %+v", result.Error)
	}
	assertProviderStatus(t, controller, http.StatusOK, "generation-one")
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: request.Generation}); result.Error != nil {
		t.Fatalf("stop: %+v", result.Error)
	}
	status := controller.Status()
	if status.Active || status.Metrics != expectedMetrics {
		t.Fatalf("post-stop status = %+v", status)
	}
	if instance.closed.Load() != 1 {
		t.Fatalf("service close count = %d, want 1", instance.closed.Load())
	}
	assertProviderStatus(t, controller, http.StatusServiceUnavailable, "")
}

func TestHandshakeRequiresProviderFeatureGrantAndArtifactIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*pluginsdk.RPCHandshakeRequest)
	}{
		{name: "feature", mutate: func(request *pluginsdk.RPCHandshakeRequest) { request.RequiredFeatures = nil }},
		{name: "grant", mutate: func(request *pluginsdk.RPCHandshakeRequest) { request.GrantedScopes = nil }},
		{name: "artifact", mutate: func(request *pluginsdk.RPCHandshakeRequest) { request.ArtifactDigest = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := newController(t, func() (acceleratorsources.GenerationService, error) { return &fakeService{}, nil })
			request := handshakeRequest("rejected-" + test.name)
			test.mutate(&request)
			if _, err := controller.Handshake(t.Context(), request); err == nil {
				t.Fatal("invalid handshake was accepted")
			}
		})
	}
}

func TestTimedOutPrepareRevokesLateService(t *testing.T) {
	instance := &fakeService{}
	release := make(chan struct{})
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", PrepareTimeout: 25 * time.Millisecond, NewService: func() (acceleratorsources.GenerationService, error) {
		<-release
		return instance, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := handshakeRequest("timed-out")
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: request.Generation, Config: []byte(`{}`)})
	if result.Error == nil {
		t.Fatal("blocked prepare did not time out")
	}
	close(release)
	for deadline := time.Now().Add(5 * time.Second); instance.closed.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if instance.closed.Load() != 1 || controller.Status().Active {
		t.Fatalf("late service close/status = %d/%+v", instance.closed.Load(), controller.Status())
	}
}

func TestFailedCandidateDoesNotReplaceLastKnownGood(t *testing.T) {
	lkgService := &fakeService{body: "lkg"}
	lkg := newController(t, func() (acceleratorsources.GenerationService, error) { return lkgService, nil })
	activateController(t, lkg, "lkg-generation")

	candidate := newController(t, func() (acceleratorsources.GenerationService, error) { return nil, errors.New("candidate unavailable") })
	request := handshakeRequest("candidate-generation")
	if _, err := candidate.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if result := candidate.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: request.Generation, Config: []byte(`{}`)}); result.Error == nil {
		t.Fatal("failed candidate prepared successfully")
	}
	assertProviderStatus(t, lkg, http.StatusOK, "lkg")
	if lkgService.closed.Load() != 0 {
		t.Fatal("failed candidate closed last-known-good generation")
	}
	if result := lkg.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "lkg-generation"}); result.Error != nil {
		t.Fatal(result.Error)
	}
}

func TestStopWaitsForLongProviderStreamAndClosesOnce(t *testing.T) {
	instance := &fakeService{metrics: acceleratorsources.Metrics{TransferredBytes: 5 << 20}, started: make(chan struct{}), release: make(chan struct{}), streamSize: 5 << 20}
	controller := newController(t, func() (acceleratorsources.GenerationService, error) { return instance, nil })
	activateController(t, controller, "stream-generation")

	requestDone := make(chan struct{})
	go func() {
		recorder := httptest.NewRecorder()
		controller.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://provider.test/stream", nil))
		close(requestDone)
	}()
	<-instance.started
	stopDone := make(chan pluginsdk.LifecycleResponse, 1)
	go func() {
		stopDone <- controller.Stop(context.Background(), pluginsdk.LifecycleRequest{Generation: "stream-generation"})
	}()
	select {
	case <-stopDone:
		t.Fatal("stop returned before the active provider stream drained")
	case <-time.After(50 * time.Millisecond):
	}
	close(instance.release)
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("provider stream did not finish")
	}
	select {
	case result := <-stopDone:
		if result.Error != nil {
			t.Fatal(result.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not finish after stream drain")
	}
	if instance.closed.Load() != 1 || controller.Status().Metrics.TransferredBytes != 5<<20 {
		t.Fatalf("close/metrics = %d/%+v", instance.closed.Load(), controller.Status().Metrics)
	}
}

func TestGenerationsUseIndependentServices(t *testing.T) {
	one := &fakeService{body: "one", metrics: acceleratorsources.Metrics{DNSQueries: 1}}
	two := &fakeService{body: "two", metrics: acceleratorsources.Metrics{DNSQueries: 2}}
	first := newController(t, func() (acceleratorsources.GenerationService, error) { return one, nil })
	second := newController(t, func() (acceleratorsources.GenerationService, error) { return two, nil })
	activateController(t, first, "generation-one")
	activateController(t, second, "generation-two")
	assertProviderStatus(t, first, http.StatusOK, "one")
	assertProviderStatus(t, second, http.StatusOK, "two")
	if first.Status().Metrics.DNSQueries != 1 || second.Status().Metrics.DNSQueries != 2 {
		t.Fatal("generation metrics were shared")
	}
	_ = first.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-one"})
	if two.closed.Load() != 0 {
		t.Fatal("stopping one generation closed another")
	}
	_ = second.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "generation-two"})
}

func newController(t *testing.T, factory acceleratorsources.ServiceFactory) *acceleratorsources.Controller {
	t.Helper()
	controller, err := acceleratorsources.NewController(acceleratorsources.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", NewService: factory})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func handshakeRequest(generation string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: acceleratorsources.PluginID, PluginVersion: acceleratorsources.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: generation, RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1}}
}

func activateController(t *testing.T, controller *acceleratorsources.Controller, generation string) {
	t.Helper()
	request := handshakeRequest(generation)
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if result := controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: generation, Config: []byte(`{}`)}); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: generation}); result.Error != nil {
		t.Fatal(result.Error)
	}
}

func assertProviderStatus(t *testing.T, handler http.Handler, wantStatus int, wantBody string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://provider.test/", nil))
	if recorder.Code != wantStatus || (wantBody != "" && recorder.Body.String() != wantBody) {
		t.Fatalf("provider response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), wantStatus, wantBody)
	}
}
