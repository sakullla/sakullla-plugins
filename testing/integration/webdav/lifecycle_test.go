package webdav_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/webdav"
)

type fakeService struct {
	body    string
	root    string
	closed  atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (service *fakeService) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	if service.started != nil {
		close(service.started)
	}
	if service.release != nil {
		<-service.release
	}
	_, _ = writer.Write([]byte(service.body))
}

func (service *fakeService) Close() error { service.closed.Add(1); return nil }
func (service *fakeService) Root() string { return service.root }

func TestGenerationLifecycleIsZeroConfigAndGenerationOwned(t *testing.T) {
	instance := &fakeService{body: "generation-one", root: t.TempDir()}
	controller := newController(t, func() (webdav.GenerationService, error) { return instance, nil })

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
	if controller.Status().Active {
		t.Fatal("generation stayed active after stop")
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
			controller := newController(t, func() (webdav.GenerationService, error) { return &fakeService{}, nil })
			request := handshakeRequest("rejected-" + test.name)
			test.mutate(&request)
			if _, err := controller.Handshake(t.Context(), request); err == nil {
				t.Fatal("invalid handshake was accepted")
			}
		})
	}
}

func TestInactiveAndStoppedGenerationsReturn503WithoutFilesystemRoot(t *testing.T) {
	owned := t.TempDir()
	marker := filepath.Join(owned, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", OwnedRoot: owned})
	if err != nil {
		t.Fatal(err)
	}
	assertProviderStatus(t, controller, http.StatusServiceUnavailable, "")
	activateController(t, controller, "owned-generation")
	status := controller.Status()
	if !status.Active || status.Root != owned {
		t.Fatalf("active status = %+v, want root %q", status, owned)
	}
	if isVolumeRoot(status.Root) {
		t.Fatalf("owned share used the filesystem root: %q", status.Root)
	}
	assertProviderStatus(t, controller, http.StatusOK, "")
	if result := controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: "owned-generation"}); result.Error != nil {
		t.Fatal(result.Error)
	}
	assertProviderStatus(t, controller, http.StatusServiceUnavailable, "")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("stop deleted owned share file: %v", err)
	}
}

func TestTimedOutPrepareRevokesLateService(t *testing.T) {
	instance := &fakeService{}
	release := make(chan struct{})
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", PrepareTimeout: 25 * time.Millisecond, NewService: func() (webdav.GenerationService, error) {
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

func newController(t *testing.T, factory webdav.ServiceFactory) *webdav.Controller {
	t.Helper()
	controller, err := webdav.NewController(webdav.ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", NewService: factory})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func handshakeRequest(generation string) pluginsdk.RPCHandshakeRequest {
	return pluginsdk.RPCHandshakeRequest{ABI: pluginsdk.RPCABIV1, PluginID: webdav.PluginID, PluginVersion: webdav.PluginVersion, PackageDigest: "package", ArtifactDigest: "artifact", GrantedScopes: []string{pluginsdk.PermissionHTTPOutbound}, Generation: generation, RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1}}
}

func activateController(t *testing.T, controller *webdav.Controller, generation string) {
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

func isVolumeRoot(path string) bool {
	cleaned := filepath.Clean(path)
	separator := string(os.PathSeparator)
	if cleaned == separator {
		return true
	}
	volume := filepath.VolumeName(cleaned)
	return volume != "" && (cleaned == volume+separator || cleaned == volume+`\` || cleaned == volume+`/`)
}
