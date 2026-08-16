package acceleratorsources

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
)

func TestConfigSchemaDeclaresClosedLoadableObject(t *testing.T) {
	data, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("accelerator-sources config schema must be a closed object: %#v", schema)
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		return
	}
	if len(properties) != 1 {
		t.Fatalf("accelerator-sources config schema must only declare sources: %#v", properties)
	}
	sources, _ := properties["sources"].(map[string]any)
	if sources == nil || sources["type"] != "array" {
		t.Fatalf("sources must be an array: %#v", properties)
	}
	items, _ := sources["items"].(map[string]any)
	if items["type"] != "object" || items["additionalProperties"] != false {
		t.Fatalf("source items must be a closed object: %#v", items)
	}
	itemProps, _ := items["properties"].(map[string]any)
	if itemProps["name"] == nil || itemProps["endpoint"] == nil || len(itemProps) != 2 {
		t.Fatalf("source items must only declare name and endpoint: %#v", itemProps)
	}
}

func TestLoadSourcesUsesDefaultSourcesWhenOmittedOrEmpty(t *testing.T) {
	want := registry.DefaultSources()
	if len(want) != 5 {
		t.Fatalf("DefaultSources() = %d, want 5", len(want))
	}
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "omitted empty object", wire: []byte(`{}`)},
		{name: "omitted empty wire", wire: nil},
		{name: "empty array", wire: []byte(`{"sources":[]}`)},
		{name: "null sources", wire: []byte(`{"sources":null}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := loadSources(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			assertSourcesMatch(t, got, want)
		})
	}
}

func TestLoadSourcesReplacesEntireListForValidHTTPSDocument(t *testing.T) {
	got, err := loadSources([]byte(`{"sources":[{"name":"ghcr.io","endpoint":"https://ghcr.example"},{"name":"mirror.example","endpoint":"https://mirror.example"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d sources, want a wholesale replacement of 2", len(got))
	}
	if got[0].Name != "ghcr.io" || got[0].Endpoint.String() != "https://ghcr.example" || len(got[0].Aliases) != 0 || len(got[0].TokenHosts) != 0 {
		t.Fatalf("known name override = %+v", got[0])
	}
	if got[1].Name != "mirror.example" || got[1].Endpoint.String() != "https://mirror.example" || len(got[1].Aliases) != 0 || len(got[1].TokenHosts) != 0 {
		t.Fatalf("custom source = %+v", got[1])
	}
	if got[0].AllowHTTP || got[0].AllowPrivate || got[1].AllowHTTP || got[1].AllowPrivate {
		t.Fatal("user sources must not enable http or private escape")
	}
}

func TestLoadSourcesMapsKnownPublicRegistryMetadata(t *testing.T) {
	got, err := loadSources([]byte(`{"sources":[{"name":"docker.io","endpoint":"https://docker.example"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("loaded %d sources, want 1", len(got))
	}
	want := knownDockerSource(t)
	if got[0].Name != "docker.io" || got[0].Endpoint.String() != "https://docker.example" {
		t.Fatalf("docker.io override = %+v", got[0])
	}
	assertStringSlice(t, got[0].Aliases, want.Aliases)
	assertStringSlice(t, got[0].TokenHosts, want.TokenHosts)
}

func TestLoadSourcesRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{name: "unknown field", wire: []byte(`{"legacy":true}`), want: "unknown field"},
		{name: "unknown source field", wire: []byte(`{"sources":[{"name":"ghcr.io","endpoint":"https://ghcr.io","token_hosts":[]}]}`), want: "unknown field"},
		{name: "http endpoint", wire: []byte(`{"sources":[{"name":"ghcr.io","endpoint":"http://ghcr.io"}]}`), want: "sources[0].endpoint must be an https URL"},
		{name: "private ip", wire: []byte(`{"sources":[{"name":"ghcr.io","endpoint":"https://10.0.0.1"}]}`), want: "sources[0].endpoint must not target a private network"},
		{name: "localhost", wire: []byte(`{"sources":[{"name":"ghcr.io","endpoint":"https://localhost"}]}`), want: "sources[0].endpoint must not target a private network"},
		{name: "missing name", wire: []byte(`{"sources":[{"endpoint":"https://ghcr.io"}]}`), want: "sources[0].name is invalid"},
		{name: "query string", wire: []byte(`{"sources":[{"name":"mirror.example","endpoint":"https://mirror.example?q=1"}]}`), want: "sources[0].endpoint contains unsupported components"},
		{name: "mixed valid and http", wire: []byte(`{"sources":[{"name":"ghcr.io","endpoint":"https://ghcr.io"},{"name":"bad.example","endpoint":"http://bad.example"}]}`), want: "sources[1].endpoint must be an https URL"},
		{name: "two documents", wire: []byte(`{}{}`), want: "accelerator-sources configuration must contain one object"},
		{name: "too large", wire: bytes.Repeat([]byte("a"), MaxConfigBytes+1), want: "plugin configuration exceeds the canonical bound"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := loadSources(test.wire)
			if err == nil {
				t.Fatalf("accepted invalid document: %+v", got)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q, want substring %q", err, test.want)
			}
			if got != nil {
				t.Fatalf("rejected document still returned sources: %+v", got)
			}
		})
	}
}

func TestPrepareOmitsSourcesUsesDefaultList(t *testing.T) {
	controller := newTestController(t, nil)
	if result := handshakeAndPrepare(t, controller, "default-sources", []byte(`{}`)); result.Error != nil {
		t.Fatalf("prepare: %+v", result.Error)
	}
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "default-sources"}); result.Error != nil {
		t.Fatalf("activate: %+v", result.Error)
	}
	assertSourcesMatch(t, controller.snapshotSources(), registry.DefaultSources())
	assertRegistryUnsupported(t, controller, "/v2/unknown.registry.example/library/alpine/manifests/latest")
}

func TestPrepareHTTPSOverrideReplacesSourceList(t *testing.T) {
	controller := newTestController(t, nil)
	config := []byte(`{"sources":[{"name":"mirror.example","endpoint":"https://mirror.example"}]}`)
	if result := handshakeAndPrepare(t, controller, "override-sources", config); result.Error != nil {
		t.Fatalf("prepare: %+v", result.Error)
	}
	if result := controller.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "override-sources"}); result.Error != nil {
		t.Fatalf("activate: %+v", result.Error)
	}
	got := controller.snapshotSources()
	if len(got) != 1 || got[0].Name != "mirror.example" || got[0].Endpoint.String() != "https://mirror.example" {
		t.Fatalf("override sources = %+v", got)
	}
	assertRegistryUnsupported(t, controller, "/v2/ghcr.io/library/alpine/manifests/latest")
	assertRegistryUnsupported(t, controller, "/v2/docker.io/library/alpine/manifests/latest")
}

func TestPrepareRejectsInvalidDocumentWithoutCreatingService(t *testing.T) {
	var created int
	controller := newTestController(t, func() (GenerationService, error) {
		created++
		return nopService{}, nil
	})
	active := newTestController(t, nil)
	if result := handshakeAndPrepare(t, active, "active-default", []byte(`{}`)); result.Error != nil {
		t.Fatalf("active prepare: %+v", result.Error)
	}
	if result := active.Activate(t.Context(), pluginsdk.LifecycleRequest{Generation: "active-default"}); result.Error != nil {
		t.Fatalf("active activate: %+v", result.Error)
	}
	if result := handshakeAndPrepare(t, controller, "invalid-override", []byte(`{"sources":[{"name":"bad.example","endpoint":"http://bad.example"}]}`)); result.Error == nil {
		t.Fatal("non-https override was accepted")
	}
	if created != 0 {
		t.Fatalf("invalid document created %d services", created)
	}
	if controller.Status().Active {
		t.Fatal("rejected override activated a generation")
	}
	assertSourcesMatch(t, active.snapshotSources(), registry.DefaultSources())
	assertRegistryUnsupported(t, active, "/v2/unknown.registry.example/library/alpine/manifests/latest")
}

type nopService struct{}

func (nopService) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (nopService) Close() error                                 { return nil }
func (nopService) Metrics() Metrics                             { return Metrics{} }

func newTestController(t *testing.T, factory ServiceFactory) *Controller {
	t.Helper()
	controller, err := NewController(ControllerConfig{PackageDigest: "package", ArtifactDigest: "artifact", NewService: factory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = controller.Stop(t.Context(), pluginsdk.LifecycleRequest{Generation: controller.Status().Generation})
	})
	return controller
}

func handshakeAndPrepare(t *testing.T, controller *Controller, generation string, config []byte) pluginsdk.LifecycleResponse {
	t.Helper()
	request := pluginsdk.RPCHandshakeRequest{
		ABI: pluginsdk.RPCABIV1, PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: "package", ArtifactDigest: "artifact", Generation: generation,
		GrantedScopes:    []string{pluginsdk.PermissionHTTPOutbound},
		RequiredFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
	}
	if _, err := controller.Handshake(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	return controller.Prepare(t.Context(), pluginsdk.LifecycleRequest{Generation: generation, Config: config})
}

func assertRegistryUnsupported(t *testing.T, handler http.Handler, path string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "REGISTRY_UNSUPPORTED") {
		t.Fatalf("path %s: status=%d body=%s", path, recorder.Code, recorder.Body.String())
	}
}

func assertSourcesMatch(t *testing.T, got []registry.Source, want []registry.Source) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("source count = %d, want %d", len(got), len(want))
	}
	for index := range got {
		if got[index].Name != want[index].Name {
			t.Fatalf("sources[%d].name = %q, want %q", index, got[index].Name, want[index].Name)
		}
		if sourceEndpoint(got[index]) != sourceEndpoint(want[index]) {
			t.Fatalf("sources[%d].endpoint = %q, want %q", index, sourceEndpoint(got[index]), sourceEndpoint(want[index]))
		}
		assertStringSlice(t, got[index].Aliases, want[index].Aliases)
		assertStringSlice(t, got[index].TokenHosts, want[index].TokenHosts)
		if got[index].AllowHTTP != want[index].AllowHTTP || got[index].AllowPrivate != want[index].AllowPrivate {
			t.Fatalf("sources[%d] escape flags = http:%t private:%t", index, got[index].AllowHTTP, got[index].AllowPrivate)
		}
	}
}

func assertStringSlice(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slice %#v, want %#v", got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("slice[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func sourceEndpoint(source registry.Source) string {
	if source.Endpoint == nil {
		return ""
	}
	return source.Endpoint.String()
}

func knownDockerSource(t *testing.T) registry.Source {
	t.Helper()
	for _, source := range registry.DefaultSources() {
		if source.Name == "docker.io" {
			return source
		}
	}
	t.Fatal("DefaultSources() missing docker.io")
	return registry.Source{}
}
