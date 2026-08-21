package dockerapp_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	dockerapp "github.com/sakullla/sakullla-plugins/plugins/docker-app"
)

func TestHandshakeWithoutComposeGrantReachesDeployableState(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
			return dockerapp.PreparedAdmissionFuncs{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{"http.rule", "ui.dynamic"}
	for _, grant := range grants {
		if grant == "container.compose" {
			t.Fatal("test grants must omit container.compose")
		}
	}
	if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatalf("handshake without container.compose: %v", err)
	}
	document := []byte(`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27\n","generation":"generation-1"}]}`)
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: document}); response.Error != nil {
		t.Fatalf("prepare without container.compose: %#v", response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatalf("activate without container.compose: %#v", response.Error)
	}
	apps := controller.Apps()
	if len(apps) != 1 || apps[0].ID != "media" || apps[0].Image != "nginx:1.27" {
		t.Fatalf("deployable apps = %#v", apps)
	}
}

func TestHandshakeStillAcceptsRedundantComposeGrant(t *testing.T) {
	controller, err := dockerapp.NewController(dockerapp.ControllerConfig{
		PackageDigest: "package", ArtifactDigest: "artifact",
		Admission: dockerapp.TypedHandleAdmissionFunc(func(context.Context, pluginsdk.RPCHandshakeRequest, []dockerapp.App) (dockerapp.PreparedAdmission, error) {
			return dockerapp.PreparedAdmissionFuncs{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	grants := append(append([]string{}, requiredGrants()...), "container.compose")
	if _, err := controller.Handshake(context.Background(), handshake(grants)); err != nil {
		t.Fatalf("handshake with extra container.compose: %v", err)
	}
	if response := controller.Prepare(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1", Config: configWire(t, 1)}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := controller.Activate(context.Background(), pluginsdk.LifecycleRequest{Generation: "generation-1"}); response.Error != nil {
		t.Fatal(response.Error)
	}
}

func TestZeroConfigInstallOmitsDockerConnectionFields(t *testing.T) {
	pluginDir := filepath.Join("..", "..", "..", "plugins", "docker-app")
	manifest, err := os.ReadFile(filepath.Join(pluginDir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	if !strings.Contains(text, "host_scope: agent") || !strings.Contains(text, `agent: "*"`) {
		t.Fatalf("plugin.yaml is not per-agent / non-local: %s", text)
	}
	if !strings.Contains(text, "ui.route") || !strings.Contains(text, "ui_route_id: docker-app") {
		t.Fatalf("plugin.yaml must register a plugin-owned UI route: %s", text)
	}
	if !strings.Contains(text, "ui/index.html") || !strings.Contains(text, "ui/app.js") {
		t.Fatalf("plugin.yaml must ship ui/ frontend assets: %s", text)
	}
	if strings.Contains(text, "host_scope: local") || strings.Contains(text, "container.compose") {
		t.Fatalf("plugin.yaml still gates Docker API or local-only install: %s", text)
	}

	schemaBytes, err := os.ReadFile(filepath.Join(pluginDir, "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defaultBytes, err := os.ReadFile(filepath.Join(pluginDir, "config.default.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertNoDockerConnectionForm(t, "config.schema.json", schemaBytes)
	assertNoDockerConnectionForm(t, "config.default.json", defaultBytes)

	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	properties, _ := schema["properties"].(map[string]any)
	apps, _ := properties["apps"].(map[string]any)
	if injected, _ := apps["hostInjected"].(bool); !injected {
		t.Fatal("apps must be hostInjected so the generic schema form is not the product UI")
	}
	if _, hasDefault := apps["default"]; !hasDefault {
		t.Fatal("hostInjected apps must declare a schema default so omitted configure payloads stay valid")
	}
	if _, hasTitle := apps["title"]; hasTitle {
		t.Fatal("apps must not carry a form title")
	}
	items, _ := apps["items"].(map[string]any)
	itemProperties, _ := items["properties"].(map[string]any)
	compose, _ := itemProperties["compose"].(map[string]any)
	if _, hasTitle := compose["title"]; hasTitle {
		t.Fatal("compose must not carry a form title")
	}
	if err := walkSchemaRequired(schema, func(name string) error {
		if isDockerConnectionField(name) {
			return errDockerConnectionField(name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, document := range []string{
		`{"apps":[],"docker_host":"tcp://127.0.0.1:2375"}`,
		`{"apps":[],"socket":"/var/run/docker.sock"}`,
		`{"apps":[],"unix_socket":"/var/run/docker.sock"}`,
		`{"apps":[],"api_key":"secret"}`,
		`{"apps":[{"id":"media","compose":"services:\n  web:\n    image: nginx:1.27\n","generation":"generation-1","docker_host":"tcp://127.0.0.1:2375"}]}`,
	} {
		if _, err := dockerapp.ParseConfiguration([]byte(document)); err == nil {
			t.Fatalf("overlay accepted Docker connection field: %s", document)
		}
	}
}

func assertNoDockerConnectionForm(t *testing.T, name string, raw []byte) {
	t.Helper()
	lower := strings.ToLower(string(raw))
	for _, token := range []string{
		"docker_host", "dockerhost", "docker-host", "docker host",
		"unix_socket", "unixsocket", "docker_socket", "dockersocket",
		"api_key", "apikey", "api-key", "api key", "api密钥",
		"docker 主机", "套接字", "npipe", "docker_api",
	} {
		if strings.Contains(lower, token) {
			t.Fatalf("%s contains Docker connection field %q", name, token)
		}
	}
}

func isDockerConnectionField(name string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), " ", "_")) {
	case "host", "docker_host", "dockerhost", "socket", "unix_socket", "docker_socket",
		"api_key", "apikey", "api_token", "docker_api", "docker_api_key", "npipe", "endpoint":
		return true
	default:
		return false
	}
}

type dockerConnectionFieldError string

func errDockerConnectionField(name string) error {
	return dockerConnectionFieldError(name)
}

func (err dockerConnectionFieldError) Error() string {
	return "install/deploy form requires Docker connection field " + string(err)
}

func walkSchemaRequired(node any, visit func(string) error) error {
	switch typed := node.(type) {
	case map[string]any:
		if required, ok := typed["required"].([]any); ok {
			for _, item := range required {
				name, _ := item.(string)
				if err := visit(name); err != nil {
					return err
				}
			}
		}
		if properties, ok := typed["properties"].(map[string]any); ok {
			for name, child := range properties {
				if err := visit(name); err != nil {
					return err
				}
				if err := walkSchemaRequired(child, visit); err != nil {
					return err
				}
			}
		}
		if items, ok := typed["items"]; ok {
			if err := walkSchemaRequired(items, visit); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := walkSchemaRequired(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
