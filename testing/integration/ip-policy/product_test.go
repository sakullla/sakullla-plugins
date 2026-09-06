package ippolicyintegration

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	ippolicy "github.com/sakullla/sakullla-plugins/plugins/ip-policy"
	"gopkg.in/yaml.v3"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
}

func TestControlPlaneEntrypointProbeUsesPublishedSDK(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "./plugins/ip-policy/cmd/ip-policy", ippolicy.CIHandshakeFlag)
	command.Dir = repositoryRoot(t)
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte(pluginsdk.RPCABIV1)) {
		t.Fatalf("probe error=%v output=%s", err, output)
	}
}

func TestOfficialPackageIsOneControlPlaneUIPlusAgentPolicy(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "plugins", "ip-policy", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	projection, ok := pluginsdk.ProjectAgentPolicy(manifest)
	if !ok || manifest.Runtime.Kind != pluginsdk.RuntimeRPCService || manifest.Runtime.HostScope != pluginsdk.HostScopeControlPlane || projection.HostScope != pluginsdk.HostScopeAgent || projection.ModeHandling != pluginsdk.PolicyModeHandlingRaw {
		t.Fatalf("package faces runtime=%+v policy=%+v", manifest.Runtime, projection)
	}
	if pluginsdk.RuntimeProjectsAgentRPC(manifest.Runtime) {
		t.Fatal("Agent policy was projected as RPC")
	}
	for _, path := range []string{"assets/ui/index.html", "assets/ui/app.js", "assets/ui/style.css"} {
		if _, err := os.Stat(filepath.Join(root, "plugins", "ip-policy", filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(string(raw), "ui_schema:") || !strings.Contains(string(raw), "policy.mode.handling: raw-decision-v1") {
		t.Fatalf("manifest UI/mode handling drift: %s", raw)
	}
}

func TestDefaultProductConfigurationIsObserveReadyAndDataIndependent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "plugins", "ip-policy", "config.default.json"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := ippolicy.ParseConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if config.DefaultAction != "allow" || len(config.Datasets) != 0 || len(config.ProvinceWhitelist) != 0 || len(config.Rules) != 0 {
		t.Fatalf("fresh-install config=%+v", config)
	}
}
