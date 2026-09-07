package waf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"gopkg.in/yaml.v3"
)

func TestNodeBulkModePreservesOtherNodesAndInstanceDefault(t *testing.T) {
	catalog := newMemoryCatalog()
	for _, id := range []string{"node-a", "node-b"} {
		catalog.entries[id] = []HTTPEntry{{RuleRef: "1", Enabled: true, Attached: true, Mode: ModeObserve}}
	}
	controller := newUIController(t, uiControllerOptions{catalog: catalog, overlays: catalog})
	response := httptest.NewRecorder()
	controller.ServeHTTP(response, uiJSONRequest(http.MethodPost, "/api/entries/mode-all", `{"agent_id":"node-a","mode":"deny"}`))
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if catalog.entries["node-a"][0].Mode != ModeDeny || catalog.entries["node-b"][0].Mode != ModeObserve || controller.currentConfig().Mode != ModeObserve {
		t.Fatal("node-only update leaked into another node or instance default")
	}
}

func TestWAFDeclaresCompleteOwnedDataCleanup(t *testing.T) {
	data, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	cleanup := manifest.Cleanup
	if cleanup.Instances != "delete" || cleanup.Config != "delete" || cleanup.OwnedData != "delete" || cleanup.Grants != "delete" {
		t.Fatalf("plugin-owned state must be deleted on uninstall: %+v", cleanup)
	}
	controller := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	if err := controller.addCustomRule(t.Context(), CustomRule{ID: "temporary", Target: "path", Needle: "/private"}); err != nil {
		t.Fatal(err)
	}
	if err := controller.stop(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if controller.uiReady() || len(controller.currentConfig().CustomRules) != 0 {
		t.Fatal("stopped plugin retained a live management view or configuration")
	}
}

func TestCustomRuleRemovalRemovesRelatedExclusions(t *testing.T) {
	controller := newUIController(t, uiControllerOptions{catalog: newMemoryCatalog()})
	if err := controller.addCustomRule(t.Context(), CustomRule{ID: "test-rule", Target: "path", Needle: "/private"}); err != nil {
		t.Fatal(err)
	}
	if err := controller.addExclusion(t.Context(), Exclusion{RuleID: "test-rule", PathPrefix: "/public"}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	controller.ServeHTTP(response, uiJSONRequest(http.MethodDelete, "/api/custom-rules", `{"id":"test-rule"}`))
	config := controller.currentConfig()
	if response.Code != http.StatusOK || len(config.CustomRules) != 0 || len(config.Exclusions) != 0 {
		t.Fatalf("response=%s config=%+v", response.Body.String(), config)
	}
	if len(managedRuleCatalog()) != len(managedRuleIDs) {
		t.Fatal("managed catalog drifted from compiled rules")
	}
}
