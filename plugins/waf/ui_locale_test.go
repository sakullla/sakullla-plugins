package waf_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestOfficialConfigUICopyIsChineseAndBindingsStayStable(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("missing caller path")
	}
	wafDir := filepath.Dir(file)
	pluginsDir := filepath.Dir(wafDir)

	manifest, err := os.ReadFile(filepath.Join(wafDir, "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "ui_schema: ui.schema.json") {
		t.Fatal("waf plugin.yaml must declare ui_schema: ui.schema.json")
	}

	cases := []struct {
		rel      string
		title    string
		bindings map[string][]string
	}{
		{
			rel:   filepath.Join("ip-policy", "ui.schema.json"),
			title: "IP 策略设置",
			bindings: map[string][]string{
				"/default_action":      {"allow", "deny"},
				"/geo/failure_policy":  {"allow", "deny"},
				"/geo/mmdb_handle":     nil,
			},
		},
		{
			rel:   filepath.Join("rate-limit", "ui.schema.json"),
			title: "速率限制设置",
			bindings: map[string][]string{
				"/enabled":                         nil,
				"/max_keys":                        nil,
				"/http/source/emission_interval_ns": nil,
				"/http/source/burst":               nil,
				"/http/global/enabled":             nil,
				"/l4/source/emission_interval_ns":  nil,
				"/l4/source/burst":                 nil,
			},
		},
		{
			rel:   filepath.Join("waf", "ui.schema.json"),
			title: "Web 防火墙设置",
			bindings: map[string][]string{
				"/mode":        {"deny", "observe"},
				"/custom_rules": nil,
				"/id":          nil,
				"/target":      {"path", "query", "headers", "body"},
				"/needle":      nil,
				"/exclusions":  nil,
				"/rule_id":     nil,
				"/path_prefix": nil,
			},
		},
	}

	englishLabel := regexp.MustCompile(`\b(Save|Reset|Allow|Deny|Enabled|Policy|Enforcement|Settings)\b`)
	for _, test := range cases {
		data, err := os.ReadFile(filepath.Join(pluginsDir, test.rel))
		if err != nil {
			t.Fatal(err)
		}
		if englishLabel.Match(data) {
			t.Fatalf("%s still contains English user-facing copy", test.rel)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("%s: %v", test.rel, err)
		}
		if document["title"] != test.title {
			t.Fatalf("%s title = %v, want %s", test.rel, document["title"], test.title)
		}
		seen := collectBindings(document)
		for binding, values := range test.bindings {
			got, ok := seen[binding]
			if !ok {
				t.Fatalf("%s missing binding %s", test.rel, binding)
			}
			if !sameStrings(got, values) {
				t.Fatalf("%s binding %s values = %v, want %v", test.rel, binding, got, values)
			}
		}
	}
}

func collectBindings(node any) map[string][]string {
	seen := map[string][]string{}
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			if binding, ok := typed["binding"].(string); ok && binding != "" {
				var values []string
				if options, ok := typed["options"].([]any); ok {
					for _, option := range options {
						item, _ := option.(map[string]any)
						if item == nil {
							continue
						}
						if optionValue, ok := item["value"].(string); ok {
							values = append(values, optionValue)
						}
					}
				}
				seen[binding] = values
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(node)
	return seen
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
