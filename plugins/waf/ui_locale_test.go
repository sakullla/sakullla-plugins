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
	if strings.Contains(string(manifest), "ui_schema:") {
		t.Fatal("waf plugin.yaml must not declare ui_schema as the operator path")
	}
	page, err := os.ReadFile(filepath.Join(wafDir, "assets", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Web 防火墙", "观察中", "拦截", "排除", "自定义规则", "命中与跳过事件"} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("management page missing %q", want)
		}
	}

	cases := []struct {
		rel                string
		title              string
		bindings           map[string][]string
		absent             []string
		nanosecondBindings []string
	}{
		{
			rel:   filepath.Join("ip-policy", "ui.schema.json"),
			title: "IP 策略设置",
			bindings: map[string][]string{
				"/default_action":     {"allow", "deny"},
				"/geo/failure_policy": {"allow", "deny"},
			},
			absent: []string{"/geo/mmdb_handle"},
		},
		{
			rel:   filepath.Join("rate-limit", "ui.schema.json"),
			title: "速率限制设置",
			bindings: map[string][]string{
				"/enabled":                          nil,
				"/max_keys":                         nil,
				"/http/source/emission_interval_ns": nil,
				"/http/source/burst":                nil,
				"/http/global/enabled":              nil,
				"/l4/source/emission_interval_ns":   nil,
				"/l4/source/burst":                  nil,
			},
			nanosecondBindings: []string{
				"/http/source/emission_interval_ns",
				"/l4/source/emission_interval_ns",
			},
		},
	}

	englishLabel := regexp.MustCompile(`\b(Save|Reset|Allow|Deny|Enabled|Policy|Enforcement|Settings|Handle)\b`)
	for _, test := range cases {
		data, err := os.ReadFile(filepath.Join(pluginsDir, test.rel))
		if err != nil {
			t.Fatal(err)
		}
		if englishLabel.Match(data) {
			t.Fatalf("%s still contains English user-facing copy", test.rel)
		}
		if strings.Contains(string(data), "mmdb_handle") {
			t.Fatalf("%s still contains mmdb_handle", test.rel)
		}
		if strings.Contains(string(data), "句柄") {
			t.Fatalf("%s still exposes host handle copy", test.rel)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("%s: %v", test.rel, err)
		}
		if document["title"] != test.title {
			t.Fatalf("%s title = %v, want %s", test.rel, document["title"], test.title)
		}
		seen, labels, fields := collectBindings(document)
		for binding, values := range test.bindings {
			got, ok := seen[binding]
			if !ok {
				t.Fatalf("%s missing binding %s", test.rel, binding)
			}
			if !sameStrings(got, values) {
				t.Fatalf("%s binding %s values = %v, want %v", test.rel, binding, got, values)
			}
		}
		for _, binding := range test.absent {
			if _, ok := seen[binding]; ok {
				t.Fatalf("%s still exposes binding %s", test.rel, binding)
			}
		}
		for _, binding := range test.nanosecondBindings {
			label := labels[binding]
			if !strings.Contains(label, "纳秒") {
				t.Fatalf("%s binding %s label = %q, want nanosecond units", test.rel, binding, label)
			}
			field := fields[binding]
			if jsonInt(field["minimum"]) != 1 || jsonInt(field["maximum"]) != 3_600_000_000_000 {
				t.Fatalf("%s binding %s bounds = %v–%v, want 1–3600000000000", test.rel, binding, field["minimum"], field["maximum"])
			}
			if _, ok := field["scale"]; ok {
				t.Fatalf("%s binding %s uses unsupported scale", test.rel, binding)
			}
			if _, ok := field["unit"]; ok {
				t.Fatalf("%s binding %s uses unsupported unit", test.rel, binding)
			}
		}
	}
}

func collectBindings(node any) (map[string][]string, map[string]string, map[string]map[string]any) {
	seen := map[string][]string{}
	labels := map[string]string{}
	fields := map[string]map[string]any{}
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
				fields[binding] = typed
				if label, ok := typed["label"].(string); ok {
					labels[binding] = label
				}
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
	return seen, labels, fields
}

func jsonInt(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case int:
		return int64(typed)
	case int64:
		return typed
	default:
		return 0
	}
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
