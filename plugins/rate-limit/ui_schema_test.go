package rate_limit_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestIntervalInputsUseSupportedNanosecondContract(t *testing.T) {
	wire, err := os.ReadFile("ui.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components []struct {
			Children []map[string]any `json:"children"`
		} `json:"components"`
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"http_source_interval": false,
		"l4_source_interval":   false,
	}
	for _, component := range document.Components {
		for _, field := range component.Children {
			id, _ := field["id"].(string)
			if _, ok := want[id]; !ok {
				continue
			}
			want[id] = true
			if _, ok := field["unit"]; ok {
				t.Errorf("%s uses unsupported number field unit", id)
			}
			if _, ok := field["scale"]; ok {
				t.Errorf("%s uses unsupported number field scale", id)
			}
			if got := field["maximum"]; got != float64(3_600_000_000_000) {
				t.Errorf("%s maximum = %v, want config-schema nanosecond maximum", id, got)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("missing interval input %s", id)
		}
	}
}
