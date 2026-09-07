package ippolicy

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

func TestConfigSchemaBootstrapsDefaultConfiguration(t *testing.T) {
	raw, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string                  `json:"required"`
		Properties map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	// Installation submits {}. Only named hostInjected properties receive
	// schema defaults before the host validates and prepares the management RPC.
	initial := make(map[string]any)
	for name, property := range schema.Properties {
		injected, err := pluginsdk.ConfigSchemaHostInjected(property)
		if err != nil {
			t.Fatal(err)
		}
		if value, exists := property["default"]; injected && exists {
			initial[name] = value
		}
	}
	for _, name := range schema.Required {
		if _, exists := initial[name]; !exists {
			t.Fatalf("empty install configuration cannot initialize required property %q", name)
		}
	}
	encoded, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfiguration(encoded)
	if err != nil {
		t.Fatalf("management RPC cannot prepare the installation defaults: %v", err)
	}
	if !reflect.DeepEqual(config, DefaultConfiguration()) {
		t.Fatalf("installation defaults = %+v, want %+v", config, DefaultConfiguration())
	}
}
