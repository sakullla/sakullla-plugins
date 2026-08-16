package acceleratorsources

import (
	"encoding/json"
	"os"
	"testing"
)

func TestConfigSchemaDeclaresOnlyTheEmptyObjectContract(t *testing.T) {
	data, err := os.ReadFile("config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema) != 3 || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("accelerator-sources config schema must describe only an empty object: %#v", schema)
	}
}
