package main

import (
	"fmt"
	"strings"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestGeneratedOptionalPolicyImportsCoverCanonicalDescriptor(t *testing.T) {
	generated, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	for _, symbol := range []string{pluginsdk.PolicyHostReadTrustedSource, pluginsdk.PolicyHostDatasetQuery, pluginsdk.PolicyHostDatasetResolve} {
		if strings.Count(text, `"`+symbol+`"`) != 1 || strings.Count(text, "fn "+symbol+"(") != 1 {
			t.Fatalf("optional Host import %q is not generated as one constant and one extern", symbol)
		}
	}

	modules := map[string]struct {
		message string
		fields  map[string]string
	}{
		"read_trusted_source_request": {"ReadTrustedSourceRequest", map[string]string{}},
		"trusted_source":              {"TrustedSource", map[string]string{"INSTANCE_ID": "instance_id", "GENERATION": "generation", "ENTRY_ID": "entry_id", "PEER_ADDRESS": "peer_address", "SOURCE_ADDRESS": "source_address", "AUTHORITY": "authority"}},
		"trusted_source_response":     {"TrustedSourceResponse", map[string]string{"SOURCE": "source", "ERROR": "error"}},
		"dataset_reference":           {"DatasetReference", map[string]string{"HANDLE": "handle", "INSTANCE_ID": "instance_id", "GENERATION": "generation", "SOURCE_ID": "source_id", "VERSION_DIGEST": "version_digest"}},
		"dataset_resolve_request":     {"DatasetResolveRequest", map[string]string{"SOURCE_ID": "source_id", "MAX_DURATION_MICROS": "max_duration_micros", "MAX_RESPONSE_BYTES": "max_response_bytes"}},
		"dataset_resolve_response":    {"DatasetResolveResponse", map[string]string{"REFERENCE": "reference", "ERROR": "error"}},
		"dataset_classification":      {"DatasetClassification", map[string]string{"NAME": "name", "KIND": "kind"}},
		"dataset_query_request":       {"DatasetQueryRequest", map[string]string{"REFERENCE": "reference", "CLASSIFICATIONS": "classifications", "MAX_DURATION_MICROS": "max_duration_micros", "MAX_RESPONSE_BYTES": "max_response_bytes"}},
		"dataset_match":               {"DatasetMatch", map[string]string{"INDEX": "index", "MATCHED": "matched", "COVERAGE": "coverage"}},
		"dataset_query_response":      {"DatasetQueryResponse", map[string]string{"REFERENCE": "reference", "STATUS": "status", "MATCHES": "matches"}},
	}
	for module, projection := range modules {
		message, err := protoschema.Message(protoreflect.FullName("nre.plugin.policy.v1." + projection.message))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "pub mod "+module+" {") {
			t.Fatalf("missing generated field module %s", module)
		}
		for constant, fieldName := range projection.fields {
			field := message.Fields().ByName(protoreflect.Name(fieldName))
			if field == nil || !strings.Contains(text, fmt.Sprintf("pub const %s: u32 = %d;", constant, field.Number())) {
				t.Fatalf("%s.%s does not match canonical descriptor", module, constant)
			}
		}
	}

	for _, enumName := range []string{"TrustedSourceAuthority", "DatasetClassificationKind", "DatasetMatchCoverage", "DatasetQueryStatus"} {
		if !strings.Contains(text, "pub enum "+enumName+" {") {
			t.Fatalf("missing generated wire enum %s", enumName)
		}
	}
}
