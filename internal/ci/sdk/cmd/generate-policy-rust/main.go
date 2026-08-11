package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type enumValue struct {
	RustName string
	Value    uint32
}

type templateData struct {
	DescriptorSHA256 string
	Fields           string
	ABIStatuses      []enumValue
	RuntimeErrors    []enumValue
	PolicyActions    []enumValue
	SecurityCodes    []enumValue
	SecurityActions  []enumValue
}

type messageProjection struct {
	RustModule string
	FullName   protoreflect.FullName
	Fields     [][2]string
}

func main() {
	output := flag.String("output", "crates/nre-policy-guest/src/abi_generated.rs", "generated Rust output")
	check := flag.Bool("check", false, "fail when the generated output is stale")
	flag.Parse()

	generated, err := generate()
	if err != nil {
		fatal(err)
	}
	formatted, err := rustfmt(generated)
	if err != nil {
		fatal(err)
	}
	if *check {
		current, err := os.ReadFile(*output)
		if err != nil {
			fatal(err)
		}
		if !bytes.Equal(current, formatted) {
			fatal(fmt.Errorf("%s is stale; run generate-policy-rust", *output))
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, formatted, 0o644); err != nil {
		fatal(err)
	}
}

func generate() ([]byte, error) {
	descriptors, err := protoschema.DescriptorSetBytes()
	if err != nil {
		return nil, err
	}
	fields, err := projectFields()
	if err != nil {
		return nil, err
	}
	data := templateData{
		DescriptorSHA256: fmt.Sprintf("%x", sha256.Sum256(descriptors)),
		Fields:           fields,
		ABIStatuses: []enumValue{
			{"Ok", uint32(pluginsdk.PolicyStatusOK)},
			{"InvalidArgument", uint32(pluginsdk.PolicyStatusInvalidArgument)},
			{"PermissionDenied", uint32(pluginsdk.PolicyStatusPermissionDenied)},
			{"ResourceExhausted", uint32(pluginsdk.PolicyStatusResourceExhausted)},
			{"DeadlineExceeded", uint32(pluginsdk.PolicyStatusDeadlineExceeded)},
			{"Unavailable", uint32(pluginsdk.PolicyStatusUnavailable)},
			{"IncompatibleAbi", uint32(pluginsdk.PolicyStatusIncompatibleABI)},
			{"Internal", uint32(pluginsdk.PolicyStatusInternal)},
		},
		RuntimeErrors: []enumValue{
			{"Unspecified", uint32(pluginsdk.ErrorUnspecified)},
			{"InvalidArgument", uint32(pluginsdk.ErrorInvalidArgument)},
			{"PermissionDenied", uint32(pluginsdk.ErrorPermissionDenied)},
			{"ResourceExhausted", uint32(pluginsdk.ErrorResourceExhausted)},
			{"DeadlineExceeded", uint32(pluginsdk.ErrorDeadlineExceeded)},
			{"Unavailable", uint32(pluginsdk.ErrorUnavailable)},
			{"IncompatibleAbi", uint32(pluginsdk.ErrorIncompatibleABI)},
			{"Internal", uint32(pluginsdk.ErrorInternal)},
		},
		PolicyActions: []enumValue{
			{"Unspecified", uint32(pluginsdk.PolicyActionUnspecified)},
			{"Allow", uint32(pluginsdk.PolicyActionAllow)},
			{"Deny", uint32(pluginsdk.PolicyActionDeny)},
			{"Observe", uint32(pluginsdk.PolicyActionObserve)},
		},
		SecurityCodes: []enumValue{
			{"Unspecified", uint32(pluginsdk.PolicySecurityEventCodeUnspecified)},
			{"WafRuleMatch", uint32(pluginsdk.PolicySecurityEventCodeWAFRuleMatch)},
		},
		SecurityActions: []enumValue{
			{"Unspecified", uint32(pluginsdk.PolicySecurityEventActionUnspecified)},
			{"Observe", uint32(pluginsdk.PolicySecurityEventActionObserve)},
			{"Deny", uint32(pluginsdk.PolicySecurityEventActionDeny)},
		},
	}
	if err := verifyDescriptorEnums(data); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := generatedTemplate.Execute(&output, data); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func projectFields() (string, error) {
	projections := []messageProjection{
		{"init_request", "nre.plugin.policy.v1.InitRequest", [][2]string{{"CONFIG", "config"}, {"GRANTED_SCOPES", "granted_scopes"}, {"GENERATION", "generation"}}},
		{"evaluate_request", "nre.plugin.policy.v1.EvaluateRequest", [][2]string{{"EXTENSION_POINT", "extension_point"}, {"REQUEST_ID", "request_id"}, {"PAYLOAD", "payload"}, {"NORMALIZED_HTTP", "normalized_http"}}},
		{"evaluate_response", "nre.plugin.policy.v1.EvaluateResponse", [][2]string{{"SUCCESS", "success"}, {"ERROR", "error"}}},
		{"evaluate_success", "nre.plugin.policy.v1.EvaluateSuccess", [][2]string{{"ACTION", "action"}, {"PAYLOAD", "payload"}}},
		{"runtime_error", "nre.plugin.policy.v1.RuntimeError", [][2]string{{"CODE", "code"}, {"MESSAGE", "message"}, {"RETRYABLE", "retryable"}}},
		{"read_field_request", "nre.plugin.policy.v1.ReadFieldRequest", [][2]string{{"NAME", "name"}}},
		{"read_normalized_http_request", "nre.plugin.policy.v1.ReadNormalizedHTTPRequest", [][2]string{}},
		{"normalized_http_response", "nre.plugin.policy.v1.NormalizedHTTPResponse", [][2]string{{"PATH", "path"}, {"QUERY", "query"}, {"HEADERS", "headers"}, {"TRUSTED_SOURCE", "trusted_source"}, {"TRUSTED_SOURCE_AUTHENTICATED", "trusted_source_authenticated"}, {"BODY_WINDOW_COMPLETE", "body_window_complete"}, {"BODY_WINDOW_LENGTH", "body_window_length"}}},
		{"read_body_window_request", "nre.plugin.policy.v1.ReadBodyWindowRequest", [][2]string{{"OFFSET", "offset"}, {"LENGTH", "length"}}},
		{"state_get_request", "nre.plugin.policy.v1.StateGetRequest", [][2]string{{"KEY", "key"}}},
		{"state_put_request", "nre.plugin.policy.v1.StatePutRequest", [][2]string{{"KEY", "key"}, {"VALUE", "value"}}},
		{"emit_event_request", "nre.plugin.policy.v1.EmitEventRequest", [][2]string{{"CODE", "code"}, {"ACTION", "action"}}},
		{"add_metric_request", "nre.plugin.policy.v1.AddMetricRequest", [][2]string{{"NAME", "name"}, {"DELTA", "delta"}}},
		{"bytes_response", "nre.plugin.policy.v1.BytesResponse", [][2]string{{"VALUE", "value"}, {"FOUND", "found"}}},
	}
	var output strings.Builder
	for _, projection := range projections {
		message, err := protoschema.Message(projection.FullName)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&output, "    pub mod %s {\n", projection.RustModule)
		for _, field := range projection.Fields {
			descriptor := message.Fields().ByName(protoreflect.Name(field[1]))
			if descriptor == nil {
				return "", fmt.Errorf("canonical message %s has no field %s", projection.FullName, field[1])
			}
			fmt.Fprintf(&output, "        pub const %s: u32 = %d;\n", field[0], descriptor.Number())
		}
		output.WriteString("    }\n")
	}
	return output.String(), nil
}

func verifyDescriptorEnums(data templateData) error {
	checks := []struct {
		Message protoreflect.FullName
		Field   protoreflect.Name
		Values  []enumValue
	}{
		{"nre.plugin.policy.v1.RuntimeError", "code", data.RuntimeErrors},
		{"nre.plugin.policy.v1.EvaluateSuccess", "action", data.PolicyActions},
		{"nre.plugin.policy.v1.EmitEventRequest", "code", data.SecurityCodes},
		{"nre.plugin.policy.v1.EmitEventRequest", "action", data.SecurityActions},
	}
	for _, check := range checks {
		message, err := protoschema.Message(check.Message)
		if err != nil {
			return err
		}
		enum := message.Fields().ByName(check.Field).Enum()
		if enum == nil || enum.Values().Len() != len(check.Values) {
			return fmt.Errorf("canonical enum projection changed for %s.%s", check.Message, check.Field)
		}
		for index, value := range check.Values {
			if uint32(enum.Values().Get(index).Number()) != value.Value {
				return fmt.Errorf("canonical enum value changed for %s.%s", check.Message, check.Field)
			}
		}
	}
	return nil
}

func rustfmt(input []byte) ([]byte, error) {
	executable, err := exec.LookPath("rustfmt")
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return nil, fmt.Errorf("locate rustfmt: %w", err)
		}
		executable = filepath.Join(home, ".cargo", "bin", "rustfmt")
		if _, statErr := os.Stat(executable); statErr != nil {
			executable += ".exe"
			if _, statErr = os.Stat(executable); statErr != nil {
				return nil, fmt.Errorf("locate rustfmt: %w", err)
			}
		}
	}
	command := exec.Command(executable, "--edition", "2024", "--emit", "stdout")
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rustfmt generated SDK projection: %w: %s", err, output)
	}
	return output, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

var generatedTemplate = template.Must(template.New("rust").Funcs(template.FuncMap{
	"map": func(values ...any) map[string]any {
		result := make(map[string]any, len(values)/2)
		for index := 0; index < len(values); index += 2 {
			result[values[index].(string)] = values[index+1]
		}
		return result
	},
}).Parse(`// Code generated by internal/ci/sdk from canonical public pluginsdk and protoschema; DO NOT EDIT.

pub const CANONICAL_DESCRIPTOR_SET_SHA256: &str = "{{.DescriptorSHA256}}";
pub const POLICY_ABI_V1: &str = "` + pluginsdk.PolicyABIV1 + `";
pub const ABI_MAJOR_VERSION: u32 = ` + fmt.Sprint(pluginsdk.PolicyABIMajorVersion) + `;

pub const EXPORT_VERSION: &str = "` + pluginsdk.PolicyExportVersion + `";
pub const EXPORT_ALLOCATE: &str = "` + pluginsdk.PolicyExportAllocate + `";
pub const EXPORT_FREE: &str = "` + pluginsdk.PolicyExportFree + `";
pub const EXPORT_INIT: &str = "` + pluginsdk.PolicyExportInit + `";
pub const EXPORT_EVALUATE: &str = "` + pluginsdk.PolicyExportEvaluate + `";
pub const EXPORT_RESET: &str = "` + pluginsdk.PolicyExportReset + `";
pub const EXPORT_MEMORY: &str = "` + pluginsdk.PolicyExportMemory + `";

pub const HOST_MODULE: &str = "` + pluginsdk.PolicyHostModule + `";
pub const HOST_READ_FIELD: &str = "` + pluginsdk.PolicyHostReadField + `";
pub const HOST_READ_NORMALIZED_HTTP: &str = "` + pluginsdk.PolicyHostReadNormalizedHTTP + `";
pub const HOST_READ_BODY_WINDOW: &str = "` + pluginsdk.PolicyHostReadBodyWindow + `";
pub const HOST_STATE_GET: &str = "` + pluginsdk.PolicyHostStateGet + `";
pub const HOST_STATE_PUT: &str = "` + pluginsdk.PolicyHostStatePut + `";
pub const HOST_EMIT_EVENT: &str = "` + pluginsdk.PolicyHostEmitEvent + `";
pub const HOST_ADD_METRIC: &str = "` + pluginsdk.PolicyHostAddMetric + `";

pub const MAX_TIMEOUT_MILLISECONDS: u32 = ` + fmt.Sprint(pluginsdk.PolicyV1MaxTimeoutMilliseconds) + `;
pub const MIN_MEMORY_BYTES: u64 = ` + fmt.Sprint(pluginsdk.PolicyV1MinMemoryBytes) + `;
pub const MAX_MEMORY_BYTES: u64 = ` + fmt.Sprint(pluginsdk.PolicyV1MaxMemoryBytes) + `;
pub const MAX_CONCURRENCY: u32 = ` + fmt.Sprint(pluginsdk.PolicyV1MaxConcurrency) + `;
pub const MIN_INPUT_FRAME_BYTES: usize = ` + fmt.Sprint(pluginsdk.PolicyV1MinInputFrameBytes) + `;
pub const MAX_INPUT_FRAME_BYTES: usize = ` + fmt.Sprint(pluginsdk.PolicyV1MaxInputFrameBytes) + `;
pub const MIN_OUTPUT_FRAME_BYTES: usize = ` + fmt.Sprint(pluginsdk.PolicyV1MinOutputFrameBytes) + `;
pub const MAX_OUTPUT_FRAME_BYTES: usize = ` + fmt.Sprint(pluginsdk.PolicyV1MaxOutputFrameBytes) + `;

pub const BUDGET_INPUT: &str = "` + string(pluginsdk.BudgetDimensionInput) + `";
pub const BUDGET_OUTPUT: &str = "` + string(pluginsdk.BudgetDimensionOutput) + `";
pub const BUDGET_MEMORY: &str = "` + string(pluginsdk.BudgetDimensionMemory) + `";
pub const BUDGET_CONCURRENCY: &str = "` + string(pluginsdk.BudgetDimensionConcurrency) + `";
pub const BUDGET_DEADLINE: &str = "` + string(pluginsdk.BudgetDimensionDeadline) + `";
pub const BUDGET_STATE: &str = "` + string(pluginsdk.BudgetDimensionState) + `";

{{define "enum"}}#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum {{.Name}} {
{{- range .Values}}
    {{.RustName}} = {{.Value}},
{{- end}}
}

impl {{.Name}} {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
{{- range .Values}}
            {{.Value}} => Some(Self::{{.RustName}}),
{{- end}}
            _ => None,
        }
    }
}
{{end}}
{{template "enum" (map "Name" "AbiStatus" "Values" .ABIStatuses)}}
{{template "enum" (map "Name" "RuntimeErrorCode" "Values" .RuntimeErrors)}}
impl RuntimeErrorCode {
    pub const fn is_failure(self) -> bool { !matches!(self, Self::Unspecified) }
}
{{template "enum" (map "Name" "PolicyAction" "Values" .PolicyActions)}}
impl PolicyAction {
    pub const fn is_decision(self) -> bool { !matches!(self, Self::Unspecified) }
}
{{template "enum" (map "Name" "SecurityEventCode" "Values" .SecurityCodes)}}
{{template "enum" (map "Name" "SecurityEventAction" "Values" .SecurityActions)}}

pub mod field {
{{.Fields}}}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "` + pluginsdk.PolicyHostModule + `")]
unsafe extern "C" {
    pub(crate) fn ` + pluginsdk.PolicyHostReadField + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostReadNormalizedHTTP + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostReadBodyWindow + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostStateGet + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostStatePut + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostEmitEvent + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
    pub(crate) fn ` + pluginsdk.PolicyHostAddMetric + `(request_ptr: u32, request_len: u32, response_ptr: u32, response_capacity: u32) -> u64;
}
`))
