package hostfixture

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
	ciwasm "github.com/sakullla/sakullla-plugins/internal/ci/wasm"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestWAFStreamingBodyWindowObserveDenyBudgetGeneration(t *testing.T) {
	artifact := buildWAFArtifact(t)
	if err := pluginsdk.ValidatePolicyV1WASM(artifact, pluginsdk.PolicyV1MaxMemoryBytes); err != nil {
		t.Fatalf("WAF artifact violates canonical nre:policy/v1 ABI: %v", err)
	}
	if bytes.Contains(artifact, []byte("wasi_snapshot_preview1")) {
		t.Fatal("WAF artifact unexpectedly imports WASI")
	}
}

func TestWAFArtifactInitEvaluateConfigAndBodyWindowBoundaries(t *testing.T) {
	artifact := buildWAFArtifact(t)
	denyWithObserveNeedle := []byte(`{"mode":"deny","custom_rules":[{"id":"observe-probe","target":"path","needle":"observe"}],"exclusions":[{"rule_id":"observe-probe","path_prefix":"/allowed"}]}`)
	if status, action := runWAFArtifact(t, artifact, denyWithObserveNeedle, "/observe", nil, true); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionDeny {
		t.Fatalf("deny custom rule = status %d action %d", status, action)
	}
	if status, action := runWAFArtifact(t, artifact, denyWithObserveNeedle, "/allowed/observe", nil, true); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionAllow {
		t.Fatalf("excluded custom rule = status %d action %d", status, action)
	}
	if status, _ := runWAFArtifact(t, artifact, []byte(`{"mode":"deny","unknown":true}`), "/", nil, true); status != pluginsdk.PolicyStatusInvalidArgument {
		t.Fatalf("invalid config init status = %d", status)
	}

	complete := bytes.Repeat([]byte{'a'}, 4088)
	copy(complete[len(complete)-len("<script"):], []byte("<script"))
	if status, action := runWAFArtifact(t, artifact, []byte(`{"mode":"deny"}`), "/upload", complete, true); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionDeny {
		t.Fatalf("complete 4088-byte window = status %d action %d", status, action)
	}
	truncated := bytes.Repeat([]byte{'a'}, 4089)
	if status, action := runWAFArtifact(t, artifact, []byte(`{"mode":"deny"}`), "/upload", truncated, false); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionObserve {
		t.Fatalf("truncated 4089-byte body = status %d action %d", status, action)
	}
}

func TestWAFArtifactResetPreservesInitializedGenerationConfig(t *testing.T) {
	artifact := buildWAFArtifact(t)
	observeWithCustomRule := []byte(`{"mode":"observe","custom_rules":[{"id":"reset-probe","target":"path","needle":"reset-probe"}]}`)
	session, status := initPolicyArtifact(t, artifact, observeWithCustomRule, "/reset-probe", nil, true)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK {
		t.Fatalf("init status = %d", status)
	}
	for evaluation := 1; evaluation <= 3; evaluation++ {
		if action := session.Evaluate(); action != pluginsdk.PolicyActionObserve {
			t.Fatalf("evaluation %d after one init = action %d, want observe", evaluation, action)
		}
		if evaluation < 3 {
			session.Reset()
		}
	}
}

func buildWAFArtifact(t *testing.T) []byte {
	t.Helper()
	repositoryRoot := filepath.Clean(filepath.Join(testSourceDirectory(t), "..", ".."))
	cargo := testCargo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, args := range [][]string{
		{"test", "-p", "sakullla-waf", "--locked"},
		{"build", "-p", "sakullla-waf", "--target", "wasm32v1-none", "--release", "--locked"},
	} {
		command := exec.CommandContext(ctx, cargo, args...)
		command.Dir = repositoryRoot
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cargo %v failed: %v\n%s", args, err, output)
		}
	}
	artifactPath := filepath.Join(repositoryRoot, "target", "wasm32v1-none", "release", "sakullla_waf.wasm")
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = ciwasm.NormalizeEmptyFunctionTable(artifact)
	if err != nil {
		t.Fatalf("normalize empty rust-lld function table: %v", err)
	}
	return artifact
}

type policyArtifactSession struct {
	t             *testing.T
	ctx           context.Context
	runtime       wazero.Runtime
	guest         api.Module
	evaluateCount int
	eventCount    int
	statePutCount int
}

func runWAFArtifact(t *testing.T, artifact, config []byte, path string, body []byte, complete bool) (pluginsdk.PolicyStatus, pluginsdk.PolicyAction) {
	t.Helper()
	session, status := initPolicyArtifact(t, artifact, config, path, body, complete)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK {
		return status, pluginsdk.PolicyActionUnspecified
	}
	return status, session.Evaluate()
}

func initPolicyArtifact(t *testing.T, artifact, config []byte, path string, body []byte, complete bool) (*policyArtifactSession, pluginsdk.PolicyStatus) {
	t.Helper()
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(api.CoreFeaturesV1))
	session := &policyArtifactSession{t: t, ctx: ctx, runtime: runtime}
	fields := map[string][]byte{
		"site":                         []byte("site-a"),
		"method":                       []byte("POST"),
		"path":                         []byte(path),
		"query":                        nil,
		"headers":                      []byte("content-type: application/octet-stream"),
		"trusted_source":               []byte("192.0.2.10"),
		"trusted_source_authenticated": []byte("true"),
		"body_window_complete":         []byte(map[bool]string{true: "true", false: "false"}[complete]),
	}
	host := runtime.NewHostModuleBuilder(pluginsdk.PolicyHostModule)
	for name, signature := range pluginsdk.PolicyV1HostFunctions() {
		name := name
		host.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, module api.Module, stack []uint64) {
			requestPointer, requestLength := api.DecodeU32(stack[0]), api.DecodeU32(stack[1])
			responsePointer, responseCapacity := api.DecodeU32(stack[2]), api.DecodeU32(stack[3])
			request, ok := module.Memory().Read(requestPointer, requestLength)
			if !ok {
				stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusInvalidArgument, 0)
				return
			}
			var response []byte
			var err error
			switch name {
			case pluginsdk.PolicyHostReadField:
				message := decodeWAFPolicyMessage(t, "ReadFieldRequest", request)
				value, found := fields[wafMessageString(t, message, "name")]
				response, err = marshalWAFBytesResponse(value, found)
			case pluginsdk.PolicyHostReadBodyWindow:
				message := decodeWAFPolicyMessage(t, "ReadBodyWindowRequest", request)
				limit := int(wafMessageUint(t, message, "length"))
				if limit > len(body) {
					limit = len(body)
				}
				response, err = marshalWAFBytesResponse(body[:limit], true)
			case pluginsdk.PolicyHostStateGet:
				response, err = marshalWAFBytesResponse(nil, true)
			case pluginsdk.PolicyHostStatePut:
				session.statePutCount++
				response = nil
			case pluginsdk.PolicyHostEmitEvent:
				session.eventCount++
				response = nil
			case pluginsdk.PolicyHostAddMetric:
				response = nil
			default:
				stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusInvalidArgument, 0)
				return
			}
			if err != nil {
				stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusInternal, 0)
				return
			}
			if len(response) > int(responseCapacity) {
				stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusResourceExhausted, uint32(len(response)))
				return
			}
			if len(response) != 0 && !module.Memory().Write(responsePointer, response) {
				stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusInvalidArgument, 0)
				return
			}
			stack[0] = pluginsdk.PackPolicyHostResult(pluginsdk.PolicyStatusOK, uint32(len(response)))
		}), wafValueTypes(t, signature.Parameters), wafValueTypes(t, signature.Results)).Export(name)
	}
	if _, err := host.Instantiate(ctx); err != nil {
		t.Fatal(err)
	}
	guest, err := runtime.Instantiate(ctx, artifact)
	if err != nil {
		t.Fatal(err)
	}
	session.guest = guest
	initWire := marshalWAFInit(t, config)
	initPointer := wafAllocateAndWrite(t, ctx, guest, initWire)
	result, err := guest.ExportedFunction(pluginsdk.PolicyExportInit).Call(ctx, uint64(initPointer), uint64(len(initWire)))
	if err != nil || len(result) != 1 {
		t.Fatalf("init call = %v, %v", result, err)
	}
	status := pluginsdk.PolicyStatus(uint32(result[0]))
	return session, status
}

func (session *policyArtifactSession) Close() {
	if session.guest != nil {
		_ = session.guest.Close(session.ctx)
	}
	_ = session.runtime.Close(session.ctx)
}

func (session *policyArtifactSession) Evaluate() pluginsdk.PolicyAction {
	session.t.Helper()
	session.evaluateCount++
	evaluateWire := marshalWAFEvaluate(session.t)
	evaluatePointer := wafAllocateAndWrite(session.t, session.ctx, session.guest, evaluateWire)
	result, err := session.guest.ExportedFunction(pluginsdk.PolicyExportEvaluate).Call(session.ctx, uint64(evaluatePointer), uint64(len(evaluateWire)))
	if err != nil || len(result) != 1 {
		session.t.Fatalf("evaluate call = %v, %v", result, err)
	}
	outputPointer, outputLength := pluginsdk.UnpackPolicyBuffer(result[0])
	output, ok := session.guest.Memory().Read(outputPointer, outputLength)
	if !ok {
		session.t.Fatal("evaluate returned invalid output range")
	}
	message := decodeWAFPolicyMessage(session.t, "EvaluateResponse", output)
	successField := wafField(session.t, message, "success")
	if !message.ProtoReflect().Has(successField) {
		session.t.Fatalf("evaluate response has no success: %v", message)
	}
	success := message.ProtoReflect().Get(successField).Message()
	actionField := success.Descriptor().Fields().ByName("action")
	if actionField == nil {
		session.t.Fatal("canonical EvaluateSuccess.action is missing")
	}
	return pluginsdk.PolicyAction(success.Get(actionField).Enum())
}

func (session *policyArtifactSession) Reset() {
	session.t.Helper()
	result, err := session.guest.ExportedFunction(pluginsdk.PolicyExportReset).Call(session.ctx)
	if err != nil || len(result) != 1 {
		session.t.Fatalf("reset call = %v, %v", result, err)
	}
	if status := pluginsdk.PolicyStatus(uint32(result[0])); status != pluginsdk.PolicyStatusOK {
		session.t.Fatalf("reset status = %d", status)
	}
}

func marshalWAFInit(t *testing.T, config []byte) []byte {
	message := newWAFPolicyMessage(t, "InitRequest")
	message.ProtoReflect().Set(wafField(t, message, "config"), protoreflect.ValueOfBytes(config))
	grants := message.ProtoReflect().Mutable(wafField(t, message, "granted_scopes")).List()
	for _, grant := range []string{"policy.read-normalized-http", "policy.read-body-window", "policy.emit-event", "policy.add-metric"} {
		grants.Append(protoreflect.ValueOfString(grant))
	}
	message.ProtoReflect().Set(wafField(t, message, "generation"), protoreflect.ValueOfString("waf-test-1"))
	return marshalWAFMessage(t, message)
}

func marshalWAFEvaluate(t *testing.T) []byte {
	message := newWAFPolicyMessage(t, "EvaluateRequest")
	message.ProtoReflect().Set(wafField(t, message, "extension_point"), protoreflect.ValueOfString("http.request"))
	message.ProtoReflect().Set(wafField(t, message, "request_id"), protoreflect.ValueOfString("waf-request-1"))
	return marshalWAFMessage(t, message)
}

func marshalWAFBytesResponse(value []byte, found bool) ([]byte, error) {
	descriptor, err := protoschema.Message("nre.plugin.policy.v1.BytesResponse")
	if err != nil {
		return nil, err
	}
	message := dynamicpb.NewMessage(descriptor)
	message.Set(descriptor.Fields().ByName("value"), protoreflect.ValueOfBytes(value))
	message.Set(descriptor.Fields().ByName("found"), protoreflect.ValueOfBool(found))
	return (proto.MarshalOptions{Deterministic: true}).Marshal(message)
}

func newWAFPolicyMessage(t *testing.T, name protoreflect.Name) *dynamicpb.Message {
	t.Helper()
	descriptor, err := protoschema.Message(protoreflect.FullName("nre.plugin.policy.v1." + string(name)))
	if err != nil {
		t.Fatal(err)
	}
	return dynamicpb.NewMessage(descriptor)
}

func decodeWAFPolicyMessage(t *testing.T, name protoreflect.Name, wire []byte) *dynamicpb.Message {
	t.Helper()
	message := newWAFPolicyMessage(t, name)
	if err := proto.Unmarshal(wire, message); err != nil {
		t.Fatal(err)
	}
	return message
}

func marshalWAFMessage(t *testing.T, message proto.Message) []byte {
	t.Helper()
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func wafField(t *testing.T, message protoreflect.ProtoMessage, name protoreflect.Name) protoreflect.FieldDescriptor {
	t.Helper()
	field := message.ProtoReflect().Descriptor().Fields().ByName(name)
	if field == nil {
		t.Fatalf("canonical field %s.%s is missing", message.ProtoReflect().Descriptor().FullName(), name)
	}
	return field
}

func wafMessageString(t *testing.T, message protoreflect.ProtoMessage, name protoreflect.Name) string {
	return message.ProtoReflect().Get(wafField(t, message, name)).String()
}

func wafMessageUint(t *testing.T, message protoreflect.ProtoMessage, name protoreflect.Name) uint64 {
	return message.ProtoReflect().Get(wafField(t, message, name)).Uint()
}

func wafAllocateAndWrite(t *testing.T, ctx context.Context, guest api.Module, wire []byte) uint32 {
	t.Helper()
	result, err := guest.ExportedFunction(pluginsdk.PolicyExportAllocate).Call(ctx, uint64(len(wire)))
	if err != nil || len(result) != 1 {
		t.Fatalf("allocate = %v, %v", result, err)
	}
	pointer := uint32(result[0])
	if pointer == 0 || !guest.Memory().Write(pointer, wire) {
		t.Fatalf("allocator returned unusable pointer %d", pointer)
	}
	return pointer
}

func wafValueTypes(t *testing.T, values []pluginsdk.WASMValueType) []api.ValueType {
	t.Helper()
	result := make([]api.ValueType, len(values))
	for index, value := range values {
		switch value {
		case pluginsdk.WASMI32:
			result[index] = api.ValueTypeI32
		case pluginsdk.WASMI64:
			result[index] = api.ValueTypeI64
		default:
			t.Fatalf("unsupported canonical wasm value type %d", value)
		}
	}
	return result
}

func testSourceDirectory(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate WAF host fixture source")
	}
	return filepath.Dir(source)
}

func testCargo(t *testing.T) string {
	t.Helper()
	if cargo, err := exec.LookPath("cargo"); err == nil {
		return cargo
	}
	home, err := os.UserHomeDir()
	if err == nil {
		cargo := filepath.Join(home, ".cargo", "bin", "cargo")
		if runtime.GOOS == "windows" {
			cargo += ".exe"
		}
		if _, err := os.Stat(cargo); err == nil {
			return cargo
		}
	}
	t.Fatal("cargo is required for WAF host fixture")
	return ""
}
