package hostfixture

import (
	"bytes"
	"context"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
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

func TestWAFDefaultObserveOverlayAndExpandedManagedRules(t *testing.T) {
	artifact := buildWAFArtifact(t)
	if status, action := runWAFArtifact(t, artifact, []byte(`{}`), "/etc/passwd", nil, true); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionObserve {
		t.Fatalf("default observe /etc/passwd = status %d action %d", status, action)
	}
	if status, action := runWAFArtifact(t, artifact, []byte(`{}`), "/safe", nil, true); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionAllow {
		t.Fatalf("default observe benign = status %d action %d", status, action)
	}
	if status, action := runWAFArtifactWith(t, artifact, wafArtifactOptions{
		config: []byte(`{}`), path: "/etc/passwd", complete: true, overlay: []byte(`{"mode":"deny"}`),
	}); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionDeny {
		t.Fatalf("deny overlay = status %d action %d", status, action)
	}
	if status, action := runWAFArtifactWith(t, artifact, wafArtifactOptions{
		config: []byte(`{"mode":"deny"}`), path: "/etc/passwd", complete: true, overlay: []byte(`{"mode":"observe"}`),
	}); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionObserve {
		t.Fatalf("observe overlay = status %d action %d", status, action)
	}
	if status, action := runWAFArtifactWith(t, artifact, wafArtifactOptions{
		config: []byte(`{}`), path: "/", query: "q=1 OR 1=1", complete: true,
	}); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionObserve {
		t.Fatalf("expanded sqli observe = status %d action %d", status, action)
	}
	if status, action := runWAFArtifactWith(t, artifact, wafArtifactOptions{
		config:   []byte(`{}`),
		path:     "/",
		headers:  []byte("${jndi:ldap://evil}"),
		complete: true,
	}); status != pluginsdk.PolicyStatusOK || action != pluginsdk.PolicyActionObserve {
		t.Fatalf("expanded log4j observe = status %d action %d", status, action)
	}

	session, status := startWAFArtifact(t, artifact, wafArtifactOptions{
		config: []byte(`{}`), path: "/etc/passwd", complete: true, overlay: []byte(`{"mode":"block"}`),
	})
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK {
		t.Fatalf("invalid overlay init status = %d", status)
	}
	if !session.EvaluateHasError() {
		t.Fatal("invalid overlay evaluate succeeded")
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

func TestWAFArtifactHostCallsAreDemandDriven(t *testing.T) {
	artifact := buildWAFArtifact(t)

	t.Run("allow", func(t *testing.T) {
		session, status := initPolicyArtifact(t, artifact, []byte(`{"mode":"deny"}`), "/safe", nil, true)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionAllow {
			t.Fatalf("allow evaluation status = %d", status)
		}
		for _, name := range []string{pluginsdk.PolicyHostStateGet, pluginsdk.PolicyHostStatePut} {
			if calls := session.HostCalls(name); calls != 0 {
				t.Fatalf("%s calls = %d, want 0", name, calls)
			}
		}
		for _, field := range []string{"method", "site"} {
			if calls := session.FieldCalls(field); calls != 0 {
				t.Fatalf("read_field(%q) calls = %d, want 0", field, calls)
			}
		}
		if len(session.lastPayload) != 0 {
			t.Fatalf("ALLOW payload = %q, want empty", session.lastPayload)
		}
		if calls := session.HostCalls(pluginsdk.PolicyHostReadNormalizedHTTP); calls != 0 {
			t.Fatalf("normalized HTTP calls = %d, want 0", calls)
		}
		if calls := session.TotalHostCalls(); calls != 0 {
			t.Fatalf("ALLOW host calls = %d, want 0", calls)
		}
	})

	t.Run("snapshot import fallback", func(t *testing.T) {
		session, status := initPolicyArtifact(t, artifact, []byte(`{"mode":"deny"}`), "/safe", nil, true)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK || session.EvaluateWithImportFallback() != pluginsdk.PolicyActionAllow {
			t.Fatalf("fallback evaluation status = %d", status)
		}
		if calls := session.HostCalls(pluginsdk.PolicyHostReadNormalizedHTTP); calls != 1 {
			t.Fatalf("normalized HTTP fallback calls = %d, want 1", calls)
		}
		if calls := session.TotalHostCalls(); calls != 1 {
			t.Fatalf("fallback host calls = %d, want 1", calls)
		}
	})

	t.Run("path match", func(t *testing.T) {
		config := []byte(`{"mode":"deny","custom_rules":[{"id":"path-probe","target":"path","needle":"probe"}]}`)
		session, status := initPolicyArtifact(t, artifact, config, "/probe", nil, true)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionDeny {
			t.Fatalf("path evaluation status = %d", status)
		}
		if calls := session.HostCalls(pluginsdk.PolicyHostReadBodyWindow); calls != 0 {
			t.Fatalf("read_body_window calls = %d, want 0", calls)
		}
		if calls := session.FieldCalls("body_window_complete"); calls != 0 {
			t.Fatalf("body_window_complete calls = %d, want 0", calls)
		}
		if calls := session.TotalHostCalls(); calls != 2 {
			t.Fatalf("path match host calls = %d, want 2", calls)
		}
	})

	t.Run("body rule excluded", func(t *testing.T) {
		config := []byte(`{"mode":"deny","exclusions":[{"rule_id":"managed-xss-script","path_prefix":"/"},{"rule_id":"managed-xss-iframe","path_prefix":"/"},{"rule_id":"managed-xss-svg","path_prefix":"/"},{"rule_id":"managed-sqli-union-body","path_prefix":"/"}]}`)
		session, status := initPolicyArtifact(t, artifact, config, "/safe", nil, true)
		defer session.Close()
		if status != pluginsdk.PolicyStatusOK || session.Evaluate() != pluginsdk.PolicyActionAllow {
			t.Fatalf("excluded body evaluation status = %d", status)
		}
		if calls := session.HostCalls(pluginsdk.PolicyHostReadBodyWindow); calls != 0 {
			t.Fatalf("read_body_window calls = %d, want 0", calls)
		}
		if calls := session.TotalHostCalls(); calls != 0 {
			t.Fatalf("excluded body host calls = %d, want 0", calls)
		}
	})
}

type wafArtifactOptions struct {
	config   []byte
	path     string
	query    string
	headers  []byte
	body     []byte
	complete bool
	overlay  []byte
}

type policyArtifactSession struct {
	t              *testing.T
	ctx            context.Context
	runtime        wazero.Runtime
	guest          api.Module
	evaluateCount  int
	eventCount     int
	statePutCount  int
	hostCalls      map[string]int
	fieldCalls     map[string]int
	lastPayload    []byte
	normalizedHTTP []byte
	overlay        []byte
}

func runWAFArtifact(t *testing.T, artifact, config []byte, path string, body []byte, complete bool) (pluginsdk.PolicyStatus, pluginsdk.PolicyAction) {
	t.Helper()
	return runWAFArtifactWith(t, artifact, wafArtifactOptions{config: config, path: path, body: body, complete: complete})
}

func runWAFArtifactWith(t *testing.T, artifact []byte, options wafArtifactOptions) (pluginsdk.PolicyStatus, pluginsdk.PolicyAction) {
	t.Helper()
	session, status := startWAFArtifact(t, artifact, options)
	defer session.Close()
	if status != pluginsdk.PolicyStatusOK {
		return status, pluginsdk.PolicyActionUnspecified
	}
	return status, session.Evaluate()
}

func initPolicyArtifact(t *testing.T, artifact, config []byte, path string, body []byte, complete bool) (*policyArtifactSession, pluginsdk.PolicyStatus) {
	t.Helper()
	return startWAFArtifact(t, artifact, wafArtifactOptions{config: config, path: path, body: body, complete: complete})
}

func startWAFArtifact(t *testing.T, artifact []byte, options wafArtifactOptions) (*policyArtifactSession, pluginsdk.PolicyStatus) {
	t.Helper()
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(api.CoreFeaturesV2))
	session := &policyArtifactSession{t: t, ctx: ctx, runtime: runtime, hostCalls: make(map[string]int), fieldCalls: make(map[string]int), overlay: options.overlay}
	headers := options.headers
	if headers == nil {
		headers = []byte("content-type: application/octet-stream")
	}
	path, body, complete := options.path, options.body, options.complete
	fields := map[string][]byte{
		"site":                         []byte("site-a"),
		"method":                       []byte("POST"),
		"path":                         []byte(path),
		"query":                        []byte(options.query),
		"headers":                      headers,
		"trusted_source":               []byte("192.0.2.10"),
		"trusted_source_authenticated": []byte("true"),
		"body_window_complete":         []byte(map[bool]string{true: "true", false: "false"}[complete]),
	}
	host := runtime.NewHostModuleBuilder(pluginsdk.PolicyHostModule)
	for name, signature := range pluginsdk.PolicyV1HostFunctions() {
		name := name
		host.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(_ context.Context, module api.Module, stack []uint64) {
			session.hostCalls[name]++
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
				field := wafMessageString(t, message, "name")
				session.fieldCalls[field]++
				value, found := fields[field]
				response, err = marshalWAFBytesResponse(value, found)
			case pluginsdk.PolicyHostReadNormalizedHTTP:
				response, err = marshalWAFNormalizedHTTPResponse(path, options.query, fields["headers"], fields["trusted_source"], len(body), complete)
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
	session.normalizedHTTP, err = marshalWAFNormalizedHTTPResponse(
		path, options.query, fields["headers"], fields["trusted_source"], len(body), complete,
	)
	if err != nil {
		t.Fatal(err)
	}
	initWire := marshalWAFInit(t, options.config)
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
	return session.evaluate(session.normalizedHTTP)
}

func (session *policyArtifactSession) EvaluateWithImportFallback() pluginsdk.PolicyAction {
	return session.evaluate(nil)
}

func (session *policyArtifactSession) EvaluateHasError() bool {
	session.t.Helper()
	message := session.evaluateResponse(session.normalizedHTTP)
	return message.ProtoReflect().Has(wafField(session.t, message, "error"))
}

func (session *policyArtifactSession) evaluate(normalizedHTTP []byte) pluginsdk.PolicyAction {
	session.t.Helper()
	message := session.evaluateResponse(normalizedHTTP)
	successField := wafField(session.t, message, "success")
	if !message.ProtoReflect().Has(successField) {
		session.t.Fatalf("evaluate response has no success: %v", message)
	}
	success := message.ProtoReflect().Get(successField).Message()
	actionField := success.Descriptor().Fields().ByName("action")
	if actionField == nil {
		session.t.Fatal("canonical EvaluateSuccess.action is missing")
	}
	payloadField := success.Descriptor().Fields().ByName("payload")
	if payloadField == nil {
		session.t.Fatal("canonical EvaluateSuccess.payload is missing")
	}
	session.lastPayload = append(session.lastPayload[:0], success.Get(payloadField).Bytes()...)
	return pluginsdk.PolicyAction(success.Get(actionField).Enum())
}

func (session *policyArtifactSession) evaluateResponse(normalizedHTTP []byte) *dynamicpb.Message {
	session.t.Helper()
	session.evaluateCount++
	evaluateWire := marshalWAFEvaluate(session.t, normalizedHTTP, session.overlay)
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
	return decodeWAFPolicyMessage(session.t, "EvaluateResponse", output)
}

func (session *policyArtifactSession) HostCalls(name string) int {
	return session.hostCalls[name]
}

func (session *policyArtifactSession) FieldCalls(name string) int {
	return session.fieldCalls[name]
}

func (session *policyArtifactSession) TotalHostCalls() int {
	total := 0
	for _, calls := range session.hostCalls {
		total += calls
	}
	return total
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

func marshalWAFEvaluate(t *testing.T, normalizedHTTP, overlay []byte) []byte {
	message := newWAFPolicyMessage(t, "EvaluateRequest")
	message.ProtoReflect().Set(wafField(t, message, "extension_point"), protoreflect.ValueOfString("http.request"))
	message.ProtoReflect().Set(wafField(t, message, "request_id"), protoreflect.ValueOfString("waf-request-1"))
	if len(normalizedHTTP) != 0 {
		message.ProtoReflect().Set(
			wafField(t, message, "normalized_http"),
			protoreflect.ValueOfBytes(normalizedHTTP),
		)
	}
	if len(overlay) != 0 {
		message.ProtoReflect().Set(wafField(t, message, "payload"), protoreflect.ValueOfBytes(overlay))
	}
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

func marshalWAFNormalizedHTTPResponse(path, query string, headers, source []byte, bodyLength int, complete bool) ([]byte, error) {
	descriptor, err := protoschema.Message("nre.plugin.policy.v1.NormalizedHTTPResponse")
	if err != nil {
		return nil, err
	}
	message := dynamicpb.NewMessage(descriptor)
	message.Set(descriptor.Fields().ByName("path"), protoreflect.ValueOfBytes([]byte(path)))
	if query != "" {
		message.Set(descriptor.Fields().ByName("query"), protoreflect.ValueOfBytes([]byte(query)))
	}
	message.Set(descriptor.Fields().ByName("headers"), protoreflect.ValueOfBytes(headers))
	message.Set(descriptor.Fields().ByName("trusted_source"), protoreflect.ValueOfBytes(source))
	message.Set(descriptor.Fields().ByName("trusted_source_authenticated"), protoreflect.ValueOfBool(true))
	message.Set(descriptor.Fields().ByName("body_window_complete"), protoreflect.ValueOfBool(complete))
	message.Set(descriptor.Fields().ByName("body_window_length"), protoreflect.ValueOfUint32(uint32(bodyLength)))
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
