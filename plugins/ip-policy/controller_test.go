package ippolicy

import (
	"context"
	"encoding/json"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type runtimeStub struct {
	policyCalls  []pluginsdk.PolicyControlRequest
	bindingCalls []pluginsdk.DatasetBindingRequest
}

func (runtime *runtimeStub) ControlPolicy(_ context.Context, request pluginsdk.PolicyControlRequest) (pluginsdk.PolicyControlResponse, error) {
	runtime.policyCalls = append(runtime.policyCalls, request)
	mode := pluginsdk.PolicyModeObserve
	return pluginsdk.PolicyControlResponse{InstanceID: "ip-instance", Stage: pluginsdk.PolicyStageIdentity{Kind: "ip", PolicyID: "ip-instance"}, Entry: request.Entry, Desired: pluginsdk.PolicySettingsSnapshot{Version: pluginsdk.PolicySettingsVersion{Revision: 2, InstanceVersion: 7}, Settings: pluginsdk.PolicyModeSettings{Handling: pluginsdk.PolicyModeHandlingRaw, DefaultMode: &mode}}}, nil
}

func (runtime *runtimeStub) ManageDatasetBinding(_ context.Context, request pluginsdk.DatasetBindingRequest) (pluginsdk.DatasetBindingResponse, error) {
	runtime.bindingCalls = append(runtime.bindingCalls, request)
	if request.Action == pluginsdk.DatasetBindingInspect {
		return pluginsdk.DatasetBindingResponse{InstanceID: request.InstanceID, SourceID: request.SourceID, Targets: []pluginsdk.DatasetBindingTargetStatus{}}, nil
	}
	return pluginsdk.DatasetBindingResponse{OperationID: request.OperationID, InstanceID: request.InstanceID, SourceID: request.SourceID, Revision: 1, InstanceRevision: 8, PolicyRevision: 3, Desired: &pluginsdk.DatasetBindingRecord{InstanceID: request.InstanceID, SourceID: request.SourceID, Revision: 1, Targets: request.Targets, Spec: *request.Spec}, Targets: []pluginsdk.DatasetBindingTargetStatus{}}, nil
}
func (*runtimeStub) ControlDataset(_ context.Context, operation string, request pluginsdk.DatasetControlRequest) (pluginsdk.DatasetControlResponse, error) {
	return pluginsdk.DatasetControlResponse{OperationID: operation, SourceID: request.SourceID}, nil
}
func (*runtimeStub) DatasetStatus(context.Context, pluginsdk.DatasetStatusRequest) (pluginsdk.DatasetStatusResponse, error) {
	return pluginsdk.DatasetStatusResponse{}, nil
}
func (*runtimeStub) DatasetCatalog(context.Context, pluginsdk.DatasetCatalogRequest) (pluginsdk.DatasetCatalogResponse, error) {
	return pluginsdk.DatasetCatalogResponse{}, nil
}
func (*runtimeStub) Call(context.Context, pluginsdk.HostRuntimeCall, any) error { return nil }

func TestDatasetBindingCommitsConfigAndDefaultModeAtomically(t *testing.T) {
	runtime := &runtimeStub{}
	controller, err := NewController(ControllerConfig{Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	config := validConfiguration()
	response, err := controller.bindDatasetAtomic(t.Context(), BindingMutation{SourceID: "dbip-cn-province", VersionDigest: "sha256:" + stringsOf("a", 64), DatasetID: "province-data", Mode: "observe", Config: config})
	if err != nil {
		t.Fatal(err)
	}
	if response.InstanceRevision != 8 || len(runtime.policyCalls) != 1 || len(runtime.bindingCalls) != 2 {
		t.Fatalf("calls policy=%d binding=%d response=%+v", len(runtime.policyCalls), len(runtime.bindingCalls), response)
	}
	mutation := runtime.bindingCalls[1]
	if mutation.InstanceUpdate == nil || mutation.InstanceUpdate.PolicyDefaults == nil || len(mutation.InstanceUpdate.Config) == 0 || mutation.InstanceUpdate.ExpectedRevision != 7 || mutation.InstanceUpdate.PolicyDefaults.ExpectedRevision != 2 {
		t.Fatalf("atomic mutation = %+v", mutation)
	}
	var persisted Configuration
	if err := json.Unmarshal(mutation.InstanceUpdate.Config, &persisted); err != nil || persisted.Schema != ConfigSchema {
		t.Fatalf("atomic config = %+v, %v", persisted, err)
	}
}

func stringsOf(value string, count int) string {
	result := ""
	for len(result) < count {
		result += value
	}
	return result[:count]
}
