package ippolicy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

type runtimeStub struct {
	policyCalls     []pluginsdk.PolicyControlRequest
	bindingCalls    []pluginsdk.DatasetBindingRequest
	entries         []pluginsdk.PolicyEntrySnapshot
	revision        uint64
	instanceVersion uint64
	defaultMode     pluginsdk.PolicyMode
	policyErr       error
	staleResponse   bool
}

func (runtime *runtimeStub) policyState() (pluginsdk.PolicyStageIdentity, pluginsdk.PolicySettingsSnapshot) {
	if runtime.revision == 0 {
		runtime.revision = 2
	}
	if runtime.instanceVersion == 0 {
		runtime.instanceVersion = 7
	}
	if runtime.defaultMode == "" {
		runtime.defaultMode = pluginsdk.PolicyModeObserve
	}
	stage := pluginsdk.PolicyStageIdentity{Kind: pluginsdk.PolicyOverlayStageIP, PolicyID: "ip-instance"}
	desired := pluginsdk.PolicySettingsSnapshot{Version: pluginsdk.PolicySettingsVersion{Revision: runtime.revision, InstanceVersion: runtime.instanceVersion}, Settings: pluginsdk.PolicyModeSettings{Handling: pluginsdk.PolicyModeHandlingRaw, DefaultMode: &runtime.defaultMode}}
	return stage, desired
}

func (runtime *runtimeStub) refreshEntryVersions(desired pluginsdk.PolicySettingsSnapshot) {
	for index := range runtime.entries {
		entryMode := runtime.entries[index].Desired.Settings.EntryMode
		runtime.entries[index].Desired = desired
		runtime.entries[index].Desired.Settings.EntryMode = entryMode
	}
}

func (runtime *runtimeStub) ControlPolicy(_ context.Context, request pluginsdk.PolicyControlRequest) (pluginsdk.PolicyControlResponse, error) {
	runtime.policyCalls = append(runtime.policyCalls, request)
	if runtime.policyErr != nil {
		return pluginsdk.PolicyControlResponse{}, runtime.policyErr
	}
	stage, desired := runtime.policyState()
	runtime.refreshEntryVersions(desired)
	response := pluginsdk.PolicyControlResponse{InstanceID: "ip-instance", Stage: stage, Entry: request.Entry, Desired: desired}
	switch request.Action {
	case pluginsdk.PolicyControlListEntries:
		response.Entry = nil
		response.Entries = append([]pluginsdk.PolicyEntrySnapshot(nil), runtime.entries...)
	case pluginsdk.PolicyControlInspect:
		if request.Entry != nil {
			for _, snapshot := range runtime.entries {
				if snapshot.Entry == *request.Entry {
					response.Desired = snapshot.Desired
					response.Overlay = append(json.RawMessage(nil), snapshot.Overlay...)
					response.Node = snapshot.Node
					break
				}
			}
		}
	case pluginsdk.PolicyControlReplaceInstance:
		runtime.revision = *request.ExpectedRevision + 1
		runtime.instanceVersion = *request.ExpectedInstanceVersion + 1
		runtime.defaultMode = request.Mode
		_, response.Desired = runtime.policyState()
		response.OperationID = request.OperationID
	case pluginsdk.PolicyControlReplaceEntry, pluginsdk.PolicyControlResetEntry:
		runtime.revision = *request.ExpectedRevision + 1
		runtime.instanceVersion = *request.ExpectedInstanceVersion + 1
		_, desired = runtime.policyState()
		for index := range runtime.entries {
			if request.Entry != nil && runtime.entries[index].Entry == *request.Entry {
				runtime.entries[index].Desired = desired
				if request.Action == pluginsdk.PolicyControlReplaceEntry {
					mode := request.Mode
					runtime.entries[index].Desired.Settings.EntryMode = &mode
					runtime.entries[index].Overlay = append(json.RawMessage(nil), request.Overlay...)
				} else {
					runtime.entries[index].Desired.Settings.EntryMode = nil
					runtime.entries[index].Overlay = nil
				}
				response.Desired = runtime.entries[index].Desired
				response.Overlay = append(json.RawMessage(nil), runtime.entries[index].Overlay...)
				break
			}
		}
		response.OperationID = request.OperationID
	}
	if runtime.staleResponse {
		response.InstanceID = "stale-instance"
	}
	return response, nil
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

func entrySnapshot(kind, id, token string) pluginsdk.PolicyEntrySnapshot {
	mode := pluginsdk.PolicyModeObserve
	return pluginsdk.PolicyEntrySnapshot{
		Entry: pluginsdk.PolicyEntryTarget{NodeID: "local", Kind: kind, ID: id, Token: token},
		Desired: pluginsdk.PolicySettingsSnapshot{
			Version:  pluginsdk.PolicySettingsVersion{Revision: 2, InstanceVersion: 7},
			Settings: pluginsdk.PolicyModeSettings{Handling: pluginsdk.PolicyModeHandlingRaw, DefaultMode: &mode},
		},
	}
}

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
}

func TestEntryRulesUseListedTokenAndAtomicOverlayForEveryEntryKind(t *testing.T) {
	kinds := []string{pluginsdk.PolicyEntryHTTP, pluginsdk.PolicyEntryTCP, pluginsdk.PolicyEntryUDP, pluginsdk.PolicyEntryManagedTCP, pluginsdk.PolicyEntryManagedUDP}
	for index, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			token := "entry-token-00000000000" + string(rune('1'+index))
			snapshot := entrySnapshot(kind, "entry-7", token)
			runtime := &runtimeStub{entries: []pluginsdk.PolicyEntrySnapshot{snapshot}}
			controller, err := NewController(ControllerConfig{Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			controller.rememberConfig(validConfiguration())
			rules := []Rule{
				{ID: "entry-deny", Action: DefaultActionDeny, Selector: Selector{Type: "ip", Value: "192.0.2.9"}},
				{ID: "entry-province", Action: DefaultActionAllow, Selector: Selector{Type: "classification", DatasetID: "province-data", ClassificationID: "guangdong"}},
			}
			if _, err := controller.setEntryRules(t.Context(), snapshot.Entry, rules); err != nil {
				t.Fatal(err)
			}
			request := runtime.policyCalls[len(runtime.policyCalls)-1]
			if request.Action != pluginsdk.PolicyControlReplaceEntry || request.Entry == nil || request.Entry.Token != token || request.ExpectedRevision == nil || *request.ExpectedRevision != 2 || request.ExpectedInstanceVersion == nil || *request.ExpectedInstanceVersion != 7 || request.Mode != pluginsdk.PolicyModeObserve {
				t.Fatalf("entry mutation=%+v", request)
			}
			parsed, err := ParseEntryOverlay(request.Overlay, validConfiguration())
			if err != nil || len(parsed.Rules) != 2 {
				t.Fatalf("overlay=%s parsed=%+v err=%v", request.Overlay, parsed, err)
			}
			if _, err := controller.setEntryMode(t.Context(), snapshot.Entry, pluginsdk.PolicyModeEnforce, false); err != nil {
				t.Fatal(err)
			}
			modeRequest := runtime.policyCalls[len(runtime.policyCalls)-1]
			if modeRequest.Action != pluginsdk.PolicyControlReplaceEntry || modeRequest.Mode != pluginsdk.PolicyModeEnforce || string(modeRequest.Overlay) != string(request.Overlay) {
				t.Fatalf("mode mutation did not preserve overlay: %+v", modeRequest)
			}
			if _, err := controller.setEntryMode(t.Context(), snapshot.Entry, "", true); err != nil {
				t.Fatal(err)
			}
			reset := runtime.policyCalls[len(runtime.policyCalls)-1]
			if reset.Action != pluginsdk.PolicyControlResetEntry || reset.Entry == nil || reset.Entry.Token != token || len(reset.Overlay) != 0 || reset.Mode != "" {
				t.Fatalf("reset=%+v", reset)
			}
		})
	}
}

func TestEntryMutationRejectsUnlistedTokenAndStaleResponse(t *testing.T) {
	snapshot := entrySnapshot(pluginsdk.PolicyEntryTCP, "entry-7", "entry-token-000000000001")
	runtime := &runtimeStub{entries: []pluginsdk.PolicyEntrySnapshot{snapshot}}
	controller, _ := NewController(ControllerConfig{Runtime: runtime})
	claimed := snapshot.Entry
	claimed.Token = "entry-token-000000000099"
	if _, err := controller.setEntryRules(t.Context(), claimed, []Rule{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unlisted token err=%v", err)
	}
	for _, call := range runtime.policyCalls {
		if call.Action == pluginsdk.PolicyControlReplaceEntry {
			t.Fatal("unlisted token reached mutation")
		}
	}
	runtime.staleResponse = true
	if _, err := controller.inspectPolicyTarget(t.Context(), "ip-instance", pluginsdk.PolicyStageIdentity{Kind: pluginsdk.PolicyOverlayStageIP}, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale response err=%v", err)
	}
}

func TestEntryMutationRejectsMoreThanSixtyFourRulesBeforeHostLookup(t *testing.T) {
	snapshot := entrySnapshot(pluginsdk.PolicyEntryHTTP, "entry-7", "entry-token-000000000001")
	runtime := &runtimeStub{entries: []pluginsdk.PolicyEntrySnapshot{snapshot}}
	controller, _ := NewController(ControllerConfig{Runtime: runtime})
	rules := make([]Rule, MaxOverlayRules+1)
	if _, err := controller.setEntryRules(t.Context(), snapshot.Entry, rules); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized rules err=%v", err)
	}
	if len(runtime.policyCalls) != 0 {
		t.Fatalf("oversized rules reached Host: %+v", runtime.policyCalls)
	}
}

func stringsOf(value string, count int) string {
	result := ""
	for len(result) < count {
		result += value
	}
	return result[:count]
}
