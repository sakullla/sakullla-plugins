package ippolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

var ipStage = pluginsdk.PolicyStageIdentity{Kind: pluginsdk.PolicyOverlayStageIP}

type DatasetMutation struct {
	Action        pluginsdk.DatasetControlAction    `json:"action"`
	SourceID      string                            `json:"source_id"`
	Source        *pluginsdk.DatasetSource          `json:"source,omitempty"`
	Candidate     *pluginsdk.DatasetImportCandidate `json:"candidate,omitempty"`
	VersionDigest string                            `json:"version_digest,omitempty"`
}

type BindingMutation struct {
	SourceID      string        `json:"source_id"`
	VersionDigest string        `json:"version_digest"`
	DatasetID     string        `json:"dataset_id"`
	NodeIDs       []string      `json:"node_ids,omitempty"`
	Mode          string        `json:"mode"`
	Config        Configuration `json:"config"`
}

func (controller *Controller) inspectPolicy(ctx context.Context, entry *pluginsdk.PolicyEntryTarget) (pluginsdk.PolicyControlResponse, error) {
	return controller.inspectPolicyTarget(ctx, "", ipStage, entry)
}

func (controller *Controller) inspectPolicyTarget(ctx context.Context, instanceID string, stage pluginsdk.PolicyStageIdentity, entry *pluginsdk.PolicyEntryTarget) (pluginsdk.PolicyControlResponse, error) {
	if controller == nil || controller.runtime == nil {
		return pluginsdk.PolicyControlResponse{}, ErrUnavailable
	}
	return controller.controlPolicy(ctx, pluginsdk.PolicyControlRequest{Action: pluginsdk.PolicyControlInspect, InstanceID: instanceID, Stage: stage, Entry: entry})
}

func (controller *Controller) controlPolicy(ctx context.Context, request pluginsdk.PolicyControlRequest) (pluginsdk.PolicyControlResponse, error) {
	response, err := controller.runtime.ControlPolicy(ctx, request)
	if err != nil {
		return response, publicRuntimeError(err)
	}
	if err := response.ValidateFor(request); err != nil {
		return pluginsdk.PolicyControlResponse{}, ErrUnavailable
	}
	return response, nil
}

func (controller *Controller) replacePolicy(ctx context.Context, config Configuration, mode pluginsdk.PolicyMode) (pluginsdk.PolicyControlResponse, error) {
	if err := config.Validate(); err != nil {
		return pluginsdk.PolicyControlResponse{}, err
	}
	if mode.Validate() != nil {
		return pluginsdk.PolicyControlResponse{}, fmt.Errorf("%w: 模式无效", ErrInvalidConfig)
	}
	current, err := controller.inspectPolicy(ctx, nil)
	if err != nil {
		return pluginsdk.PolicyControlResponse{}, err
	}
	encoded, err := EncodeConfiguration(config)
	if err != nil {
		return pluginsdk.PolicyControlResponse{}, err
	}
	revision, instance := current.Desired.Version.Revision, current.Desired.Version.InstanceVersion
	request := pluginsdk.PolicyControlRequest{
		Action: pluginsdk.PolicyControlReplaceInstance, InstanceID: current.InstanceID,
		Stage: current.Stage, Mode: mode, ExpectedRevision: &revision, ExpectedInstanceVersion: &instance, Config: encoded,
	}
	request.OperationID = operationIDFor("policy", request)
	response, err := controller.controlPolicy(ctx, request)
	if err != nil {
		return response, err
	}
	controller.rememberConfig(config)
	return response, nil
}

func (controller *Controller) listPolicyEntries(ctx context.Context) (pluginsdk.PolicyControlResponse, error) {
	if controller == nil || controller.runtime == nil {
		return pluginsdk.PolicyControlResponse{}, ErrUnavailable
	}
	return controller.controlPolicy(ctx, pluginsdk.PolicyControlRequest{Action: pluginsdk.PolicyControlListEntries, Stage: ipStage})
}

func (controller *Controller) resolvePolicyEntry(ctx context.Context, claimed pluginsdk.PolicyEntryTarget) (pluginsdk.PolicyControlResponse, pluginsdk.PolicyEntryTarget, error) {
	if claimed.Validate() != nil || claimed.Token == "" {
		return pluginsdk.PolicyControlResponse{}, pluginsdk.PolicyEntryTarget{}, fmt.Errorf("%w: 入口身份无效", ErrInvalidConfig)
	}
	listed, err := controller.listPolicyEntries(ctx)
	if err != nil {
		return pluginsdk.PolicyControlResponse{}, pluginsdk.PolicyEntryTarget{}, err
	}
	for _, snapshot := range listed.Entries {
		if snapshot.Entry == claimed {
			return listed, snapshot.Entry, nil
		}
	}
	return pluginsdk.PolicyControlResponse{}, pluginsdk.PolicyEntryTarget{}, fmt.Errorf("%w: Host 列表中不存在该入口", ErrInvalidConfig)
}

func (controller *Controller) inspectResolvedEntry(ctx context.Context, claimed pluginsdk.PolicyEntryTarget) (pluginsdk.PolicyControlResponse, error) {
	listed, entry, err := controller.resolvePolicyEntry(ctx, claimed)
	if err != nil {
		return pluginsdk.PolicyControlResponse{}, err
	}
	return controller.inspectPolicyTarget(ctx, listed.InstanceID, listed.Stage, &entry)
}

func (controller *Controller) replaceEntry(ctx context.Context, current pluginsdk.PolicyControlResponse, mode pluginsdk.PolicyMode, overlay json.RawMessage) (pluginsdk.PolicyControlResponse, error) {
	if current.Entry == nil || current.Entry.Token == "" || mode.Validate() != nil {
		return pluginsdk.PolicyControlResponse{}, fmt.Errorf("%w: 入口状态或模式无效", ErrInvalidConfig)
	}
	revision, instance := current.Desired.Version.Revision, current.Desired.Version.InstanceVersion
	request := pluginsdk.PolicyControlRequest{Action: pluginsdk.PolicyControlReplaceEntry, InstanceID: current.InstanceID, Stage: current.Stage, Entry: current.Entry, Mode: mode, ExpectedRevision: &revision, ExpectedInstanceVersion: &instance, Overlay: append(json.RawMessage(nil), overlay...)}
	request.OperationID = operationIDFor("entry", request)
	return controller.controlPolicy(ctx, request)
}

func (controller *Controller) setEntryMode(ctx context.Context, claimed pluginsdk.PolicyEntryTarget, mode pluginsdk.PolicyMode, reset bool) (pluginsdk.PolicyControlResponse, error) {
	if claimed.Validate() != nil || claimed.Token == "" || mode.Validate() != nil && !reset {
		return pluginsdk.PolicyControlResponse{}, fmt.Errorf("%w: 入口或模式无效", ErrInvalidConfig)
	}
	current, err := controller.inspectResolvedEntry(ctx, claimed)
	if err != nil {
		return pluginsdk.PolicyControlResponse{}, err
	}
	revision, instance := current.Desired.Version.Revision, current.Desired.Version.InstanceVersion
	if reset {
		request := pluginsdk.PolicyControlRequest{Action: pluginsdk.PolicyControlResetEntry, InstanceID: current.InstanceID, Stage: current.Stage, Entry: current.Entry, ExpectedRevision: &revision, ExpectedInstanceVersion: &instance}
		request.OperationID = operationIDFor("entry-reset", request)
		return controller.controlPolicy(ctx, request)
	}
	overlay := append(json.RawMessage(nil), current.Overlay...)
	if len(overlay) == 0 {
		overlay, _ = json.Marshal(EntryOverlay{Schema: OverlaySchema, Rules: []Rule{}})
	}
	return controller.replaceEntry(ctx, current, mode, overlay)
}

func (controller *Controller) bindDatasetAtomic(ctx context.Context, mutation BindingMutation) (pluginsdk.DatasetBindingResponse, error) {
	if err := mutation.Config.Validate(); err != nil {
		return pluginsdk.DatasetBindingResponse{}, err
	}
	mode := pluginsdk.PolicyMode(mutation.Mode)
	if mode.Validate() != nil {
		return pluginsdk.DatasetBindingResponse{}, fmt.Errorf("%w: 模式无效", ErrInvalidConfig)
	}
	var dataset *DatasetDefinition
	for index := range mutation.Config.Datasets {
		if mutation.Config.Datasets[index].ID == mutation.DatasetID && mutation.Config.Datasets[index].SourceID == mutation.SourceID {
			dataset = &mutation.Config.Datasets[index]
			break
		}
	}
	if dataset == nil {
		return pluginsdk.DatasetBindingResponse{}, fmt.Errorf("%w: 数据集字典不存在", ErrInvalidConfig)
	}
	policyState, err := controller.inspectPolicy(ctx, nil)
	if err != nil {
		return pluginsdk.DatasetBindingResponse{}, err
	}
	targets := pluginsdk.ExecutionTargetSelection{Mode: pluginsdk.ExecutionTargetsEffective}
	if len(mutation.NodeIDs) > 0 {
		targets = pluginsdk.ExecutionTargetSelection{Mode: pluginsdk.ExecutionTargetsSubset, AgentIDs: append([]string(nil), mutation.NodeIDs...)}
	}
	inspectRequest := pluginsdk.DatasetBindingRequest{Action: pluginsdk.DatasetBindingInspect, InstanceID: policyState.InstanceID, SourceID: mutation.SourceID, Targets: targets}
	current, err := controller.runtime.ManageDatasetBinding(ctx, inspectRequest)
	if err != nil {
		return pluginsdk.DatasetBindingResponse{}, publicRuntimeError(err)
	}
	encoded, err := EncodeConfiguration(mutation.Config)
	if err != nil {
		return pluginsdk.DatasetBindingResponse{}, err
	}
	action := pluginsdk.DatasetBindingBind
	if current.Desired != nil {
		action = pluginsdk.DatasetBindingReplace
	}
	request := pluginsdk.DatasetBindingRequest{
		Action: action, InstanceID: policyState.InstanceID,
		SourceID: mutation.SourceID, Targets: targets, ExpectedRevision: current.Revision,
		Spec: &pluginsdk.DatasetBindingSpec{VersionDigest: mutation.VersionDigest, Classifications: dataset.SDKClassifications()},
		InstanceUpdate: &pluginsdk.DatasetBindingInstanceUpdate{
			ExpectedRevision: policyState.Desired.Version.InstanceVersion, Config: encoded,
			PolicyDefaults: &pluginsdk.PolicyDefaultSettingsUpdate{Stage: policyState.Stage, Mode: mode, ExpectedRevision: policyState.Desired.Version.Revision},
		},
	}
	request.OperationID = operationIDFor("binding", request)
	response, err := controller.runtime.ManageDatasetBinding(ctx, request)
	if err != nil {
		return response, publicRuntimeError(err)
	}
	controller.rememberConfig(mutation.Config)
	return response, nil
}

func (controller *Controller) controlDataset(ctx context.Context, mutation DatasetMutation) (pluginsdk.DatasetControlResponse, error) {
	request := pluginsdk.DatasetControlRequest{Action: mutation.Action, SourceID: mutation.SourceID, Source: mutation.Source, Candidate: mutation.Candidate, VersionDigest: mutation.VersionDigest}
	if err := request.Validate(); err != nil {
		return pluginsdk.DatasetControlResponse{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	operation := operationIDFor("dataset", request)
	response, err := controller.runtime.ControlDataset(ctx, operation, request)
	if err != nil {
		return response, publicRuntimeError(err)
	}
	return response, nil
}

func operationIDFor(kind string, value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("ip-%s-%x", kind, digest[:12])
}

func publicRuntimeError(err error) error {
	if err == nil {
		return nil
	}
	var runtimeError *pluginsdk.RuntimeError
	if errors.As(err, &runtimeError) && runtimeError.Code == pluginsdk.ErrorPermissionDenied {
		return ErrUnauthorized
	}
	return ErrUnavailable
}

func cleanSourceID(value string) string { return strings.TrimSpace(value) }
