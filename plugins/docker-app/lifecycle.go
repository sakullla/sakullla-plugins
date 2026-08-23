package dockerapp

import (
	"context"
	"errors"
	"strings"
)

type ComposeDeploySpec struct {
	AppID, Generation, Compose, RuleRef, WorkDirRoot, AgentID, Env string
}

type AppApplyExecutor interface {
	ApplyApp(context.Context, App) error
}
type AppApplyExecutorFunc func(context.Context, App) error

func (function AppApplyExecutorFunc) ApplyApp(ctx context.Context, app App) error {
	return function(ctx, app)
}

type StartExecutor interface {
	Start(context.Context, App) error
}
type StartExecutorFunc func(context.Context, App) error

func (function StartExecutorFunc) Start(ctx context.Context, app App) error {
	return function(ctx, app)
}

type RestartExecutor interface {
	Restart(context.Context, App) error
}
type RestartExecutorFunc func(context.Context, App) error

func (function RestartExecutorFunc) Restart(ctx context.Context, app App) error {
	return function(ctx, app)
}

type ServiceLogReader interface {
	ReadLogs(context.Context, App, string) (string, error)
}
type ServiceLogReaderFunc func(context.Context, App, string) (string, error)

func (function ServiceLogReaderFunc) ReadLogs(ctx context.Context, app App, service string) (string, error) {
	return function(ctx, app, service)
}

type AppRemoveExecutor interface {
	RemoveApp(context.Context, App) error
}
type AppRemoveExecutorFunc func(context.Context, App) error

func (function AppRemoveExecutorFunc) RemoveApp(ctx context.Context, app App) error {
	return function(ctx, app)
}

func AppFromCompose(appID, generation, document string) (App, error) {
	_, app, err := ParseComposeDocument(document, appID, generation, "")
	return app, err
}

func UpsertManaged(apps []App, app App) ([]App, error) {
	if err := app.Validate(); err != nil {
		return nil, err
	}
	for index, existing := range apps {
		if existing.ID == app.ID {
			result := cloneApps(apps)
			result[index] = cloneApp(app)
			return result, nil
		}
	}
	return RegisterManaged(apps, app)
}

func DeployComposeAppForAgent(ctx context.Context, apps []App, spec ComposeDeploySpec, report AgentEngineReport, executor AppApplyExecutor, auditor Auditor) ([]App, error) {
	preserved := cloneApps(apps)
	if auditor == nil {
		return preserved, ErrAuditRequired
	}
	if !validAgentID(report.AgentID) || !report.Online {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "denied", Detail: ErrAgentOffline.Error()})
		return preserved, ErrAgentOffline
	}
	spec.AgentID = report.AgentID
	return DeployComposeApp(ctx, apps, spec, ObservationFromReport(report), executor, auditor)
}

func bindAppToAgent(app *App, apps []App, agentID string) error {
	if !validAgentID(agentID) {
		return ErrAgentOffline
	}
	for _, existing := range apps {
		if existing.ID == app.ID && existing.AgentID != "" && existing.AgentID != agentID {
			return ErrAppAgentConflict
		}
	}
	app.AgentID = agentID
	return nil
}

func DeployComposeApp(ctx context.Context, apps []App, spec ComposeDeploySpec, engine EngineObservation, executor AppApplyExecutor, auditor Auditor) ([]App, error) {
	preserved := cloneApps(apps)
	if auditor == nil {
		return preserved, ErrAuditRequired
	}
	app, err := AppFromCompose(spec.AppID, spec.Generation, spec.Compose)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "denied", Detail: deployDenial(err)})
		return preserved, err
	}
	app.Env = spec.Env
	if spec.RuleRef != "" {
		if !boundedText(spec.RuleRef, 128) {
			audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "denied", Detail: ErrInvalidPreview.Error()})
			return preserved, ErrInvalidPreview
		}
		app.RuleRef = spec.RuleRef
	}
	if spec.AgentID != "" {
		if err := bindAppToAgent(&app, apps, spec.AgentID); err != nil {
			audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "denied", Detail: err.Error()})
			return preserved, err
		}
	}
	if !ProjectEngine(engine).Ready {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "denied", Detail: ErrEngineNotReady.Error()})
		return preserved, ErrEngineNotReady
	}
	if executor == nil {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return preserved, ErrTypedHandlesUnavailable
	}
	if err := executor.ApplyApp(ctx, app); err != nil {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return preserved, safeFailure(ErrOperationFailed, err)
	}
	next, err := UpsertManaged(apps, app)
	if err != nil {
		audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return preserved, err
	}
	audit(auditor, AuditRecord{Action: "compose.deploy", Outcome: "succeeded", Detail: app.ID})
	return next, nil
}

func deployDenial(err error) string {
	switch {
	case errors.Is(err, ErrMissingComposeImage):
		return ErrMissingComposeImage.Error()
	case errors.Is(err, ErrInvalidCompose):
		return ErrInvalidCompose.Error()
	default:
		return ErrInvalidPreview.Error()
	}
}

func StartManaged(ctx context.Context, app App, executor StartExecutor, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if executor == nil {
		audit(auditor, AuditRecord{Action: "app.start", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	if err := executor.Start(ctx, app); err != nil {
		audit(auditor, AuditRecord{Action: "app.start", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	audit(auditor, AuditRecord{Action: "app.start", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func RestartManaged(ctx context.Context, app App, executor RestartExecutor, auditor Auditor) error {
	if auditor == nil {
		return ErrAuditRequired
	}
	if executor == nil {
		audit(auditor, AuditRecord{Action: "app.restart", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return ErrTypedHandlesUnavailable
	}
	if err := executor.Restart(ctx, app); err != nil {
		audit(auditor, AuditRecord{Action: "app.restart", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return safeFailure(ErrOperationFailed, err)
	}
	audit(auditor, AuditRecord{Action: "app.restart", Outcome: "succeeded", Detail: app.ID})
	return nil
}

func ReadServiceLogs(ctx context.Context, app App, service string, reader ServiceLogReader, auditor Auditor) (string, error) {
	if auditor == nil {
		return "", ErrAuditRequired
	}
	if reader == nil {
		audit(auditor, AuditRecord{Action: "app.logs", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return "", ErrTypedHandlesUnavailable
	}
	service = strings.TrimSpace(service)
	if !validID(service) {
		audit(auditor, AuditRecord{Action: "app.logs", Outcome: "denied", Detail: ErrUnknownService.Error()})
		return "", ErrUnknownService
	}
	if names := composeServiceNames(app.Compose); len(names) > 0 {
		found := false
		for _, name := range names {
			if name == service {
				found = true
				break
			}
		}
		if !found {
			audit(auditor, AuditRecord{Action: "app.logs", Outcome: "denied", Detail: ErrUnknownService.Error()})
			return "", ErrUnknownService
		}
	}
	text, err := reader.ReadLogs(ctx, app, service)
	if err != nil {
		audit(auditor, AuditRecord{Action: "app.logs", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return "", safeFailure(ErrOperationFailed, err)
	}
	audit(auditor, AuditRecord{Action: "app.logs", Outcome: "succeeded", Detail: app.ID})
	return text, nil
}

func DeleteManagedApp(ctx context.Context, apps []App, appID string, confirmed bool, executor AppRemoveExecutor, auditor Auditor) ([]App, error) {
	preserved := cloneApps(apps)
	if auditor == nil {
		return preserved, ErrAuditRequired
	}
	if !confirmed {
		audit(auditor, AuditRecord{Action: "app.delete", Outcome: "denied", Detail: ErrDeleteUnconfirmed.Error()})
		return preserved, ErrDeleteUnconfirmed
	}
	if executor == nil {
		audit(auditor, AuditRecord{Action: "app.delete", Outcome: "unavailable", Detail: ErrTypedHandlesUnavailable.Error()})
		return preserved, ErrTypedHandlesUnavailable
	}
	target := App{ID: appID}
	for _, existing := range apps {
		if existing.ID == appID {
			target = existing
			break
		}
	}
	if err := executor.RemoveApp(ctx, target); err != nil {
		audit(auditor, AuditRecord{Action: "app.delete", Outcome: "failed", Detail: ErrOperationFailed.Error()})
		return preserved, safeFailure(ErrOperationFailed, err)
	}
	audit(auditor, AuditRecord{Action: "app.delete", Outcome: "succeeded", Detail: appID})
	return RemoveManaged(apps, appID), nil
}
