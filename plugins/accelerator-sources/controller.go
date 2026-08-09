package acceleratorsources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

const MaxConfigBytes = 1 << 20

type ProbeConfig struct {
	Method           ProbeMethod `json:"method"`
	MaxRedirects     int         `json:"max_redirects"`
	MaxResponseBytes int64       `json:"max_response_bytes"`
	TimeoutMillis    int64       `json:"timeout_ms"`
	Concurrency      int         `json:"concurrency"`
}

func (config ProbeConfig) Policy() ProbePolicy {
	return ProbePolicy{Method: config.Method, MaxRedirects: config.MaxRedirects, MaxResponseBytes: config.MaxResponseBytes, Timeout: time.Duration(config.TimeoutMillis) * time.Millisecond, Concurrency: config.Concurrency}
}

type Configuration struct {
	Generation      string      `json:"generation"`
	ScheduleSeconds int64       `json:"schedule_seconds"`
	Probe           ProbeConfig `json:"probe"`
	Sources         []Source    `json:"sources"`
}

func (configuration Configuration) Validate() error {
	if len(configuration.Generation) == 0 || len(configuration.Generation) > 128 || configuration.ScheduleSeconds < 30 || configuration.ScheduleSeconds > 86400 || len(configuration.Sources) > MaxSources {
		return ErrBoundExceeded
	}
	if err := configuration.Probe.Policy().validate(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(configuration.Sources))
	for _, source := range configuration.Sources {
		if err := source.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[source.ID]; duplicate {
			return ErrSourceExists
		}
		seen[source.ID] = struct{}{}
	}
	return nil
}

type SchedulerRegistration struct {
	Generation     string
	Interval       time.Duration
	MaxConcurrency int
	OperationKey   string
}

type Scheduler interface {
	Register(context.Context, SchedulerRegistration) error
}

type SchedulerFunc func(context.Context, SchedulerRegistration) error

func (function SchedulerFunc) Register(ctx context.Context, registration SchedulerRegistration) error {
	return function(ctx, registration)
}

type RuntimeAdapters struct {
	Probe     NetworkProbe
	Scheduler Scheduler
	UI        DynamicUI
	Auditor   Auditor
}

type PreparedAdmission interface {
	// Abort compensates Commit and any idempotent scheduler registration made
	// with the returned adapters. It must be safe after partial activation.
	Commit(context.Context) (RuntimeAdapters, error)
	Abort()
}

type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) (RuntimeAdapters, error)
	AbortFunc  func()
}

func (prepared PreparedAdmissionFuncs) Commit(ctx context.Context) (RuntimeAdapters, error) {
	if prepared.CommitFunc == nil {
		return RuntimeAdapters{}, ErrTypedHandlesUnavailable
	}
	return prepared.CommitFunc(ctx)
}

func (prepared PreparedAdmissionFuncs) Abort() {
	if prepared.AbortFunc != nil {
		prepared.AbortFunc()
	}
}

type TypedHandleAdmission interface {
	// Prepare returns a transaction with no durable or host-visible effect.
	// Abort must be idempotent and non-blocking because generation revoke calls
	// it synchronously as the compensation boundary.
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)
}

type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error)

func (function TypedHandleAdmissionFunc) Prepare(ctx context.Context, request pluginsdk.RPCHandshakeRequest, configuration Configuration) (PreparedAdmission, error) {
	return function(ctx, request, configuration)
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, Configuration) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	ActivationAuditor                                          Auditor
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type controllerEpoch struct {
	generation string
	live       atomic.Bool
}

type activationAuditState struct {
	auditor  Auditor
	started  atomic.Bool
	terminal atomic.Bool
}

func (state *activationAuditState) write(ctx context.Context, outcome string) error {
	if state == nil || state.auditor == nil {
		return ErrAuditRequired
	}
	if outcome != "started" && state.terminal.Load() {
		return nil
	}
	if err := state.auditor.Audit(ctx, AuditRecord{Action: "activate", Outcome: outcome}); err != nil {
		return ErrAuditUnavailable
	}
	if outcome == "started" {
		state.started.Store(true)
	} else {
		state.terminal.Store(true)
	}
	return nil
}

// close is the bounded generation-revoke fallback when an activation hook
// cannot return to its ordinary terminal-audit path.
func (state *activationAuditState) close() {
	if state == nil || !state.started.Load() || state.terminal.Load() {
		return
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	go func() { done <- state.write(ctx, "failed") }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	cancel()
}

type boundRuntime struct {
	probe       *rpcplugin.Handle[NetworkProbe]
	scheduler   *rpcplugin.Handle[Scheduler]
	ui          *rpcplugin.Handle[DynamicUI]
	auditor     *rpcplugin.Handle[Auditor]
	transaction *rpcplugin.Handle[PreparedAdmission]
}

type Controller struct {
	mu               sync.Mutex
	configuration    Configuration
	request          pluginsdk.RPCHandshakeRequest
	epoch            *controllerEpoch
	commit           *rpcplugin.Handle[*controllerEpoch]
	runtime          *boundRuntime
	activationAudit  *rpcplugin.Handle[*activationAuditState]
	admission        TypedHandleAdmission
	bootstrapAuditor Auditor
	lifecycle        *rpcplugin.Lifecycle
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Admission == nil {
		config.Admission = unavailableAdmission{}
	}
	if config.PrepareTimeout <= 0 {
		config.PrepareTimeout = time.Second
	}
	if config.ActivateTimeout <= 0 {
		config.ActivateTimeout = time.Second
	}
	if config.StopTimeout <= 0 {
		config.StopTimeout = time.Second
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = time.Second
	}
	controller := &Controller{admission: config.Admission, bootstrapAuditor: config.ActivationAuditor}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"accelerator-sources.business-model"},
		RequiredGrants: []string{"audit", "dynamic-ui", "network-probe", "scheduler"},
		Timeouts:       rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout},
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.lifecycle = lifecycle
	return controller, nil
}

func (controller *Controller) Handshake(ctx context.Context, request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	response, err := controller.lifecycle.Handshake(ctx, request)
	if err == nil {
		controller.mu.Lock()
		controller.request = request
		controller.mu.Unlock()
	}
	return response, err
}

func (controller *Controller) Prepare(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Prepare(ctx, request)
}

func (controller *Controller) Activate(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Activate(ctx, request)
}

func (controller *Controller) Stop(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return controller.lifecycle.Stop(ctx, request)
}

func (controller *Controller) Sources() []Source {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return append([]Source(nil), controller.configuration.Sources...)
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if len(wire) > MaxConfigBytes {
		return ErrBoundExceeded
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return ErrInvalidSource
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidSource
	}
	if err := configuration.Validate(); err != nil {
		return err
	}
	if configuration.Generation != generation.ID() {
		return rpcplugin.ErrGenerationMismatch
	}
	epoch := &controllerEpoch{generation: generation.ID()}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "network-probe", epoch, func(epoch *controllerEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.configuration = Configuration{}
			controller.commit = nil
			controller.epoch = nil
			controller.runtime = nil
			controller.activationAudit = nil
		}
		controller.mu.Unlock()
	})
	if err != nil {
		return err
	}
	var activationAudit *rpcplugin.Handle[*activationAuditState]
	if controller.bootstrapAuditor != nil {
		state := &activationAuditState{auditor: controller.bootstrapAuditor}
		activationAudit, err = rpcplugin.BindHandle(generation, "audit", state, func(state *activationAuditState) { state.close() })
		if err != nil {
			handle.Revoke()
			return err
		}
	}
	return handle.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil || !value.live.Load() {
			if err != nil {
				return err
			}
			return rpcplugin.ErrRevoked
		}
		controller.mu.Lock()
		controller.configuration = cloneConfiguration(configuration)
		controller.commit = handle
		controller.epoch = epoch
		controller.runtime = nil
		controller.activationAudit = activationAudit
		controller.mu.Unlock()
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, configuration, commit, epoch, activationAudit := controller.request, cloneConfiguration(controller.configuration), controller.commit, controller.epoch, controller.activationAudit
	controller.mu.Unlock()
	if commit == nil || epoch == nil || activationAudit == nil {
		return rpcplugin.ErrRevoked
	}
	return commit.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil || value != epoch || !value.live.Load() {
			if err != nil {
				return err
			}
			return rpcplugin.ErrRevoked
		}
		if err := controller.writeActivationAudit(ctx, activationAudit, "started"); err != nil {
			return err
		}
		fail := func(result error) error {
			terminalCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			auditErr := controller.writeActivationAudit(terminalCtx, activationAudit, "failed")
			cancel()
			if auditErr != nil {
				return auditErr
			}
			return result
		}
		prepared, err := controller.admission.Prepare(ctx, request, configuration)
		if err != nil {
			return fail(safeAdapterFailure(err))
		}
		if prepared == nil {
			return fail(ErrTypedHandlesUnavailable)
		}
		transaction, err := rpcplugin.BindHandle(generation, "network-probe", prepared, func(prepared PreparedAdmission) { prepared.Abort() })
		if err != nil {
			prepared.Abort()
			return fail(err)
		}
		var runtime RuntimeAdapters
		if err = transaction.Use(ctx, func(ctx context.Context, prepared PreparedAdmission) error {
			var commitErr error
			runtime, commitErr = prepared.Commit(ctx)
			return commitErr
		}); err != nil {
			transaction.Revoke()
			return fail(safeAdapterFailure(err))
		}
		if runtime.Probe == nil || runtime.Scheduler == nil || runtime.UI == nil || runtime.Auditor == nil {
			transaction.Revoke()
			return fail(ErrTypedHandlesUnavailable)
		}
		bound := &boundRuntime{transaction: transaction}
		if bound.probe, err = rpcplugin.BindHandle(generation, "network-probe", runtime.Probe, nil); err != nil {
			transaction.Revoke()
			return fail(err)
		}
		if bound.scheduler, err = rpcplugin.BindHandle(generation, "scheduler", runtime.Scheduler, nil); err != nil {
			transaction.Revoke()
			return fail(err)
		}
		if bound.ui, err = rpcplugin.BindHandle(generation, "dynamic-ui", runtime.UI, nil); err != nil {
			transaction.Revoke()
			return fail(err)
		}
		if bound.auditor, err = rpcplugin.BindHandle(generation, "audit", runtime.Auditor, nil); err != nil {
			transaction.Revoke()
			return fail(err)
		}
		if err = bound.ui.Use(ctx, func(ctx context.Context, ui DynamicUI) error {
			if err := ui.Emit(ctx, DynamicEvent{Kind: "action", Action: "activate-start"}); err != nil {
				return ErrDynamicUIUnavailable
			}
			return nil
		}); err != nil {
			transaction.Revoke()
			return fail(err)
		}
		if err = bound.scheduler.Use(ctx, func(ctx context.Context, scheduler Scheduler) error {
			return scheduler.Register(ctx, SchedulerRegistration{Generation: generation.ID(), Interval: time.Duration(configuration.ScheduleSeconds) * time.Second, MaxConcurrency: configuration.Probe.Concurrency, OperationKey: "activate:" + generation.ID()})
		}); err != nil {
			transaction.Revoke()
			return fail(safeAdapterFailure(err))
		}
		if err := ctx.Err(); err != nil || !epoch.live.Load() {
			transaction.Revoke()
			if err != nil {
				return fail(err)
			}
			return fail(rpcplugin.ErrRevoked)
		}
		controller.mu.Lock()
		if controller.epoch != epoch || !epoch.live.Load() {
			controller.mu.Unlock()
			transaction.Revoke()
			return fail(rpcplugin.ErrRevoked)
		}
		controller.runtime = bound
		controller.mu.Unlock()
		terminalCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = controller.writeActivationAudit(terminalCtx, activationAudit, "succeeded")
		cancel()
		if err != nil {
			transaction.Revoke()
			controller.mu.Lock()
			if controller.runtime == bound {
				controller.runtime = nil
			}
			controller.mu.Unlock()
			failedCtx, failedCancel := context.WithTimeout(context.Background(), time.Second)
			_ = controller.writeActivationAudit(failedCtx, activationAudit, "failed")
			failedCancel()
			return err
		}
		return nil
	})
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.configuration = Configuration{}
	controller.commit = nil
	controller.epoch = nil
	controller.runtime = nil
	controller.activationAudit = nil
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) writeActivationAudit(ctx context.Context, handle *rpcplugin.Handle[*activationAuditState], outcome string) error {
	if handle == nil {
		return ErrAuditRequired
	}
	return handle.Use(ctx, func(ctx context.Context, state *activationAuditState) error {
		return state.write(ctx, outcome)
	})
}

func safeAdapterFailure(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, rpcplugin.ErrRevoked):
		return rpcplugin.ErrRevoked
	case errors.Is(err, rpcplugin.ErrDraining):
		return rpcplugin.ErrDraining
	case errors.Is(err, ErrAuditRequired):
		return ErrAuditRequired
	case errors.Is(err, ErrAuditUnavailable):
		return ErrAuditUnavailable
	case errors.Is(err, ErrDynamicUIRequired):
		return ErrDynamicUIRequired
	case errors.Is(err, ErrDynamicUIUnavailable):
		return ErrDynamicUIUnavailable
	case errors.Is(err, ErrTypedHandlesUnavailable):
		return ErrTypedHandlesUnavailable
	default:
		return ErrAdapterOperationFailed
	}
}

func cloneConfiguration(configuration Configuration) Configuration {
	configuration.Sources = append([]Source(nil), configuration.Sources...)
	return configuration
}
