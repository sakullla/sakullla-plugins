package dockerapp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

const MaxConfigBytes = 1 << 20

type TypedHandleAdmission interface {
	// Prepare validates/acquires a transaction without any host-visible effect.
	Prepare(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error)
}
type TypedHandleAdmissionFunc func(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error)

func (function TypedHandleAdmissionFunc) Prepare(ctx context.Context, request pluginsdk.RPCHandshakeRequest, apps []App) (PreparedAdmission, error) {
	return function(ctx, request, apps)
}

// PreparedAdmission is controller-owned after Prepare returns. Commit may
// perform effects. Abort must be idempotent and non-blocking; generation revoke
// invokes it synchronously as the final compensation boundary.
type PreparedAdmission interface {
	Commit(context.Context) error
	Abort()
}

type PreparedAdmissionFuncs struct {
	CommitFunc func(context.Context) error
	AbortFunc  func()
}

func (prepared PreparedAdmissionFuncs) Commit(ctx context.Context) error {
	if prepared.CommitFunc == nil {
		return nil
	}
	return prepared.CommitFunc(ctx)
}
func (prepared PreparedAdmissionFuncs) Abort() {
	if prepared.AbortFunc != nil {
		prepared.AbortFunc()
	}
}

type unavailableAdmission struct{}

func (unavailableAdmission) Prepare(context.Context, pluginsdk.RPCHandshakeRequest, []App) (PreparedAdmission, error) {
	return nil, ErrTypedHandlesUnavailable
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	PrepareGate                                                func(context.Context) error
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type Controller struct {
	mu             sync.Mutex
	apps           []App
	registryMirror string
	request        pluginsdk.RPCHandshakeRequest
	admission      TypedHandleAdmission
	prepareGate    func(context.Context) error
	lifecycle      *rpcplugin.Lifecycle
	commit         *rpcplugin.Handle[*commitEpoch]
	epoch          *commitEpoch
}

type commitEpoch struct {
	generation string
	live       atomic.Bool
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
	controller := &Controller{admission: config.Admission, prepareGate: config.PrepareGate}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"docker-app.business-model"},
		RequiredGrants: requiredGrants(),
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
func (controller *Controller) Apps() []App {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return cloneApps(controller.apps)
}

func (controller *Controller) RegistryMirror() string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.registryMirror
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, config []byte) error {
	configuration, err := ParseConfiguration(config)
	if err != nil {
		return err
	}
	for _, app := range configuration.Apps {
		if app.Generation != generation.ID() {
			return errors.New("app generation does not match lifecycle generation")
		}
	}
	if controller.prepareGate != nil {
		if err := controller.prepareGate(ctx); err != nil {
			return err
		}
	}
	epoch := &commitEpoch{generation: generation.ID()}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, generationHandleScope, epoch, func(epoch *commitEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.apps = nil
			controller.registryMirror = ""
			controller.commit = nil
			controller.epoch = nil
		}
		controller.mu.Unlock()
	})
	if err != nil {
		return err
	}
	return handle.Use(ctx, func(ctx context.Context, epoch *commitEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		controller.mu.Lock()
		defer controller.mu.Unlock()
		if !epoch.live.Load() {
			return rpcplugin.ErrRevoked
		}
		controller.apps, controller.registryMirror, controller.commit, controller.epoch = cloneApps(configuration.Apps), configuration.RegistryMirror, handle, epoch
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, apps, handle, epoch := controller.request, cloneApps(controller.apps), controller.commit, controller.epoch
	controller.mu.Unlock()
	if handle == nil || epoch == nil {
		return rpcplugin.ErrRevoked
	}
	return handle.Use(ctx, func(ctx context.Context, value *commitEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value != epoch || !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		prepared, err := controller.admission.Prepare(ctx, request, apps)
		if err != nil {
			return err
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, generationHandleScope, prepared, func(prepared PreparedAdmission) { prepared.Abort() })
		if err != nil {
			prepared.Abort()
			return err
		}
		return transaction.Use(ctx, func(ctx context.Context, prepared PreparedAdmission) error { return prepared.Commit(ctx) })
	})
}
func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.apps = nil
	controller.registryMirror = ""
	controller.commit = nil
	controller.epoch = nil
	controller.mu.Unlock()
	return nil
}

// generationHandleScope binds process-local overlay state to the panel grant.
// Docker/Compose API is not a plugin permission and is not required to start.
const generationHandleScope = "ui.dynamic"

func requiredGrants() []string {
	return []string{"http.rule", "ui.dynamic"}
}

func cloneApps(apps []App) []App {
	result := append([]App(nil), apps...)
	for index := range result {
		result[index].SecretRefs = append([]string(nil), result[index].SecretRefs...)
		result[index].AutoUpdate = cloneBool(result[index].AutoUpdate)
	}
	return result
}
