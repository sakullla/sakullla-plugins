package cloudflaredns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
)

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	Admission                                                  TypedHandleAdmission
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}
type controllerEpoch struct{ live atomic.Bool }

type Controller struct {
	mu            sync.Mutex
	request       pluginsdk.RPCHandshakeRequest
	configuration Configuration
	epoch         *controllerEpoch
	commit        *rpcplugin.Handle[*controllerEpoch]
	service       *rpcplugin.Handle[*Service]
	serviceValue  *Service
	transaction   *rpcplugin.Handle[PreparedAdmission]
	admission     TypedHandleAdmission
	lifecycle     *rpcplugin.Lifecycle
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
	controller := &Controller{admission: config.Admission}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest, Capabilities: requiredGrants(), RequiredGrants: requiredGrants(), SupportedFeatures: []string{pluginsdk.RPCFeatureDurableActionsV1}, Timeouts: rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
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

func (controller *Controller) Use(ctx context.Context, function func(context.Context, *Service) error) error {
	controller.mu.Lock()
	service := controller.service
	controller.mu.Unlock()
	if service == nil {
		return ErrRevoked
	}
	return service.Use(ctx, function)
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := controller.Use(request.Context(), func(_ context.Context, service *Service) error {
		service.ServeHTTP(writer, request)
		return nil
	})
	if err != nil {
		serveUnavailableMappingUI(writer, request)
	}
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if len(wire) > MaxConfigBytes {
		return ErrBoundExceeded
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return ErrInvalidInput
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	if err := configuration.Validate(); err != nil {
		return err
	}
	if configuration.Generation != generation.ID() {
		return rpcplugin.ErrGenerationMismatch
	}
	epoch := &controllerEpoch{}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "service.revocable-resource-handle", epoch, func(epoch *controllerEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.configuration = Configuration{}
			controller.epoch, controller.commit, controller.service, controller.transaction, controller.serviceValue = nil, nil, nil, nil, nil
		}
		controller.mu.Unlock()
	})
	if err != nil {
		return err
	}
	return handle.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		controller.mu.Lock()
		controller.configuration, controller.epoch, controller.commit = configuration, epoch, handle
		controller.service, controller.transaction, controller.serviceValue = nil, nil, nil
		controller.mu.Unlock()
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, configuration, epoch, commit := controller.request, controller.configuration, controller.epoch, controller.commit
	controller.mu.Unlock()
	if epoch == nil || commit == nil {
		return rpcplugin.ErrRevoked
	}
	return commit.Use(ctx, func(ctx context.Context, value *controllerEpoch) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value != epoch || !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		prepared, err := controller.admission.Prepare(ctx, request, configuration)
		if errors.Is(err, ErrTypedHandlesUnavailable) {
			// ui.route is independently useful and remains fail-closed for every
			// secret or DNS operation until the Host supplies resource handles.
			return nil
		}
		if err != nil {
			return safeControllerError(err)
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, "secret.use", prepared, func(prepared PreparedAdmission) { prepared.Abort() })
		if err != nil {
			prepared.Abort()
			return err
		}
		var runtime RuntimeAdapters
		if err = transaction.Use(ctx, func(ctx context.Context, prepared PreparedAdmission) error {
			var commitErr error
			runtime, commitErr = prepared.Commit(ctx)
			return commitErr
		}); err != nil {
			transaction.Revoke()
			return safeControllerError(err)
		}
		if runtime.Catalog == nil && runtime.Vault != nil {
			runtime.Catalog = newVaultMappingCatalog(runtime.Vault, configuration.SecretRef)
		}
		service, err := NewService(configuration, runtime)
		if err != nil {
			transaction.Revoke()
			return err
		}
		serviceHandle, err := rpcplugin.BindHandle(generation, "service.revocable-resource-handle", service, func(service *Service) { service.Cancel() })
		if err != nil {
			transaction.Revoke()
			return err
		}
		if err := ctx.Err(); err != nil || !epoch.live.Load() {
			serviceHandle.Revoke()
			transaction.Revoke()
			if err != nil {
				return err
			}
			return rpcplugin.ErrRevoked
		}
		controller.mu.Lock()
		if controller.epoch != epoch || !epoch.live.Load() {
			controller.mu.Unlock()
			serviceHandle.Revoke()
			transaction.Revoke()
			return rpcplugin.ErrRevoked
		}
		controller.service, controller.transaction, controller.serviceValue = serviceHandle, transaction, service
		controller.mu.Unlock()
		return nil
	})
}

func (controller *Controller) stop(ctx context.Context, _ *rpcplugin.Generation) error {
	controller.mu.Lock()
	service := controller.serviceValue
	controller.mu.Unlock()
	if service != nil {
		if err := service.Close(ctx); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	controller.configuration = Configuration{}
	controller.epoch, controller.commit, controller.service, controller.transaction, controller.serviceValue = nil, nil, nil, nil, nil
	controller.mu.Unlock()
	return nil
}
func safeControllerError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, rpcplugin.ErrRevoked):
		return rpcplugin.ErrRevoked
	case errors.Is(err, ErrTypedHandlesUnavailable):
		return ErrTypedHandlesUnavailable
	default:
		return ErrTypedHandlesUnavailable
	}
}
func requiredGrants() []string {
	return []string{"dns.manage", "event.emit", "secret.use", "service.revocable-resource-handle"}
}
