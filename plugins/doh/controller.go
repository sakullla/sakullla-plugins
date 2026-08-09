package doh

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
	published     *Service
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
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:   []string{"doh.business-model"},
		RequiredGrants: []string{"audit", "cache", "ip-policy", "listener", "log", "monotonic-clock", "network", "secret"},
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

func (controller *Controller) Serve(ctx context.Context, request HTTPRequest) (HTTPResponse, error) {
	controller.mu.Lock()
	service := controller.service
	controller.mu.Unlock()
	if service == nil {
		return HTTPResponse{}, ErrRevoked
	}
	var response HTTPResponse
	err := service.Use(ctx, func(ctx context.Context, current *Service) error {
		var err error
		response, err = current.serve(ctx, request)
		return err
	})
	return response, safeServeError(err)
}

func (controller *Controller) Statuses() []UpstreamStatus {
	controller.mu.Lock()
	service := controller.service
	controller.mu.Unlock()
	if service == nil {
		return nil
	}
	var statuses []UpstreamStatus
	_ = service.Use(context.Background(), func(_ context.Context, current *Service) error { statuses = current.Statuses(); return nil })
	return statuses
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if len(wire) > MaxConfigBytes {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return ErrInvalidRequest
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	if err := configuration.Validate(); err != nil {
		return err
	}
	if configuration.Generation != generation.ID() {
		return rpcplugin.ErrGenerationMismatch
	}
	epoch := &controllerEpoch{}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "listener", epoch, func(epoch *controllerEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.configuration = Configuration{}
			controller.epoch, controller.commit, controller.service, controller.published, controller.transaction = nil, nil, nil, nil, nil
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
		controller.configuration, controller.epoch, controller.commit = cloneConfiguration(configuration), epoch, handle
		controller.service, controller.published, controller.transaction = nil, nil, nil
		controller.mu.Unlock()
		return nil
	})
}

func (controller *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	controller.mu.Lock()
	request, configuration, epoch, commit := controller.request, cloneConfiguration(controller.configuration), controller.epoch, controller.commit
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
		if err != nil {
			return safeControllerError(err)
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, "network", prepared, func(prepared PreparedAdmission) { prepared.Abort() })
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
		if !runtime.valid() {
			transaction.Revoke()
			return ErrTypedHandlesUnavailable
		}
		service, err := NewService(configuration, runtime)
		if err != nil {
			transaction.Revoke()
			return err
		}
		serviceHandle, err := rpcplugin.BindHandle(generation, "listener", service, func(service *Service) {
			go func() {
				closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = service.Close(closeCtx)
			}()
		})
		if err != nil {
			transaction.Revoke()
			return err
		}
		service.bindRequestLease(func(ctx context.Context, request HTTPRequest) (HTTPResponse, error) {
			var response HTTPResponse
			err := serviceHandle.Use(ctx, func(ctx context.Context, current *Service) error {
				var err error
				response, err = current.serve(ctx, request)
				return err
			})
			return response, safeServeError(err)
		})
		if err = serviceHandle.Use(ctx, func(ctx context.Context, service *Service) error {
			return runtime.Listener.Register(ctx, configuration.ListenerRef, service)
		}); err != nil {
			serviceHandle.Revoke()
			transaction.Revoke()
			return safeControllerError(err)
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
		controller.service, controller.published, controller.transaction = serviceHandle, service, transaction
		controller.mu.Unlock()
		return nil
	})
}

func (controller *Controller) stop(ctx context.Context, _ *rpcplugin.Generation) error {
	controller.mu.Lock()
	service := controller.published
	controller.service, controller.published = nil, nil
	controller.mu.Unlock()
	var closeErr error
	if service != nil {
		closeErr = service.Close(ctx)
	}
	controller.mu.Lock()
	controller.configuration = Configuration{}
	controller.epoch, controller.commit, controller.transaction = nil, nil, nil
	controller.mu.Unlock()
	return closeErr
}

func safeServeError(err error) error {
	switch {
	case errors.Is(err, rpcplugin.ErrDraining), errors.Is(err, rpcplugin.ErrRevoked):
		return ErrRevoked
	default:
		return err
	}
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
