package shadowsocksserver

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
	c := &Controller{admission: config.Admission}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities: []string{"shadowsocks.business-model"}, RequiredGrants: requiredGrants(),
		Timeouts: rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout},
	}, rpcplugin.HookFuncs{PrepareFunc: c.prepare, ActivateFunc: c.activate, StopFunc: c.stop})
	if err != nil {
		return nil, err
	}
	c.lifecycle = lifecycle
	return c, nil
}

func (c *Controller) Handshake(ctx context.Context, r pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	response, err := c.lifecycle.Handshake(ctx, r)
	if err == nil {
		c.mu.Lock()
		c.request = r
		c.mu.Unlock()
	}
	return response, err
}
func (c *Controller) Prepare(ctx context.Context, r pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return c.lifecycle.Prepare(ctx, r)
}
func (c *Controller) Activate(ctx context.Context, r pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return c.lifecycle.Activate(ctx, r)
}
func (c *Controller) Stop(ctx context.Context, r pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	return c.lifecycle.Stop(ctx, r)
}
func (c *Controller) Use(ctx context.Context, f func(context.Context, *Service) error) error {
	c.mu.Lock()
	service := c.service
	c.mu.Unlock()
	if service == nil {
		return ErrRevoked
	}
	return service.Use(ctx, f)
}

func (c *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if len(wire) > MaxConfigBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
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
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.epoch == epoch {
			c.configuration = Configuration{}
			c.epoch, c.commit, c.service, c.published, c.transaction = nil, nil, nil, nil, nil
		}
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
		c.mu.Lock()
		c.configuration, c.epoch, c.commit = clone(configuration), epoch, handle
		c.service, c.published, c.transaction = nil, nil, nil
		c.mu.Unlock()
		return nil
	})
}

func (c *Controller) activate(ctx context.Context, generation *rpcplugin.Generation) error {
	c.mu.Lock()
	request, configuration, epoch, commit := c.request, clone(c.configuration), c.epoch, c.commit
	c.mu.Unlock()
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
		prepared, err := c.admission.Prepare(ctx, request, configuration)
		if err != nil {
			return safeControllerError(err)
		}
		if prepared == nil {
			return ErrTypedHandlesUnavailable
		}
		transaction, err := rpcplugin.BindHandle(generation, "listener", prepared, func(p PreparedAdmission) { p.Abort() })
		if err != nil {
			prepared.Abort()
			return err
		}
		var runtime RuntimeAdapters
		if err = transaction.Use(ctx, func(ctx context.Context, p PreparedAdmission) error {
			var commitErr error
			runtime, commitErr = p.Commit(ctx)
			return commitErr
		}); err != nil {
			transaction.Revoke()
			return safeControllerError(err)
		}
		service, err := NewService(configuration, runtime)
		if err != nil {
			transaction.Revoke()
			return err
		}
		if err = service.Initialize(ctx); err != nil {
			service.Disable()
			transaction.Revoke()
			return safeControllerError(err)
		}
		serviceHandle, err := rpcplugin.BindHandle(generation, "listener", service, func(service *Service) { service.Disable() })
		if err != nil {
			service.Disable()
			transaction.Revoke()
			return err
		}
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
		c.mu.Lock()
		if c.epoch != epoch || !epoch.live.Load() {
			c.mu.Unlock()
			serviceHandle.Revoke()
			transaction.Revoke()
			return rpcplugin.ErrRevoked
		}
		c.service, c.published, c.transaction = serviceHandle, service, transaction
		c.mu.Unlock()
		return nil
	})
}

func (c *Controller) stop(ctx context.Context, _ *rpcplugin.Generation) error {
	c.mu.Lock()
	service := c.published
	c.service, c.published = nil, nil
	c.mu.Unlock()
	var drainErr error
	if service != nil {
		drainErr = service.Drain(ctx)
	}
	c.mu.Lock()
	c.configuration = Configuration{}
	c.epoch, c.commit, c.transaction = nil, nil, nil
	c.mu.Unlock()
	return drainErr
}

func safeControllerError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, rpcplugin.ErrRevoked):
		return rpcplugin.ErrRevoked
	default:
		return ErrTypedHandlesUnavailable
	}
}
func requiredGrants() []string {
	return []string{"audit", "listener", "monotonic-clock", "replay", "secret", "traffic"}
}
