package ippolicy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

type RuntimeClient interface {
	ControlPolicy(context.Context, pluginsdk.PolicyControlRequest) (pluginsdk.PolicyControlResponse, error)
	ManageDatasetBinding(context.Context, pluginsdk.DatasetBindingRequest) (pluginsdk.DatasetBindingResponse, error)
	ControlDataset(context.Context, string, pluginsdk.DatasetControlRequest) (pluginsdk.DatasetControlResponse, error)
	DatasetStatus(context.Context, pluginsdk.DatasetStatusRequest) (pluginsdk.DatasetStatusResponse, error)
	DatasetCatalog(context.Context, pluginsdk.DatasetCatalogRequest) (pluginsdk.DatasetCatalogResponse, error)
	Call(context.Context, pluginsdk.HostRuntimeCall, any) error
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
	Runtime                                                    RuntimeClient
}

type Controller struct {
	*rpcplugin.Adapter
	mu      sync.RWMutex
	config  Configuration
	epoch   *controllerEpoch
	commit  *rpcplugin.Handle[*controllerEpoch]
	runtime RuntimeClient
}

type controllerEpoch struct {
	generation string
	live       atomic.Bool
}

func requiredGrants() []string {
	return []string{
		"ui.dynamic", "storage.read", "storage.write", "event.emit", "http.rule",
		string(pluginsdk.CapabilityDatasetManage), string(pluginsdk.CapabilityDatasetBind),
		string(pluginsdk.CapabilityDatasetQuery), string(pluginsdk.CapabilityDatasetResolve),
		string(pluginsdk.CapabilityPolicyControl),
	}
}

func NewController(config ControllerConfig) (*Controller, error) {
	controller := &Controller{config: DefaultConfiguration(), runtime: config.Runtime}
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.UniformTimeouts(5 * time.Second))
	features := pluginsdk.RequiredRPCFeatures(requiredGrants())
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities: requiredGrants(), RequiredGrants: requiredGrants(), SupportedFeatures: features,
		Timeouts: timeouts,
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, raw []byte) error {
	config, err := ParseConfiguration(raw)
	if err != nil {
		return err
	}
	epoch := &controllerEpoch{generation: generation.ID()}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, "ui.dynamic", epoch, func(value *controllerEpoch) {
		value.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == value {
			controller.epoch, controller.commit = nil, nil
			controller.config = DefaultConfiguration()
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
		controller.mu.Lock()
		defer controller.mu.Unlock()
		if !value.live.Load() {
			return rpcplugin.ErrRevoked
		}
		controller.config = cloneConfiguration(config)
		controller.epoch, controller.commit = value, handle
		return nil
	})
}

func (*Controller) activate(context.Context, *rpcplugin.Generation) error { return nil }

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.epoch, controller.commit = nil, nil
	controller.config = DefaultConfiguration()
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) uiReady() bool {
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return controller.epoch != nil && controller.epoch.live.Load()
}

func (controller *Controller) currentConfig() Configuration {
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return cloneConfiguration(controller.config)
}

func (controller *Controller) rememberConfig(config Configuration) {
	controller.mu.Lock()
	controller.config = cloneConfiguration(config)
	controller.mu.Unlock()
}

func bindProductionRuntime(config ControllerConfig) ControllerConfig {
	if config.Runtime != nil {
		return config
	}
	client, err := pluginsdk.NewHostRuntimeClientFromEnvironment()
	if err == nil {
		config.Runtime = client
	}
	return config
}
