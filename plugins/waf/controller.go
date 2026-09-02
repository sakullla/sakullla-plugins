package waf

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

const generationHandleScope = "ui.dynamic"

type CatalogStore interface {
	LoadConfig(context.Context) (Configuration, bool, error)
	StoreConfig(context.Context, Configuration) error
	LoadOverlays(context.Context) (map[string]string, bool, error)
	StoreOverlays(context.Context, map[string]string) error
}

type HTTPEntryCatalog interface {
	List(context.Context, string) ([]HTTPEntry, error)
}

type OverlayWriter interface {
	SetMode(context.Context, string, string, string) error
}

type EventSource interface {
	ListEvents(context.Context, string) ([]SecurityEvent, error)
}

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
	Catalog                                                    HTTPEntryCatalog
	Overlays                                                   OverlayWriter
	Events                                                     EventSource
	State                                                      CatalogStore
}

type Controller struct {
	*rpcplugin.Adapter
	mu        sync.Mutex
	config    Configuration
	overlays  map[string]string
	epoch     *commitEpoch
	commit    *rpcplugin.Handle[*commitEpoch]
	catalog   HTTPEntryCatalog
	overlaysW OverlayWriter
	events    EventSource
	state     CatalogStore
}

type commitEpoch struct {
	generation string
	live       atomic.Bool
}

func NewController(config ControllerConfig) (*Controller, error) {
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.UniformTimeouts(time.Second))
	controller := &Controller{
		catalog:   config.Catalog,
		overlaysW: config.Overlays,
		events:    config.Events,
		state:     config.State,
		overlays:  map[string]string{},
	}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion, PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities: requiredGrants(), RequiredGrants: requiredGrants(),
		Timeouts: timeouts,
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}

func requiredGrants() []string {
	return []string{"http.rule", "ui.dynamic", "storage.read", "storage.write"}
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, config []byte) error {
	parsed, err := ParseConfiguration(config)
	if err != nil {
		return err
	}
	if controller.state != nil {
		persisted, found, loadErr := controller.state.LoadConfig(ctx)
		if loadErr != nil {
			return loadErr
		}
		if found {
			parsed = persisted
		}
		overlays, overlayFound, overlayErr := controller.state.LoadOverlays(ctx)
		if overlayErr != nil {
			return overlayErr
		}
		if overlayFound {
			controller.mu.Lock()
			controller.overlays = cloneOverlays(overlays)
			controller.mu.Unlock()
		}
	}
	epoch := &commitEpoch{generation: generation.ID()}
	epoch.live.Store(true)
	handle, err := rpcplugin.BindHandle(generation, generationHandleScope, epoch, func(epoch *commitEpoch) {
		epoch.live.Store(false)
		controller.mu.Lock()
		if controller.epoch == epoch {
			controller.config = Configuration{}
			controller.overlays = map[string]string{}
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
		controller.config = cloneConfiguration(parsed)
		controller.commit = handle
		controller.epoch = epoch
		return nil
	})
}

func (controller *Controller) activate(context.Context, *rpcplugin.Generation) error {
	return nil
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	controller.config = Configuration{}
	controller.overlays = map[string]string{}
	controller.commit = nil
	controller.epoch = nil
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) uiReady() bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.epoch != nil && controller.epoch.live.Load()
}

func (controller *Controller) currentConfig() Configuration {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return cloneConfiguration(controller.config)
}

func (controller *Controller) replaceConfig(ctx context.Context, next Configuration) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if controller.state != nil {
		if err := controller.state.StoreConfig(ctx, next); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.config = cloneConfiguration(next)
	return nil
}

func (controller *Controller) overlayMode(agentID, ruleRef string) (string, bool) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	mode, ok := controller.overlays[overlayKey(agentID, ruleRef)]
	return mode, ok
}

func (controller *Controller) replaceOverlays(ctx context.Context, next map[string]string) error {
	if controller.state != nil {
		if err := controller.state.StoreOverlays(ctx, next); err != nil {
			return err
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.overlays = cloneOverlays(next)
	return nil
}

func (controller *Controller) snapshotOverlays() map[string]string {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return cloneOverlays(controller.overlays)
}
