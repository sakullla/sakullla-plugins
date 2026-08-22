package doh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

type ServiceFactory func(PluginConfig) (*Service, error)

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	NewService                                                 ServiceFactory
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type generationState struct {
	config  PluginConfig
	service *Service
	once    sync.Once
}

func (value *generationState) close() {
	value.once.Do(func() {
		if value.service != nil {
			_ = value.service.Close(context.Background())
		}
	})
}

type Controller struct {
	*rpcplugin.Adapter
	mu sync.RWMutex

	config       ControllerConfig
	services     *rpcplugin.GenerationSlot[*generationState]
	pluginConfig PluginConfig
}

func NewController(config ControllerConfig) (*Controller, error) {
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.Timeouts{Prepare: 10 * time.Second, Activate: time.Second, Stop: 5 * time.Second, Drain: 30 * time.Second})
	controller := &Controller{config: config}
	controller.services = rpcplugin.NewGenerationSlot(func(value *generationState) { value.close() })
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:      []string{pluginsdk.PermissionHTTPOutbound},
		RequiredGrants:    []string{pluginsdk.PermissionHTTPOutbound},
		SupportedFeatures: []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
		RequiredFeatures:  []string{pluginsdk.RPCFeatureHTTPBackendProviderV1},
		Timeouts:          timeouts,
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return nil, err
	}
	controller.Adapter = adapter
	return controller, nil
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if _, active := controller.services.ActiveValue(); !active {
		http.Error(writer, "provider generation is not active", http.StatusServiceUnavailable)
		return
	}
	err := controller.services.UseActive(request.Context(), func(_ context.Context, state *generationState) error {
		if state == nil || state.service == nil {
			http.Error(writer, "provider generation is unavailable", http.StatusServiceUnavailable)
			return nil
		}
		state.service.ServeHTTP(writer, request)
		return nil
	})
	if err != nil {
		http.Error(writer, "provider generation is unavailable", http.StatusServiceUnavailable)
	}
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	config, err := parsePluginConfig(wire)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	service, err := controller.newService(config)
	if err != nil {
		return err
	}
	owned := &generationState{config: config, service: service}
	if err := controller.services.Prepare(generation, pluginsdk.PermissionHTTPOutbound, owned); err != nil {
		owned.close()
		return err
	}
	controller.mu.Lock()
	controller.pluginConfig = config
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) activate(ctx context.Context, _ *rpcplugin.Generation) error {
	return controller.services.Activate(ctx)
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	instance, ok := controller.services.Clear()
	controller.mu.Lock()
	controller.pluginConfig = PluginConfig{}
	controller.mu.Unlock()
	if ok {
		instance.close()
	}
	return nil
}

func (controller *Controller) newService(config PluginConfig) (*Service, error) {
	if controller.config.NewService != nil {
		return controller.config.NewService(config)
	}
	return NewService(ConfigurationFromPlugin(config), RuntimeAdapters{})
}

func parsePluginConfig(wire []byte) (PluginConfig, error) {
	if len(wire) == 0 {
		wire = []byte("{}")
	}
	if len(wire) > MaxPluginConfigBytes {
		return PluginConfig{}, errors.New("plugin configuration exceeds the canonical bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var raw struct {
		Upstreams json.RawMessage `json:"upstreams"`
	}
	if err := decoder.Decode(&raw); err != nil {
		return PluginConfig{}, errors.New("doh configuration must be an object with optional upstreams")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PluginConfig{}, errors.New("doh configuration must contain one object")
	}
	var config PluginConfig
	if len(raw.Upstreams) > 0 {
		trimmed := bytes.TrimSpace(raw.Upstreams)
		if len(trimmed) == 0 || trimmed[0] != '"' {
			return PluginConfig{}, ErrInvalidRequest
		}
		if err := json.Unmarshal(raw.Upstreams, &config.Upstreams); err != nil {
			return PluginConfig{}, ErrInvalidRequest
		}
	}
	if err := validatePluginConfig(config); err != nil {
		return PluginConfig{}, err
	}
	return config, nil
}

func validatePluginConfig(config PluginConfig) error {
	_, err := parseUpstreamText(config.Upstreams)
	return err
}
