package doh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
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
	mu sync.RWMutex

	config        ControllerConfig
	lifecycle     *rpcplugin.Lifecycle
	prepared      *rpcplugin.Handle[*generationState]
	active        *rpcplugin.Handle[*generationState]
	preparedState *generationState
	activeState   *generationState
	generation    string
	pluginConfig  PluginConfig
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.PrepareTimeout <= 0 {
		config.PrepareTimeout = 10 * time.Second
	}
	if config.ActivateTimeout <= 0 {
		config.ActivateTimeout = time.Second
	}
	if config.StopTimeout <= 0 {
		config.StopTimeout = 5 * time.Second
	}
	if config.DrainTimeout <= 0 {
		config.DrainTimeout = 30 * time.Second
	}
	return &Controller{config: config}, nil
}

func (controller *Controller) Handshake(ctx context.Context, request pluginsdk.RPCHandshakeRequest) (pluginsdk.RPCHandshakeResponse, error) {
	if err := pluginsdk.ValidateRPCFeatures(request.RequiredFeatures, []string{pluginsdk.RPCFeatureHTTPBackendProviderV1}); err != nil {
		return pluginsdk.RPCHandshakeResponse{}, err
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.lifecycle != nil {
		return pluginsdk.RPCHandshakeResponse{}, errors.New("lifecycle handshake is already complete")
	}
	packageDigest := controller.config.PackageDigest
	if packageDigest == "" {
		packageDigest = request.PackageDigest
	}
	artifactDigest := controller.config.ArtifactDigest
	if artifactDigest == "" {
		artifactDigest = request.ArtifactDigest
	}
	lifecycle, err := rpcplugin.New(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: packageDigest, ArtifactDigest: artifactDigest,
		Capabilities:   []string{pluginsdk.PermissionHTTPOutbound},
		RequiredGrants: []string{pluginsdk.PermissionHTTPOutbound},
		Timeouts: rpcplugin.Timeouts{
			Prepare:  controller.config.PrepareTimeout,
			Activate: controller.config.ActivateTimeout,
			Stop:     controller.config.StopTimeout,
			Drain:    controller.config.DrainTimeout,
		},
	}, rpcplugin.HookFuncs{PrepareFunc: controller.prepare, ActivateFunc: controller.activate, StopFunc: controller.stop})
	if err != nil {
		return pluginsdk.RPCHandshakeResponse{}, err
	}
	response, err := lifecycle.Handshake(ctx, request)
	if err != nil {
		return pluginsdk.RPCHandshakeResponse{}, err
	}
	response.Features = []string{pluginsdk.RPCFeatureHTTPBackendProviderV1}
	controller.lifecycle = lifecycle
	controller.generation = request.Generation
	return response, nil
}

func (controller *Controller) Prepare(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	controller.mu.RLock()
	lifecycle := controller.lifecycle
	controller.mu.RUnlock()
	if lifecycle == nil {
		return lifecycleFailure(pluginsdk.ErrorInvalidArgument, "handshake is required")
	}
	return lifecycle.Prepare(ctx, request)
}

func (controller *Controller) Activate(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	controller.mu.RLock()
	lifecycle := controller.lifecycle
	controller.mu.RUnlock()
	if lifecycle == nil {
		return lifecycleFailure(pluginsdk.ErrorInvalidArgument, "handshake is required")
	}
	return lifecycle.Activate(ctx, request)
}

func (controller *Controller) Stop(ctx context.Context, request pluginsdk.LifecycleRequest) pluginsdk.LifecycleResponse {
	controller.mu.RLock()
	lifecycle := controller.lifecycle
	controller.mu.RUnlock()
	if lifecycle == nil {
		return lifecycleFailure(pluginsdk.ErrorInvalidArgument, "handshake is required")
	}
	return lifecycle.Stop(ctx, request)
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	controller.mu.RLock()
	active := controller.active
	controller.mu.RUnlock()
	if active == nil {
		http.Error(writer, "provider generation is not active", http.StatusServiceUnavailable)
		return
	}
	err := active.Use(request.Context(), func(_ context.Context, state *generationState) error {
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
	handle, err := rpcplugin.BindHandle(generation, pluginsdk.PermissionHTTPOutbound, owned, controller.revokeState)
	if err != nil {
		owned.close()
		return err
	}
	controller.mu.Lock()
	controller.prepared = handle
	controller.preparedState = owned
	controller.pluginConfig = config
	controller.generation = generation.ID()
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) revokeState(value *generationState) {
	controller.mu.Lock()
	if controller.activeState == value {
		controller.active = nil
		controller.activeState = nil
	}
	if controller.preparedState == value {
		controller.prepared = nil
		controller.preparedState = nil
	}
	controller.mu.Unlock()
	value.close()
}

func (controller *Controller) activate(ctx context.Context, _ *rpcplugin.Generation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.prepared == nil {
		return rpcplugin.ErrRevoked
	}
	controller.active = controller.prepared
	controller.activeState = controller.preparedState
	return nil
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	instance := controller.activeState
	if instance == nil {
		instance = controller.preparedState
	}
	controller.active = nil
	controller.prepared = nil
	controller.activeState = nil
	controller.preparedState = nil
	controller.pluginConfig = PluginConfig{}
	controller.mu.Unlock()
	if instance != nil {
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
	var config PluginConfig
	if err := decoder.Decode(&config); err != nil {
		return PluginConfig{}, errors.New("doh configuration must be an object with optional upstreams")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PluginConfig{}, errors.New("doh configuration must contain one object")
	}
	if err := validatePluginConfig(config); err != nil {
		return PluginConfig{}, err
	}
	return config, nil
}

func validatePluginConfig(config PluginConfig) error {
	if len(config.Upstreams) > MaxUpstreams {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(config.Upstreams))
	for _, upstream := range config.Upstreams {
		if !opaqueRefPattern.MatchString(upstream.ID) || strings.TrimSpace(upstream.Endpoint) == "" || upstream.Priority < -1000 || upstream.Priority > 1000 {
			return ErrInvalidRequest
		}
		if _, exists := seen[upstream.ID]; exists {
			return ErrInvalidRequest
		}
		seen[upstream.ID] = struct{}{}
	}
	return nil
}

func lifecycleFailure(code pluginsdk.ErrorCode, message string) pluginsdk.LifecycleResponse {
	return pluginsdk.LifecycleResponse{Error: &pluginsdk.RuntimeError{Code: code, Message: message}}
}
