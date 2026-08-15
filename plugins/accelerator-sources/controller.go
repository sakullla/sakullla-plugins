package acceleratorsources

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
	"github.com/sakullla/sakullla-plugins/internal/rpcplugin"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/service"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

const (
	PluginID       = "accelerator-sources"
	PluginVersion  = "0.1.0"
	ProviderID     = "default"
	MaxConfigBytes = 4096
)

type GenerationService interface {
	http.Handler
	Close() error
	Metrics() Metrics
}

type Metrics = upstream.Metrics

type ServiceFactory func() (GenerationService, error)

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	NewService                                                 ServiceFactory
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type generationService struct {
	service GenerationService
	once    sync.Once
}

func (value *generationService) close() {
	value.once.Do(func() { _ = value.service.Close() })
}

type Status struct {
	Generation string
	Active     bool
	Metrics    upstream.Metrics
}

type Controller struct {
	mu sync.RWMutex

	config          ControllerConfig
	lifecycle       *rpcplugin.Lifecycle
	prepared        *rpcplugin.Handle[*generationService]
	active          *rpcplugin.Handle[*generationService]
	preparedService *generationService
	activeService   *generationService
	generation      string
	lastMetrics     upstream.Metrics
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.NewService == nil {
		config.NewService = func() (GenerationService, error) { return service.NewHandler(service.Options{}) }
	}
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
	err := active.Use(request.Context(), func(_ context.Context, value *generationService) error {
		value.service.ServeHTTP(writer, request)
		return nil
	})
	if err != nil {
		http.Error(writer, "provider generation is unavailable", http.StatusServiceUnavailable)
	}
}

func (controller *Controller) Status() Status {
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	status := Status{Generation: controller.generation, Active: controller.active != nil, Metrics: controller.lastMetrics}
	if controller.activeService != nil {
		status.Metrics = controller.activeService.service.Metrics()
	}
	return status
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	if err := validateEmptyConfig(wire); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	instance, err := controller.config.NewService()
	if err != nil {
		return err
	}
	owned := &generationService{service: instance}
	handle, err := rpcplugin.BindHandle(generation, pluginsdk.PermissionHTTPOutbound, owned, controller.revokeService)
	if err != nil {
		owned.close()
		return err
	}
	controller.mu.Lock()
	controller.prepared = handle
	controller.preparedService = owned
	controller.generation = generation.ID()
	controller.mu.Unlock()
	return nil
}

func (controller *Controller) revokeService(value *generationService) {
	controller.mu.Lock()
	if controller.activeService == value {
		controller.active = nil
		controller.activeService = nil
	}
	if controller.preparedService == value {
		controller.prepared = nil
		controller.preparedService = nil
	}
	controller.lastMetrics = value.service.Metrics()
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
	controller.activeService = controller.preparedService
	return nil
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	controller.mu.Lock()
	instance := controller.activeService
	if instance == nil {
		instance = controller.preparedService
	}
	controller.active = nil
	controller.prepared = nil
	controller.activeService = nil
	controller.preparedService = nil
	if instance != nil {
		controller.lastMetrics = instance.service.Metrics()
	}
	controller.mu.Unlock()
	return nil
}

func validateEmptyConfig(wire []byte) error {
	if len(wire) == 0 {
		wire = []byte("{}")
	}
	if len(wire) > MaxConfigBytes {
		return errors.New("plugin configuration exceeds the canonical bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var config map[string]json.RawMessage
	if err := decoder.Decode(&config); err != nil || config == nil || len(config) != 0 {
		return errors.New("accelerator-sources configuration must be an empty object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("accelerator-sources configuration must contain one object")
	}
	return nil
}

func lifecycleFailure(code pluginsdk.ErrorCode, message string) pluginsdk.LifecycleResponse {
	return pluginsdk.LifecycleResponse{Error: &pluginsdk.RuntimeError{Code: code, Message: message}}
}
