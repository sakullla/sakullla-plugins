package webdav

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
)

const (
	PluginID         = "webdav"
	PluginVersion    = "0.1.1"
	ProviderID       = "default"
	MaxConfigBytes   = 4096
	MaxPasswordBytes = 256
	MaxRootPathBytes = 4096
)

type GenerationService interface {
	http.Handler
	Close() error
	Root() string
}

type ServiceFactory func() (GenerationService, error)

type ControllerConfig struct {
	PackageDigest, ArtifactDigest                              string
	OwnedRoot                                                  string
	NewService                                                 ServiceFactory
	PrepareTimeout, ActivateTimeout, StopTimeout, DrainTimeout time.Duration
}

type generationService struct {
	service GenerationService
	once    sync.Once
}

func (value *generationService) close() {
	value.once.Do(func() {
		if value.service != nil {
			_ = value.service.Close()
		}
	})
}

type Status struct {
	Generation string
	Active     bool
	Root       string
}

type PluginConfig struct {
	Password string
	RootPath string
}

type Controller struct {
	*rpcplugin.Adapter
	mu sync.RWMutex

	config       ControllerConfig
	services     *rpcplugin.GenerationSlot[*generationService]
	pluginConfig PluginConfig
}

func NewController(config ControllerConfig) (*Controller, error) {
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.Timeouts{Prepare: 10 * time.Second, Activate: time.Second, Stop: 5 * time.Second, Drain: 30 * time.Second})
	controller := &Controller{config: config}
	controller.services = rpcplugin.NewGenerationSlot(func(value *generationService) { value.close() })
	if controller.config.NewService == nil {
		controller.config.NewService = controller.newConfiguredService
	}
	adapter, err := rpcplugin.NewAdapter(rpcplugin.Config{
		PluginID: PluginID, PluginVersion: PluginVersion,
		PackageDigest: config.PackageDigest, ArtifactDigest: config.ArtifactDigest,
		Capabilities:      []string{pluginsdk.PermissionHTTPOutbound, pluginsdk.PermissionStorageWrite},
		RequiredGrants:    []string{pluginsdk.PermissionHTTPOutbound, pluginsdk.PermissionStorageWrite},
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

func (controller *Controller) newConfiguredService() (GenerationService, error) {
	config := controller.snapshotConfig()
	if config.Password == "" {
		return nil, errors.New("password is required")
	}
	root, err := resolveShareRoot(controller.config.OwnedRoot, config.RootPath)
	if err != nil {
		return nil, err
	}
	return NewHandler(root, config.Password)
}

func (controller *Controller) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if _, active := controller.services.ActiveValue(); !active {
		http.Error(writer, "provider generation is not active", http.StatusServiceUnavailable)
		return
	}
	err := controller.services.UseActive(request.Context(), func(_ context.Context, value *generationService) error {
		value.service.ServeHTTP(writer, request)
		return nil
	})
	if err != nil {
		http.Error(writer, "provider generation is unavailable", http.StatusServiceUnavailable)
	}
}

func (controller *Controller) Status() Status {
	request, _ := controller.Request()
	activeService, active := controller.services.ActiveValue()
	status := Status{Generation: request.Generation, Active: active}
	if active {
		status.Root = activeService.service.Root()
	}
	return status
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	config, err := loadConfig(wire)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.mu.Lock()
	controller.pluginConfig = config
	controller.mu.Unlock()
	instance, err := controller.config.NewService()
	if err != nil {
		return err
	}
	owned := &generationService{service: instance}
	if err := controller.services.Prepare(generation, pluginsdk.PermissionHTTPOutbound, owned); err != nil {
		owned.close()
		return err
	}
	return nil
}

func (controller *Controller) activate(ctx context.Context, _ *rpcplugin.Generation) error {
	return controller.services.Activate(ctx)
}

func (controller *Controller) stop(context.Context, *rpcplugin.Generation) error {
	if instance, ok := controller.services.Clear(); ok {
		instance.close()
	}
	return nil
}

func (controller *Controller) snapshotConfig() PluginConfig {
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return controller.pluginConfig
}

func loadConfig(wire []byte) (PluginConfig, error) {
	if len(wire) == 0 {
		wire = []byte("{}")
	}
	if len(wire) > MaxConfigBytes {
		return PluginConfig{}, errors.New("plugin configuration exceeds the canonical bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document struct {
		Password *string `json:"password"`
		RootPath *string `json:"root_path"`
	}
	if err := decoder.Decode(&document); err != nil {
		return PluginConfig{}, fmt.Errorf("webdav configuration is invalid: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PluginConfig{}, errors.New("webdav configuration must contain one object")
	}
	if document.Password == nil {
		return PluginConfig{}, errors.New("password is required")
	}
	password := *document.Password
	if !validPassword(password) {
		return PluginConfig{}, errors.New("password is invalid")
	}
	config := PluginConfig{Password: password}
	if document.RootPath != nil {
		rootPath := strings.TrimSpace(*document.RootPath)
		if rootPath == "" || len(rootPath) > MaxRootPathBytes {
			return PluginConfig{}, errors.New("root_path is invalid")
		}
		config.RootPath = rootPath
	}
	return config, nil
}

func validPassword(password string) bool {
	return password != "" && len(password) <= MaxPasswordBytes
}
