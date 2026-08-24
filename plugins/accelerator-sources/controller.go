package acceleratorsources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/rpcplugin"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/imagetar"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/service"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

const (
	PluginID       = "accelerator-sources"
	PluginVersion  = "0.1.6"
	ProviderID     = "default"
	MaxConfigBytes = 4096
	maxSources     = 32
	maxSourceName  = 253
	maxEndpointLen = 512
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
	*rpcplugin.Adapter
	mu sync.RWMutex

	config      ControllerConfig
	services    *rpcplugin.GenerationSlot[*generationService]
	lastMetrics upstream.Metrics
	sources     []registry.Source
}

func NewController(config ControllerConfig) (*Controller, error) {
	timeouts := (rpcplugin.Timeouts{Prepare: config.PrepareTimeout, Activate: config.ActivateTimeout, Stop: config.StopTimeout, Drain: config.DrainTimeout}).WithDefaults(rpcplugin.Timeouts{Prepare: 10 * time.Second, Activate: time.Second, Stop: 5 * time.Second, Drain: 30 * time.Second})
	controller := &Controller{config: config}
	controller.services = rpcplugin.NewGenerationSlot(func(value *generationService) {
		controller.mu.Lock()
		controller.lastMetrics = value.service.Metrics()
		controller.mu.Unlock()
		value.close()
	})
	if controller.config.NewService == nil {
		controller.config.NewService = controller.newConfiguredService
	}
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

func (controller *Controller) newConfiguredService() (GenerationService, error) {
	sources := controller.snapshotSources()
	return service.NewHandler(service.Options{
		Registry: registry.Options{Sources: sources},
		ImageTar: imagetar.Options{Sources: imageTarSources(sources)},
	})
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
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	status := Status{Generation: request.Generation, Active: active, Metrics: controller.lastMetrics}
	if active {
		status.Metrics = activeService.service.Metrics()
	}
	return status
}

func (controller *Controller) prepare(ctx context.Context, generation *rpcplugin.Generation, wire []byte) error {
	sources, err := loadSources(wire)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controller.mu.Lock()
	controller.sources = sources
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
		controller.mu.Lock()
		controller.lastMetrics = instance.service.Metrics()
		controller.mu.Unlock()
	}
	return nil
}

type sourceDocument struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

func loadSources(wire []byte) ([]registry.Source, error) {
	if len(wire) == 0 {
		wire = []byte("{}")
	}
	if len(wire) > MaxConfigBytes {
		return nil, errors.New("plugin configuration exceeds the canonical bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document struct {
		Sources *[]sourceDocument `json:"sources"`
	}
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("accelerator-sources configuration is invalid: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("accelerator-sources configuration must contain one object")
	}
	if document.Sources == nil || len(*document.Sources) == 0 {
		return registry.DefaultSources(), nil
	}
	if len(*document.Sources) > maxSources {
		return nil, errors.New("sources exceeds the canonical bound")
	}
	known := knownSources()
	sources := make([]registry.Source, 0, len(*document.Sources))
	seen := make(map[string]int, len(*document.Sources))
	for index, item := range *document.Sources {
		source, err := parseSourceDocument(index, item, known)
		if err != nil {
			return nil, err
		}
		for _, key := range append([]string{source.Name}, source.Aliases...) {
			key = strings.ToLower(key)
			if previous, exists := seen[key]; exists {
				return nil, fmt.Errorf("sources[%d] duplicates sources[%d] name %q", index, previous, key)
			}
			seen[key] = index
		}
		sources = append(sources, source)
	}
	return sources, nil
}

func parseSourceDocument(index int, item sourceDocument, known map[string]registry.Source) (registry.Source, error) {
	name := strings.TrimSpace(item.Name)
	if name == "" || len(name) > maxSourceName || strings.ContainsAny(name, "/\\\t\r\n ") {
		return registry.Source{}, fmt.Errorf("sources[%d].name is invalid", index)
	}
	endpointRaw := strings.TrimSpace(item.Endpoint)
	if endpointRaw == "" || len(endpointRaw) > maxEndpointLen {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint is invalid", index)
	}
	endpoint, err := url.Parse(endpointRaw)
	if err != nil || endpoint.Hostname() == "" {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint is invalid", index)
	}
	if endpoint.Scheme != "https" || (endpoint.Port() != "" && endpoint.Port() != "443") {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint must be an https URL", index)
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint contains unsupported components", index)
	}
	host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint must not target a private network", index)
	}
	if address := net.ParseIP(host); address != nil && !upstream.IsPublicIP(address) {
		return registry.Source{}, fmt.Errorf("sources[%d].endpoint must not target a private network", index)
	}
	source := registry.Source{Name: name, Endpoint: endpoint}
	if matched, ok := known[strings.ToLower(name)]; ok {
		source.Aliases = append([]string(nil), matched.Aliases...)
		source.TokenHosts = append([]string(nil), matched.TokenHosts...)
	}
	return source, nil
}

func knownSources() map[string]registry.Source {
	known := make(map[string]registry.Source)
	for _, source := range registry.DefaultSources() {
		known[strings.ToLower(source.Name)] = source
	}
	return known
}

func (controller *Controller) snapshotSources() []registry.Source {
	controller.mu.RLock()
	defer controller.mu.RUnlock()
	return cloneRegistrySources(controller.sources)
}

func cloneRegistrySources(sources []registry.Source) []registry.Source {
	if sources == nil {
		return nil
	}
	cloned := make([]registry.Source, len(sources))
	for index, source := range sources {
		cloned[index] = source
		if source.Endpoint != nil {
			endpoint := *source.Endpoint
			cloned[index].Endpoint = &endpoint
		}
		cloned[index].Aliases = append([]string(nil), source.Aliases...)
		cloned[index].TokenHosts = append([]string(nil), source.TokenHosts...)
	}
	return cloned
}

func imageTarSources(sources []registry.Source) map[string]imagetar.Source {
	mapped := make(map[string]imagetar.Source, len(sources))
	for _, source := range sources {
		item := imagetar.Source{
			Endpoint:     source.Endpoint,
			TokenHosts:   append([]string(nil), source.TokenHosts...),
			AllowHTTP:    source.AllowHTTP,
			AllowPrivate: source.AllowPrivate,
		}
		mapped[strings.ToLower(source.Name)] = item
		for _, alias := range source.Aliases {
			mapped[strings.ToLower(alias)] = item
		}
	}
	return mapped
}
