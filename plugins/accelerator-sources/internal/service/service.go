// Package service composes the accelerator-sources HTTP data plane.
package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/catalog"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/imagetar"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/sourceproxy"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
	webui "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/web"
)

type Options struct {
	Upstream    *upstream.Manager
	Registry    registry.Options
	SourceProxy sourceproxy.Options
	Catalog     catalog.Options
	ImageTar    imagetar.Options
	Config      []byte
}

type Handler struct {
	mux      *http.ServeMux
	source   *sourceproxy.Handler
	upstream *upstream.Manager
}

// NewHandler builds the HTTP service. Omitted or empty sources keep
// DefaultSources. A valid Config overlay replaces the entire source list
// used to pull images; an invalid document is rejected wholesale.
func NewHandler(options Options) (*Handler, error) {
	if len(options.Registry.Document) == 0 {
		options.Registry.Document = options.Config
	}
	if len(options.Registry.Sources) == 0 {
		sources, err := registry.SourcesFromDocument(options.Registry.Document)
		if err != nil {
			return nil, err
		}
		options.Registry.Sources = sources
	}
	if len(options.ImageTar.Sources) == 0 {
		options.ImageTar.Sources = imageTarSources(options.Registry.Sources)
	}
	manager := options.Upstream
	ownedManager := manager == nil
	if manager == nil {
		manager = options.Registry.Upstream
		ownedManager = manager == nil
	}
	if manager == nil {
		var resolver upstream.Resolver
		if options.Registry.Resolver != nil {
			resolver = upstream.NetResolverAdapter{Resolver: options.Registry.Resolver, TTL: time.Minute, NegativeTTL: 15 * time.Second}
		}
		var err error
		manager, err = upstream.New(upstream.Options{Client: options.Registry.Client, Resolver: resolver})
		if err != nil {
			return nil, err
		}
	}
	options.Registry.Upstream = manager
	registryHandler, err := registry.NewHandler(options.Registry)
	if err != nil {
		if ownedManager {
			manager.Close()
		}
		return nil, err
	}
	options.SourceProxy.Upstream = manager
	sourceHandler, err := sourceproxy.NewHandler(options.SourceProxy)
	if err != nil {
		if ownedManager {
			manager.Close()
		}
		return nil, err
	}
	options.Catalog.Upstream = manager
	catalogHandler, err := catalog.NewHandler(options.Catalog)
	if err != nil {
		if ownedManager {
			manager.Close()
		}
		return nil, err
	}
	options.ImageTar.Upstream = manager
	imageHandler, err := imagetar.NewHandler(options.ImageTar)
	if err != nil {
		if ownedManager {
			manager.Close()
		}
		return nil, err
	}
	webHandler := webui.NewHandler()
	mux := http.NewServeMux()
	mux.Handle("/v2", registryHandler)
	mux.Handle("/v2/", registryHandler)
	mux.Handle("/api/search", catalogHandler)
	mux.Handle("/api/tags", catalogHandler)
	mux.Handle("/api/offline", imageHandler)
	mux.Handle("/api/offline/", imageHandler)
	for _, prefix := range []string{"/github/", "/github-api/", "/github-raw/", "/github-gist/", "/huggingface/", "/proxy/", "/github.com/", "/api.github.com/", "/codeload.github.com/", "/raw.githubusercontent.com/", "/gist.github.com/", "/gist.githubusercontent.com/", "/objects.githubusercontent.com/", "/release-assets.githubusercontent.com/", "/github.githubassets.com/", "/huggingface.co/"} {
		mux.Handle(prefix, sourceHandler)
	}
	mux.Handle("/", webHandler)
	return &Handler{mux: mux, source: sourceHandler, upstream: manager}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.EscapedPath(), "/https://") {
		handler.source.ServeHTTP(writer, request)
		return
	}
	handler.mux.ServeHTTP(writer, request)
}

// Close releases generation-owned DNS/cache state and idle upstream
// connections after the host has drained active sessions.
func (handler *Handler) Close() error {
	return handler.upstream.Close()
}

// Metrics returns the generation-local upstream counters.
func (handler *Handler) Metrics() upstream.Metrics {
	return handler.upstream.Snapshot()
}

func imageTarSources(sources []registry.Source) map[string]imagetar.Source {
	projected := make(map[string]imagetar.Source, len(sources))
	for _, source := range sources {
		item := imagetar.Source{
			Endpoint:     source.Endpoint,
			TokenHosts:   append([]string(nil), source.TokenHosts...),
			AllowHTTP:    source.AllowHTTP,
			AllowPrivate: source.AllowPrivate,
		}
		names := append([]string{source.Name}, source.Aliases...)
		for _, name := range names {
			projected[strings.ToLower(name)] = item
		}
	}
	return projected
}
