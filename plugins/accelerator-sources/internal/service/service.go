// Package service composes the accelerator-sources HTTP data plane.
package service

import (
	"net/http"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
)

type Options struct {
	Registry registry.Options
}

type Handler struct {
	mux      *http.ServeMux
	registry *registry.Handler
}

// NewHandler builds the self-contained, zero-configuration HTTP service. The
// returned handler can run directly in any repository-owned net/http server.
func NewHandler(options Options) (*Handler, error) {
	registryHandler, err := registry.NewHandler(options.Registry)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/v2", registryHandler)
	mux.Handle("/v2/", registryHandler)
	return &Handler{mux: mux, registry: registryHandler}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.mux.ServeHTTP(writer, request)
}

// Close releases generation-owned DNS/cache state and idle upstream
// connections after the host has drained active sessions.
func (handler *Handler) Close() error {
	return handler.registry.Close()
}
