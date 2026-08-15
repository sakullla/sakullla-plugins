// Package service composes the accelerator-sources HTTP data plane.
package service

import (
	"net/http"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/registry"
)

type Options struct {
	Registry registry.Options
}

// NewHandler builds the self-contained, zero-configuration HTTP service. The
// returned handler can run directly in any repository-owned net/http server.
func NewHandler(options Options) (http.Handler, error) {
	registryHandler, err := registry.NewHandler(options.Registry)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/v2", registryHandler)
	mux.Handle("/v2/", registryHandler)
	return mux, nil
}
