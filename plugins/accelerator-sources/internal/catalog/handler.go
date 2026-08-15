// Package catalog exposes the repository-owned Docker Hub search and tag API.
package catalog

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/streaming"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

var imagePartPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

type Options struct {
	Upstream     *upstream.Manager
	Endpoint     *url.URL
	AllowHTTP    bool
	AllowPrivate bool
}

type Handler struct {
	upstream     *upstream.Manager
	endpoint     *url.URL
	allowHTTP    bool
	allowPrivate bool
}

func NewHandler(options Options) (*Handler, error) {
	if options.Upstream == nil {
		return nil, errors.New("catalog requires shared upstream manager")
	}
	if options.Endpoint == nil {
		options.Endpoint = &url.URL{Scheme: "https", Host: "hub.docker.com"}
	}
	if options.Endpoint.Hostname() == "" || options.Endpoint.User != nil || options.Endpoint.RawQuery != "" || options.Endpoint.Fragment != "" || (options.Endpoint.Scheme != "https" && !(options.AllowHTTP && options.Endpoint.Scheme == "http")) {
		return nil, errors.New("invalid catalog endpoint")
	}
	clone := *options.Endpoint
	return &Handler{upstream: options.Upstream, endpoint: &clone, allowHTTP: options.AllowHTTP, allowPrivate: options.AllowPrivate}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeError(writer, http.StatusMethodNotAllowed, "catalog requests support GET and HEAD")
		return
	}
	target := *handler.endpoint
	query := url.Values{}
	query.Set("page_size", strconv.Itoa(boundedInt(request.URL.Query().Get("page_size"), 25, 1, 100)))
	query.Set("page", strconv.Itoa(boundedInt(request.URL.Query().Get("page"), 1, 1, 10000)))
	switch request.URL.Path {
	case "/api/search":
		term := strings.TrimSpace(request.URL.Query().Get("q"))
		if term == "" || len(term) > 128 {
			writeError(writer, http.StatusBadRequest, "search query is required")
			return
		}
		target.Path = joinPath(handler.endpoint.Path, "/v2/search/repositories/")
		query.Set("query", term)
	case "/api/tags":
		namespace, repository, ok := parseImage(request.URL.Query().Get("image"))
		if !ok {
			writeError(writer, http.StatusBadRequest, "valid Docker Hub image is required")
			return
		}
		target.Path = joinPath(handler.endpoint.Path, "/v2/repositories/"+namespace+"/"+repository+"/tags")
	default:
		http.NotFound(writer, request)
		return
	}
	target.RawQuery = query.Encode()
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), request.Method, target.String(), nil)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "catalog request failed")
		return
	}
	upstreamRequest.Header.Set("Accept", "application/json")
	response, err := handler.upstream.Do(upstreamRequest, upstream.Policy{AllowHTTP: handler.allowHTTP, AllowPrivate: handler.allowPrivate})
	if err != nil {
		writeError(writer, http.StatusBadGateway, "catalog upstream failed")
		return
	}
	defer response.Body.Close()
	writer.Header().Set("Content-Type", "application/json")
	if response.ContentLength >= 0 {
		writer.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	}
	writer.WriteHeader(response.StatusCode)
	if request.Method != http.MethodHead {
		_, _ = streaming.Copy(writer, response.Body, streaming.CopyOptions{ExpectedLength: response.ContentLength, Flush: streaming.FlushFunc(writer)})
	}
}

func parseImage(value string) (string, string, bool) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || strings.ContainsAny(value, "@:") {
		return "", "", false
	}
	parts := strings.Split(value, "/")
	if len(parts) == 1 {
		parts = []string{"library", parts[0]}
	}
	if len(parts) != 2 || !imagePartPattern.MatchString(parts[0]) || !imagePartPattern.MatchString(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func boundedInt(raw string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func joinPath(prefix, suffix string) string {
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(suffix, "/")
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, `{"error":%q}`, message)
}
