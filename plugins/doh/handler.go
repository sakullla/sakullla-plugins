package doh

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const (
	pageIndexName  = "static/index.html"
	pageScriptName = "static/app.js"
	pageStyleName  = "static/style.css"
)

//go:embed static/index.html static/app.js static/style.css
var pageAssets embed.FS

func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != DNSQueryPath {
		service.servePage(writer, request)
		return
	}
	body, err := readDNSBody(request)
	if err != nil {
		writeDoHError(writer, err)
		return
	}
	response, err := service.Serve(request.Context(), HTTPRequest{
		Method:      request.Method,
		Query:       request.URL.RawQuery,
		ContentType: request.Header.Get("Content-Type"),
		Accept:      request.Header.Get("Accept"),
		Forwarded:   singleForwarded(request.Header.Values("Forwarded")),
		Body:        body,
	})
	if err != nil {
		writeDoHError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", response.ContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response.Body)
}

func (service *Service) servePage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	name := ""
	switch request.URL.Path {
	case "/", "/index.html":
		name = pageIndexName
	case "/app.js":
		name = pageScriptName
	case "/style.css":
		name = pageStyleName
	default:
		http.NotFound(writer, request)
		return
	}
	serveEmbeddedPage(writer, request, name)
}

func serveEmbeddedPage(writer http.ResponseWriter, request *http.Request, name string) {
	file, err := pageAssets.Open(name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	defer file.Close()
	info, err := fs.Stat(pageAssets, name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(writer, "page asset is unavailable", http.StatusInternalServerError)
		return
	}
	http.ServeContent(writer, request, path.Base(name), info.ModTime(), seeker)
}

func readDNSBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(MaxDNSRequestBytes)+1))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if len(body) > MaxDNSRequestBytes {
		return nil, ErrRequestTooLarge
	}
	return body, nil
}

func singleForwarded(values []string) string {
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func writeDoHError(writer http.ResponseWriter, err error) {
	http.Error(writer, http.StatusText(dohStatus(err)), dohStatus(err))
}

func dohStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, ErrRequestTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidDNSMessage):
		return http.StatusBadRequest
	case errors.Is(err, ErrConcurrencyExhausted), errors.Is(err, ErrRevoked), errors.Is(err, ErrCacheUnavailable), errors.Is(err, ErrClockUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNoHealthyUpstream), errors.Is(err, ErrUpstreamFailed), errors.Is(err, ErrResponseMismatch), errors.Is(err, ErrResponseTooLarge):
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}
