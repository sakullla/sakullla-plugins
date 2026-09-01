package webdav

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	xwebdav "golang.org/x/net/webdav"
)

const (
	DavPrefix        = "/dav"
	DavMountUsername = "webdav"
	pageIndexName    = "static/index.html"
	pageScriptName   = "static/app.js"
	pageStyleName    = "static/style.css"
	basicChallenge   = `Basic realm="webdav"`
	bearerChallenge  = `Bearer realm="webdav"`
)

//go:embed static/index.html static/app.js static/style.css
var pageAssets embed.FS

type Handler struct {
	root     string
	password string
	locksMu  sync.Mutex
	locks    map[string]xwebdav.LockSystem
}

type requestScopeKey struct{}

type requestScope struct {
	root    string
	lockKey string
}

func NewHandler(root, password string) (*Handler, error) {
	if !validPassword(password) {
		return nil, errors.New("password is invalid")
	}
	cleaned, err := validateShareRoot(root, false)
	if err != nil {
		return nil, err
	}
	return &Handler{
		root:     cleaned,
		password: password,
		locks:    make(map[string]xwebdav.LockSystem),
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler.password == "" {
		http.Error(writer, "provider generation is not active", http.StatusServiceUnavailable)
		return
	}
	if isPublicPageRequest(request) {
		handler.servePage(writer, request)
		return
	}
	scope, err := handler.authorize(request)
	if errors.Is(err, errUnauthorized) {
		switch {
		case isDAVPath(request.URL.Path):
			writeUnauthorized(writer)
		case strings.HasPrefix(request.URL.Path, "/api/"):
			writeAPIUnauthorized(writer)
		default:
			writeUnauthorized(writer)
		}
		return
	}
	if err != nil {
		http.Error(writer, "request scope is unavailable", http.StatusInternalServerError)
		return
	}
	request = request.WithContext(context.WithValue(request.Context(), requestScopeKey{}, scope))
	switch {
	case isDAVPath(request.URL.Path):
		handler.serveDAV(writer, request, scope)
	case strings.HasPrefix(request.URL.Path, "/api/"):
		handler.serveAPI(writer, request)
	default:
		handler.servePage(writer, request)
	}
}

func (handler *Handler) Close() error { return nil }

func (handler *Handler) Root() string { return handler.root }

var errUnauthorized = errors.New("unauthorized")

func (handler *Handler) authorize(request *http.Request) (requestScope, error) {
	header := request.Header.Get("Authorization")
	if username, password, ok := request.BasicAuth(); ok {
		if subtle.ConstantTimeCompare([]byte(password), []byte(handler.password)) != 1 {
			return requestScope{}, errUnauthorized
		}
		root, key, err := ensureBasicNamespace(handler.root, username)
		if err != nil {
			if errors.Is(err, errInvalidBasicUsername) {
				return requestScope{}, errUnauthorized
			}
			return requestScope{}, err
		}
		return requestScope{root: root, lockKey: key}, nil
	}
	credential, ok := bearerCredential(header)
	if ok && subtle.ConstantTimeCompare([]byte(credential), []byte(handler.password)) == 1 {
		return requestScope{root: handler.root, lockKey: "bearer"}, nil
	}
	return requestScope{}, errUnauthorized
}

func bearerCredential(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)-1], prefix[:len(prefix)-1]) || header[len(prefix)-1] != ' ' {
		return "", false
	}
	credential := header[len(prefix):]
	if !validPassword(credential) {
		return "", false
	}
	return credential, true
}

func isPublicPageRequest(request *http.Request) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}
	path := request.URL.Path
	return path == "/" || path == "/index.html" || strings.HasPrefix(path, "/static/")
}

func isDAVPath(path string) bool {
	return path == DavPrefix || strings.HasPrefix(path, DavPrefix+"/")
}

func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Add("WWW-Authenticate", basicChallenge)
	writer.Header().Add("WWW-Authenticate", bearerChallenge)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func writeAPIUnauthorized(writer http.ResponseWriter) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	writeAPIError(writer, http.StatusUnauthorized, errUnauthorized)
}

func (handler *Handler) serveDAV(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	if isConditionalCreate(request) {
		ctx, state := withConditionalCreate(request.Context())
		request = request.WithContext(ctx)
		writer = &conditionalCreateResponseWriter{ResponseWriter: writer, state: state}
	}
	dav := &xwebdav.Handler{
		Prefix:     DavPrefix,
		FileSystem: shareFS{root: scope.root},
		LockSystem: handler.lockSystem(scope.lockKey),
	}
	dav.ServeHTTP(writer, request)
}

func isConditionalCreate(request *http.Request) bool {
	values := request.Header.Values("If-None-Match")
	return request.Method == http.MethodPut && len(values) == 1 && strings.TrimSpace(values[0]) == "*"
}

type conditionalCreateResponseWriter struct {
	http.ResponseWriter
	state *conditionalCreateState
}

func (writer *conditionalCreateResponseWriter) WriteHeader(status int) {
	if writer.state.preconditionFailed() {
		status = http.StatusPreconditionFailed
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (handler *Handler) lockSystem(key string) xwebdav.LockSystem {
	handler.locksMu.Lock()
	defer handler.locksMu.Unlock()
	locks := handler.locks[key]
	if locks == nil {
		locks = xwebdav.NewMemLS()
		handler.locks[key] = locks
	}
	return locks
}

func requestRoot(request *http.Request) (string, error) {
	scope, ok := request.Context().Value(requestScopeKey{}).(requestScope)
	if !ok || scope.root == "" {
		return "", errors.New("request scope is unavailable")
	}
	return scope.root, nil
}

func (handler *Handler) servePage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(writer, "GET, HEAD")
		return
	}
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	name := ""
	switch request.URL.Path {
	case "/", "/index.html":
		name = pageIndexName
	case "/static/app.js":
		name = pageScriptName
	case "/static/style.css":
		name = pageStyleName
	default:
		http.NotFound(writer, request)
		return
	}
	if request.URL.Path == "/index.html" {
		serveEmbeddedAsset(writer, request, name)
		return
	}
	http.ServeFileFS(writer, request, pageAssets, name)
}

func serveEmbeddedAsset(writer http.ResponseWriter, request *http.Request, name string) {
	data, err := pageAssets.ReadFile(name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	http.ServeContent(writer, request, path.Base(name), time.Time{}, bytes.NewReader(data))
}
