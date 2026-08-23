package webdav

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"net/http"
	"strings"
	"sync"

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
	if password == "" {
		return nil, errors.New("password is required")
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
	scope, err := handler.authorize(request)
	if errors.Is(err, errUnauthorized) {
		writeUnauthorized(writer)
		return
	}
	if err != nil {
		http.Error(writer, "request scope is unavailable", http.StatusInternalServerError)
		return
	}
	request = request.WithContext(context.WithValue(request.Context(), requestScopeKey{}, scope))
	switch {
	case request.URL.Path == DavPrefix || strings.HasPrefix(request.URL.Path, DavPrefix+"/"):
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
	fields := strings.Fields(header)
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && fields[1] != "" && subtle.ConstantTimeCompare([]byte(fields[1]), []byte(handler.password)) == 1 {
		return requestScope{root: handler.root, lockKey: "bearer"}, nil
	}
	return requestScope{}, errUnauthorized
}

func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Add("WWW-Authenticate", basicChallenge)
	writer.Header().Add("WWW-Authenticate", bearerChallenge)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
}

func (handler *Handler) serveDAV(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	dav := &xwebdav.Handler{
		Prefix:     DavPrefix,
		FileSystem: shareFS{root: scope.root},
		LockSystem: handler.lockSystem(scope.lockKey),
	}
	dav.ServeHTTP(writer, request)
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
	http.ServeFileFS(writer, request, pageAssets, name)
}
