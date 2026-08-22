package webdav

import (
	"crypto/subtle"
	"embed"
	"errors"
	"net/http"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
	xwebdav "golang.org/x/net/webdav"
)

const (
	DavPrefix         = "/dav"
	DavMountUsername  = "webdav"
	pageIndexName     = "static/index.html"
	pageScriptName    = "static/app.js"
	pageStyleName     = "static/style.css"
	authenticateRealm = `Basic realm="webdav"`
)

//go:embed static/index.html static/app.js static/style.css
var pageAssets embed.FS

type Handler struct {
	root     string
	password string
	dav      *xwebdav.Handler
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
		dav: &xwebdav.Handler{
			Prefix:     DavPrefix,
			FileSystem: shareFS{root: cleaned},
			LockSystem: xwebdav.NewMemLS(),
		},
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler.password == "" {
		http.Error(writer, "provider generation is not active", http.StatusServiceUnavailable)
		return
	}
	if !handler.authorize(writer, request) {
		return
	}
	switch {
	case request.URL.Path == DavPrefix || strings.HasPrefix(request.URL.Path, DavPrefix+"/"):
		handler.dav.ServeHTTP(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/"):
		handler.serveAPI(writer, request)
	default:
		handler.servePage(writer, request)
	}
}

func (handler *Handler) Close() error { return nil }

func (handler *Handler) Root() string { return handler.root }

func (handler *Handler) authorize(writer http.ResponseWriter, request *http.Request) bool {
	_, password, ok := request.BasicAuth()
	if ok && subtle.ConstantTimeCompare([]byte(password), []byte(handler.password)) == 1 {
		return true
	}
	writer.Header().Set("WWW-Authenticate", authenticateRealm)
	http.Error(writer, "unauthorized", http.StatusUnauthorized)
	return false
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
