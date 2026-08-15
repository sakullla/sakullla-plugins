// Package sourceproxy provides the fixed GitHub and Hugging Face acceleration
// routes owned by accelerator-sources.
package sourceproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/streaming"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

const (
	maxRedirects   = 5
	maxScriptBytes = 4 << 20
)

var scriptURLPattern = regexp.MustCompile(`https://(?:github\.com|api\.github\.com|codeload\.github\.com|raw\.githubusercontent\.com|gist\.github\.com|gist\.githubusercontent\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com|github\.githubassets\.com|huggingface\.co)/[^\s"'<>]+`)

type Options struct {
	Upstream     *upstream.Manager
	Targets      map[string]*url.URL
	AllowHTTP    bool
	AllowPrivate bool
}

type Handler struct {
	upstream     *upstream.Manager
	targets      map[string]*url.URL
	allowHTTP    bool
	allowPrivate bool
}

func NewHandler(options Options) (*Handler, error) {
	if options.Upstream == nil {
		return nil, errors.New("source proxy requires shared upstream manager")
	}
	targets := defaultTargets()
	if options.Targets != nil {
		targets = make(map[string]*url.URL, len(options.Targets))
		for host, target := range options.Targets {
			if target == nil || target.Hostname() == "" || (target.Scheme != "https" && !(options.AllowHTTP && target.Scheme == "http")) {
				return nil, errors.New("invalid source proxy target")
			}
			clone := *target
			targets[strings.ToLower(host)] = &clone
		}
	}
	return &Handler{upstream: options.Upstream, targets: targets, allowHTTP: options.AllowHTTP, allowPrivate: options.AllowPrivate}, nil
}

func defaultTargets() map[string]*url.URL {
	hosts := []string{"github.com", "api.github.com", "codeload.github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github.githubassets.com", "huggingface.co"}
	targets := make(map[string]*url.URL, len(hosts))
	for _, host := range hosts {
		targets[host] = &url.URL{Scheme: "https", Host: host}
	}
	return targets
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	target, class, err := handler.resolve(request.URL)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "unsupported source target")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead && !(request.Method == http.MethodPost && class == "github" && strings.HasSuffix(target.Path, "/git-upload-pack")) {
		writer.Header().Set("Allow", "GET, HEAD")
		writeError(writer, http.StatusMethodNotAllowed, "unsupported source method")
		return
	}
	isScript := request.Method == http.MethodGet && (strings.EqualFold(path.Ext(target.Path), ".sh") || strings.EqualFold(path.Ext(target.Path), ".ps1"))
	var authority *url.URL
	if isScript {
		authority, err = ExternalAuthority(request)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "trusted external authority is required for script rewriting")
			return
		}
	}
	response, err := handler.follow(request, target, class)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "source upstream request failed")
		return
	}
	defer response.Body.Close()
	if isScript && response.StatusCode >= 200 && response.StatusCode < 300 {
		handler.serveScript(writer, response, authority)
		return
	}
	copyHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	if request.Method != http.MethodHead {
		_, _ = streaming.Copy(writer, response.Body, streaming.CopyOptions{ExpectedLength: response.ContentLength, Flush: streaming.FlushFunc(writer)})
	}
}

func (handler *Handler) resolve(incoming *url.URL) (*url.URL, string, error) {
	clean := strings.TrimPrefix(incoming.EscapedPath(), "/")
	if strings.HasPrefix(clean, "https://") {
		nested, err := url.Parse(clean)
		if err != nil || nested.Scheme != "https" || nested.Hostname() == "" || nested.User != nil || nested.Fragment != "" {
			return nil, "", errors.New("invalid source URL")
		}
		clean = strings.ToLower(nested.Hostname()) + nested.EscapedPath()
	}
	segments := strings.Split(clean, "/")
	if len(segments) < 2 {
		return nil, "", errors.New("missing source path")
	}
	host := strings.ToLower(segments[0])
	if host == "github" {
		host = "github.com"
	} else if host == "github-api" {
		host = "api.github.com"
	} else if host == "github-raw" {
		host = "raw.githubusercontent.com"
	} else if host == "github-gist" {
		host = "gist.github.com"
	} else if host == "huggingface" {
		host = "huggingface.co"
	} else if host == "proxy" && len(segments) >= 3 {
		host = strings.ToLower(segments[1])
		segments = segments[1:]
	}
	base, found := handler.targets[host]
	if !found {
		return nil, "", errors.New("unsupported source host")
	}
	decodedPath, err := url.PathUnescape("/" + strings.Join(segments[1:], "/"))
	if err != nil || strings.Contains(decodedPath, "\\") || strings.Contains(decodedPath, "\x00") {
		return nil, "", errors.New("invalid source path")
	}
	target := *base
	target.Path = joinPath(base.Path, decodedPath)
	target.RawQuery = incoming.RawQuery
	class := sourceClass(host)
	if host == "github.com" {
		parts := strings.Split(strings.TrimPrefix(decodedPath, "/"), "/")
		if len(parts) >= 5 && parts[2] == "blob" {
			rawBase, ok := handler.targets["raw.githubusercontent.com"]
			if !ok {
				return nil, "", errors.New("raw target unavailable")
			}
			target = *rawBase
			target.Path = joinPath(rawBase.Path, "/"+strings.Join(append(parts[:2], parts[3:]...), "/"))
		}
	}
	return &target, class, nil
}

func sourceClass(host string) string {
	if host == "huggingface.co" {
		return "huggingface"
	}
	return "github"
}

func (handler *Handler) follow(incoming *http.Request, target *url.URL, class string) (*http.Response, error) {
	current := target
	for redirects := 0; redirects <= maxRedirects; redirects++ {
		request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, current.String(), incoming.Body)
		if err != nil {
			return nil, err
		}
		copyRequestHeaders(request.Header, incoming.Header)
		response, err := handler.upstream.Do(request, upstream.Policy{AllowHTTP: handler.allowHTTP, AllowPrivate: handler.allowPrivate})
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response, nil
		}
		location, err := response.Location()
		drainAndClose(response.Body)
		if err != nil || !handler.allowedRedirect(location, class) {
			return nil, errors.New("unsafe source redirect")
		}
		current = location
	}
	return nil, errors.New("too many source redirects")
}

func (handler *Handler) allowedRedirect(target *url.URL, class string) bool {
	if target == nil || target.User != nil || target.Fragment != "" || (target.Scheme != "https" && !(handler.allowHTTP && target.Scheme == "http")) {
		return false
	}
	if handler.allowPrivate {
		for _, configured := range handler.targets {
			if strings.EqualFold(configured.Host, target.Host) {
				return true
			}
		}
	}
	host := strings.ToLower(target.Hostname())
	if class == "github" {
		return host == "github.com" || host == "api.github.com" || host == "codeload.github.com" || host == "objects.githubusercontent.com" || host == "release-assets.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
	}
	return host == "huggingface.co" || strings.HasSuffix(host, ".huggingface.co") || host == "hf.co" || strings.HasSuffix(host, ".hf.co") || strings.HasSuffix(host, ".xethub.hf.co")
}

func (handler *Handler) serveScript(writer http.ResponseWriter, response *http.Response, authority *url.URL) {
	if response.ContentLength > maxScriptBytes {
		writeError(writer, http.StatusBadGateway, "script exceeds rewrite limit")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxScriptBytes+1))
	if err != nil || len(body) > maxScriptBytes {
		writeError(writer, http.StatusBadGateway, "script exceeds rewrite limit")
		return
	}
	prefix := strings.TrimSuffix(authority.String(), "/") + "/"
	rewritten := scriptURLPattern.ReplaceAllFunc(body, func(value []byte) []byte { return append([]byte(prefix), value[len("https://"):]...) })
	copyHeaders(writer.Header(), response.Header)
	writer.Header().Del("Content-Encoding")
	writer.Header().Set("Content-Length", strconv.Itoa(len(rewritten)))
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, bytes.NewReader(rewritten))
}

func joinPath(prefix, suffix string) string {
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(suffix, "/")
}

func copyRequestHeaders(destination, source http.Header) {
	for _, name := range []string{"Accept", "Content-Type", "If-Modified-Since", "If-None-Match", "Range", "User-Agent"} {
		if value := source.Get(name); value != "" {
			destination.Set(name, value)
		}
	}
	destination.Set("Accept-Encoding", "identity")
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, (64<<10)+1)
	_ = body.Close()
}

func copyHeaders(destination, source http.Header) {
	for _, name := range []string{"Accept-Ranges", "Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Length", "Content-Range", "Content-Type", "ETag", "Last-Modified"} {
		if value := source.Get(name); value != "" {
			destination.Set(name, value)
		}
	}
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, `{"error":%q}`, message)
}
