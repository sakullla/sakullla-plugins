// Package registry implements the zero-configuration public Registry v2 data
// plane for accelerator-sources.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/streaming"
	upstreamclient "github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

const (
	defaultTag       = "latest"
	defaultNamespace = "library"
	maxManifestBytes = 16 << 20
	maxTokenBytes    = 1 << 20
	maxRedirects     = 5
)

var (
	repositoryPartPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	tagPattern            = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestPattern         = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
)

// Source is a repository-owned Registry mapping. Callers should use
// DefaultSources in production. AllowPrivate exists only so deterministic
// local fixtures can exercise the exact production handler.
type Source struct {
	Name         string
	Aliases      []string
	Endpoint     *url.URL
	TokenHosts   []string
	AllowHTTP    bool
	AllowPrivate bool
}

// Options supplies infrastructure owned by the plugin binary. Sources is not
// user configuration; an empty value installs the fixed product defaults.
type Options struct {
	Client   *http.Client
	Resolver Resolver
	Sources  []Source
	Upstream *upstreamclient.Manager
}

// Resolver is the bounded DNS capability used both for preflight policy and
// for the transport's actual, address-pinned dial.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type Handler struct {
	upstream *upstreamclient.Manager
	sources  map[string]*Source
	docker   *Source
}

// DefaultSources returns the supported public registries and no arbitrary
// forwarding escape hatch.
func DefaultSources() []Source {
	return []Source{
		mustSource("docker.io", "https://registry-1.docker.io", []string{"registry-1.docker.io", "index.docker.io"}, []string{"auth.docker.io"}),
		mustSource("ghcr.io", "https://ghcr.io", nil, nil),
		mustSource("gcr.io", "https://gcr.io", nil, nil),
		mustSource("quay.io", "https://quay.io", nil, nil),
		mustSource("registry.k8s.io", "https://registry.k8s.io", nil, nil),
	}
}

func mustSource(name string, rawURL string, aliases []string, tokenHosts []string) Source {
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return Source{Name: name, Aliases: aliases, Endpoint: endpoint, TokenHosts: tokenHosts}
}

func NewHandler(options Options) (*Handler, error) {
	if len(options.Sources) == 0 {
		options.Sources = DefaultSources()
	}
	manager := options.Upstream
	if manager == nil {
		var err error
		var resolver upstreamclient.Resolver
		if options.Resolver != nil {
			resolver = upstreamclient.NetResolverAdapter{Resolver: options.Resolver, TTL: time.Minute, NegativeTTL: 15 * time.Second}
		}
		manager, err = upstreamclient.New(upstreamclient.Options{
			Client: options.Client, Resolver: resolver,
		})
		if err != nil {
			return nil, err
		}
	}
	handler := &Handler{upstream: manager, sources: make(map[string]*Source)}
	for index := range options.Sources {
		source := &options.Sources[index]
		if err := validateSource(source); err != nil {
			return nil, err
		}
		keys := append([]string{source.Name}, source.Aliases...)
		for _, key := range keys {
			key = strings.ToLower(key)
			if _, exists := handler.sources[key]; exists {
				return nil, fmt.Errorf("duplicate registry alias %q", key)
			}
			handler.sources[key] = source
		}
		if source.Name == "docker.io" || handler.docker == nil {
			handler.docker = source
		}
	}
	return handler, nil
}

func (handler *Handler) Close() error {
	return handler.upstream.Close()
}

func validateSource(source *Source) error {
	if source == nil || source.Name == "" || source.Endpoint == nil || source.Endpoint.Hostname() == "" {
		return errors.New("invalid registry source")
	}
	if source.Endpoint.Scheme != "https" && !(source.AllowHTTP && source.Endpoint.Scheme == "http") {
		return errors.New("registry source requires https")
	}
	if source.Endpoint.User != nil || source.Endpoint.RawQuery != "" || source.Endpoint.Fragment != "" {
		return errors.New("registry source URL contains unsupported components")
	}
	return nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeError(writer, http.StatusMethodNotAllowed, "METHOD_UNSUPPORTED", "registry requests support GET and HEAD")
		return
	}
	resolved, err := handler.resolve(request.URL.Path)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	if resolved.kind == resourcePing {
		writer.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		writer.WriteHeader(http.StatusOK)
		return
	}
	upstreamURL := *resolved.source.Endpoint
	upstreamURL.Path = joinURLPath(resolved.source.Endpoint.Path, resolved.upstreamPath)
	upstreamURL.RawQuery = request.URL.RawQuery
	if resolved.kind == resourceManifest && request.Method == http.MethodGet {
		handler.serveCachedManifest(writer, request, resolved, &upstreamURL)
		return
	}
	response, err := handler.fetch(request.Context(), request, resolved, &upstreamURL)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		copyUpstreamError(writer, response)
		return
	}
	if resolved.kind == resourceManifest {
		handler.serveManifest(writer, request, resolved, response)
		return
	}
	handler.serveStream(writer, request, resolved, response)
}

type resourceKind int

const (
	resourcePing resourceKind = iota
	resourceManifest
	resourceBlob
)

type resolvedRequest struct {
	source       *Source
	repository   string
	reference    string
	kind         resourceKind
	upstreamPath string
}

var (
	errInvalidRoute        = errors.New("invalid registry route")
	errUnsupportedRegistry = errors.New("unsupported registry")
	errUnsafeUpstream      = errors.New("unsafe upstream")
	errUpstreamAuth        = errors.New("upstream authentication failed")
	errManifestInvalid     = errors.New("manifest is invalid")
	errRangeInvalid        = errors.New("registry range is invalid")
)

func (handler *Handler) resolve(requestPath string) (resolvedRequest, error) {
	if requestPath == "/v2" || requestPath == "/v2/" {
		return resolvedRequest{source: handler.docker, kind: resourcePing, upstreamPath: "/v2/"}, nil
	}
	if !strings.HasPrefix(requestPath, "/v2/") || strings.Contains(requestPath, "//") {
		return resolvedRequest{}, errInvalidRoute
	}
	segments := strings.Split(strings.TrimPrefix(requestPath, "/v2/"), "/")
	if len(segments) == 0 {
		return resolvedRequest{}, errInvalidRoute
	}
	source := handler.docker
	if selected, found := handler.sources[strings.ToLower(segments[0])]; found {
		source = selected
		segments = segments[1:]
	} else if strings.Contains(segments[0], ".") || strings.Contains(segments[0], ":") {
		return resolvedRequest{}, errUnsupportedRegistry
	}
	marker := -1
	kind := resourcePing
	for index, segment := range segments {
		switch segment {
		case "manifests":
			marker, kind = index, resourceManifest
		case "blobs":
			marker, kind = index, resourceBlob
		}
		if marker >= 0 {
			break
		}
	}
	if marker <= 0 || len(segments) > marker+2 {
		return resolvedRequest{}, errInvalidRoute
	}
	repositorySegments := segments[:marker]
	for _, segment := range repositorySegments {
		if !repositoryPartPattern.MatchString(segment) {
			return resolvedRequest{}, errInvalidRoute
		}
	}
	if source == handler.docker && len(repositorySegments) == 1 {
		repositorySegments = append([]string{defaultNamespace}, repositorySegments...)
	}
	reference := ""
	if len(segments) == marker+2 {
		reference = segments[marker+1]
	}
	if kind == resourceManifest && reference == "" {
		reference = defaultTag
	}
	if kind == resourceManifest && !tagPattern.MatchString(reference) && !digestPattern.MatchString(reference) {
		return resolvedRequest{}, errInvalidRoute
	}
	if kind == resourceBlob && !digestPattern.MatchString(reference) {
		return resolvedRequest{}, errInvalidRoute
	}
	repository := strings.Join(repositorySegments, "/")
	return resolvedRequest{
		source: source, repository: repository, reference: reference, kind: kind,
		upstreamPath: "/v2/" + repository + "/" + segments[marker] + "/" + reference,
	}, nil
}

func joinURLPath(base string, suffix string) string {
	if base == "" || base == "/" {
		return suffix
	}
	return strings.TrimSuffix(base, "/") + suffix
}

func (handler *Handler) fetch(ctx context.Context, incoming *http.Request, resolved resolvedRequest, target *url.URL) (*http.Response, error) {
	request, err := handler.upstreamRequest(ctx, incoming, target, "")
	if err != nil {
		return nil, err
	}
	response, err := handler.doFollowing(ctx, resolved.source, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusUnauthorized {
		return response, nil
	}
	challenge := response.Header.Get("WWW-Authenticate")
	drainAndClose(response.Body)
	token, tokenKey, err := handler.fetchToken(ctx, resolved, challenge)
	if err != nil {
		return nil, err
	}
	request, err = handler.upstreamRequest(ctx, incoming, target, "Bearer "+token.Value)
	if err != nil {
		return nil, err
	}
	response, err = handler.doFollowing(ctx, resolved.source, request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	// A registry can revoke a token before its advertised expiry. Invalidate it
	// and permit one exact reacquisition/retry; a second 401 is authoritative.
	drainAndClose(response.Body)
	handler.upstream.Tokens().CompareAndDelete(tokenKey, func(current upstreamclient.TokenEntry) bool {
		return current.Version == token.Version
	})
	if nextChallenge := response.Header.Get("WWW-Authenticate"); nextChallenge != "" {
		challenge = nextChallenge
	}
	token, _, err = handler.fetchToken(ctx, resolved, challenge)
	if err != nil {
		return nil, err
	}
	request, err = handler.upstreamRequest(ctx, incoming, target, "Bearer "+token.Value)
	if err != nil {
		return nil, err
	}
	return handler.doFollowing(ctx, resolved.source, request)
}

func (handler *Handler) upstreamRequest(ctx context.Context, incoming *http.Request, target *url.URL, authorization string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, incoming.Method, target.String(), nil)
	if err != nil {
		return nil, err
	}
	for _, header := range []string{"Accept", "Range", "If-Range", "If-None-Match", "If-Modified-Since", "User-Agent"} {
		for _, value := range incoming.Header.Values(header) {
			request.Header.Add(header, value)
		}
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request, nil
}

func (handler *Handler) doFollowing(ctx context.Context, source *Source, request *http.Request) (*http.Response, error) {
	current := request
	for redirects := 0; ; redirects++ {
		if err := handler.validateOutbound(ctx, source, current.URL, false); err != nil {
			return nil, err
		}
		response, err := handler.upstream.Do(current, upstreamclient.Policy{AllowHTTP: source.AllowHTTP, AllowPrivate: source.AllowPrivate})
		if err != nil {
			if errors.Is(err, upstreamclient.ErrUnsafeAddress) || errors.Is(err, upstreamclient.ErrUnsafePort) {
				return nil, errUnsafeUpstream
			}
			return nil, err
		}
		if response.StatusCode < 300 || response.StatusCode > 399 || response.Header.Get("Location") == "" {
			return response, nil
		}
		if redirects >= maxRedirects {
			drainAndClose(response.Body)
			return nil, errors.New("too many registry redirects")
		}
		nextURL, err := current.URL.Parse(response.Header.Get("Location"))
		drainAndClose(response.Body)
		if err != nil {
			return nil, errUnsafeUpstream
		}
		next, err := http.NewRequestWithContext(ctx, current.Method, nextURL.String(), nil)
		if err != nil {
			return nil, err
		}
		next.Header = current.Header.Clone()
		if !sameAuthority(current.URL, nextURL) {
			next.Header.Del("Authorization")
		}
		current = next
	}
}

func sameAuthority(left *url.URL, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

type bearerChallenge struct {
	realm, service, scope string
}

func parseBearerChallenge(value string) (bearerChallenge, error) {
	value = strings.TrimSpace(value)
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer")], "Bearer") {
		return bearerChallenge{}, errUpstreamAuth
	}
	parameters := strings.TrimSpace(value[len("Bearer"):])
	result := bearerChallenge{}
	for _, item := range splitChallenge(parameters) {
		key, raw, found := strings.Cut(strings.TrimSpace(item), "=")
		if !found {
			return bearerChallenge{}, errUpstreamAuth
		}
		decoded, err := strconv.Unquote(strings.TrimSpace(raw))
		if err != nil {
			return bearerChallenge{}, errUpstreamAuth
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "realm":
			result.realm = decoded
		case "service":
			result.service = decoded
		case "scope":
			result.scope = decoded
		}
	}
	if result.realm == "" {
		return bearerChallenge{}, errUpstreamAuth
	}
	return result, nil
}

func splitChallenge(value string) []string {
	var result []string
	start := 0
	quoted := false
	for index, character := range value {
		switch character {
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				result = append(result, value[start:index])
				start = index + 1
			}
		}
	}
	return append(result, value[start:])
}

func (handler *Handler) fetchToken(ctx context.Context, resolved resolvedRequest, rawChallenge string) (upstreamclient.TokenEntry, string, error) {
	var zero upstreamclient.TokenEntry
	challenge, err := parseBearerChallenge(rawChallenge)
	if err != nil {
		return zero, "", err
	}
	realm, err := url.Parse(challenge.realm)
	if err != nil || realm.Hostname() == "" {
		return zero, "", errUpstreamAuth
	}
	if err := handler.validateOutbound(ctx, resolved.source, realm, true); err != nil {
		return zero, "", err
	}
	query := realm.Query()
	if challenge.service != "" {
		query.Set("service", challenge.service)
	}
	expectedScope := "repository:" + resolved.repository + ":pull"
	if challenge.scope != "" && challenge.scope != expectedScope {
		return zero, "", errUpstreamAuth
	}
	query.Set("scope", expectedScope)
	realm.RawQuery = query.Encode()
	cacheKey := strings.Join([]string{realm.String(), challenge.service, expectedScope, resolved.source.Name, resolved.repository, "anonymous", strconv.FormatBool(resolved.source.AllowHTTP), strconv.FormatBool(resolved.source.AllowPrivate)}, "\x00")
	entry, err := handler.upstream.Tokens().GetOrLoad(ctx, cacheKey, func(ctx context.Context) (upstreamclient.Loaded[upstreamclient.TokenEntry], error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
		if err != nil {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, err
		}
		response, err := handler.upstream.Do(request, upstreamclient.Policy{AllowHTTP: resolved.source.AllowHTTP, AllowPrivate: resolved.source.AllowPrivate})
		if err != nil {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			drainAndClose(response.Body)
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, errUpstreamAuth
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
		if err != nil || len(body) > maxTokenBytes {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, errUpstreamAuth
		}
		var payload struct {
			Token       string          `json:"token"`
			AccessToken string          `json:"access_token"`
			ExpiresIn   json.RawMessage `json:"expires_in"`
			IssuedAt    string          `json:"issued_at"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, errUpstreamAuth
		}
		if payload.Token == "" {
			payload.Token = payload.AccessToken
		}
		if payload.Token == "" {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, errUpstreamAuth
		}
		var expiresIn int64
		if len(payload.ExpiresIn) > 0 {
			_ = json.Unmarshal(payload.ExpiresIn, &expiresIn)
		}
		receivedAt := handler.upstream.Now()
		expiresAt, refreshAt, timingErr := tokenCacheTiming(receivedAt, payload.IssuedAt, expiresIn)
		if timingErr != nil {
			return upstreamclient.Loaded[upstreamclient.TokenEntry]{}, timingErr
		}
		ttl, swr := tokenCacheWindows(receivedAt, refreshAt, expiresAt)
		entry := handler.upstream.NewTokenEntry(payload.Token, expiresAt)
		return upstreamclient.Loaded[upstreamclient.TokenEntry]{Value: entry, Size: int64(len(payload.Token)), TTL: ttl, StaleWhileRevalidate: swr}, nil
	})
	if err != nil {
		return zero, cacheKey, err
	}
	if !entry.ExpiresAt.After(handler.upstream.Now()) {
		handler.upstream.Tokens().CompareAndDelete(cacheKey, func(current upstreamclient.TokenEntry) bool {
			return current.Version == entry.Version
		})
		return zero, cacheKey, errUpstreamAuth
	}
	return entry, cacheKey, nil
}

func tokenCacheWindows(receivedAt time.Time, refreshAt time.Time, expiresAt time.Time) (time.Duration, time.Duration) {
	remaining := expiresAt.Sub(receivedAt)
	if remaining <= 0 {
		return 0, 0
	}
	fresh := refreshAt.Sub(receivedAt)
	if fresh <= 0 {
		fresh = min(time.Nanosecond, remaining)
	}
	if fresh > remaining {
		fresh = remaining
	}
	return fresh, remaining - fresh
}

func tokenCacheTiming(receivedAt time.Time, issuedRaw string, expiresIn int64) (time.Time, time.Time, error) {
	lifetime := time.Duration(expiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = time.Minute
	}
	issuedAt := receivedAt
	if issuedRaw != "" {
		parsed, err := time.Parse(time.RFC3339, issuedRaw)
		if err != nil {
			return time.Time{}, time.Time{}, errUpstreamAuth
		}
		issuedAt = parsed
	}
	expiresAt := issuedAt.Add(lifetime)
	if !expiresAt.After(receivedAt) {
		return time.Time{}, time.Time{}, errUpstreamAuth
	}
	refreshAt := issuedAt.Add(lifetime * 4 / 5)
	if beforeExpiry := expiresAt.Add(-30 * time.Second); beforeExpiry.Before(refreshAt) {
		refreshAt = beforeExpiry
	}
	return expiresAt, refreshAt, nil
}

func (handler *Handler) validateOutbound(_ context.Context, source *Source, target *url.URL, token bool) error {
	if target == nil || target.User != nil || target.Hostname() == "" || target.Fragment != "" {
		return errUnsafeUpstream
	}
	if target.Scheme != "https" && !(source.AllowHTTP && target.Scheme == "http") {
		return errUnsafeUpstream
	}
	port := target.Port()
	if !source.AllowPrivate && port != "" && port != "443" {
		return errUnsafeUpstream
	}
	if token {
		allowed := strings.EqualFold(target.Hostname(), source.Endpoint.Hostname())
		for _, host := range source.TokenHosts {
			allowed = allowed || strings.EqualFold(target.Hostname(), host)
		}
		if !allowed {
			return errUnsafeUpstream
		}
	}
	if source.AllowPrivate {
		return nil
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errUnsafeUpstream
	}
	if address := net.ParseIP(host); address != nil && !upstreamclient.IsPublicIP(address) {
		return errUnsafeUpstream
	}
	return nil
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	_ = body.Close()
}

func (handler *Handler) serveManifest(writer http.ResponseWriter, request *http.Request, resolved resolvedRequest, response *http.Response) {
	if request.Method == http.MethodHead {
		advertised := response.Header.Get("Docker-Content-Digest")
		if advertised != "" && !digestPattern.MatchString(advertised) {
			writeMappedError(writer, streaming.ErrDigestInvalid)
			return
		}
		if digestPattern.MatchString(resolved.reference) && !strings.EqualFold(advertised, resolved.reference) {
			writeMappedError(writer, streaming.ErrDigestMismatch)
			return
		}
		if mediaType := response.Header.Get("Content-Type"); mediaType != "" && !recognizedManifestMediaType(mediaType) {
			writeMappedError(writer, errManifestInvalid)
			return
		}
		copyResponseHeaders(writer.Header(), response.Header)
		writer.WriteHeader(response.StatusCode)
		return
	}
	entry, err := manifestEntryFromResponse(resolved, response)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	serveManifestEntry(writer, entry)
}

type upstreamStatusError struct{ status int }

func (statusError upstreamStatusError) Error() string {
	return "registry upstream rejected the manifest request"
}

func (handler *Handler) serveCachedManifest(writer http.ResponseWriter, request *http.Request, resolved resolvedRequest, target *url.URL) {
	key := strings.Join([]string{resolved.source.Name, resolved.repository, resolved.reference, strings.Join(request.Header.Values("Accept"), ","), "anonymous", strconv.FormatBool(resolved.source.AllowHTTP), strconv.FormatBool(resolved.source.AllowPrivate)}, "\x00")
	requestTemplate := request.Clone(context.Background())
	previous, hasPrevious := handler.upstream.Manifests().Peek(key)
	entry, err := handler.upstream.Manifests().GetOrLoad(request.Context(), key, func(ctx context.Context) (upstreamclient.Loaded[upstreamclient.ManifestEntry], error) {
		refreshRequest := requestTemplate.Clone(context.Background())
		if hasPrevious {
			refreshRequest.Header.Del("If-None-Match")
			refreshRequest.Header.Del("If-Modified-Since")
			if etag := previous.Header.Get("ETag"); etag != "" {
				refreshRequest.Header.Set("If-None-Match", etag)
			} else if modified := previous.Header.Get("Last-Modified"); modified != "" {
				refreshRequest.Header.Set("If-Modified-Since", modified)
			}
		}
		response, err := handler.fetch(ctx, refreshRequest, resolved, target)
		if err != nil {
			return upstreamclient.Loaded[upstreamclient.ManifestEntry]{}, err
		}
		defer response.Body.Close()
		ttl, swr, sie := manifestCacheWindows(resolved.reference)
		if response.StatusCode == http.StatusNotModified {
			if !hasPrevious {
				header := make(http.Header)
				copyResponseHeaders(header, response.Header)
				return upstreamclient.Loaded[upstreamclient.ManifestEntry]{Value: upstreamclient.ManifestEntry{Status: http.StatusNotModified, Header: header}}, nil
			}
			if err := validateManifest304(previous, response.Header); err != nil {
				return upstreamclient.Loaded[upstreamclient.ManifestEntry]{}, upstreamclient.PermanentCacheError(err)
			}
			updated := previous
			updated.Header = previous.Header.Clone()
			mergeManifestValidators(updated.Header, response.Header)
			return upstreamclient.Loaded[upstreamclient.ManifestEntry]{Value: updated, Size: int64(len(updated.Body) + headerSize(updated.Header)), TTL: ttl, StaleWhileRevalidate: swr, StaleIfError: sie}, nil
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			drainAndClose(response.Body)
			err := error(upstreamStatusError{status: response.StatusCode})
			if response.StatusCode < 500 || response.StatusCode > 599 {
				err = upstreamclient.PermanentCacheError(err)
			}
			return upstreamclient.Loaded[upstreamclient.ManifestEntry]{}, err
		}
		manifest, err := manifestEntryFromResponse(resolved, response)
		if err != nil {
			return upstreamclient.Loaded[upstreamclient.ManifestEntry]{}, upstreamclient.PermanentCacheError(err)
		}
		return upstreamclient.Loaded[upstreamclient.ManifestEntry]{Value: manifest, Size: int64(len(manifest.Body) + headerSize(manifest.Header)), TTL: ttl, StaleWhileRevalidate: swr, StaleIfError: sie}, nil
	})
	if err != nil {
		var statusError upstreamStatusError
		if errors.As(err, &statusError) {
			writeError(writer, statusError.status, "UPSTREAM_ERROR", "registry upstream rejected the request")
			return
		}
		writeMappedError(writer, err)
		return
	}
	serveManifestEntryConditional(writer, request, entry)
}

func manifestCacheWindows(reference string) (time.Duration, time.Duration, time.Duration) {
	if digestPattern.MatchString(reference) {
		return 10 * time.Minute, 5 * time.Minute, 30 * time.Minute
	}
	return time.Minute, 30 * time.Second, 5 * time.Minute
}

func mergeManifestValidators(destination http.Header, source http.Header) {
	for _, header := range []string{"ETag", "Last-Modified"} {
		if values := source.Values(header); len(values) > 0 {
			destination.Del(header)
			for _, value := range values {
				destination.Add(header, value)
			}
		}
	}
}

func validateManifest304(entry upstreamclient.ManifestEntry, header http.Header) error {
	for _, advertised := range header.Values("Docker-Content-Digest") {
		if advertised == "" || !strings.EqualFold(advertised, entry.Digest) {
			return streaming.ErrDigestMismatch
		}
	}
	for _, advertised := range header.Values("Content-Length") {
		length, err := strconv.ParseInt(strings.TrimSpace(advertised), 10, 64)
		if err != nil || length != int64(len(entry.Body)) {
			return errManifestInvalid
		}
	}
	for _, advertised := range header.Values("Content-Type") {
		if advertised == "" || !validManifest(entry.Body, advertised) {
			return errManifestInvalid
		}
		if cached := entry.Header.Get("Content-Type"); cached != "" && normalizeManifestMediaType(cached) != normalizeManifestMediaType(advertised) {
			return errManifestInvalid
		}
	}
	return nil
}

func serveManifestEntryConditional(writer http.ResponseWriter, request *http.Request, entry upstreamclient.ManifestEntry) {
	if entry.Status == http.StatusNotModified || manifestNotModified(request.Header, entry.Header) {
		copyResponseHeaders(writer.Header(), entry.Header)
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	serveManifestEntry(writer, entry)
}

func manifestNotModified(request http.Header, cached http.Header) bool {
	if condition := request.Get("If-None-Match"); condition != "" {
		etag := cached.Get("ETag")
		for _, candidate := range strings.Split(condition, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || (etag != "" && strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/")) {
				return true
			}
		}
		return false
	}
	condition := request.Get("If-Modified-Since")
	modified := cached.Get("Last-Modified")
	if condition == "" || modified == "" {
		return false
	}
	conditionTime, conditionErr := http.ParseTime(condition)
	modifiedTime, modifiedErr := http.ParseTime(modified)
	return conditionErr == nil && modifiedErr == nil && !modifiedTime.After(conditionTime)
}

func manifestEntryFromResponse(resolved resolvedRequest, response *http.Response) (upstreamclient.ManifestEntry, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil || len(body) > maxManifestBytes || !validManifest(body, response.Header.Get("Content-Type")) {
		return upstreamclient.ManifestEntry{}, errManifestInvalid
	}
	digest := "sha256:" + hashHex(body)
	upstreamDigest := response.Header.Get("Docker-Content-Digest")
	if upstreamDigest != "" && !strings.EqualFold(upstreamDigest, digest) {
		return upstreamclient.ManifestEntry{}, streaming.ErrDigestMismatch
	}
	if digestPattern.MatchString(resolved.reference) && !strings.EqualFold(resolved.reference, digest) {
		return upstreamclient.ManifestEntry{}, streaming.ErrDigestMismatch
	}
	header := make(http.Header)
	copyResponseHeaders(header, response.Header)
	header.Set("Docker-Content-Digest", digest)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return upstreamclient.ManifestEntry{Status: response.StatusCode, Header: header, Body: append([]byte(nil), body...), Digest: digest}, nil
}

func serveManifestEntry(writer http.ResponseWriter, entry upstreamclient.ManifestEntry) {
	for key, values := range entry.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(entry.Status)
	_, _ = writer.Write(entry.Body)
}

func headerSize(header http.Header) int {
	size := 0
	for key, values := range header {
		size += len(key)
		for _, value := range values {
			size += len(value)
		}
	}
	return size
}

type manifestDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      *int64 `json:"size"`
}

func validManifest(body []byte, contentType string) bool {
	var envelope struct {
		SchemaVersion int                  `json:"schemaVersion"`
		MediaType     string               `json:"mediaType"`
		Config        *manifestDescriptor  `json:"config"`
		Layers        []manifestDescriptor `json:"layers"`
		Manifests     []manifestDescriptor `json:"manifests"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.SchemaVersion != 2 {
		return false
	}
	bodyMediaType := normalizeManifestMediaType(envelope.MediaType)
	headerMediaType := normalizeManifestMediaType(contentType)
	if bodyMediaType != "" && headerMediaType != "" && bodyMediaType != headerMediaType {
		return false
	}
	mediaType := bodyMediaType
	if mediaType == "" {
		mediaType = headerMediaType
	}
	switch mediaType {
	case "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json":
		if envelope.Config == nil || envelope.Layers == nil || !validManifestDescriptor(*envelope.Config) {
			return false
		}
		for _, descriptor := range envelope.Layers {
			if !validManifestDescriptor(descriptor) {
				return false
			}
		}
		return true
	case "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.index.v1+json":
		if len(envelope.Manifests) == 0 {
			return false
		}
		for _, descriptor := range envelope.Manifests {
			if !validManifestDescriptor(descriptor) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func recognizedManifestMediaType(value string) bool {
	value = normalizeManifestMediaType(value)
	switch value {
	case "application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json":
		return true
	default:
		return false
	}
}

func normalizeManifestMediaType(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
}

func validManifestDescriptor(descriptor manifestDescriptor) bool {
	return descriptor.MediaType != "" && descriptor.Size != nil && *descriptor.Size >= 0 && digestPattern.MatchString(descriptor.Digest)
}

func hashHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func (handler *Handler) serveStream(writer http.ResponseWriter, request *http.Request, resolved resolvedRequest, response *http.Response) {
	expectedDigest := ""
	expectedLength := response.ContentLength
	if resolved.kind == resourceBlob {
		if response.StatusCode != http.StatusPartialContent {
			expectedDigest = resolved.reference
		}
		advertised := response.Header.Get("Docker-Content-Digest")
		if advertised != "" && !strings.EqualFold(advertised, resolved.reference) {
			writeMappedError(writer, streaming.ErrDigestMismatch)
			return
		}
		if request.Method == http.MethodHead && advertised == "" {
			writeMappedError(writer, streaming.ErrDigestInvalid)
			return
		}
		if response.StatusCode == http.StatusPartialContent {
			var err error
			expectedLength, err = validatePartialRange(request.Header.Get("Range"), response.Header.Get("Content-Range"))
			if err != nil || (response.ContentLength >= 0 && response.ContentLength != expectedLength) {
				writeMappedError(writer, errRangeInvalid)
				return
			}
		}
	}
	copyResponseHeaders(writer.Header(), response.Header)
	if request.Method != http.MethodHead {
		// Declaring a trailer forces framed streaming instead of a fixed-size
		// response. A late integrity failure can then abort observably rather
		// than looking like a successfully completed Content-Length body.
		writer.Header().Del("Content-Length")
		writer.Header().Set("Trailer", "X-Accelerator-Stream-Error")
	}
	writer.WriteHeader(response.StatusCode)
	if request.Method == http.MethodHead {
		return
	}
	_, err := streaming.Copy(writer, response.Body, streaming.CopyOptions{ExpectedLength: expectedLength, ExpectedDigest: expectedDigest, Flush: streaming.FlushFunc(writer)})
	if err != nil {
		writer.Header().Set("X-Accelerator-Stream-Error", "integrity-failure")
		// The response is already committed. Abort the HTTP stream instead of
		// appending an error representation to registry bytes.
		panic(http.ErrAbortHandler)
	}
}

type requestedByteRange struct {
	start  int64
	end    int64
	suffix int64
	open   bool
}

func validatePartialRange(requestRange string, contentRange string) (int64, error) {
	requested, err := parseRequestedRange(requestRange)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(contentRange, "bytes ") {
		return 0, errRangeInvalid
	}
	interval, totalValue, found := strings.Cut(strings.TrimPrefix(contentRange, "bytes "), "/")
	if !found || totalValue == "*" {
		return 0, errRangeInvalid
	}
	startValue, endValue, found := strings.Cut(interval, "-")
	if !found {
		return 0, errRangeInvalid
	}
	start, startErr := strconv.ParseInt(startValue, 10, 64)
	end, endErr := strconv.ParseInt(endValue, 10, 64)
	total, totalErr := strconv.ParseInt(totalValue, 10, 64)
	if startErr != nil || endErr != nil || totalErr != nil || start < 0 || end < start || total <= end {
		return 0, errRangeInvalid
	}
	expectedStart, expectedEnd := requested.start, requested.end
	if requested.suffix > 0 {
		expectedStart = total - requested.suffix
		if expectedStart < 0 {
			expectedStart = 0
		}
		expectedEnd = total - 1
	} else if requested.open {
		expectedEnd = total - 1
	} else if expectedEnd >= total {
		expectedEnd = total - 1
	}
	if start != expectedStart || end != expectedEnd {
		return 0, errRangeInvalid
	}
	return end - start + 1, nil
}

func parseRequestedRange(value string) (requestedByteRange, error) {
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return requestedByteRange{}, errRangeInvalid
	}
	startValue, endValue, found := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !found || (startValue == "" && endValue == "") {
		return requestedByteRange{}, errRangeInvalid
	}
	if startValue == "" {
		suffix, err := strconv.ParseInt(endValue, 10, 64)
		if err != nil || suffix <= 0 {
			return requestedByteRange{}, errRangeInvalid
		}
		return requestedByteRange{suffix: suffix}, nil
	}
	start, err := strconv.ParseInt(startValue, 10, 64)
	if err != nil || start < 0 {
		return requestedByteRange{}, errRangeInvalid
	}
	if endValue == "" {
		return requestedByteRange{start: start, open: true}, nil
	}
	end, err := strconv.ParseInt(endValue, 10, 64)
	if err != nil || end < start {
		return requestedByteRange{}, errRangeInvalid
	}
	return requestedByteRange{start: start, end: end}, nil
}

func copyResponseHeaders(destination http.Header, source http.Header) {
	for _, header := range []string{"Accept-Ranges", "Content-Length", "Content-Range", "Content-Type", "Docker-Content-Digest", "ETag", "Last-Modified"} {
		for _, value := range source.Values(header) {
			destination.Add(header, value)
		}
	}
}

func copyUpstreamError(writer http.ResponseWriter, response *http.Response) {
	status := response.StatusCode
	if status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	writeError(writer, status, "UPSTREAM_ERROR", "registry upstream rejected the request")
}

func writeMappedError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidRoute):
		writeError(writer, http.StatusBadRequest, "NAME_INVALID", "invalid registry route")
	case errors.Is(err, errUnsupportedRegistry):
		writeError(writer, http.StatusNotFound, "REGISTRY_UNSUPPORTED", "registry is not supported")
	case errors.Is(err, errUnsafeUpstream):
		writeError(writer, http.StatusForbidden, "UPSTREAM_FORBIDDEN", "registry upstream is not public")
	case errors.Is(err, errUpstreamAuth):
		writeError(writer, http.StatusBadGateway, "UNAUTHORIZED", "registry token exchange failed")
	case errors.Is(err, errManifestInvalid):
		writeError(writer, http.StatusBadGateway, "MANIFEST_INVALID", "registry manifest is invalid")
	case errors.Is(err, errRangeInvalid):
		writeError(writer, http.StatusBadGateway, "RANGE_INVALID", "registry partial response is invalid")
	case errors.Is(err, streaming.ErrDigestMismatch), errors.Is(err, streaming.ErrDigestInvalid), errors.Is(err, streaming.ErrLengthMismatch):
		writeError(writer, http.StatusBadGateway, "DIGEST_INVALID", "registry content integrity check failed")
	default:
		writeError(writer, http.StatusBadGateway, "UPSTREAM_UNAVAILABLE", "registry upstream is unavailable")
	}
}

func writeError(writer http.ResponseWriter, status int, code string, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": message}}})
}
