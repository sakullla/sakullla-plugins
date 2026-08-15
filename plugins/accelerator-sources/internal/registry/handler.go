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

	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/streaming"
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
	Resolver *net.Resolver
	Sources  []Source
}

type Handler struct {
	client   *http.Client
	resolver *net.Resolver
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
	if options.Client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true
		options.Client = &http.Client{Transport: transport}
	}
	client := *options.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	if len(options.Sources) == 0 {
		options.Sources = DefaultSources()
	}
	handler := &Handler{client: &client, resolver: options.Resolver, sources: make(map[string]*Source)}
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
	response.Body.Close()
	token, err := handler.fetchToken(ctx, resolved, challenge)
	if err != nil {
		return nil, err
	}
	request, err = handler.upstreamRequest(ctx, incoming, target, "Bearer "+token)
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
		response, err := handler.client.Do(current)
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 300 || response.StatusCode > 399 || response.Header.Get("Location") == "" {
			return response, nil
		}
		if redirects >= maxRedirects {
			response.Body.Close()
			return nil, errors.New("too many registry redirects")
		}
		nextURL, err := current.URL.Parse(response.Header.Get("Location"))
		response.Body.Close()
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

func (handler *Handler) fetchToken(ctx context.Context, resolved resolvedRequest, rawChallenge string) (string, error) {
	challenge, err := parseBearerChallenge(rawChallenge)
	if err != nil {
		return "", err
	}
	realm, err := url.Parse(challenge.realm)
	if err != nil || realm.Hostname() == "" {
		return "", errUpstreamAuth
	}
	if err := handler.validateOutbound(ctx, resolved.source, realm, true); err != nil {
		return "", err
	}
	query := realm.Query()
	if challenge.service != "" {
		query.Set("service", challenge.service)
	}
	expectedScope := "repository:" + resolved.repository + ":pull"
	if challenge.scope != "" && challenge.scope != expectedScope {
		return "", errUpstreamAuth
	}
	query.Set("scope", expectedScope)
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := handler.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errUpstreamAuth
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
	if err != nil || len(body) > maxTokenBytes {
		return "", errUpstreamAuth
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errUpstreamAuth
	}
	if payload.Token == "" {
		payload.Token = payload.AccessToken
	}
	if payload.Token == "" {
		return "", errUpstreamAuth
	}
	return payload.Token, nil
}

func (handler *Handler) validateOutbound(ctx context.Context, source *Source, target *url.URL, token bool) error {
	if target == nil || target.User != nil || target.Hostname() == "" || target.Fragment != "" {
		return errUnsafeUpstream
	}
	if target.Scheme != "https" && !(source.AllowHTTP && target.Scheme == "http") {
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
	addresses, err := handler.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return errUnsafeUpstream
	}
	for _, address := range addresses {
		if !isPublicIP(address.IP) {
			return errUnsafeUpstream
		}
	}
	return nil
}

func isPublicIP(address net.IP) bool {
	return address != nil && !address.IsUnspecified() && !address.IsLoopback() && !address.IsPrivate() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast()
}

func (handler *Handler) serveManifest(writer http.ResponseWriter, request *http.Request, resolved resolvedRequest, response *http.Response) {
	if request.Method == http.MethodHead {
		copyResponseHeaders(writer.Header(), response.Header)
		writer.WriteHeader(response.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil || len(body) > maxManifestBytes || !validManifest(body) {
		writeMappedError(writer, errManifestInvalid)
		return
	}
	digest := "sha256:" + hashHex(body)
	upstreamDigest := response.Header.Get("Docker-Content-Digest")
	if upstreamDigest != "" && !strings.EqualFold(upstreamDigest, digest) {
		writeMappedError(writer, streaming.ErrDigestMismatch)
		return
	}
	if digestPattern.MatchString(resolved.reference) && !strings.EqualFold(resolved.reference, digest) {
		writeMappedError(writer, streaming.ErrDigestMismatch)
		return
	}
	copyResponseHeaders(writer.Header(), response.Header)
	writer.Header().Set("Docker-Content-Digest", digest)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(response.StatusCode)
	_, _ = writer.Write(body)
}

func validManifest(body []byte) bool {
	var envelope struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.SchemaVersion == 2
}

func hashHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func (handler *Handler) serveStream(writer http.ResponseWriter, request *http.Request, resolved resolvedRequest, response *http.Response) {
	expectedDigest := ""
	if resolved.kind == resourceBlob {
		if response.StatusCode != http.StatusPartialContent {
			expectedDigest = resolved.reference
		}
		if advertised := response.Header.Get("Docker-Content-Digest"); advertised != "" && !strings.EqualFold(advertised, resolved.reference) {
			writeMappedError(writer, streaming.ErrDigestMismatch)
			return
		}
	}
	copyResponseHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	if request.Method == http.MethodHead {
		return
	}
	_, err := streaming.Copy(writer, response.Body, streaming.CopyOptions{ExpectedLength: response.ContentLength, ExpectedDigest: expectedDigest, Flush: streaming.FlushFunc(writer)})
	if err != nil {
		// The response is already committed. Abort the HTTP stream instead of
		// appending an error representation to registry bytes.
		panic(http.ErrAbortHandler)
	}
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
