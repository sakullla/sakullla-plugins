// Package imagetar streams Docker-compatible image archives without invoking
// Docker or materializing the archive on disk.
package imagetar

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/sourceproxy"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/streaming"
	"github.com/sakullla/sakullla-plugins/plugins/accelerator-sources/internal/upstream"
)

const (
	maxManifestBytes = 16 << 20
	maxTokenBytes    = 1 << 20
	maxImages        = 16
	maxRedirects     = 5
	planTTL          = 5 * time.Minute
	maxConfigBytes   = 16 << 20
	maxLayerBytes    = int64(64 << 30)
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

var (
	namePartPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	tagPattern      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Source struct {
	Endpoint     *url.URL
	TokenHosts   []string
	AllowHTTP    bool
	AllowPrivate bool
}

type Options struct {
	Upstream *upstream.Manager
	Sources  map[string]Source
}

type Handler struct {
	upstream *upstream.Manager
	sources  map[string]Source
	plansMu  sync.Mutex
	plans    map[string]downloadPlan
}

type downloadPlan struct {
	Images   []string
	Platform string
	Expires  time.Time
}

type tokenLease struct {
	entry upstream.TokenEntry
	key   string
}

type requestPayload struct {
	Images   []string `json:"images"`
	Image    string   `json:"image"`
	Platform string   `json:"platform"`
}

type imageRef struct {
	Registry, Repository, Reference, Tag string
	Source                               Source
}

type descriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	Platform  platform `json:"platform,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type manifestDocument struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type imageConfig struct {
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type resolvedImage struct {
	ref        imageRef
	manifest   manifestDocument
	config     descriptor
	configBody []byte
	diffIDs    []string
	layers     []descriptor
	paths      []string
}

func NewHandler(options Options) (*Handler, error) {
	if options.Upstream == nil {
		return nil, errors.New("offline image service requires shared upstream manager")
	}
	if len(options.Sources) == 0 {
		options.Sources = defaultSources()
	}
	sources := make(map[string]Source, len(options.Sources))
	for name, source := range options.Sources {
		name = strings.ToLower(name)
		if source.Endpoint == nil || source.Endpoint.Hostname() == "" || source.Endpoint.User != nil || source.Endpoint.RawQuery != "" || source.Endpoint.Fragment != "" || (source.Endpoint.Scheme != "https" && !(source.AllowHTTP && source.Endpoint.Scheme == "http")) {
			return nil, fmt.Errorf("invalid offline registry %q", name)
		}
		clone := *source.Endpoint
		source.Endpoint = &clone
		sources[name] = source
	}
	return &Handler{upstream: options.Upstream, sources: sources, plans: make(map[string]downloadPlan)}, nil
}

func defaultSources() map[string]Source {
	return map[string]Source{
		"docker.io":       {Endpoint: &url.URL{Scheme: "https", Host: "registry-1.docker.io"}, TokenHosts: []string{"auth.docker.io"}},
		"ghcr.io":         {Endpoint: &url.URL{Scheme: "https", Host: "ghcr.io"}},
		"gcr.io":          {Endpoint: &url.URL{Scheme: "https", Host: "gcr.io"}},
		"quay.io":         {Endpoint: &url.URL{Scheme: "https", Host: "quay.io"}},
		"registry.k8s.io": {Endpoint: &url.URL{Scheme: "https", Host: "registry.k8s.io"}},
	}
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/api/offline/prepare" {
		handler.prepare(writer, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/offline/") {
		handler.downloadPrepared(writer, request)
		return
	}
	if request.URL.Path != "/api/offline" {
		http.NotFound(writer, request)
		return
	}
	payload, err := parsePayload(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	handler.stream(writer, request, payload)
}

func (handler *Handler) prepare(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		writeError(writer, http.StatusMethodNotAllowed, "offline prepare requires POST")
		return
	}
	payload, err := parsePayload(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	authority, err := sourceproxy.ExternalAuthority(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "trusted external authority is required")
		return
	}
	var tokenBytes [24]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		writeError(writer, http.StatusInternalServerError, "download token unavailable")
		return
	}
	token := hex.EncodeToString(tokenBytes[:])
	handler.plansMu.Lock()
	handler.expirePlansLocked()
	if len(handler.plans) >= 128 {
		handler.plansMu.Unlock()
		writeError(writer, http.StatusServiceUnavailable, "too many prepared downloads")
		return
	}
	handler.plans[token] = downloadPlan{Images: append([]string(nil), payload.Images...), Platform: payload.Platform, Expires: handler.upstream.Now().Add(planTTL)}
	handler.plansMu.Unlock()
	download := strings.TrimSuffix(authority.String(), "/") + "/api/offline/" + token
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{"download_url": download, "expires_at": handler.upstream.Now().Add(planTTL).UTC().Format(time.RFC3339)})
}

func (handler *Handler) downloadPrepared(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		writeError(writer, http.StatusMethodNotAllowed, "prepared download requires GET or HEAD")
		return
	}
	token := strings.TrimPrefix(request.URL.Path, "/api/offline/")
	if len(token) != 48 || strings.Contains(token, "/") {
		writeError(writer, http.StatusNotFound, "download token not found")
		return
	}
	handler.plansMu.Lock()
	handler.expirePlansLocked()
	plan, found := handler.plans[token]
	if found && request.Method == http.MethodGet {
		delete(handler.plans, token)
	}
	handler.plansMu.Unlock()
	if !found {
		writeError(writer, http.StatusNotFound, "download token not found")
		return
	}
	handler.stream(writer, request, requestPayload{Images: plan.Images, Platform: plan.Platform})
}

func (handler *Handler) expirePlansLocked() {
	now := handler.upstream.Now()
	for token, plan := range handler.plans {
		if !plan.Expires.After(now) {
			delete(handler.plans, token)
		}
	}
}

func parsePayload(request *http.Request) (requestPayload, error) {
	var payload requestPayload
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		payload.Images = request.URL.Query()["image"]
		payload.Platform = request.URL.Query().Get("platform")
	case http.MethodPost:
		decoder := json.NewDecoder(io.LimitReader(request.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			return payload, errors.New("invalid offline request")
		}
		if payload.Image != "" {
			payload.Images = append(payload.Images, payload.Image)
		}
	default:
		return payload, errors.New("offline requests support GET, HEAD and POST")
	}
	if len(payload.Images) == 0 || len(payload.Images) > maxImages {
		return payload, fmt.Errorf("offline request requires 1-%d images", maxImages)
	}
	if payload.Platform == "" {
		payload.Platform = runtime.GOOS + "/" + runtime.GOARCH
		if runtime.GOOS != "linux" {
			payload.Platform = "linux/amd64"
		}
	}
	if _, err := parsePlatform(payload.Platform); err != nil {
		return payload, err
	}
	return payload, nil
}

func (handler *Handler) stream(writer http.ResponseWriter, request *http.Request, payload requestPayload) {
	resolved := make([]resolvedImage, 0, len(payload.Images))
	for _, value := range payload.Images {
		image, err := handler.resolveImage(request.Context(), value, payload.Platform)
		if err != nil {
			writeError(writer, http.StatusBadGateway, "unable to resolve image manifest")
			return
		}
		resolved = append(resolved, image)
	}
	writer.Header().Set("Content-Type", "application/x-tar")
	writer.Header().Set("Content-Disposition", `attachment; filename="images.tar"`)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	archive := tar.NewWriter(writer)
	if err := handler.writeArchive(request.Context(), archive, writer, resolved); err != nil {
		_ = archive.Close()
		return
	}
	_ = archive.Close()
}

func (handler *Handler) resolveImage(ctx context.Context, value, platformValue string) (resolvedImage, error) {
	ref, err := handler.parseImageRef(value)
	if err != nil {
		return resolvedImage{}, err
	}
	body, _, err := handler.fetchManifest(ctx, ref, ref.Reference)
	if err != nil {
		return resolvedImage{}, err
	}
	var document manifestDocument
	if err := json.Unmarshal(body, &document); err != nil || document.SchemaVersion != 2 {
		return resolvedImage{}, errors.New("invalid image manifest")
	}
	if len(document.Manifests) > 0 {
		selected, err := selectPlatform(document.Manifests, platformValue)
		if err != nil {
			return resolvedImage{}, err
		}
		body, _, err = handler.fetchManifest(ctx, ref, selected.Digest)
		if err != nil {
			return resolvedImage{}, err
		}
		if err := json.Unmarshal(body, &document); err != nil || document.SchemaVersion != 2 {
			return resolvedImage{}, errors.New("invalid selected manifest")
		}
		if selected.MediaType != "" && document.MediaType != selected.MediaType {
			return resolvedImage{}, errors.New("selected manifest media type mismatch")
		}
	}
	if err := validateDescriptor(document.Config); err != nil || !supportedConfigType(document.Config.MediaType) || len(document.Layers) == 0 {
		return resolvedImage{}, errors.New("manifest lacks config or layers")
	}
	configBody, err := handler.fetchSmallObject(ctx, ref, document.Config, maxConfigBytes)
	if err != nil {
		return resolvedImage{}, err
	}
	var config imageConfig
	if err := json.Unmarshal(configBody, &config); err != nil || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(document.Layers) {
		return resolvedImage{}, errors.New("config rootfs does not match manifest layers")
	}
	for _, diffID := range config.RootFS.DiffIDs {
		if !digestPattern.MatchString(strings.ToLower(diffID)) {
			return resolvedImage{}, errors.New("config contains invalid diff ID")
		}
	}
	paths := make([]string, len(document.Layers))
	for index, layer := range document.Layers {
		if err := validateDescriptor(layer); err != nil || !supportedLayerType(layer.MediaType) {
			return resolvedImage{}, err
		}
		paths[index] = digestHex(layer.Digest) + "/layer.tar"
	}
	return resolvedImage{ref: ref, manifest: document, config: document.Config, configBody: configBody, diffIDs: append([]string(nil), config.RootFS.DiffIDs...), layers: document.Layers, paths: paths}, nil
}

func (handler *Handler) writeArchive(ctx context.Context, archive *tar.Writer, response http.ResponseWriter, images []resolvedImage) error {
	type archiveManifest struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	manifest := make([]archiveManifest, 0, len(images))
	for _, image := range images {
		var repoTags []string
		if image.ref.Tag != "" {
			repoTags = []string{image.ref.Tag}
		}
		manifest = append(manifest, archiveManifest{Config: digestHex(image.config.Digest) + ".json", RepoTags: repoTags, Layers: image.paths})
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeBytes(archive, "manifest.json", manifestBody); err != nil {
		return err
	}
	written := make(map[string]bool)
	for _, image := range images {
		if !written[image.config.Digest] {
			written[image.config.Digest] = true
			if err := writeBytes(archive, digestHex(image.config.Digest)+".json", image.configBody); err != nil {
				return err
			}
		}
	}
	if err := streaming.FlushFunc(response)(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	for _, image := range images {
		for index, layer := range image.layers {
			if written[layer.Digest] {
				continue
			}
			written[layer.Digest] = true
			spool, size, diffID, err := handler.spoolLayer(ctx, image.ref, layer)
			if err != nil {
				return err
			}
			if diffID != strings.ToLower(image.diffIDs[index]) {
				spool.Close()
				os.Remove(spool.Name())
				return streaming.ErrDigestMismatch
			}
			if err := archive.WriteHeader(&tar.Header{Name: image.paths[index], Mode: 0o644, Size: size, ModTime: time.Unix(0, 0)}); err != nil {
				spool.Close()
				os.Remove(spool.Name())
				return err
			}
			_, copyErr := streaming.Copy(archive, spool, streaming.CopyOptions{ExpectedLength: size, ExpectedDigest: diffID, Flush: streaming.FlushFunc(response)})
			closeErr := spool.Close()
			removeErr := os.Remove(spool.Name())
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
	}
	return nil
}

func (handler *Handler) fetchSmallObject(ctx context.Context, ref imageRef, object descriptor, maximum int64) ([]byte, error) {
	if object.Size > maximum {
		return nil, errors.New("image config exceeds size limit")
	}
	body, length, err := handler.fetchBlob(ctx, ref, object.Digest)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if length >= 0 && length != object.Size {
		return nil, streaming.ErrLengthMismatch
	}
	value, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || int64(len(value)) != object.Size {
		return nil, streaming.ErrLengthMismatch
	}
	if digestBytes(value) != strings.ToLower(object.Digest) {
		return nil, streaming.ErrDigestMismatch
	}
	return value, nil
}

func (handler *Handler) spoolLayer(ctx context.Context, ref imageRef, layer descriptor) (*os.File, int64, string, error) {
	body, length, err := handler.fetchBlob(ctx, ref, layer.Digest)
	if err != nil {
		return nil, 0, "", err
	}
	defer body.Close()
	if length >= 0 && length != layer.Size {
		return nil, 0, "", streaming.ErrLengthMismatch
	}
	compressed := &digestReader{reader: body, hasher: sha256.New()}
	reader, closeReader, err := layerReader(compressed, layer.MediaType)
	if err != nil {
		return nil, 0, "", err
	}
	temporary, err := os.CreateTemp("", "accelerator-layer-*.tar")
	if err != nil {
		_ = closeReader()
		return nil, 0, "", err
	}
	cleanup := func() {
		temporary.Close()
		os.Remove(temporary.Name())
	}
	uncompressedHash := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(temporary, uncompressedHash), io.LimitReader(reader, maxLayerBytes+1), make([]byte, 64*1024))
	if err != nil || written > maxLayerBytes {
		_ = closeReader()
		cleanup()
		return nil, 0, "", errors.New("unable to unpack image layer")
	}
	if err := closeReader(); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	if compressed.read != layer.Size || "sha256:"+hex.EncodeToString(compressed.hasher.Sum(nil)) != strings.ToLower(layer.Digest) {
		cleanup()
		return nil, 0, "", streaming.ErrDigestMismatch
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	if err := validateLayerTar(temporary); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	return temporary, written, "sha256:" + hex.EncodeToString(uncompressedHash.Sum(nil)), nil
}

type digestReader struct {
	reader io.Reader
	hasher hash.Hash
	read   int64
}

func (reader *digestReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		_, _ = reader.hasher.Write(buffer[:count])
		reader.read += int64(count)
	}
	return count, err
}

func layerReader(source io.Reader, mediaType string) (io.Reader, func() error, error) {
	switch mediaType {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar":
		return source, func() error { return nil }, nil
	case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		reader, err := gzip.NewReader(source)
		if err != nil {
			return nil, func() error { return nil }, err
		}
		return reader, reader.Close, nil
	case "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		reader, err := zstd.NewReader(source)
		if err != nil {
			return nil, func() error { return nil }, err
		}
		return reader, func() error { reader.Close(); return nil }, nil
	default:
		return nil, func() error { return nil }, errors.New("unsupported layer media type")
	}
}

func validateLayerTar(source io.Reader) error {
	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("layer content is not a tar archive")
		}
		clean := path.Clean(strings.ReplaceAll(header.Name, "\\", "/"))
		if strings.HasPrefix(header.Name, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return errors.New("layer tar contains unsafe path")
		}
	}
}

func writeBytes(archive *tar.Writer, name string, body []byte) error {
	if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0)}); err != nil {
		return err
	}
	_, err := archive.Write(body)
	return err
}

func (handler *Handler) parseImageRef(value string) (imageRef, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || strings.ContainsAny(value, "?#\\") {
		return imageRef{}, errors.New("invalid image")
	}
	registry := "docker.io"
	parts := strings.Split(value, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		registry = parts[0]
		parts = parts[1:]
	}
	source, found := handler.sources[registry]
	if !found || len(parts) == 0 {
		return imageRef{}, errors.New("unsupported registry")
	}
	reference := "latest"
	last := parts[len(parts)-1]
	if at := strings.LastIndex(last, "@"); at >= 0 {
		reference = last[at+1:]
		parts[len(parts)-1] = last[:at]
	} else if colon := strings.LastIndex(last, ":"); colon >= 0 {
		reference = last[colon+1:]
		parts[len(parts)-1] = last[:colon]
	}
	if registry == "docker.io" && len(parts) == 1 {
		parts = append([]string{"library"}, parts...)
	}
	for _, part := range parts {
		if !namePartPattern.MatchString(part) {
			return imageRef{}, errors.New("invalid repository")
		}
	}
	if !tagPattern.MatchString(reference) && !digestPattern.MatchString(reference) {
		return imageRef{}, errors.New("invalid reference")
	}
	repository := strings.Join(parts, "/")
	tag := ""
	if tagPattern.MatchString(reference) {
		tag = registry + "/" + repository + ":" + reference
		if registry == "docker.io" {
			tag = repository + ":" + reference
		}
	}
	return imageRef{Registry: registry, Repository: repository, Reference: reference, Tag: tag, Source: source}, nil
}

func (handler *Handler) fetchManifest(ctx context.Context, ref imageRef, reference string) ([]byte, http.Header, error) {
	key := strings.Join([]string{"offline", ref.Registry, ref.Repository, reference, manifestAccept, "anonymous"}, "\x00")
	entry, err := handler.upstream.Manifests().GetOrLoad(ctx, key, func(ctx context.Context) (upstream.Loaded[upstream.ManifestEntry], error) {
		response, err := handler.fetch(ctx, ref, "/v2/"+ref.Repository+"/manifests/"+reference, manifestAccept)
		if err != nil {
			return upstream.Loaded[upstream.ManifestEntry]{}, err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			if response.StatusCode >= 500 {
				return upstream.Loaded[upstream.ManifestEntry]{}, errors.New("manifest upstream temporarily unavailable")
			}
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("manifest request failed"))
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
		if err != nil || len(body) > maxManifestBytes {
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("manifest too large"))
		}
		var document manifestDocument
		if err := json.Unmarshal(body, &document); err != nil || document.SchemaVersion != 2 || !supportedManifestType(document.MediaType) {
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("invalid manifest"))
		}
		contentType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if parseErr != nil || contentType != document.MediaType {
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("manifest media type mismatch"))
		}
		bodyDigest := digestBytes(body)
		if digestPattern.MatchString(reference) && bodyDigest != strings.ToLower(reference) {
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("manifest digest mismatch"))
		}
		if advertised := strings.ToLower(response.Header.Get("Docker-Content-Digest")); advertised != "" && advertised != bodyDigest {
			return upstream.Loaded[upstream.ManifestEntry]{}, upstream.PermanentCacheError(errors.New("manifest digest header mismatch"))
		}
		ttl := time.Minute
		swr := 30 * time.Second
		sie := 5 * time.Minute
		if digestPattern.MatchString(reference) {
			ttl = 10 * time.Minute
			swr = 5 * time.Minute
			sie = 30 * time.Minute
		}
		header := response.Header.Clone()
		return upstream.Loaded[upstream.ManifestEntry]{Value: upstream.ManifestEntry{Status: response.StatusCode, Header: header, Body: body, Digest: bodyDigest}, Size: int64(len(body)), TTL: ttl, StaleWhileRevalidate: swr, StaleIfError: sie}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), entry.Body...), entry.Header.Clone(), nil
}

func (handler *Handler) fetchBlob(ctx context.Context, ref imageRef, digest string) (io.ReadCloser, int64, error) {
	response, err := handler.fetch(ctx, ref, "/v2/"+ref.Repository+"/blobs/"+digest, "application/octet-stream")
	if err != nil {
		return nil, 0, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, 0, errors.New("blob request failed")
	}
	return response.Body, response.ContentLength, nil
}

func (handler *Handler) fetch(ctx context.Context, ref imageRef, requestPath, accept string) (*http.Response, error) {
	target := *ref.Source.Endpoint
	target.Path = strings.TrimSuffix(ref.Source.Endpoint.Path, "/") + requestPath
	response, err := handler.doFollowing(ctx, ref, &target, accept, "")
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	challenge := response.Header.Get("WWW-Authenticate")
	drainAndClose(response.Body)
	token, err := handler.fetchToken(ctx, ref, challenge)
	if err != nil {
		return nil, err
	}
	response, err = handler.doFollowing(ctx, ref, &target, accept, "Bearer "+token.entry.Value)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	drainAndClose(response.Body)
	handler.upstream.Tokens().CompareAndDelete(token.key, func(current upstream.TokenEntry) bool { return current.Version == token.entry.Version })
	token, err = handler.fetchToken(ctx, ref, challenge)
	if err != nil {
		return nil, err
	}
	return handler.doFollowing(ctx, ref, &target, accept, "Bearer "+token.entry.Value)
}

func (handler *Handler) doFollowing(ctx context.Context, ref imageRef, target *url.URL, accept, authorization string) (*http.Response, error) {
	current := target
	for redirects := 0; redirects <= maxRedirects; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", accept)
		if authorization != "" && strings.EqualFold(current.Host, ref.Source.Endpoint.Host) {
			request.Header.Set("Authorization", authorization)
		}
		response, err := handler.upstream.Do(request, upstream.Policy{AllowHTTP: ref.Source.AllowHTTP, AllowPrivate: ref.Source.AllowPrivate})
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response, nil
		}
		location, err := response.Location()
		drainAndClose(response.Body)
		if err != nil || !handler.allowedRegistryRedirect(ref, location) {
			return nil, errors.New("unsafe registry redirect")
		}
		current = location
	}
	return nil, errors.New("too many registry redirects")
}

func (handler *Handler) allowedRegistryRedirect(ref imageRef, target *url.URL) bool {
	if target == nil || target.User != nil || target.Fragment != "" || (target.Scheme != "https" && !(ref.Source.AllowHTTP && target.Scheme == "http")) {
		return false
	}
	if ref.Source.AllowPrivate && strings.EqualFold(target.Host, ref.Source.Endpoint.Host) {
		return true
	}
	host := strings.ToLower(target.Hostname())
	for _, suffix := range []string{"docker.io", "docker.com", "cloudflarestorage.com", "amazonaws.com", "googleapis.com", "pkg.dev", "quay.io", "githubusercontent.com", "k8s.io"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (handler *Handler) fetchToken(ctx context.Context, ref imageRef, challenge string) (tokenLease, error) {
	realm, service, scope, err := parseChallenge(challenge)
	if err != nil {
		return tokenLease{}, err
	}
	parsed, err := url.Parse(realm)
	if err != nil || !handler.allowedTokenHost(ref, parsed) {
		return tokenLease{}, errors.New("unsafe token service")
	}
	expectedScope := "repository:" + ref.Repository + ":pull"
	if scope != "" && scope != expectedScope {
		return tokenLease{}, errors.New("unexpected token scope")
	}
	query := parsed.Query()
	query.Set("scope", expectedScope)
	if service != "" {
		query.Set("service", service)
	}
	parsed.RawQuery = query.Encode()
	cacheKey := strings.Join([]string{"offline-token", parsed.String(), ref.Registry, ref.Repository, expectedScope, "anonymous"}, "\x00")
	entry, err := handler.upstream.Tokens().GetOrLoad(ctx, cacheKey, func(ctx context.Context) (upstream.Loaded[upstream.TokenEntry], error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return upstream.Loaded[upstream.TokenEntry]{}, err
		}
		response, err := handler.upstream.Do(request, upstream.Policy{AllowHTTP: ref.Source.AllowHTTP, AllowPrivate: ref.Source.AllowPrivate})
		if err != nil {
			return upstream.Loaded[upstream.TokenEntry]{}, err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return upstream.Loaded[upstream.TokenEntry]{}, errors.New("token request failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
		if err != nil || len(body) > maxTokenBytes {
			return upstream.Loaded[upstream.TokenEntry]{}, errors.New("token response too large")
		}
		var payload struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
			IssuedAt    string `json:"issued_at"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return upstream.Loaded[upstream.TokenEntry]{}, err
		}
		if payload.Token == "" {
			payload.Token = payload.AccessToken
		}
		if payload.Token == "" {
			return upstream.Loaded[upstream.TokenEntry]{}, errors.New("token is missing")
		}
		if payload.ExpiresIn <= 0 {
			payload.ExpiresIn = 60
		}
		receivedAt := handler.upstream.Now()
		issuedAt := receivedAt
		if payload.IssuedAt != "" {
			parsedIssuedAt, err := time.Parse(time.RFC3339, payload.IssuedAt)
			if err != nil || parsedIssuedAt.After(receivedAt.Add(5*time.Minute)) {
				return upstream.Loaded[upstream.TokenEntry]{}, errors.New("invalid token issued_at")
			}
			issuedAt = parsedIssuedAt
		}
		expiresAt := issuedAt.Add(time.Duration(payload.ExpiresIn) * time.Second)
		remaining := expiresAt.Sub(receivedAt)
		if remaining <= 0 {
			return upstream.Loaded[upstream.TokenEntry]{}, errors.New("token already expired")
		}
		early := minDuration(30*time.Second, remaining/10)
		ttl := remaining - early
		if ttl <= 0 {
			ttl = minDuration(time.Second, remaining)
		}
		entry := handler.upstream.NewTokenEntry(payload.Token, expiresAt)
		return upstream.Loaded[upstream.TokenEntry]{Value: entry, Size: int64(len(payload.Token)), TTL: ttl, StaleWhileRevalidate: remaining - ttl}, nil
	})
	if err != nil {
		return tokenLease{}, err
	}
	if !entry.ExpiresAt.After(handler.upstream.Now()) {
		handler.upstream.Tokens().CompareAndDelete(cacheKey, func(current upstream.TokenEntry) bool { return current.Version == entry.Version })
		return tokenLease{}, errors.New("token expired")
	}
	return tokenLease{entry: entry, key: cacheKey}, nil
}

func (handler *Handler) allowedTokenHost(ref imageRef, target *url.URL) bool {
	if target == nil || target.User != nil || target.Hostname() == "" || target.Fragment != "" || (target.Scheme != "https" && !(ref.Source.AllowHTTP && target.Scheme == "http")) {
		return false
	}
	if ref.Source.AllowPrivate && strings.EqualFold(target.Host, ref.Source.Endpoint.Host) {
		return true
	}
	if strings.EqualFold(target.Hostname(), ref.Source.Endpoint.Hostname()) {
		return true
	}
	for _, host := range ref.Source.TokenHosts {
		if strings.EqualFold(target.Hostname(), host) {
			return true
		}
	}
	return false
}

func parseChallenge(value string) (realm, service, scope string, err error) {
	value = strings.TrimSpace(value)
	if len(value) < 7 || !strings.EqualFold(value[:7], "Bearer ") {
		return "", "", "", errors.New("invalid bearer challenge")
	}
	for _, item := range splitComma(value[7:]) {
		key, raw, found := strings.Cut(strings.TrimSpace(item), "=")
		if !found {
			return "", "", "", errors.New("invalid bearer challenge")
		}
		decoded, decodeErr := strconv.Unquote(strings.TrimSpace(raw))
		if decodeErr != nil {
			return "", "", "", decodeErr
		}
		switch strings.ToLower(key) {
		case "realm":
			realm = decoded
		case "service":
			service = decoded
		case "scope":
			scope = decoded
		}
	}
	if realm == "" {
		return "", "", "", errors.New("bearer realm is missing")
	}
	return realm, service, scope, nil
}

func splitComma(value string) []string {
	var result []string
	start := 0
	quoted := false
	for index, character := range value {
		if character == '"' {
			quoted = !quoted
		} else if character == ',' && !quoted {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	return append(result, value[start:])
}

func selectPlatform(descriptors []descriptor, value string) (descriptor, error) {
	want, err := parsePlatform(value)
	if err != nil {
		return descriptor{}, err
	}
	for _, descriptor := range descriptors {
		if descriptor.Platform.OS == want.OS && descriptor.Platform.Architecture == want.Architecture && (want.Variant == "" || descriptor.Platform.Variant == want.Variant) {
			if err := validateDescriptor(descriptor); err != nil {
				return descriptor, err
			}
			return descriptor, nil
		}
	}
	return descriptor{}, errors.New("requested platform is unavailable")
}

func parsePlatform(value string) (platform, error) {
	parts := strings.Split(strings.ToLower(value), "/")
	if len(parts) < 2 || len(parts) > 3 || !namePartPattern.MatchString(parts[0]) || !namePartPattern.MatchString(parts[1]) {
		return platform{}, errors.New("platform must be os/architecture[/variant]")
	}
	result := platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		if !namePartPattern.MatchString(parts[2]) {
			return platform{}, errors.New("invalid platform variant")
		}
		result.Variant = parts[2]
	}
	return result, nil
}

func validateDescriptor(value descriptor) error {
	if !digestPattern.MatchString(strings.ToLower(value.Digest)) || value.Size < 0 {
		return errors.New("invalid image descriptor")
	}
	return nil
}

func supportedManifestType(value string) bool {
	switch value {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		return true
	default:
		return false
	}
}

func supportedConfigType(value string) bool {
	return value == "application/vnd.oci.image.config.v1+json" || value == "application/vnd.docker.container.image.v1+json"
}

func supportedLayerType(value string) bool {
	switch value {
	case "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.oci.image.layer.nondistributable.v1.tar", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		return true
	default:
		return false
	}
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestHex(value string) string { return strings.TrimPrefix(strings.ToLower(value), "sha256:") }

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, (64<<10)+1)
	_ = body.Close()
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, `{"error":%q}`, message)
}
