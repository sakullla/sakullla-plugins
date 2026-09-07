package dockerapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const registryMirrorInfoFormat = "{{json .RegistryConfig.Mirrors}}"
const registryLookupTimeout = 8 * time.Second

// Use the Agent daemon's effective mirrors. The plugin's registry_mirror
// setting is only an installation hint and may not match the running daemon.
func (controller *Controller) dockerRegistryMirrors(ctx context.Context) ([]*url.URL, error) {
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	output, err := controller.runCommand(probeCtx, "", "docker", "info", "--format", registryMirrorInfoFormat)
	if err != nil {
		return nil, errors.New("Docker registry mirrors are unavailable")
	}
	var configured []string
	if json.Unmarshal(bytes.TrimSpace(output), &configured) != nil {
		return nil, errors.New("Docker registry mirror response is invalid")
	}
	seen := map[string]bool{}
	var result []*url.URL
	for _, raw := range configured {
		endpoint, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
			return nil, errors.New("Docker registry mirror endpoint is invalid")
		}
		endpoint.Path = strings.TrimRight(endpoint.Path, "/")
		if seen[endpoint.String()] {
			continue
		}
		seen[endpoint.String()] = true
		result = append(result, endpoint)
		if len(result) == 4 {
			break
		}
	}
	return result, nil
}

func mirrorEndpoint(base *url.URL, path string) *url.URL {
	endpoint := *base
	endpoint.Path = strings.TrimRight(base.Path, "/") + path
	endpoint.RawPath = ""
	return &endpoint
}

func fetchRegistryDocument(ctx context.Context, endpoint *url.URL, accept string) ([]byte, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", accept)
	client := imageTagHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("registry lookup failed: %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxConfigBytes+1))
	if err != nil || len(data) > MaxConfigBytes {
		return nil, nil, errors.New("registry response exceeds the read budget")
	}
	return data, response.Header, nil
}

func listMirrorTags(ctx context.Context, mirror *url.URL, repository string) ([]string, error) {
	endpoint := mirrorEndpoint(mirror, "/v2/"+repository+"/tags/list")
	if tags, err := listMirrorTagPages(ctx, endpoint, false); err == nil {
		return tags, nil
	}
	// accelerator-sources serves Docker Hub's catalog separately from its
	// distribution API. Keep pagination on that mirror, even when Hub's JSON
	// contains an absolute next-page URL pointing back to hub.docker.com.
	endpoint = mirrorEndpoint(mirror, "/api/tags")
	endpoint.RawQuery = url.Values{"image": {repository}, "page_size": {"100"}, "page": {"1"}}.Encode()
	return listMirrorTagPages(ctx, endpoint, true)
}

func listMirrorTagPages(ctx context.Context, endpoint *url.URL, catalog bool) ([]string, error) {
	seenPages, seenTags := map[string]bool{}, map[string]bool{}
	tags := make([]string, 0, 32)
	for len(tags) < MaxCollectionItems && len(seenPages) < MaxCollectionItems {
		if seenPages[endpoint.String()] {
			return nil, errors.New("registry tag pagination repeated a page")
		}
		seenPages[endpoint.String()] = true
		data, headers, err := fetchRegistryDocument(ctx, endpoint, "application/json")
		if err != nil {
			return nil, err
		}
		var page struct {
			Tags    json.RawMessage         `json:"tags"`
			Results []struct{ Name string } `json:"results"`
			Next    string                  `json:"next"`
		}
		if json.Unmarshal(data, &page) != nil || (!catalog && page.Tags == nil) || (catalog && page.Results == nil) {
			return nil, errors.New("registry tags payload is invalid")
		}
		var names []string
		if catalog {
			for _, item := range page.Results {
				names = append(names, item.Name)
			}
		} else if json.Unmarshal(page.Tags, &names) != nil {
			return nil, errors.New("registry tags payload is invalid")
		}
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name != "" && !seenTags[name] && len(tags) < MaxCollectionItems {
				seenTags[name] = true
				tags = append(tags, name)
			}
		}
		if catalog {
			if page.Next == "" {
				return tags, nil
			}
			next, err := url.Parse(page.Next)
			if err != nil {
				return nil, errors.New("registry catalog pagination is invalid")
			}
			number, err := strconv.Atoi(next.Query().Get("page"))
			if err != nil || number < 1 || number > 10000 {
				return nil, errors.New("registry catalog pagination is invalid")
			}
			query := endpoint.Query()
			query.Set("page", strconv.Itoa(number))
			endpoint.RawQuery = query.Encode()
			continue
		}
		link := headers.Get("Link")
		if link == "" {
			return tags, nil
		}
		left, right := strings.Index(link, "<"), strings.Index(link, ">")
		if left < 0 || right <= left || !strings.Contains(link[right:], `rel="next"`) {
			return nil, errors.New("registry tag pagination is invalid")
		}
		next, err := endpoint.Parse(link[left+1 : right])
		if err != nil || next.Scheme != endpoint.Scheme || next.Host != endpoint.Host || next.Path != endpoint.Path || next.User != nil {
			return nil, errors.New("registry tag pagination left its repository")
		}
		endpoint = next
	}
	return tags, nil
}

func mirrorImageDigest(ctx context.Context, mirror *url.URL, image, repository, current, arch string) (string, error) {
	reference := extractDockerTag(image)
	if reference == "" || !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") {
		reference = "latest"
	}
	if _, digest, ok := strings.Cut(image, "@"); ok {
		reference = digest
	}
	endpoint := mirrorEndpoint(mirror, "/v2/"+repository+"/manifests/"+reference)
	data, headers, err := fetchRegistryDocument(ctx, endpoint, "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return "", err
	}
	var manifest struct {
		SchemaVersion int             `json:"schemaVersion"`
		Manifests     json.RawMessage `json:"manifests"`
		Config        json.RawMessage `json:"config"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 2 || (manifest.Manifests == nil && manifest.Config == nil) {
		return "", errors.New("registry manifest is invalid")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	if supplied := headers.Get("Docker-Content-Digest"); supplied != "" && supplied != digest {
		return "", errors.New("registry manifest digest does not match its body")
	}
	return resolveRegistryDigest(current, digest, parseRegistryPlatforms(data), arch), nil
}
