package doh

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpUpstreamResolver struct {
	client *http.Client
}

func newHTTPUpstreamResolver() *httpUpstreamResolver {
	return &httpUpstreamResolver{client: &http.Client{Timeout: 5 * time.Second}}
}

func (resolver *httpUpstreamResolver) Resolve(ctx context.Context, request ResolveRequest) ([]byte, error) {
	endpoint, err := normalizeUpstreamEndpoint(request.Endpoint)
	if err != nil {
		return nil, err
	}
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(request.DNSMessage))
	if err != nil {
		return nil, err
	}
	outbound.Header.Set("Content-Type", dnsMediaType)
	outbound.Header.Set("Accept", dnsMediaType)
	response, err := resolver.client.Do(outbound)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil, ErrUpstreamFailed
	}
	limit := request.MaxBytes
	if limit <= 0 || limit > MaxDNSResponseBytes {
		limit = MaxDNSResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func normalizeUpstreamEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", ErrInvalidRequest
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", ErrInvalidRequest
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = DNSQueryPath
	}
	return parsed.String(), nil
}
