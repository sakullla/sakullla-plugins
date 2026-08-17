package doh

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

type httpUpstreamResolver struct {
	client *http.Client
}

func newHTTPClientResolver() *httpUpstreamResolver {
	return &httpUpstreamResolver{client: &http.Client{Timeout: 5 * time.Second}}
}

func (resolver *httpUpstreamResolver) Resolve(ctx context.Context, request ResolveRequest) ([]byte, error) {
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, request.Endpoint, bytes.NewReader(request.DNSMessage))
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
