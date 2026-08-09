package doh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

func NewService(configuration Configuration, runtime RuntimeAdapters) (*Service, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if !runtime.valid() {
		return nil, ErrTypedHandlesUnavailable
	}
	service := &Service{configuration: cloneConfiguration(configuration), runtime: runtime, semaphore: make(chan struct{}, configuration.MaxConcurrency)}
	for _, upstream := range configuration.orderedUpstreams() {
		service.statuses = append(service.statuses, UpstreamStatus{ID: upstream.ID, Result: "unknown"})
	}
	service.live.Store(true)
	return service, nil
}

func (service *Service) Serve(parent context.Context, request HTTPRequest) (HTTPResponse, error) {
	if err := parent.Err(); err != nil {
		return HTTPResponse{}, err
	}
	if !service.live.Load() {
		return HTTPResponse{}, ErrRevoked
	}
	query, err := parseHTTPRequest(request)
	if err != nil {
		return HTTPResponse{}, err
	}
	select {
	case service.semaphore <- struct{}{}:
	default:
		return HTTPResponse{}, ErrConcurrencyExhausted
	}
	releaseSemaphore := true
	defer func() {
		if releaseSemaphore {
			<-service.semaphore
		}
	}()

	ctx, cancel := context.WithTimeout(parent, requestTimeout(service.configuration))
	defer cancel()
	if err := ctx.Err(); err != nil {
		return HTTPResponse{}, err
	}
	operationKey := fmt.Sprintf("doh:%s:%d", service.configuration.Generation, service.operation.Add(1))
	if err := service.audit(ctx, AuditRecord{Action: "query", Outcome: "started", OperationKey: operationKey, QueryDigest: query.digest}); err != nil {
		return HTTPResponse{}, err
	}
	fail := func(result string, failure error) (HTTPResponse, error) {
		logErr := service.runtime.Logger.Log(ctx, QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: result})
		if auditErr := service.audit(ctx, AuditRecord{Action: "query", Outcome: "failed", OperationKey: operationKey + ":terminal", QueryDigest: query.digest}); auditErr != nil {
			return HTTPResponse{}, auditErr
		}
		if logErr != nil {
			return HTTPResponse{}, ErrLogUnavailable
		}
		return HTTPResponse{}, failure
	}
	if len(request.Token) == 0 {
		return fail("token-denied", ErrInvalidToken)
	}
	if err := service.runtime.Tokens.Verify(ctx, service.configuration.TokenSecretRef, request.Token); err != nil {
		return fail("token-denied", safeRuntimeError(err, ErrInvalidToken))
	}
	if err := ctx.Err(); err != nil || !service.live.Load() {
		if err != nil {
			return fail("canceled", err)
		}
		return fail("revoked", ErrRevoked)
	}
	if err := service.runtime.Policy.Allow(ctx, service.configuration.IPPolicyRef, request.Source); err != nil {
		return fail("policy-denied", safeRuntimeError(err, ErrIPPolicyDenied))
	}
	now, err := service.now(ctx)
	if err != nil {
		return fail("clock-failed", ErrClockUnavailable)
	}
	cacheKey := service.configuration.Generation + ":" + query.key
	entry, hit, err := service.runtime.Cache.Get(ctx, cacheKey, now)
	if err != nil {
		return fail("cache-failed", ErrCacheUnavailable)
	}
	if hit {
		response := HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: responseWithID(entry.Response, query.id), CacheHit: true}
		if err := service.finish(ctx, operationKey, query, QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: "cache-hit", CacheHit: true}); err != nil {
			return HTTPResponse{}, err
		}
		return response, nil
	}

	for _, upstream := range service.configuration.orderedUpstreams() {
		if !upstream.Enabled {
			continue
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, upstreamTimeout(service.configuration))
		wire, resolveErr, transferred := service.resolve(attemptCtx, upstream, query.wire, func() { <-service.semaphore })
		attemptCancel()
		if transferred {
			releaseSemaphore = false
			service.updateStatus(upstream.ID, "timeout", true)
			return fail("upstream-timeout", context.DeadlineExceeded)
		}
		if resolveErr != nil {
			service.updateStatus(upstream.ID, "failed", true)
			continue
		}
		metadata, normalized, validateErr := validateDNSResponse(query, wire)
		if validateErr != nil {
			service.updateStatus(upstream.ID, "invalid-response", true)
			continue
		}
		if err := ctx.Err(); err != nil || !service.live.Load() {
			if err != nil {
				return fail("canceled", err)
			}
			return fail("revoked", ErrRevoked)
		}
		service.updateStatus(upstream.ID, "healthy", false)
		if metadata.cacheable && metadata.ttl >= service.configuration.MinTTLSeconds {
			ttl := metadata.ttl
			if ttl > service.configuration.MaxTTLSeconds {
				ttl = service.configuration.MaxTTLSeconds
			}
			cacheNow, clockErr := service.now(ctx)
			if clockErr != nil {
				return fail("clock-failed", ErrClockUnavailable)
			}
			expires := cacheNow + uint64(ttl)*uint64(time.Second)
			if expires < cacheNow {
				return fail("clock-failed", ErrClockUnavailable)
			}
			if err := service.runtime.Cache.Put(ctx, cacheKey, CacheEntry{Response: normalized, ExpiresAt: expires}); err != nil {
				return fail("cache-failed", ErrCacheUnavailable)
			}
		}
		result := "positive"
		if metadata.negative {
			result = "negative"
		}
		logRecord := QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: result, UpstreamID: upstream.ID}
		if err := service.finish(ctx, operationKey, query, logRecord); err != nil {
			return HTTPResponse{}, err
		}
		return HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: responseWithID(normalized, query.id)}, nil
	}
	return fail("upstream-failed", ErrNoHealthyUpstream)
}

func (service *Service) finish(ctx context.Context, operationKey string, query parsedQuery, record QueryLog) error {
	if err := service.runtime.Logger.Log(ctx, record); err != nil {
		_ = service.audit(ctx, AuditRecord{Action: "query", Outcome: "failed", OperationKey: operationKey + ":terminal", QueryDigest: query.digest})
		return ErrLogUnavailable
	}
	return service.audit(ctx, AuditRecord{Action: "query", Outcome: "succeeded", OperationKey: operationKey + ":terminal", QueryDigest: query.digest})
}

func (service *Service) audit(ctx context.Context, record AuditRecord) error {
	if err := service.runtime.Auditor.Audit(ctx, record); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (service *Service) now(ctx context.Context) (uint64, error) {
	now, err := service.runtime.Clock.Now(ctx)
	if err != nil {
		return 0, ErrClockUnavailable
	}
	service.clockMu.Lock()
	defer service.clockMu.Unlock()
	if service.clockSet && now < service.lastNow {
		return 0, ErrClockUnavailable
	}
	service.clockSet, service.lastNow = true, now
	return now, nil
}

type resolverCall struct {
	mu                    sync.Mutex
	finished, transferred bool
	release               func()
}

func (call *resolverCall) complete() {
	call.mu.Lock()
	call.finished = true
	transferred := call.transferred
	call.mu.Unlock()
	if transferred {
		call.release()
	}
}

func (call *resolverCall) transfer() bool {
	call.mu.Lock()
	defer call.mu.Unlock()
	if call.finished {
		return false
	}
	call.transferred = true
	return true
}

type resolverResult struct {
	wire []byte
	err  error
}

func (service *Service) resolve(ctx context.Context, upstream Upstream, query []byte, release func()) ([]byte, error, bool) {
	result := make(chan resolverResult, 1)
	call := &resolverCall{release: release}
	go func() {
		wire, err := service.runtime.Resolver.Resolve(ctx, ResolveRequest{EndpointRef: upstream.EndpointRef, DNSMessage: append([]byte(nil), query...), MaxBytes: MaxDNSResponseBytes})
		call.complete()
		result <- resolverResult{wire: wire, err: err}
	}()
	select {
	case completed := <-result:
		return completed.wire, completed.err, false
	case <-ctx.Done():
		return nil, ctx.Err(), call.transfer()
	}
}

func (service *Service) updateStatus(id, result string, failed bool) {
	if !service.live.Load() {
		return
	}
	service.statusMu.Lock()
	defer service.statusMu.Unlock()
	if !service.live.Load() {
		return
	}
	for index := range service.statuses {
		if service.statuses[index].ID == id {
			service.statuses[index].Result = result
			if failed {
				service.statuses[index].Failures++
			}
			return
		}
	}
}

func (service *Service) Statuses() []UpstreamStatus {
	service.statusMu.Lock()
	defer service.statusMu.Unlock()
	return append([]UpstreamStatus(nil), service.statuses...)
}

func (service *Service) Close(ctx context.Context) error {
	service.live.Store(false)
	service.statusMu.Lock()
	for index := range service.statuses {
		service.statuses[index].Result = "revoked"
	}
	service.statusMu.Unlock()
	if err := service.runtime.Cache.Reset(ctx, service.configuration.Generation); err != nil {
		return ErrCacheUnavailable
	}
	return nil
}

func safeRuntimeError(err, fallback error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrRevoked):
		return ErrRevoked
	default:
		return fallback
	}
}

func cloneConfiguration(configuration Configuration) Configuration {
	configuration.Upstreams = append([]Upstream(nil), configuration.Upstreams...)
	return configuration
}
