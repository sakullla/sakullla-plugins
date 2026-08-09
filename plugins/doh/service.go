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
	requestCtx, requestCancel := context.WithCancel(context.Background())
	requestZero := make(chan struct{})
	close(requestZero)
	effectZero := make(chan struct{})
	close(effectZero)
	service := &Service{
		configuration: cloneConfiguration(configuration),
		runtime:       runtime,
		semaphore:     make(chan struct{}, configuration.MaxConcurrency),
		requestCtx:    requestCtx,
		requestCancel: requestCancel,
		requestZero:   requestZero,
		effectZero:    effectZero,
		closeDone:     make(chan struct{}),
	}
	for _, upstream := range configuration.orderedUpstreams() {
		service.statuses = append(service.statuses, UpstreamStatus{ID: upstream.ID, Result: "unknown"})
	}
	service.live.Store(true)
	return service, nil
}

func (service *Service) Serve(parent context.Context, request HTTPRequest) (HTTPResponse, error) {
	service.leaseMu.RLock()
	lease := service.requestLease
	service.leaseMu.RUnlock()
	if lease != nil {
		return lease(parent, request)
	}
	return service.serve(parent, request)
}

func (service *Service) bindRequestLease(lease func(context.Context, HTTPRequest) (HTTPResponse, error)) {
	service.leaseMu.Lock()
	service.requestLease = lease
	service.leaseMu.Unlock()
}

func (service *Service) serve(parent context.Context, request HTTPRequest) (HTTPResponse, error) {
	if err := parent.Err(); err != nil {
		return HTTPResponse{}, err
	}
	requestCtx, releaseRequest, err := service.beginRequest(parent)
	if err != nil {
		return HTTPResponse{}, err
	}
	defer releaseRequest()
	query, err := parseHTTPRequest(request)
	if err != nil {
		return HTTPResponse{}, err
	}
	select {
	case service.semaphore <- struct{}{}:
	default:
		return HTTPResponse{}, ErrConcurrencyExhausted
	}
	slot := newRequestSlot(func() { <-service.semaphore })
	defer slot.returned()

	ctx, cancel := context.WithTimeout(requestCtx, requestTimeout(service.configuration))
	defer cancel()
	if err := ctx.Err(); err != nil {
		return HTTPResponse{}, err
	}
	operationKey := fmt.Sprintf("doh:%s:%d", service.configuration.Generation, service.operation.Add(1))
	if err := service.audit(ctx, slot, AuditRecord{Action: "query", Outcome: "started", OperationKey: operationKey, QueryDigest: query.digest}); err != nil {
		return HTTPResponse{}, err
	}
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	fail := func(result string, failure error) (HTTPResponse, error) {
		if err := service.ensureLive(ctx); err != nil {
			return HTTPResponse{}, err
		}
		logErr := service.log(ctx, slot, QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: result})
		if err := service.ensureLive(ctx); err != nil {
			return HTTPResponse{}, err
		}
		if auditErr := service.audit(ctx, slot, AuditRecord{Action: "query", Outcome: "failed", OperationKey: operationKey + ":terminal", QueryDigest: query.digest}); auditErr != nil {
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
	token := append([]byte(nil), request.Token...)
	_, tokenErr, _ := boundedHostCall(ctx, slot, nil, func() (struct{}, error) {
		return struct{}{}, service.runtime.Tokens.Verify(ctx, service.configuration.TokenSecretRef, token)
	})
	if tokenErr != nil {
		return fail("token-denied", safeRuntimeError(tokenErr, ErrInvalidToken))
	}
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	_, policyErr, _ := boundedHostCall(ctx, slot, nil, func() (struct{}, error) {
		return struct{}{}, service.runtime.Policy.Allow(ctx, service.configuration.IPPolicyRef, request.Source)
	})
	if policyErr != nil {
		return fail("policy-denied", safeRuntimeError(policyErr, ErrIPPolicyDenied))
	}
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	now, err := service.now(ctx, slot)
	if err != nil {
		return fail("clock-failed", ErrClockUnavailable)
	}
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	cacheKey := service.configuration.Generation + ":" + query.key
	cacheResult, err, _ := boundedHostCall(ctx, slot, nil, func() (cacheGetResult, error) {
		entry, hit, err := service.runtime.Cache.Get(ctx, cacheKey, now)
		return cacheGetResult{entry: entry, hit: hit}, err
	})
	if err != nil {
		return fail("cache-failed", safeRuntimeError(err, ErrCacheUnavailable))
	}
	entry, hit := cacheResult.entry, cacheResult.hit
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	if hit {
		candidate := responseWithID(entry.Response, query.id)
		metadata, _, validateErr := validateDNSResponse(query, candidate)
		if validateErr != nil || !metadata.cacheable || metadata.ttl < service.configuration.MinTTLSeconds {
			return fail("cache-invalid", ErrCacheUnavailable)
		}
		effectiveTTL := metadata.ttl
		if effectiveTTL > service.configuration.MaxTTLSeconds {
			effectiveTTL = service.configuration.MaxTTLSeconds
		}
		maxLifetime := uint64(effectiveTTL) * uint64(time.Second)
		maxExpiry := entry.StoredAt + maxLifetime
		if maxLifetime == 0 || maxExpiry < entry.StoredAt || entry.StoredAt > now || entry.ExpiresAt <= now || entry.ExpiresAt <= entry.StoredAt || entry.ExpiresAt > maxExpiry {
			return fail("cache-invalid", ErrCacheUnavailable)
		}
		candidate, err = clampDNSResponseTTLs(candidate, uint32((entry.ExpiresAt-now)/uint64(time.Second)))
		if err != nil {
			return fail("cache-invalid", ErrCacheUnavailable)
		}
		if err := service.ensureLive(ctx); err != nil {
			return HTTPResponse{}, err
		}
		response := HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: candidate, CacheHit: true}
		if err := service.finish(ctx, slot, operationKey, query, QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: "cache-hit", CacheHit: true}); err != nil {
			return HTTPResponse{}, err
		}
		return response, nil
	}

	for _, upstream := range service.configuration.orderedUpstreams() {
		if !upstream.Enabled {
			continue
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, upstreamTimeout(service.configuration))
		wire, resolveErr, timedOut := service.resolve(attemptCtx, slot, upstream, query.wire)
		attemptCancel()
		if timedOut {
			service.updateStatus(upstream.ID, "timeout", true)
			if err := ctx.Err(); err != nil {
				return fail("upstream-timeout", err)
			}
			continue
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
		if metadata.cacheable && metadata.ttl >= service.configuration.MinTTLSeconds && service.configuration.MaxTTLSeconds > 0 {
			ttl := metadata.ttl
			if ttl > service.configuration.MaxTTLSeconds {
				ttl = service.configuration.MaxTTLSeconds
			}
			cacheNow, clockErr := service.now(ctx, slot)
			if clockErr != nil {
				return fail("clock-failed", ErrClockUnavailable)
			}
			if err := service.ensureLive(ctx); err != nil {
				return HTTPResponse{}, err
			}
			expires := cacheNow + uint64(ttl)*uint64(time.Second)
			if expires < cacheNow {
				return fail("clock-failed", ErrClockUnavailable)
			}
			_, putErr, _ := boundedHostCall(ctx, slot, service.beginEffect, func() (struct{}, error) {
				return struct{}{}, service.runtime.Cache.Put(ctx, cacheKey, CacheEntry{Response: append([]byte(nil), normalized...), StoredAt: cacheNow, ExpiresAt: expires})
			})
			if putErr != nil {
				return fail("cache-failed", safeRuntimeError(putErr, ErrCacheUnavailable))
			}
			if err := service.ensureLive(ctx); err != nil {
				return HTTPResponse{}, err
			}
		}
		result := "positive"
		if metadata.negative {
			result = "negative"
		}
		logRecord := QueryLog{QueryDigest: query.digest, QType: query.qtype, Result: result, UpstreamID: upstream.ID}
		if err := service.finish(ctx, slot, operationKey, query, logRecord); err != nil {
			return HTTPResponse{}, err
		}
		return HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: responseWithID(normalized, query.id)}, nil
	}
	return fail("upstream-failed", ErrNoHealthyUpstream)
}

func (service *Service) finish(ctx context.Context, slot *requestSlot, operationKey string, query parsedQuery, record QueryLog) error {
	if err := service.ensureLive(ctx); err != nil {
		return err
	}
	if err := service.log(ctx, slot, record); err != nil {
		if service.ensureLive(ctx) == nil {
			_ = service.audit(ctx, slot, AuditRecord{Action: "query", Outcome: "failed", OperationKey: operationKey + ":terminal", QueryDigest: query.digest})
		}
		return safeRuntimeError(err, ErrLogUnavailable)
	}
	if err := service.ensureLive(ctx); err != nil {
		return err
	}
	if err := service.audit(ctx, slot, AuditRecord{Action: "query", Outcome: "succeeded", OperationKey: operationKey + ":terminal", QueryDigest: query.digest}); err != nil {
		return err
	}
	return service.ensureLive(ctx)
}

func (service *Service) audit(ctx context.Context, slot *requestSlot, record AuditRecord) error {
	_, err, _ := boundedHostCall(ctx, slot, service.beginEffect, func() (struct{}, error) {
		return struct{}{}, service.runtime.Auditor.Audit(ctx, record)
	})
	if err != nil {
		return safeRuntimeError(err, ErrAuditUnavailable)
	}
	return nil
}

func (service *Service) log(ctx context.Context, slot *requestSlot, record QueryLog) error {
	_, err, _ := boundedHostCall(ctx, slot, service.beginEffect, func() (struct{}, error) {
		return struct{}{}, service.runtime.Logger.Log(ctx, record)
	})
	if err != nil {
		return safeRuntimeError(err, ErrLogUnavailable)
	}
	return nil
}

func (service *Service) now(ctx context.Context, slot *requestSlot) (uint64, error) {
	now, err, _ := boundedHostCall(ctx, slot, nil, func() (uint64, error) {
		return service.runtime.Clock.Now(ctx)
	})
	if err != nil {
		return 0, safeRuntimeError(err, ErrClockUnavailable)
	}
	service.clockMu.Lock()
	defer service.clockMu.Unlock()
	if service.clockSet && now < service.lastNow {
		return 0, ErrClockUnavailable
	}
	service.clockSet, service.lastNow = true, now
	return now, nil
}

func (service *Service) ensureLive(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !service.live.Load() {
		return ErrRevoked
	}
	return nil
}

func (service *Service) beginRequest(parent context.Context) (context.Context, func(), error) {
	service.requestMu.Lock()
	if !service.live.Load() {
		service.requestMu.Unlock()
		return nil, nil, ErrRevoked
	}
	if service.requestCount == 0 {
		service.requestZero = make(chan struct{})
	}
	service.requestCount++
	root := service.requestCtx
	service.requestMu.Unlock()

	ctx, cancel := context.WithCancel(parent)
	stopRootCancel := context.AfterFunc(root, cancel)
	var once sync.Once
	release := func() {
		once.Do(func() {
			stopRootCancel()
			cancel()
			service.requestMu.Lock()
			service.requestCount--
			if service.requestCount == 0 {
				close(service.requestZero)
			}
			service.requestMu.Unlock()
		})
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, nil, err
	}
	return ctx, release, nil
}

type requestSlot struct {
	mu               sync.Mutex
	pending          uint64
	returnedToCaller bool
	released         bool
	release          func()
}

func newRequestSlot(release func()) *requestSlot {
	return &requestSlot{release: release}
}

func (slot *requestSlot) beginCall() func() {
	slot.mu.Lock()
	slot.pending++
	slot.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			slot.mu.Lock()
			slot.pending--
			shouldRelease := slot.returnedToCaller && slot.pending == 0 && !slot.released
			if shouldRelease {
				slot.released = true
			}
			slot.mu.Unlock()
			if shouldRelease {
				slot.release()
			}
		})
	}
}

func (slot *requestSlot) returned() {
	slot.mu.Lock()
	slot.returnedToCaller = true
	shouldRelease := slot.pending == 0 && !slot.released
	if shouldRelease {
		slot.released = true
	}
	slot.mu.Unlock()
	if shouldRelease {
		slot.release()
	}
}

type hostCallResult[T any] struct {
	value T
	err   error
}

type cacheGetResult struct {
	entry CacheEntry
	hit   bool
}

// boundedHostCall lets the request return at its deadline while retaining the
// request's concurrency slot until a non-cooperative host adapter really exits.
func boundedHostCall[T any](ctx context.Context, slot *requestSlot, beginEffect func() (func(), error), invoke func() (T, error)) (T, error, bool) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err, false
	}
	var endEffect func()
	if beginEffect != nil {
		var err error
		endEffect, err = beginEffect()
		if err != nil {
			return zero, err, false
		}
	}
	endCall := slot.beginCall()
	result := make(chan hostCallResult[T], 1)
	go func() {
		value, err := invoke()
		if endEffect != nil {
			endEffect()
		}
		endCall()
		result <- hostCallResult[T]{value: value, err: err}
	}()
	select {
	case completed := <-result:
		return completed.value, completed.err, false
	case <-ctx.Done():
		return zero, ctx.Err(), true
	}
}

func (service *Service) beginEffect() (func(), error) {
	service.effectMu.Lock()
	if !service.live.Load() {
		service.effectMu.Unlock()
		return nil, ErrRevoked
	}
	if service.effectCount == 0 {
		service.effectZero = make(chan struct{})
	}
	service.effectCount++
	service.effectMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			service.effectMu.Lock()
			service.effectCount--
			if service.effectCount == 0 {
				close(service.effectZero)
			}
			service.effectMu.Unlock()
		})
	}, nil
}

func (service *Service) resolve(ctx context.Context, slot *requestSlot, upstream Upstream, query []byte) ([]byte, error, bool) {
	return boundedHostCall(ctx, slot, nil, func() ([]byte, error) {
		return service.runtime.Resolver.Resolve(ctx, ResolveRequest{EndpointRef: upstream.EndpointRef, DNSMessage: append([]byte(nil), query...), MaxBytes: MaxDNSResponseBytes})
	})
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
	service.closeOnce.Do(func() {
		service.live.Store(false)
		service.requestCancel()
		service.statusMu.Lock()
		for index := range service.statuses {
			service.statuses[index].Result = "revoked"
		}
		service.statusMu.Unlock()

		go func() {
			service.requestMu.Lock()
			requestZero := service.requestZero
			service.requestMu.Unlock()
			service.effectMu.Lock()
			effectZero := service.effectZero
			service.effectMu.Unlock()
			<-requestZero
			<-effectZero
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
			cleanupErr := service.runtime.Cache.Reset(cleanupCtx, service.configuration.Generation)
			cleanupCancel()
			if cleanupErr != nil {
				cleanupErr = safeRuntimeError(cleanupErr, ErrCacheUnavailable)
			}
			service.closeMu.Lock()
			service.closeErr = cleanupErr
			service.closeMu.Unlock()
			close(service.closeDone)
		}()
	})
	waitTimer := time.NewTimer(time.Second)
	defer waitTimer.Stop()
	select {
	case <-service.closeDone:
		service.closeMu.Lock()
		err := service.closeErr
		service.closeMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-waitTimer.C:
		return context.DeadlineExceeded
	}
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
