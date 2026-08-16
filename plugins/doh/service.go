package doh

import (
	"context"
	"errors"
	"sync"
	"time"
)

func NewService(configuration Configuration, runtime RuntimeAdapters) (*Service, error) {
	configuration = applyConfigurationDefaults(configuration)
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	runtime = runtime.withDefaults(configuration)
	requestCtx, requestCancel := context.WithCancel(context.Background())
	requestZero := make(chan struct{})
	close(requestZero)
	service := &Service{
		configuration: cloneConfiguration(configuration),
		runtime:       runtime,
		semaphore:     make(chan struct{}, configuration.MaxConcurrency),
		requestCtx:    requestCtx,
		requestCancel: requestCancel,
		requestZero:   requestZero,
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
	outbound, ecsSource := applyOutboundECS(query, parseForwardedFor(request.Forwarded))
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
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	now, err := service.now(ctx, slot)
	if err != nil {
		return HTTPResponse{}, err
	}
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	cacheKey := query.key + ":" + ecsSource
	cacheResult, err, _ := boundedHostCall(ctx, slot, func() (cacheGetResult, error) {
		entry, hit, err := service.runtime.Cache.Get(ctx, cacheKey, now)
		return cacheGetResult{entry: entry, hit: hit}, err
	})
	if err != nil {
		return HTTPResponse{}, safeRuntimeError(err, ErrCacheUnavailable)
	}
	entry, hit := cacheResult.entry, cacheResult.hit
	if err := service.ensureLive(ctx); err != nil {
		return HTTPResponse{}, err
	}
	if hit {
		candidate := responseWithID(entry.Response, query.id)
		metadata, _, validateErr := validateDNSResponse(query, candidate)
		if validateErr != nil || !metadata.cacheable || metadata.ttl < service.configuration.MinTTLSeconds {
			return HTTPResponse{}, ErrCacheUnavailable
		}
		effectiveTTL := metadata.ttl
		if effectiveTTL > service.configuration.MaxTTLSeconds {
			effectiveTTL = service.configuration.MaxTTLSeconds
		}
		maxLifetime := uint64(effectiveTTL) * uint64(time.Second)
		maxExpiry := entry.StoredAt + maxLifetime
		if maxLifetime == 0 || maxExpiry < entry.StoredAt || entry.StoredAt > now || entry.ExpiresAt <= now || entry.ExpiresAt <= entry.StoredAt || entry.ExpiresAt > maxExpiry {
			return HTTPResponse{}, ErrCacheUnavailable
		}
		candidate, err = clampDNSResponseTTLs(candidate, uint32((entry.ExpiresAt-now)/uint64(time.Second)))
		if err != nil {
			return HTTPResponse{}, ErrCacheUnavailable
		}
		if err := service.ensureLive(ctx); err != nil {
			return HTTPResponse{}, err
		}
		return HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: candidate, CacheHit: true}, nil
	}

	for _, upstream := range service.configuration.orderedUpstreams() {
		if !upstream.Enabled {
			continue
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, upstreamTimeout(service.configuration))
		wire, resolveErr, timedOut := service.resolve(attemptCtx, slot, upstream, outbound)
		attemptCancel()
		if timedOut {
			service.updateStatus(upstream.ID, "timeout", true)
			if err := ctx.Err(); err != nil {
				return HTTPResponse{}, err
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
				return HTTPResponse{}, err
			}
			return HTTPResponse{}, ErrRevoked
		}
		service.updateStatus(upstream.ID, "healthy", false)
		if metadata.cacheable && metadata.ttl >= service.configuration.MinTTLSeconds && service.configuration.MaxTTLSeconds > 0 {
			ttl := metadata.ttl
			if ttl > service.configuration.MaxTTLSeconds {
				ttl = service.configuration.MaxTTLSeconds
			}
			cacheNow, clockErr := service.now(ctx, slot)
			if clockErr != nil {
				return HTTPResponse{}, ErrClockUnavailable
			}
			if err := service.ensureLive(ctx); err != nil {
				return HTTPResponse{}, err
			}
			expires := cacheNow + uint64(ttl)*uint64(time.Second)
			if expires < cacheNow {
				return HTTPResponse{}, ErrClockUnavailable
			}
			_, putErr, _ := boundedHostCall(ctx, slot, func() (struct{}, error) {
				return struct{}{}, service.runtime.Cache.Put(ctx, cacheKey, CacheEntry{Response: append([]byte(nil), normalized...), StoredAt: cacheNow, ExpiresAt: expires})
			})
			if putErr != nil {
				return HTTPResponse{}, safeRuntimeError(putErr, ErrCacheUnavailable)
			}
			if err := service.ensureLive(ctx); err != nil {
				return HTTPResponse{}, err
			}
		}
		return HTTPResponse{Status: "200", ContentType: dnsMediaType, Body: responseWithID(normalized, query.id)}, nil
	}
	return HTTPResponse{}, ErrNoHealthyUpstream
}

func (service *Service) now(ctx context.Context, slot *requestSlot) (uint64, error) {
	now, err, _ := boundedHostCall(ctx, slot, func() (uint64, error) {
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

func boundedHostCall[T any](ctx context.Context, slot *requestSlot, invoke func() (T, error)) (T, error, bool) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err, false
	}
	endCall := slot.beginCall()
	result := make(chan hostCallResult[T], 1)
	go func() {
		value, err := invoke()
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

func (service *Service) resolve(ctx context.Context, slot *requestSlot, upstream Upstream, query []byte) ([]byte, error, bool) {
	return boundedHostCall(ctx, slot, func() ([]byte, error) {
		return service.runtime.Resolver.Resolve(ctx, ResolveRequest{Endpoint: upstream.Endpoint, DNSMessage: append([]byte(nil), query...), MaxBytes: MaxDNSResponseBytes})
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
			<-requestZero
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
			cleanupErr := service.runtime.Cache.Reset(cleanupCtx, "")
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
