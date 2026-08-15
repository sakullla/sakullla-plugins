package upstream

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrClosed         = errors.New("upstream owner is closed")
	ErrPermanentCache = errors.New("cache fill failure must invalidate stale state")
)

func PermanentCacheError(err error) error {
	return errors.Join(ErrPermanentCache, err)
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type Loaded[V any] struct {
	Value                V
	Size                 int64
	TTL                  time.Duration
	StaleWhileRevalidate time.Duration
	StaleIfError         time.Duration
}

type cacheEntry[V any] struct {
	key       string
	value     V
	size      int64
	expiresAt time.Time
	swrUntil  time.Time
	sieUntil  time.Time
}

type cacheCall[V any] struct {
	done   chan struct{}
	loaded Loaded[V]
	err    error
}

type refreshGroup struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
	wait    sync.WaitGroup
	closed  bool
}

func newRefreshGroup(timeout time.Duration) *refreshGroup {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &refreshGroup{ctx: ctx, cancel: cancel, timeout: timeout}
}

func (group *refreshGroup) start(run func(context.Context)) bool {
	group.mu.Lock()
	if group.closed {
		group.mu.Unlock()
		return false
	}
	group.wait.Add(1)
	group.mu.Unlock()
	go func() {
		defer group.wait.Done()
		ctx, cancel := context.WithTimeout(group.ctx, group.timeout)
		defer cancel()
		run(ctx)
	}()
	return true
}

func (group *refreshGroup) close() {
	group.mu.Lock()
	if !group.closed {
		group.closed = true
		group.cancel()
	}
	group.mu.Unlock()
	done := make(chan struct{})
	go func() {
		group.wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// Cache is a generation-local bounded byte+entry LRU with per-key
// singleflight. Values are never persisted or shared across generations.
type Cache[V any] struct {
	mu         sync.Mutex
	clock      Clock
	maxEntries int
	maxBytes   int64
	bytes      int64
	entries    map[string]*list.Element
	lru        *list.List
	flights    map[string]*cacheCall[V]
	closed     bool
	onHit      func()
	onMiss     func()
	onEvict    func()
	refreshes  *refreshGroup
	ownsGroup  bool
}

func NewCache[V any](clock Clock, maxEntries int, maxBytes int64) *Cache[V] {
	if clock == nil {
		clock = realClock{}
	}
	if maxEntries <= 0 {
		maxEntries = 1
	}
	if maxBytes <= 0 {
		maxBytes = 1
	}
	return &Cache[V]{clock: clock, maxEntries: maxEntries, maxBytes: maxBytes, entries: make(map[string]*list.Element), lru: list.New(), flights: make(map[string]*cacheCall[V]), refreshes: newRefreshGroup(30 * time.Second), ownsGroup: true}
}

func (cache *Cache[V]) withRefreshGroup(group *refreshGroup) *Cache[V] {
	cache.mu.Lock()
	old, owned := cache.refreshes, cache.ownsGroup
	cache.refreshes, cache.ownsGroup = group, false
	cache.mu.Unlock()
	if owned {
		old.close()
	}
	return cache
}

func (cache *Cache[V]) WithMetrics(hit func(), miss func(), evict func()) *Cache[V] {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.onHit, cache.onMiss, cache.onEvict = hit, miss, evict
	return cache
}

func (cache *Cache[V]) Get(key string) (V, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.getLocked(key)
}

// Peek returns an entry throughout its bounded freshness/SWR/SIE window.
// Callers use it only to attach validators to a refresh; it does not extend
// the entry or count as a cache hit.
func (cache *Cache[V]) Peek(key string) (V, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	var zero V
	if cache.closed {
		return zero, false
	}
	entry, state := cache.inspectLocked(key)
	if state == cacheMissing {
		return zero, false
	}
	return entry.value, true
}

func (cache *Cache[V]) Delete(key string) {
	cache.mu.Lock()
	if element, found := cache.entries[key]; found {
		cache.removeLocked(element)
	}
	cache.mu.Unlock()
}

// CompareAndDelete removes key only when its current value still matches the
// value observed by the caller. It prevents a delayed failure from evicting a
// newer singleflight result published under the same cache key.
func (cache *Cache[V]) CompareAndDelete(key string, match func(V) bool) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element, found := cache.entries[key]
	if !found || match == nil || !match(element.Value.(*cacheEntry[V]).value) {
		return false
	}
	cache.removeLocked(element)
	return true
}

func (cache *Cache[V]) getLocked(key string) (V, bool) {
	var zero V
	if cache.closed {
		return zero, false
	}
	element, found := cache.entries[key]
	if !found {
		if cache.onMiss != nil {
			cache.onMiss()
		}
		return zero, false
	}
	entry := element.Value.(*cacheEntry[V])
	if !cache.clock.Now().Before(entry.expiresAt) {
		if !cache.clock.Now().Before(entry.sieUntil) {
			cache.removeLocked(element)
		}
		if cache.onMiss != nil {
			cache.onMiss()
		}
		return zero, false
	}
	cache.lru.MoveToFront(element)
	if cache.onHit != nil {
		cache.onHit()
	}
	return entry.value, true
}

type cacheState int

const (
	cacheMissing cacheState = iota
	cacheFresh
	cacheSWR
	cacheSIE
)

func (cache *Cache[V]) inspectLocked(key string) (*cacheEntry[V], cacheState) {
	element, found := cache.entries[key]
	if !found {
		return nil, cacheMissing
	}
	entry := element.Value.(*cacheEntry[V])
	now := cache.clock.Now()
	if now.Before(entry.expiresAt) {
		cache.lru.MoveToFront(element)
		return entry, cacheFresh
	}
	if now.Before(entry.swrUntil) {
		cache.lru.MoveToFront(element)
		return entry, cacheSWR
	}
	if now.Before(entry.sieUntil) {
		cache.lru.MoveToFront(element)
		return entry, cacheSIE
	}
	cache.removeLocked(element)
	return nil, cacheMissing
}

func (cache *Cache[V]) GetOrLoad(ctx context.Context, key string, load func(context.Context) (Loaded[V], error)) (V, error) {
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		var zero V
		return zero, ErrClosed
	}
	stale, state := cache.inspectLocked(key)
	if state == cacheFresh {
		if cache.onHit != nil {
			cache.onHit()
		}
		value := stale.value
		cache.mu.Unlock()
		return value, nil
	}
	if state == cacheSWR {
		if cache.onHit != nil {
			cache.onHit()
		}
		if _, running := cache.flights[key]; !running {
			call := &cacheCall[V]{done: make(chan struct{})}
			cache.flights[key] = call
			cache.startLoad(key, call, load)
		}
		value := stale.value
		cache.mu.Unlock()
		return value, nil
	}
	if cache.onMiss != nil {
		cache.onMiss()
	}
	if call, found := cache.flights[key]; found {
		staleValue, mayUseStale := staleValue(stale, state)
		cache.mu.Unlock()
		return waitCacheCall(ctx, call, staleValue, mayUseStale)
	}
	call := &cacheCall[V]{done: make(chan struct{})}
	cache.flights[key] = call
	staleValue, mayUseStale := staleValue(stale, state)
	cache.startLoad(key, call, load)
	cache.mu.Unlock()
	return waitCacheCall(ctx, call, staleValue, mayUseStale)
}

func (cache *Cache[V]) startLoad(key string, call *cacheCall[V], load func(context.Context) (Loaded[V], error)) {
	if cache.refreshes.start(func(ctx context.Context) { cache.runLoad(ctx, key, call, load) }) {
		return
	}
	call.err = ErrClosed
	delete(cache.flights, key)
	close(call.done)
}

func staleValue[V any](entry *cacheEntry[V], state cacheState) (V, bool) {
	if entry != nil && state == cacheSIE {
		return entry.value, true
	}
	var zero V
	return zero, false
}

func waitCacheCall[V any](ctx context.Context, call *cacheCall[V], stale V, mayUseStale bool) (V, error) {
	select {
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	case <-call.done:
		if call.err != nil && mayUseStale && !errors.Is(call.err, ErrPermanentCache) {
			return stale, nil
		}
		return call.loaded.Value, call.err
	}
}

func (cache *Cache[V]) runLoad(ctx context.Context, key string, call *cacheCall[V], load func(context.Context) (Loaded[V], error)) {
	call.loaded, call.err = load(ctx)
	cache.mu.Lock()
	if errors.Is(call.err, ErrPermanentCache) {
		if element, found := cache.entries[key]; found {
			cache.removeLocked(element)
		}
	}
	if call.err == nil && !cache.closed && call.loaded.TTL > 0 && call.loaded.Size <= cache.maxBytes {
		cache.setLocked(key, call.loaded)
	}
	delete(cache.flights, key)
	close(call.done)
	cache.mu.Unlock()
}

func (cache *Cache[V]) setLocked(key string, loaded Loaded[V]) {
	if old, found := cache.entries[key]; found {
		cache.removeLocked(old)
	}
	expiresAt := cache.clock.Now().Add(loaded.TTL)
	swrUntil := expiresAt.Add(loaded.StaleWhileRevalidate)
	sieUntil := swrUntil.Add(loaded.StaleIfError)
	entry := &cacheEntry[V]{key: key, value: loaded.Value, size: loaded.Size, expiresAt: expiresAt, swrUntil: swrUntil, sieUntil: sieUntil}
	cache.entries[key] = cache.lru.PushFront(entry)
	cache.bytes += loaded.Size
	for cache.lru.Len() > cache.maxEntries || cache.bytes > cache.maxBytes {
		cache.removeLocked(cache.lru.Back())
	}
}

func (cache *Cache[V]) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*cacheEntry[V])
	delete(cache.entries, entry.key)
	cache.bytes -= entry.size
	cache.lru.Remove(element)
	if cache.onEvict != nil {
		cache.onEvict()
	}
}

func (cache *Cache[V]) Close() {
	cache.mu.Lock()
	cache.closed = true
	cache.entries = make(map[string]*list.Element)
	cache.lru.Init()
	cache.bytes = 0
	group, owned := cache.refreshes, cache.ownsGroup
	cache.mu.Unlock()
	if owned {
		group.close()
	}
}
