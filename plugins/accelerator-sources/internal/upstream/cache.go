package upstream

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

var ErrClosed = errors.New("upstream owner is closed")

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type Loaded[V any] struct {
	Value V
	Size  int64
	TTL   time.Duration
}

type cacheEntry[V any] struct {
	key       string
	value     V
	size      int64
	expiresAt time.Time
}

type cacheCall[V any] struct {
	done   chan struct{}
	loaded Loaded[V]
	err    error
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
	return &Cache[V]{clock: clock, maxEntries: maxEntries, maxBytes: maxBytes, entries: make(map[string]*list.Element), lru: list.New(), flights: make(map[string]*cacheCall[V])}
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
		cache.removeLocked(element)
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

func (cache *Cache[V]) GetOrLoad(ctx context.Context, key string, load func(context.Context) (Loaded[V], error)) (V, error) {
	if value, found := cache.Get(key); found {
		return value, nil
	}
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		var zero V
		return zero, ErrClosed
	}
	if call, found := cache.flights[key]; found {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err()
		case <-call.done:
			return call.loaded.Value, call.err
		}
	}
	call := &cacheCall[V]{done: make(chan struct{})}
	cache.flights[key] = call
	cache.mu.Unlock()

	call.loaded, call.err = load(ctx)
	cache.mu.Lock()
	if call.err == nil && !cache.closed && call.loaded.TTL > 0 && call.loaded.Size <= cache.maxBytes {
		cache.setLocked(key, call.loaded)
	}
	delete(cache.flights, key)
	close(call.done)
	cache.mu.Unlock()
	return call.loaded.Value, call.err
}

func (cache *Cache[V]) setLocked(key string, loaded Loaded[V]) {
	if old, found := cache.entries[key]; found {
		cache.removeLocked(old)
	}
	entry := &cacheEntry[V]{key: key, value: loaded.Value, size: loaded.Size, expiresAt: cache.clock.Now().Add(loaded.TTL)}
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
	cache.mu.Unlock()
}
