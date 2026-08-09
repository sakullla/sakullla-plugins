package doh

import (
	"context"
	"sync"
)

type memoryCacheRecord struct {
	entry CacheEntry
	size  int
	order uint64
}

// MemoryCache is a deterministic bounded model for tests. Production still
// requires a generation-owned typed cache adapter from the host admission.
type MemoryCache struct {
	mu         sync.Mutex
	entries    map[string]memoryCacheRecord
	maxEntries int
	maxBytes   int
	bytes      int
	order      uint64
}

func NewMemoryCache(maxEntries, maxBytes int) *MemoryCache {
	return &MemoryCache{entries: make(map[string]memoryCacheRecord), maxEntries: maxEntries, maxBytes: maxBytes}
}

func (cache *MemoryCache) Get(ctx context.Context, key string, now uint64) (CacheEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return CacheEntry{}, false, err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	record, exists := cache.entries[key]
	if !exists {
		return CacheEntry{}, false, nil
	}
	if now >= record.entry.ExpiresAt {
		delete(cache.entries, key)
		cache.bytes -= record.size
		return CacheEntry{}, false, nil
	}
	record.entry.Response = append([]byte(nil), record.entry.Response...)
	return record.entry, true, nil
}

func (cache *MemoryCache) Put(ctx context.Context, key string, entry CacheEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) == 0 || len(entry.Response) > cache.maxBytes {
		return ErrCacheUnavailable
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if previous, exists := cache.entries[key]; exists {
		cache.bytes -= previous.size
		delete(cache.entries, key)
	}
	cache.order++
	record := memoryCacheRecord{entry: CacheEntry{Response: append([]byte(nil), entry.Response...), StoredAt: entry.StoredAt, ExpiresAt: entry.ExpiresAt}, size: len(key) + len(entry.Response), order: cache.order}
	for len(cache.entries) >= cache.maxEntries || cache.bytes+record.size > cache.maxBytes {
		var oldestKey string
		var oldest uint64
		for currentKey, current := range cache.entries {
			if oldestKey == "" || current.order < oldest || current.order == oldest && currentKey < oldestKey {
				oldestKey, oldest = currentKey, current.order
			}
		}
		if oldestKey == "" {
			return ErrCacheUnavailable
		}
		cache.bytes -= cache.entries[oldestKey].size
		delete(cache.entries, oldestKey)
	}
	cache.entries[key] = record
	cache.bytes += record.size
	return nil
}

func (cache *MemoryCache) Reset(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	cache.entries = make(map[string]memoryCacheRecord)
	cache.bytes = 0
	cache.mu.Unlock()
	return nil
}

func (cache *MemoryCache) Stats() (int, int) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries), cache.bytes
}
