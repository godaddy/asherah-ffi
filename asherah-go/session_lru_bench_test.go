package asherah

import (
	"container/list"
	"fmt"
	"testing"
)

// BenchmarkLRU exercises lruTouch/lruInsertEvict directly against a
// bare map+list, mirroring FuzzSessionLRU's harness. These functions
// are new on this branch (extracted from acquireSession's previously
// inline bookkeeping), so there's no equivalent on main to compare
// against — this records absolute numbers for the cache logic in
// isolation, without the FFI/crypto cost that dominates a real
// Encrypt/Decrypt call.
func BenchmarkLRU(b *testing.B) {
	b.Run("hit", func(b *testing.B) {
		cache := make(map[string]*list.Element)
		lru := list.New()
		const maxSize = 100
		for i := 0; i < maxSize; i++ {
			key := fmt.Sprintf("partition-%d", i)
			lruInsertEvict(cache, lru, maxSize, sessionCacheEntry{partition: key, session: &Session{}})
		}

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			lruTouch(cache, lru, "partition-50")
		}
	})

	b.Run("insert-with-eviction", func(b *testing.B) {
		cache := make(map[string]*list.Element)
		lru := list.New()
		const maxSize = 100

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("partition-%d", i)
			lruInsertEvict(cache, lru, maxSize, sessionCacheEntry{partition: key, session: &Session{}})
		}
	})
}
