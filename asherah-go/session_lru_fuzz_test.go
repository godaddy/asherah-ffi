package asherah

import (
	"container/list"
	"testing"
)

// FuzzSessionLRU replays a byte-encoded sequence of cache lookups/inserts
// against lruTouch/lruInsertEvict (the pure bookkeeping acquireSession
// uses under sessionMu) and asserts the cache/list invariants hold after
// every single operation:
//
//   - the map and list always have the same number of entries
//   - the list never exceeds maxSize (clamped to >= 1 — see below)
//   - every element reachable from the list is exactly the element the
//     map has recorded for its key (no drift between the two structures)
//   - no key appears more than once in the list
//   - lruInsertEvict never reports the entry it just inserted as evicted
//
// Each byte of ops drives one simulated acquireSession call: low bits
// select one of a small number of partition keys (to force collisions,
// like real callers reusing a handful of hot partitions), mirroring
// acquireSession's own pattern of "touch first; if absent, insert".
//
// maxSize is deliberately fuzzed across its full uint8 range, including
// 0, rather than pre-clamped here: lruInsertEvict clamps maxSize < 1 to
// 1 internally, and this is what exercises that guard against real
// input instead of only unit-testing it directly.
func FuzzSessionLRU(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 1, 2, 3}, uint8(2))
	f.Add([]byte{0, 0, 0, 0, 0}, uint8(1))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{255, 254, 253, 252, 251, 250}, uint8(3))
	f.Add([]byte{0, 1, 2}, uint8(0))

	const numKeys = 8

	f.Fuzz(func(t *testing.T, ops []byte, maxSizeByte uint8) {
		maxSize := int(maxSizeByte)

		cache := make(map[string]*list.Element)
		lru := list.New()
		keys := make([]string, numKeys)
		for i := range keys {
			keys[i] = string([]byte{'a' + byte(i)})
		}

		effectiveMaxSize := maxSize
		if effectiveMaxSize < 1 {
			effectiveMaxSize = 1
		}

		for step, b := range ops {
			key := keys[int(b)%numKeys]

			if _, ok := lruTouch(cache, lru, key); !ok {
				sess := &Session{} // stand-in; never dereferenced by the LRU logic
				evicted, evictedOK := lruInsertEvict(cache, lru, maxSize, sessionCacheEntry{partition: key, session: sess})
				if evictedOK && evicted == sess {
					t.Fatalf("step %d: lruInsertEvict(maxSize=%d) evicted the session it just inserted", step, maxSize)
				}
			}

			assertLRUInvariants(t, cache, lru, effectiveMaxSize, step)
		}
	})
}

func assertLRUInvariants(t *testing.T, cache map[string]*list.Element, lru *list.List, maxSize, step int) {
	t.Helper()

	if len(cache) != lru.Len() {
		t.Fatalf("step %d: len(cache)=%d != lru.Len()=%d", step, len(cache), lru.Len())
	}
	if lru.Len() > maxSize {
		t.Fatalf("step %d: lru.Len()=%d exceeds maxSize=%d", step, lru.Len(), maxSize)
	}

	seen := make(map[string]struct{}, lru.Len())
	for e := lru.Front(); e != nil; e = e.Next() {
		entry := e.Value.(sessionCacheEntry)
		if _, dup := seen[entry.partition]; dup {
			t.Fatalf("step %d: key %q appears more than once in the list", step, entry.partition)
		}
		seen[entry.partition] = struct{}{}

		elem, ok := cache[entry.partition]
		if !ok {
			t.Fatalf("step %d: key %q is in the list but not in the map", step, entry.partition)
		}
		if elem != e {
			t.Fatalf("step %d: cache[%q] does not point at its list element", step, entry.partition)
		}
	}
}
