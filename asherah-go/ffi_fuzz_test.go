package asherah

import (
	"math"
	"testing"
)

// FuzzSafeBufferLen exercises the length/capacity arithmetic readBuffer
// uses to decode the {data, len, capacity} triple returned by the native
// asherah_encrypt_to_json/asherah_decrypt_from_json calls. A corrupted or
// mismatched native library response controls bufLen and capacity
// directly, so this must never produce a length that overflows int or
// exceeds the buffer's own reported capacity.
func FuzzSafeBufferLen(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(10), uint64(10))
	f.Add(uint64(10), uint64(4)) // len > capacity: must be rejected
	f.Add(uint64(0), uint64(100))
	f.Add(^uint64(0), uint64(4)) // max uintptr, tiny capacity
	f.Add(uint64(math.MaxInt), uint64(math.MaxInt))
	f.Add(uint64(math.MaxInt)+1, uint64(math.MaxInt)+1) // overflows int on conversion

	f.Fuzz(func(t *testing.T, bufLen, capacity uint64) {
		n, ok := safeBufferLen(uintptr(bufLen), uintptr(capacity))
		if !ok {
			return
		}
		if n < 0 {
			t.Fatalf("safeBufferLen(%d, %d) = (%d, true): negative length must never be reported safe", bufLen, capacity, n)
		}
		if uint64(n) != bufLen {
			t.Fatalf("safeBufferLen(%d, %d) = (%d, true): length does not round-trip", bufLen, capacity, n)
		}
		if bufLen > capacity {
			t.Fatalf("safeBufferLen(%d, %d) = (%d, true): a length exceeding capacity must be rejected", bufLen, capacity, n)
		}
	})
}
