package asherah

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// benchCstrSink forces cstr's result to escape. Assigning to a package-
// level var (rather than "_ = cstr(ptr)" or a benchmark-local var whose
// last write the compiler can prove is dead) is the standard Go
// benchmarking idiom for this: without it, a short enough non-escaping
// result can be proven safe for a compiler stack-allocation fast path
// for string([]byte) conversions that real callers never actually get,
// since every real caller (log fields, error messages, MetricsEvent
// names) uses the returned string for something and it always escapes.
// Confirmed via testing.AllocsPerRun in isolation, independent of this
// benchmark file: with "_ = cstr(ptr)", the pre-bytes.IndexByte
// implementation showed 0 allocs/op at 8 bytes specifically (not 64 or
// 4096) purely because that discard pattern let escape analysis prove
// the tiny result didn't need to escape — a benchmark-only code shape
// with no real analogue in this codebase.
var benchCstrSink string

// BenchmarkCstr exercises cstr end-to-end against a real Go-owned byte
// slice (via unsafe.Pointer, same trick used to feed it a controlled
// "native" buffer in tests). Comparable against main: cstr's name and
// signature are unchanged, only its internal C-string scan (now
// scanCString, previously an inline byte-append loop) differs.
func BenchmarkCstr(b *testing.B) {
	for _, n := range []int{8, 64, 4096} {
		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			mem := make([]byte, n+1) // +1 for the NUL terminator
			for i := 0; i < n; i++ {
				mem[i] = 'a'
			}
			mem[n] = 0
			ptr := uintptr(unsafe.Pointer(&mem[0]))

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchCstrSink = cstr(ptr)
			}
			// mem is only reachable through the bare uintptr ptr inside the
			// loop above, which the GC does not treat as a live reference —
			// without this, mem's backing array can be collected mid-benchmark
			// and cstr ends up scanning freed/reused memory.
			runtime.KeepAlive(mem)
		})
	}
}
