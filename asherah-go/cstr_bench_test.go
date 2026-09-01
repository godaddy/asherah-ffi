package asherah

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

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
				_ = cstr(ptr)
			}
			// mem is only reachable through the bare uintptr ptr inside the
			// loop above, which the GC does not treat as a live reference —
			// without this, mem's backing array can be collected mid-benchmark
			// and cstr ends up scanning freed/reused memory.
			runtime.KeepAlive(mem)
		})
	}
}
