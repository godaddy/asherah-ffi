package asherah

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// BenchmarkLastErrorMessage exercises lastErrorMessage end-to-end,
// stubbing fnLastErrorMessage to point at a real Go-owned buffer instead
// of requiring the native library. Comparable against main:
// lastErrorMessage's name and signature are unchanged, only its
// internal C-string scan (now scanCString) differs.
func BenchmarkLastErrorMessage(b *testing.B) {
	msg := []byte("asherah-go: encrypt failed: session is closed\x00")
	ptr := uintptr(unsafe.Pointer(&msg[0]))

	orig := fnLastErrorMessage
	fnLastErrorMessage = func() uintptr { return ptr }
	defer func() { fnLastErrorMessage = orig }()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = lastErrorMessage()
	}
	// msg is only reachable through the bare uintptr ptr captured by the
	// fnLastErrorMessage stub, which the GC does not treat as a live
	// reference — without this, msg's backing array can be collected
	// mid-benchmark.
	runtime.KeepAlive(msg)
}

// BenchmarkReadBuffer exercises readBuffer's decode-and-copy path
// against a real Go-owned buffer of varying size. Comparable against
// main: readBuffer exists there under the same name and is called the
// same way here (bare statement, so it compiles whether it returns one
// value, as on main, or two, as on this branch).
func BenchmarkReadBuffer(b *testing.B) {
	for _, n := range []int{64, 1024, 65536} {
		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			data := make([]byte, n)
			buf := &asherahBuffer{
				data:     uintptr(unsafe.Pointer(&data[0])),
				len:      uintptr(n),
				capacity: uintptr(n),
			}

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				readBuffer(buf)
			}
			// data is only reachable through the bare uintptr stored in
			// buf.data, which the GC does not treat as a live reference —
			// without this, data's backing array can be collected
			// mid-benchmark and readBuffer ends up copying freed/reused
			// memory.
			runtime.KeepAlive(data)
		})
	}
}

// BenchmarkFreeBuffer exercises freeBuffer's metadata-validation guard
// with fnBufferFree stubbed to a no-op (no native library required).
// Comparable against main: freeBuffer's name and signature are
// unchanged; the only difference is the added safeBufferLen check
// before forwarding to the native free routine.
func BenchmarkFreeBuffer(b *testing.B) {
	orig := fnBufferFree
	fnBufferFree = func(uintptr) {}
	defer func() { fnBufferFree = orig }()

	data := make([]byte, 64)
	buf := &asherahBuffer{
		data:     uintptr(unsafe.Pointer(&data[0])),
		len:      64,
		capacity: 64,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		freeBuffer(buf)
	}
	// Same GC-liveness concern as BenchmarkReadBuffer above.
	runtime.KeepAlive(data)
}
