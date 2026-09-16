package asherah

import "testing"

// FuzzScanCString exercises the pure NUL-scan logic shared by cstr
// (hooks.go) and lastErrorMessage (ffi.go), which read C strings out of
// native-library-controlled memory without cgo. A malformed or corrupted
// native response (missing NUL terminator, NUL at the very start or
// very end, etc.) must never panic.
//
// Only a single []byte input, no separate bound: scanCString has no
// maxLen parameter (see cstr.go), so there's no clamp to apply here —
// the fuzzer can generate any []byte, including the empty slice,
// without the harness forbidding an input class the function itself
// mishandles.
func FuzzScanCString(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte("hello\x00world"))
	f.Add([]byte("no-nul-terminator"))
	f.Add([]byte{'a', 'b', 'c', 0}) // NUL at the very end

	f.Fuzz(func(t *testing.T, mem []byte) {
		got := scanCString(mem)

		if len(got) > len(mem) {
			t.Fatalf("scanCString(%q) returned %d bytes, longer than the input (%d)", mem, len(got), len(mem))
		}
		for i, b := range got {
			if b == 0 {
				t.Fatalf("scanCString result contains embedded NUL at index %d", i)
			}
		}
		// The byte immediately after the result, if any remains, must be
		// the NUL terminator (i.e. we stopped at the first one, not
		// early and not late).
		if len(got) < len(mem) && mem[len(got)] != 0 {
			t.Fatalf("scanCString(%q) stopped at index %d but mem[%d]=%d is not NUL", mem, len(got), len(got), mem[len(got)])
		}
	})
}
