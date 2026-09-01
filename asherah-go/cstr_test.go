package asherah

import "testing"

// FuzzScanCString exercises the pure NUL-scan logic shared by cstr
// (hooks.go) and lastErrorMessage (ffi.go), which read C strings out of
// native-library-controlled memory without cgo. A malformed or corrupted
// native response (missing NUL terminator, NUL beyond the buffer, etc.)
// must never panic or read past maxLen.
func FuzzScanCString(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0}, 1)
	f.Add([]byte("hello\x00world"), 64*1024)
	f.Add([]byte("no-nul-terminator"), 4)
	f.Add([]byte("no-nul-terminator"), 4096)
	f.Add([]byte{'a', 'b', 'c', 0}, 3) // NUL sits exactly at maxLen
	f.Add([]byte{'a', 'b', 'c', 0}, 4) // NUL sits exactly at maxLen-1

	f.Fuzz(func(t *testing.T, mem []byte, maxLen int) {
		if maxLen < 0 {
			maxLen = 0
		}
		got := scanCString(mem, maxLen)

		wantMax := maxLen
		if wantMax > len(mem) {
			wantMax = len(mem)
		}
		if len(got) > wantMax {
			t.Fatalf("scanCString(len(mem)=%d, maxLen=%d) returned %d bytes, want <= %d", len(mem), maxLen, len(got), wantMax)
		}
		for i, b := range got {
			if b == 0 {
				t.Fatalf("scanCString result contains embedded NUL at index %d", i)
			}
		}
		// The byte immediately after the result, if within the scanned
		// window, must be the NUL terminator (i.e. we stopped at the
		// first one, not early and not late).
		if len(got) < wantMax && mem[len(got)] != 0 {
			t.Fatalf("scanCString stopped at index %d but mem[%d]=%d is not NUL", len(got), len(got), mem[len(got)])
		}
	})
}
