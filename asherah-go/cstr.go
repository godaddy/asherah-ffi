package asherah

// scanCString finds the NUL terminator in mem, bounded by maxLen, and
// returns the bytes before it. It is the pure, fuzzable core of the
// unsafe C-string reads in cstr (hooks.go) and lastErrorMessage (ffi.go):
// both build an unsafe.Slice view of native memory bounded to a fixed cap
// and hand it here so the scan logic itself can be exercised without raw
// pointers.
func scanCString(mem []byte, maxLen int) []byte {
	if maxLen > len(mem) {
		maxLen = len(mem)
	}
	for i := 0; i < maxLen; i++ {
		if mem[i] == 0 {
			return mem[:i]
		}
	}
	return mem[:maxLen]
}
