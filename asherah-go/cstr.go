package asherah

import "bytes"

// scanCString finds the NUL terminator in mem and returns the bytes
// before it, or mem unchanged if no NUL is present. It is the pure,
// fuzzable core of the unsafe C-string reads in cstr (hooks.go) and
// lastErrorMessage (ffi.go): both build an unsafe.Slice view of native
// memory bounded to a fixed cap and hand the whole view here so the
// scan logic itself can be exercised without raw pointers.
//
// There is deliberately no separate maxLen parameter: both callers
// already bound mem to exactly the size they want scanned via
// unsafe.Slice(ptr, maxLen), so mem's own length is that bound. An
// earlier version took maxLen as a second argument, which was
// redundant with len(mem) on every real call and let a caller pass a
// bound smaller (or negative) than the slice's actual length —
// scanCString(mem, -1) panicked on mem[:-1]. Dropping the parameter
// removes that panic class by construction instead of guarding it.
func scanCString(mem []byte) []byte {
	if i := bytes.IndexByte(mem, 0); i >= 0 {
		return mem[:i]
	}
	return mem
}
