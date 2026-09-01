package asherah

import (
	"fmt"
	"math"
	"unsafe"
)

// asherahBuffer mirrors the C AsherahBuffer struct { data *uint8; len uintptr; capacity uintptr }.
type asherahBuffer struct {
	data     uintptr
	len      uintptr
	capacity uintptr
}

// Function pointers populated by loadSymbols.
var (
	fnFactoryNewFromEnv    func() uintptr
	fnFactoryNewWithConfig func(configJSON string) uintptr
	fnFactoryFree          func(factory uintptr)
	fnFactoryGetSession    func(factory uintptr, partitionID string) uintptr
	fnSessionFree          func(session uintptr)
	fnEncryptToJSON        func(session uintptr, data uintptr, dataLen uintptr, out uintptr) int
	fnDecryptFromJSON      func(session uintptr, json uintptr, jsonLen uintptr, out uintptr) int
	fnBufferFree           func(buf uintptr)
	fnLastErrorMessage     func() uintptr // returns *const c_char
)

// lastErrorMessage reads the most recent error from the FFI's
// thread-local LAST_ERROR slot.
//
// **Threading caveat:** The asherah-ffi side stores the message in a
// thread-local on the OS thread that produced the error. Go
// goroutines can be migrated between OS threads at any point —
// including between an FFI call that sets the error and the
// follow-up `lastErrorMessage()` read. Callers MUST wrap the FFI
// call + `lastErrorMessage()` pair in
// `runtime.LockOSThread()`/`runtime.UnlockOSThread()` so the
// goroutine stays pinned and reads back the same thread-local it
// just wrote. T-finding "lastErrorMessage reads thread-local C
// string from arbitrary OS thread" in
// `docs/review-2026-05-05-findings.md`.
func lastErrorMessage() string {
	ptr := fnLastErrorMessage()
	if ptr == 0 {
		return "(unknown error)"
	}
	// Read null-terminated C string without CGO (bounded to 4096 bytes).
	const maxLen = 4096
	mem := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), maxLen)
	return string(scanCString(mem, maxLen))
}

// safeBufferLen converts a native buffer's self-reported length to an int
// suitable for unsafe.Slice, rejecting anything that doesn't fit in an int
// (which would otherwise wrap negative and panic inside unsafe.Slice) or
// that exceeds the buffer's own reported capacity. A corrupted or
// mismatched native library response fully controls both fields, so both
// checks are load-bearing, not just defensive.
func safeBufferLen(bufLen, capacity uintptr) (int, bool) {
	if bufLen > capacity || bufLen > uintptr(math.MaxInt) {
		return 0, false
	}
	return int(bufLen), true
}

// readBuffer copies the native buffer's contents into a Go-owned []byte.
// It returns an error — rather than silently treating the result as an
// empty success — if the buffer's self-reported metadata is invalid, so
// a corrupted or mismatched native library response is never mistaken
// for "encrypted/decrypted to zero bytes."
//
// Only buf.len == 0 takes the empty-success path, regardless of
// buf.data: a legitimate empty result may still carry a non-null
// (dangling) data pointer, and len == 0 means nothing gets dereferenced
// either way. buf.len > 0 with buf.data == 0 is the malformed case —
// the native side promised data but supplied no pointer — and must
// error rather than silently produce an empty result indistinguishable
// from success.
func readBuffer(buf *asherahBuffer) ([]byte, error) {
	if buf.len == 0 {
		return nil, nil
	}
	if buf.data == 0 {
		return nil, fmt.Errorf("asherah-go: native buffer metadata invalid (len=%d, data=nil)", buf.len)
	}
	n, ok := safeBufferLen(buf.len, buf.capacity)
	if !ok {
		return nil, fmt.Errorf("asherah-go: native buffer metadata invalid (len=%d, capacity=%d)", buf.len, buf.capacity)
	}
	// Copy the data out before the buffer is freed.
	src := unsafe.Slice((*byte)(unsafe.Pointer(buf.data)), n)
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst, nil
}

// freeBuffer releases the native buffer's underlying allocation. It
// deliberately does nothing — leaking the native allocation rather than
// freeing it — if the buffer's self-reported length exceeds its
// capacity: asherah_buffer_free reconstructs a Vec<u8> from these exact
// fields (zeroizing `len` bytes, then Vec::from_raw_parts(data, len,
// capacity)), both of which are undefined behavior when len > capacity
// (asherah-ffi/src/lib.rs). A corrupted or mismatched native library
// response can produce such a triple — see safeBufferLen. A leak is a
// bounded, recoverable failure mode; forwarding corrupted metadata into
// more unsafe native code is not.
func freeBuffer(buf *asherahBuffer) {
	if buf.data == 0 {
		return
	}
	if _, ok := safeBufferLen(buf.len, buf.capacity); !ok {
		return
	}
	fnBufferFree(uintptr(unsafe.Pointer(buf)))
}
