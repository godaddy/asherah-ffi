package asherah

import "unsafe"

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

func lastErrorMessage() string {
	ptr := fnLastErrorMessage()
	if ptr == 0 {
		return "(unknown error)"
	}
	// Read null-terminated C string without CGO (bounded to 4096 bytes).
	var buf []byte
	for i := uintptr(0); i < 4096; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func readBuffer(buf *asherahBuffer) []byte {
	if buf.len == 0 || buf.data == 0 {
		return nil
	}
	// Copy the data out before the buffer is freed.
	src := unsafe.Slice((*byte)(unsafe.Pointer(buf.data)), int(buf.len))
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func freeBuffer(buf *asherahBuffer) {
	if buf.data != 0 {
		fnBufferFree(uintptr(unsafe.Pointer(buf)))
	}
}
