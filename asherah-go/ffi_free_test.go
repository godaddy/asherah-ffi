package asherah

import "testing"

// TestFreeBuffer_RejectsCorruptedMetadata locks in the fix for a gap the
// earlier safeBufferLen fix left open: readBuffer stopped Go from
// reading past a len>capacity buffer, but freeBuffer still forwarded
// that same corrupted triple to fnBufferFree — which on the native side
// (asherah_buffer_free) reconstructs a Vec<u8> from these exact fields,
// undefined behavior when len > capacity. freeBuffer must leak rather
// than forward corrupted metadata to native code.
func TestFreeBuffer_RejectsCorruptedMetadata(t *testing.T) {
	called := false
	orig := fnBufferFree
	fnBufferFree = func(uintptr) { called = true }
	defer func() { fnBufferFree = orig }()

	buf := &asherahBuffer{data: 1, len: 10, capacity: 4} // len > capacity
	freeBuffer(buf)

	if called {
		t.Fatal("freeBuffer must not forward a len>capacity triple to the native free routine")
	}
}

// TestFreeBuffer_ForwardsValidMetadata confirms the guard above doesn't
// also break the normal path: a well-formed triple must still reach the
// native free routine, or every buffer would leak.
func TestFreeBuffer_ForwardsValidMetadata(t *testing.T) {
	called := false
	orig := fnBufferFree
	fnBufferFree = func(uintptr) { called = true }
	defer func() { fnBufferFree = orig }()

	buf := &asherahBuffer{data: 1, len: 4, capacity: 4}
	freeBuffer(buf)

	if !called {
		t.Fatal("freeBuffer should forward valid metadata to the native free routine")
	}
}

// TestReadBuffer_ErrorsOnCorruptedMetadata confirms readBuffer surfaces
// an explicit error instead of returning (nil, nil) — which would look
// identical to "successfully encrypted/decrypted to zero bytes" — when
// the native buffer's self-reported length exceeds its capacity.
func TestReadBuffer_ErrorsOnCorruptedMetadata(t *testing.T) {
	buf := &asherahBuffer{data: 1, len: 10, capacity: 4}
	data, err := readBuffer(buf)
	if err == nil {
		t.Fatalf("readBuffer should return an error for corrupted metadata, got data=%v, err=nil", data)
	}
	if data != nil {
		t.Fatalf("readBuffer should return nil data alongside the error, got %v", data)
	}
}

// TestReadBuffer_EmptyBufferIsNotAnError confirms the legitimate "no
// data" case (len==0, e.g. encrypting empty plaintext) still returns
// (nil, nil) rather than an error, regardless of whether data is null —
// a legitimate empty result may still carry a non-null dangling
// pointer, and len==0 means nothing gets dereferenced either way.
func TestReadBuffer_EmptyBufferIsNotAnError(t *testing.T) {
	for _, buf := range []*asherahBuffer{
		{data: 0, len: 0, capacity: 0},
		{data: 1, len: 0, capacity: 0}, // non-null dangling pointer, still empty
	} {
		data, err := readBuffer(buf)
		if err != nil {
			t.Fatalf("readBuffer(%+v) should not error, got %v", buf, err)
		}
		if data != nil {
			t.Fatalf("readBuffer(%+v) should return nil data, got %v", buf, data)
		}
	}
}

// TestReadBuffer_ErrorsOnNilDataWithNonZeroLen confirms readBuffer
// treats len > 0 with a null data pointer as malformed metadata rather
// than taking the empty-success path — the native side promised data
// but supplied no pointer, which is not the same as "zero bytes."
func TestReadBuffer_ErrorsOnNilDataWithNonZeroLen(t *testing.T) {
	buf := &asherahBuffer{data: 0, len: 10, capacity: 10}
	data, err := readBuffer(buf)
	if err == nil {
		t.Fatalf("readBuffer should return an error for len>0 with data==nil, got data=%v, err=nil", data)
	}
	if data != nil {
		t.Fatalf("readBuffer should return nil data alongside the error, got %v", data)
	}
}
