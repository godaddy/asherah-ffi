package asherah

import "testing"

// TestEncrypt_RejectsEmptyResultFromNativeLibrary guards against a
// skewed native library reporting success (rc == 0) without ever
// writing the output buffer, leaving the zero-valued struct from
// `buf := new(asherahBuffer)` in factory.go's Encrypt. readBuffer's
// buf.len == 0 fast path is correct for Decrypt (empty plaintext is
// legitimate and round-trips — see TestEmptyPayload in
// asherah_test.go), but Encrypt's output is always the non-empty
// DataRowRecord JSON envelope from to_json_fast, so a zero-length
// result there can only mean the native call skipped writing *out.
//
// Symbols are resolved by name with no version handshake, and both
// install-native --version and ASHERAH_GO_NATIVE are unchecked, so a
// mismatched/skewed native library is one flag away — not a purely
// theoretical scenario.
func TestEncrypt_RejectsEmptyResultFromNativeLibrary(t *testing.T) {
	origEncrypt := fnEncryptToJSON
	fnEncryptToJSON = func(session, data, dataLen, out uintptr) int {
		return 0 // reports success but never writes *out
	}
	defer func() { fnEncryptToJSON = origEncrypt }()

	sess := &Session{ptr: 1} // non-zero so the closed-session check passes
	ct, err := sess.Encrypt([]byte("plaintext"))
	if err == nil {
		t.Fatalf("Encrypt should reject an empty result from a native library that reports success without writing the output buffer, got ct=%v, err=nil", ct)
	}
	if ct != nil {
		t.Fatalf("Encrypt should return nil ciphertext alongside the error, got %v", ct)
	}
}
