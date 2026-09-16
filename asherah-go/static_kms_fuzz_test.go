package asherah

import (
	"encoding/hex"
	"testing"
)

// FuzzStaticKMSHex is a formality: fmt.Sprintf("%x", string) can't fail on
// arbitrary input. Locks in the encoding contract StaticKMS.applyConfig
// relies on: the result is always valid lowercase hex that decodes back
// to the exact original key bytes.
func FuzzStaticKMSHex(f *testing.F) {
	f.Add("")
	f.Add("test-key")
	f.Add("\x00\xff\x01")
	f.Add("unicode-\u00e9\u4e2d")

	f.Fuzz(func(t *testing.T, key string) {
		got := hexEncodeKey(key)
		if len(got) != 2*len(key) {
			t.Fatalf("hexEncodeKey(%q) has length %d, want %d", key, len(got), 2*len(key))
		}
		decoded, err := hex.DecodeString(got)
		if err != nil {
			t.Fatalf("hexEncodeKey(%q) = %q is not valid hex: %v", key, got, err)
		}
		if string(decoded) != key {
			t.Fatalf("hexEncodeKey(%q) round-trip mismatch: got %q", key, decoded)
		}
	})
}
