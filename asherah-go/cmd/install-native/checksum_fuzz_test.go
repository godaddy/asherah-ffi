package main

import (
	"strings"
	"testing"
)

// FuzzParseChecksumLines exercises the SHA256SUMS parser against a
// tampered, truncated, or corrupted release asset. It must never panic,
// and any hash it reports must be traceable back to a real "<hash>
// <filename>" line in the input matching assetName.
func FuzzParseChecksumLines(f *testing.F) {
	f.Add([]byte("deadbeef  libasherah-x64.so\n"), "libasherah-x64.so")
	f.Add([]byte(""), "libasherah-x64.so")
	f.Add([]byte("not a sums file at all"), "libasherah-x64.so")
	f.Add([]byte("deadbeef libasherah-x64.so\nextra fields here too many\n"), "libasherah-x64.so")
	f.Add([]byte("deadbeef  other-file.so\n"), "libasherah-x64.so")
	f.Add([]byte("\x00\x00binary garbage\x00\x00"), "libasherah-x64.so")

	f.Fuzz(func(t *testing.T, sums []byte, assetName string) {
		hash, ok := parseChecksumLines(sums, assetName)
		if !ok {
			if hash != "" {
				t.Fatalf("parseChecksumLines returned ok=false but hash=%q", hash)
			}
			return
		}
		found := false
		for _, line := range strings.Split(string(sums), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 && parts[1] == assetName && parts[0] == hash {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("parseChecksumLines(%q) returned hash %q that isn't a real line for asset %q", sums, hash, assetName)
		}
	})
}
