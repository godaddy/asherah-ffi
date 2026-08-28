package main

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseChecksumLines exercises the SHA256SUMS parser against a
// tampered, truncated, or corrupted release asset. It must never panic;
// any hash it reports must be traceable back to a real "<hash>
// <filename>" line in the input matching assetName; and it must never
// report both a non-nil error and a non-empty hash simultaneously.
//
// bytes.Reader itself never fails a Read, but bufio.Scanner can still
// surface bufio.ErrTooLong for a single line/token exceeding
// bufio.MaxScanTokenSize (64KB) — the seed below exercises that path so
// it's fuzzed rather than only reachable by chance mutation.
func FuzzParseChecksumLines(f *testing.F) {
	f.Add([]byte("deadbeef  libasherah-x64.so\n"), "libasherah-x64.so")
	f.Add([]byte(""), "libasherah-x64.so")
	f.Add([]byte("not a sums file at all"), "libasherah-x64.so")
	f.Add([]byte("deadbeef libasherah-x64.so\nextra fields here too many\n"), "libasherah-x64.so")
	f.Add([]byte("deadbeef  other-file.so\n"), "libasherah-x64.so")
	f.Add([]byte("\x00\x00binary garbage\x00\x00"), "libasherah-x64.so")
	f.Add(bytes.Repeat([]byte("a"), 100_000), "libasherah-x64.so") // triggers bufio.ErrTooLong

	f.Fuzz(func(t *testing.T, sums []byte, assetName string) {
		hash, err := parseChecksumLines(bytes.NewReader(sums), assetName)
		if err != nil {
			if hash != "" {
				t.Fatalf("parseChecksumLines returned a non-nil error but hash=%q (want empty)", hash)
			}
			return
		}
		if hash == "" {
			return // clean scan, no matching entry — not an error
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
