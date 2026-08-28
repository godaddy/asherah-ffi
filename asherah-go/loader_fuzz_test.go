package asherah

import (
	"strings"
	"testing"
)

// FuzzDedupeStrings exercises the order-preserving dedup helper used to
// build the native-library search path list. Splits the fuzz input on
// newlines to produce a candidate []string.
func FuzzDedupeStrings(f *testing.F) {
	f.Add("")
	f.Add("a\na\nb")
	f.Add("\n\n\n")
	f.Add("a\nb\na\nb\nc")

	f.Fuzz(func(t *testing.T, input string) {
		values := strings.Split(input, "\n")
		out := dedupeStrings(values)

		seen := make(map[string]struct{}, len(out))
		for _, v := range out {
			if v == "" {
				t.Fatalf("dedupeStrings(%q) kept an empty string", values)
			}
			if _, dup := seen[v]; dup {
				t.Fatalf("dedupeStrings(%q) kept a duplicate: %q", values, v)
			}
			seen[v] = struct{}{}
		}

		// Order of first occurrences must be preserved.
		var wantOrder []string
		wantSeen := make(map[string]struct{})
		for _, v := range values {
			if v == "" {
				continue
			}
			if _, dup := wantSeen[v]; dup {
				continue
			}
			wantSeen[v] = struct{}{}
			wantOrder = append(wantOrder, v)
		}
		if len(out) != len(wantOrder) {
			t.Fatalf("dedupeStrings(%q) = %v, want %v", values, out, wantOrder)
		}
		for i := range out {
			if out[i] != wantOrder[i] {
				t.Fatalf("dedupeStrings(%q) = %v, want %v", values, out, wantOrder)
			}
		}
	})
}
