package main

import (
	"fmt"
	"testing"
)

// TestChecksumIsFatal locks in the soft-versus-fatal decision main()
// relies on to hard-fail on a real checksum mismatch while still
// soft-warning on every other verifyChecksum error (sums file
// unavailable, network error, etc.). Regression guard for the fail-open
// bug where a tampered download was reported as "checksum verification
// skipped" and installed anyway.
//
// This calls checksumIsFatal directly rather than re-implementing its
// errors.As logic inline: the decision itself lives only in that
// function (and, before it was extracted, only reachable from main()
// behind flag parsing, network I/O, and os.Exit), so a test that
// duplicates the same errors.As check independently can stay green
// even if the real decision is deleted or inverted.
func TestChecksumIsFatal(t *testing.T) {
	mismatchErr := fmt.Errorf("wrapped: %w", &checksumMismatchError{expected: "aaaa", actual: "bbbb"})
	if !checksumIsFatal(mismatchErr) {
		t.Fatal("checksumIsFatal(wrapped mismatch) = false, want true")
	}

	softErr := fmt.Errorf("checksums not available (HTTP %d)", 404)
	if checksumIsFatal(softErr) {
		t.Fatal("checksumIsFatal(404-style error) = true, want false")
	}
}
