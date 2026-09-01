package main

import (
	"errors"
	"fmt"
	"testing"
)

// TestChecksumMismatchDispatch locks in the errors.As dispatch main() relies
// on to hard-fail on a real checksum mismatch while still soft-warning on
// every other verifyChecksum error (sums file unavailable, network error,
// etc.). Regression guard for the fail-open bug where a tampered download
// was reported as "checksum verification skipped" and installed anyway.
func TestChecksumMismatchDispatch(t *testing.T) {
	mismatchErr := fmt.Errorf("wrapped: %w", &checksumMismatchError{expected: "aaaa", actual: "bbbb"})
	var mismatch *checksumMismatchError
	if !errors.As(mismatchErr, &mismatch) {
		t.Fatal("errors.As failed to unwrap a checksumMismatchError")
	}
	if mismatch.expected != "aaaa" || mismatch.actual != "bbbb" {
		t.Fatalf("unwrapped mismatch has wrong fields: %+v", mismatch)
	}

	softErr := fmt.Errorf("checksums not available (HTTP %d)", 404)
	var notMismatch *checksumMismatchError
	if errors.As(softErr, &notMismatch) {
		t.Fatal("errors.As incorrectly matched a non-mismatch error as checksumMismatchError")
	}
}
