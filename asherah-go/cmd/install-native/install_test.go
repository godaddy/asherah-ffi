package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newInstallTestServer serves assetName's content at /<assetName> and a
// SHA256SUMS listing it correctly at /SHA256SUMS, unless sumsHandler is
// non-nil, in which case it overrides the SHA256SUMS route (used to
// simulate a mismatch or an unavailable sums file).
func newInstallTestServer(t *testing.T, assetName string, assetContent []byte, sumsHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(assetContent)
	})
	if sumsHandler != nil {
		mux.HandleFunc("/SHA256SUMS", sumsHandler)
	} else {
		hash := sha256.Sum256(assetContent)
		sums := hex.EncodeToString(hash[:]) + "  " + assetName + "\n"
		mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(sums))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestInstallAsset_ChecksumMatch_Installs is the happy path: a correct
// checksum installs the asset at destFile and leaves no temp file
// behind.
func TestInstallAsset_ChecksumMatch_Installs(t *testing.T) {
	const assetName = "test-asset.bin"
	assetContent := []byte("pretend native library bytes")
	srv := newInstallTestServer(t, assetName, assetContent, nil)

	destFile := filepath.Join(t.TempDir(), "installed-lib")
	if err := installAsset(srv.URL+"/"+assetName, srv.URL+"/SHA256SUMS", assetName, destFile); err != nil {
		t.Fatalf("installAsset: %v", err)
	}

	got, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("destFile not installed: %v", err)
	}
	if string(got) != string(assetContent) {
		t.Fatalf("destFile content = %q, want %q", got, assetContent)
	}
	if _, statErr := os.Stat(destFile + ".verify"); !os.IsNotExist(statErr) {
		t.Fatalf("temp download file should not remain after a successful install, stat err = %v", statErr)
	}
}

// TestInstallAsset_ChecksumMismatch_NeverInstalls is the TOCTOU fix
// itself: on a genuine mismatch, destFile must never be written — not
// written-then-deleted, never written at all — and the temp download
// is cleaned up.
func TestInstallAsset_ChecksumMismatch_NeverInstalls(t *testing.T) {
	const assetName = "test-asset.bin"
	assetContent := []byte("pretend native library bytes")
	srv := newInstallTestServer(t, assetName, assetContent, func(w http.ResponseWriter, r *http.Request) {
		// A syntactically valid but deliberately wrong hash.
		_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + assetName + "\n"))
	})

	destFile := filepath.Join(t.TempDir(), "installed-lib")
	err := installAsset(srv.URL+"/"+assetName, srv.URL+"/SHA256SUMS", assetName, destFile)
	if err == nil {
		t.Fatal("installAsset should fail on a checksum mismatch")
	}
	if !checksumIsFatal(err) {
		t.Fatalf("installAsset's error should be fatal per checksumIsFatal, got: %v", err)
	}

	if _, statErr := os.Stat(destFile); !os.IsNotExist(statErr) {
		t.Fatalf("destFile must never be written on a checksum mismatch, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(destFile + ".verify"); !os.IsNotExist(statErr) {
		t.Fatalf("temp download file should be removed on a mismatch, stat err = %v", statErr)
	}
}

// TestInstallAsset_ChecksumMismatch_PreservesExistingInstall is the
// real TOCTOU distinction TestInstallAsset_ChecksumMismatch_NeverInstalls
// can't see: that test only checks the end state (no file), which is
// identical whether destFile was truly never touched or was written by
// the download and then successfully removed on mismatch — a
// single-threaded test can't observe the difference in final state
// alone. Seeding a pre-existing "previously installed" file first
// makes the two designs diverge observably: the old write-then-verify
// order overwrites it with the bad download before detecting the
// mismatch and removing it, destroying the working install even though
// nothing should have changed; the fixed order never touches destFile
// at all on a mismatch; the existing install must survive untouched.
func TestInstallAsset_ChecksumMismatch_PreservesExistingInstall(t *testing.T) {
	const assetName = "test-asset.bin"
	badContent := []byte("corrupted or tampered bytes")
	srv := newInstallTestServer(t, assetName, badContent, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + assetName + "\n"))
	})

	destFile := filepath.Join(t.TempDir(), "installed-lib")
	existingContent := []byte("previously installed, known-good bytes")
	if err := os.WriteFile(destFile, existingContent, 0o644); err != nil {
		t.Fatalf("seed existing install: %v", err)
	}

	err := installAsset(srv.URL+"/"+assetName, srv.URL+"/SHA256SUMS", assetName, destFile)
	if err == nil || !checksumIsFatal(err) {
		t.Fatalf("installAsset should fail fatally on a checksum mismatch, got: %v", err)
	}

	got, readErr := os.ReadFile(destFile)
	if readErr != nil {
		t.Fatalf("an existing install must survive a failed re-install attempt, but destFile is gone: %v", readErr)
	}
	if string(got) != string(existingContent) {
		t.Fatalf("existing install was disturbed by a failed re-install attempt: destFile = %q, want unchanged %q", got, existingContent)
	}
}

// TestInstallAsset_ChecksumUnavailable_SoftInstallsWithWarning matches
// this tool's long-standing behavior for releases that predate
// SHA256SUMS: verification being unavailable is a soft failure, not a
// fatal one, and the asset still gets installed.
func TestInstallAsset_ChecksumUnavailable_SoftInstallsWithWarning(t *testing.T) {
	const assetName = "test-asset.bin"
	assetContent := []byte("pretend native library bytes")
	srv := newInstallTestServer(t, assetName, assetContent, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	destFile := filepath.Join(t.TempDir(), "installed-lib")
	if err := installAsset(srv.URL+"/"+assetName, srv.URL+"/SHA256SUMS", assetName, destFile); err != nil {
		t.Fatalf("installAsset should soft-skip an unavailable SHA256SUMS, got error: %v", err)
	}

	got, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("destFile not installed: %v", err)
	}
	if string(got) != string(assetContent) {
		t.Fatalf("destFile content = %q, want %q", got, assetContent)
	}
}
