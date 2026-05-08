// Rotation, revocation, and concurrent rotation tests for the
// asherah-go binding.
//
// The Rust core has comprehensive rotation/revocation coverage in
// asherah/tests/. The Go binding had zero rotation tests prior to
// this file. Mirrors the asherah-node, asherah-py, asherah-java, and
// asherah-dotnet rotation suites (Go has no separate async API —
// goroutines + sync calls cover concurrent use).
//
// Hermetic: Metastore: "memory" + KMS: "test-debug-static" produces
// a hermetic factory with no Docker or network dependency.

package asherah_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func ptrInt64(v int64) *int64 { return &v }
func ptrBool(v bool) *bool    { return &v }

func shortExpiryConfig(suffix string) asherah.Config {
	return asherah.Config{
		ServiceName:          "rot-" + suffix + "-svc",
		ProductID:            "rot-" + suffix + "-prod",
		Metastore:            "memory",
		KMS:                  "test-debug-static",
		ExpireAfter:          ptrInt64(1),
		CheckInterval:        ptrInt64(1),
		EnableSessionCaching: ptrBool(false),
	}
}

// ikCreated extracts Key.ParentKeyMeta.Created from a DRR JSON
// string. The Rust core uses Pascal-cased fields for cross-language
// compatibility with the Go reference.
func ikCreated(t *testing.T, drr string) int64 {
	t.Helper()
	var parsed struct {
		Key struct {
			ParentKeyMeta struct {
				Created int64 `json:"Created"`
			} `json:"ParentKeyMeta"`
		} `json:"Key"`
	}
	if err := json.Unmarshal([]byte(drr), &parsed); err != nil {
		t.Fatalf("DRR JSON parse failed: %v\nDRR: %s", err, drr)
	}
	return parsed.Key.ParentKeyMeta.Created
}

// ──────────── Sync rotation ────────────

func TestSyncRotationAcrossExpiry(t *testing.T) {
	ensureNativeLibrary(t)
	t.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	if err := asherah.Setup(shortExpiryConfig("sync")); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	drr1, err := asherah.EncryptString("p1", "before")
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	ik1 := ikCreated(t, drr1)

	time.Sleep(3 * time.Second)

	drr2, err := asherah.EncryptString("p1", "after")
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	ik2 := ikCreated(t, drr2)

	if ik2 <= ik1 {
		t.Fatalf("expected IK rotation across expiry: ik2=%d should be > ik1=%d", ik2, ik1)
	}

	pt1, err := asherah.DecryptString("p1", drr1)
	if err != nil || pt1 != "before" {
		t.Fatalf("decrypt drr1: pt=%q err=%v", pt1, err)
	}
	pt2, err := asherah.DecryptString("p1", drr2)
	if err != nil || pt2 != "after" {
		t.Fatalf("decrypt drr2: pt=%q err=%v", pt2, err)
	}
}

// ──────────── Multiple rotation cycles ────────────

func TestMultipleRotationCycles(t *testing.T) {
	ensureNativeLibrary(t)
	t.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	if err := asherah.Setup(shortExpiryConfig("multi")); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	type cycle struct {
		drr     string
		payload string
		ik      int64
	}
	var history []cycle
	for i := 0; i < 3; i++ {
		payload := fmt.Sprintf("cycle-%d", i)
		drr, err := asherah.EncryptString("p1", payload)
		if err != nil {
			t.Fatalf("cycle %d encrypt: %v", i, err)
		}
		history = append(history, cycle{drr, payload, ikCreated(t, drr)})
		time.Sleep(3 * time.Second)
	}

	// Each cycle's IK must be strictly newer than the previous.
	for i := 1; i < len(history); i++ {
		if history[i].ik <= history[i-1].ik {
			t.Fatalf("cycle %d: ik=%d should be > prev ik=%d",
				i, history[i].ik, history[i-1].ik)
		}
	}

	// Every historical DRR still decrypts.
	for _, c := range history {
		pt, err := asherah.DecryptString("p1", c.drr)
		if err != nil || pt != c.payload {
			t.Fatalf("decrypt %q: pt=%q err=%v", c.payload, pt, err)
		}
	}
}

// ──────────── Concurrent rotation across expiry ────────────

// Concurrent goroutines all encrypt on the same partition just after
// expiry. Every DRR must decrypt to its plaintext, regardless of
// which goroutine produced it. Catches FFI marshalling regressions
// that misuse goroutine-local state.
func TestConcurrentRotation(t *testing.T) {
	ensureNativeLibrary(t)
	t.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	if err := asherah.Setup(shortExpiryConfig("conc")); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	// Seed an IK so the goroutine burst exercises rotation.
	if _, err := asherah.EncryptString("hot", "seed"); err != nil {
		t.Fatalf("seed encrypt: %v", err)
	}
	time.Sleep(3 * time.Second)

	const goroutines = 8
	type result struct {
		idx     int
		drr     string
		payload string
	}
	results := make(chan result, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := fmt.Sprintf("burst-%d", idx)
			drr, err := asherah.EncryptString("hot", payload)
			if err != nil {
				t.Errorf("goroutine %d encrypt: %v", idx, err)
				return
			}
			results <- result{idx, drr, payload}
		}(i)
	}
	wg.Wait()
	close(results)

	count := 0
	for r := range results {
		count++
		pt, err := asherah.DecryptString("hot", r.drr)
		if err != nil || pt != r.payload {
			t.Fatalf("goroutine %d: decrypt %q: pt=%q err=%v",
				r.idx, r.payload, pt, err)
		}
	}
	if count != goroutines {
		t.Fatalf("expected %d results, got %d", goroutines, count)
	}
}
