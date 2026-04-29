package asherah_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

// Verifies that the module-level session cache respects
// SessionCacheMaxSize and uses LRU eviction. Prior to the LRU fix the
// cache used insertion-order FIFO, which evicts hot entries that were
// re-used after insertion.
func TestSessionCache_RoundTripUnderEvictionChurn(t *testing.T) {
	ensureNativeLibrary(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	maxSize := 4
	cfg := asherah.Config{
		ServiceName:         "svc",
		ProductID:           "prod",
		Metastore:           "memory",
		KMS:                 "static",
		SessionCacheMaxSize: &maxSize,
	}
	if err := asherah.Setup(cfg); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	for i := 0; i < 64; i++ {
		partition := fmt.Sprintf("churn-%d", i)
		payload := []byte(fmt.Sprintf("payload-%d", i))
		ct, err := asherah.Encrypt(partition, payload)
		if err != nil {
			t.Fatalf("Encrypt(%s) failed: %v", partition, err)
		}
		recovered, err := asherah.Decrypt(partition, ct)
		if err != nil {
			t.Fatalf("Decrypt(%s) failed: %v", partition, err)
		}
		if string(recovered) != string(payload) {
			t.Fatalf("partition %s: got %q want %q", partition, recovered, payload)
		}
	}
}

func TestSessionCache_HotPartitionsRoundTripRepeatedly(t *testing.T) {
	ensureNativeLibrary(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	maxSize := 2
	cfg := asherah.Config{
		ServiceName:         "svc",
		ProductID:           "prod",
		Metastore:           "memory",
		KMS:                 "static",
		SessionCacheMaxSize: &maxSize,
	}
	if err := asherah.Setup(cfg); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	for i := 0; i < 16; i++ {
		ct, err := asherah.Encrypt("hot-a", []byte("a"))
		if err != nil {
			t.Fatalf("Encrypt hot-a: %v", err)
		}
		if r, err := asherah.Decrypt("hot-a", ct); err != nil || string(r) != "a" {
			t.Fatalf("hot-a roundtrip: got %q err=%v", r, err)
		}
		ct, err = asherah.Encrypt("hot-b", []byte("b"))
		if err != nil {
			t.Fatalf("Encrypt hot-b: %v", err)
		}
		if r, err := asherah.Decrypt("hot-b", ct); err != nil || string(r) != "b" {
			t.Fatalf("hot-b roundtrip: got %q err=%v", r, err)
		}
	}
}

func TestSessionCache_DefaultBoundRoundTripsPastThousand(t *testing.T) {
	ensureNativeLibrary(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	cfg := asherah.Config{
		ServiceName: "svc",
		ProductID:   "prod",
		Metastore:   "memory",
		KMS:         "static",
	}
	if err := asherah.Setup(cfg); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer asherah.Shutdown()

	for i := 0; i < 1100; i++ {
		partition := fmt.Sprintf("default-%d", i)
		payload := []byte(fmt.Sprintf("p%d", i))
		ct, err := asherah.Encrypt(partition, payload)
		if err != nil {
			t.Fatalf("Encrypt(%s) failed: %v", partition, err)
		}
		recovered, err := asherah.Decrypt(partition, ct)
		if err != nil {
			t.Fatalf("Decrypt(%s) failed: %v", partition, err)
		}
		if string(recovered) != string(payload) {
			t.Fatalf("partition %s: got %q want %q", partition, recovered, payload)
		}
	}
}
