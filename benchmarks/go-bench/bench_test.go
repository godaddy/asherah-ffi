package gobench

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	asherah "github.com/godaddy/asherah-go"
)

var sizes = []int{64, 1024, 8192}

func boolPtr(b bool) *bool { return &b }

func TestMain(m *testing.M) {
	os.Setenv("STATIC_MASTER_KEY_HEX", "2222222222222222222222222222222222222222222222222222222222222222")

	cfg := asherah.Config{
		ServiceName:          "bench-svc",
		ProductID:            "bench-prod",
		Metastore:            "memory",
		KMS:                  "static",
		EnableSessionCaching: boolPtr(true),
	}
	if err := asherah.Setup(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}

	// Verify round-trip correctness for each payload size
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		ct, err := asherah.Encrypt("bench-partition", payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt failed for %dB: %v\n", size, err)
			os.Exit(1)
		}
		pt, err := asherah.Decrypt("bench-partition", ct)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decrypt failed for %dB: %v\n", size, err)
			os.Exit(1)
		}
		if !bytes.Equal(payload, pt) {
			fmt.Fprintf(os.Stderr, "Round-trip verification failed for %dB\n", size)
			os.Exit(1)
		}
	}

	code := m.Run()
	asherah.Shutdown()
	os.Exit(code)
}

func BenchmarkEncrypt(b *testing.B) {
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ct, err := asherah.Encrypt("bench-partition", payload)
				if err != nil {
					b.Fatal(err)
				}
				_ = ct
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		ct, err := asherah.Encrypt("bench-partition", payload)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pt, err := asherah.Decrypt("bench-partition", ct)
				if err != nil {
					b.Fatal(err)
				}
				_ = pt
			}
		})
	}
}
