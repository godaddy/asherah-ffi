package gobench

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"testing"

	asherah "github.com/godaddy/asherah-go"
)

var sizes = []int{64, 1024, 8192}

func boolPtr(b bool) *bool { return &b }

func TestMain(m *testing.M) {
	if os.Getenv("STATIC_MASTER_KEY_HEX") == "" {
		os.Setenv("STATIC_MASTER_KEY_HEX", "746869734973415374617469634d61737465724b6579466f7254657374696e67")
	}

	metastore := os.Getenv("BENCH_METASTORE")
	if metastore == "" {
		metastore = "memory"
	}
	cfg := asherah.Config{
		ServiceName:          "bench-svc",
		ProductID:            "bench-prod",
		Metastore:            metastore,
		KMS:                  "static",
		EnableSessionCaching: boolPtr(true),
	}
	if cs := os.Getenv("BENCH_CONNECTION_STRING"); cs != "" {
		cfg.ConnectionString = &cs
	}
	if ci := os.Getenv("BENCH_CHECK_INTERVAL"); ci != "" {
		if v, err := strconv.ParseInt(ci, 10, 64); err == nil {
			cfg.CheckInterval = &v
		}
	}
	if os.Getenv("BENCH_COLD") == "1" {
		os.Setenv("INTERMEDIATE_KEY_CACHE_MAX_SIZE", "1")
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
	cold := os.Getenv("BENCH_COLD") == "1"
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		if cold {
			// Warm SK cache
			asherah.Encrypt("cold-warmup", payload)

			b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_, err := asherah.Encrypt(fmt.Sprintf("cold-enc-%d-%d", size, i), payload)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		} else {
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
}

func BenchmarkDecrypt(b *testing.B) {
	cold := os.Getenv("BENCH_COLD") == "1"

	// Warmup
	asherah.Encrypt("bench-partition", []byte("warmup"))

	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		if cold {
			// Pre-encrypt on 2 partitions, alternate to force IK cache miss
			ct0, err := asherah.Encrypt("cold-0", payload)
			if err != nil {
				b.Fatal(err)
			}
			ct1, err := asherah.Encrypt("cold-1", payload)
			if err != nil {
				b.Fatal(err)
			}
			// Warm SK cache
			asherah.Decrypt("cold-0", ct0)

			b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					idx := i % 2
					var ct []byte
					var p string
					if idx == 0 {
						ct, p = ct0, "cold-0"
					} else {
						ct, p = ct1, "cold-1"
					}
					pt, err := asherah.Decrypt(p, ct)
					if err != nil {
						b.Fatal(err)
					}
					_ = pt
				}
			})
		} else {
			ct, err := asherah.Encrypt("bench-partition", payload)
			if err != nil {
				b.Fatal(err)
			}
			if len(ct) == 0 {
				b.Fatal("encrypt returned empty ciphertext")
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
}
