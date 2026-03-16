package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	appencryption "github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
	"github.com/godaddy/asherah/go/securememory/memguard"
)

const staticKey = "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"

var (
	factory *appencryption.SessionFactory
	session *appencryption.Session
	sizes   = []int{64, 1024, 8192}
)

func TestMain(m *testing.M) {
	crypto := aead.NewAES256GCM()
	metastore := persistence.NewMemoryMetastore()
	kmsService, err := kms.NewStatic(staticKey, crypto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KMS setup failed: %v\n", err)
		os.Exit(1)
	}

	cfg := &appencryption.Config{
		Service: "bench-svc",
		Product: "bench-prod",
		Policy:  appencryption.NewCryptoPolicy(),
	}

	factory = appencryption.NewSessionFactory(cfg, metastore, kmsService, crypto,
		appencryption.WithMetrics(false),
		appencryption.WithSecretFactory(new(memguard.SecretFactory)))

	session, err = factory.GetSession("bench-partition")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Session creation failed: %v\n", err)
		os.Exit(1)
	}

	// Verify round-trip correctness
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		drr, err := session.Encrypt(ctx, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt failed for %dB: %v\n", size, err)
			os.Exit(1)
		}
		pt, err := session.Decrypt(ctx, *drr)
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
	session.Close()
	factory.Close()
	os.Exit(code)
}

func BenchmarkEncrypt(b *testing.B) {
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				drr, err := session.Encrypt(ctx, payload)
				if err != nil {
					b.Fatal(err)
				}
				_ = drr
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		drr, err := session.Encrypt(ctx, payload)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pt, err := session.Decrypt(ctx, *drr)
				if err != nil {
					b.Fatal(err)
				}
				_ = pt
			}
		})
	}
}
