package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	appencryption "github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
	"github.com/godaddy/asherah/go/securememory/memguard"
	"github.com/godaddy/asherah/go/securememory/protectedmemory"
)

const (
	warmup     = 500
	iterations = 5000
	staticKey  = "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
)

func benchFactory(label string, opts ...appencryption.FactoryOption) {
	crypto := aead.NewAES256GCM()
	metastore := persistence.NewMemoryMetastore()
	kmsService, err := kms.NewStatic(staticKey, crypto)
	if err != nil {
		panic(err)
	}

	cfg := &appencryption.Config{
		Service: "bench-svc",
		Product: "bench-prod",
		Policy:  appencryption.NewCryptoPolicy(),
	}

	allOpts := append([]appencryption.FactoryOption{appencryption.WithMetrics(false)}, opts...)
	factory := appencryption.NewSessionFactory(cfg, metastore, kmsService, crypto, allOpts...)
	defer factory.Close()

	session, err := factory.GetSession("bench-partition")
	if err != nil {
		panic(err)
	}
	defer session.Close()

	sizes := []int{64, 1024, 8192}
	ctx := context.Background()

	fmt.Printf("=== %s ===\n\n", label)

	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)

		// Warmup
		for i := 0; i < warmup; i++ {
			drr, err := session.Encrypt(ctx, payload)
			if err != nil {
				panic(err)
			}
			jsonBytes, _ := json.Marshal(drr)
			var drr2 appencryption.DataRowRecord
			json.Unmarshal(jsonBytes, &drr2)
			session.Decrypt(ctx, drr2)
		}

		// Benchmark encrypt
		start := time.Now()
		var lastDrr *appencryption.DataRowRecord
		for i := 0; i < iterations; i++ {
			drr, err := session.Encrypt(ctx, payload)
			if err != nil {
				panic(err)
			}
			lastDrr = drr
		}
		encDur := time.Since(start)
		encUs := float64(encDur.Microseconds()) / float64(iterations)

		// Serialize for decrypt benchmark
		jsonBytes, _ := json.Marshal(lastDrr)

		// Benchmark decrypt
		start = time.Now()
		for i := 0; i < iterations; i++ {
			var drr appencryption.DataRowRecord
			json.Unmarshal(jsonBytes, &drr)
			_, err := session.Decrypt(ctx, drr)
			if err != nil {
				panic(err)
			}
		}
		decDur := time.Since(start)
		decUs := float64(decDur.Microseconds()) / float64(iterations)

		fmt.Printf("  %5dB  encrypt: %10.2f µs  decrypt: %10.2f µs\n", size, encUs, decUs)
	}
	fmt.Println()
}

func main() {
	benchFactory("Go Canonical Asherah — memguard (default)",
		appencryption.WithSecretFactory(new(memguard.SecretFactory)))

	benchFactory("Go Canonical Asherah — protectedmemory",
		appencryption.WithSecretFactory(new(protectedmemory.SecretFactory)))
}
