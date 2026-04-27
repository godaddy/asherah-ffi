package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func main() {
	// Memory metastore + static KMS — testing only.
	// See production config at the bottom of this file.
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	config := asherah.Config{
		ServiceName: "sample-service",
		ProductID:   "sample-product",
		Metastore:   "memory",
		KMS:         "static", // testing only — use "aws" in production
	}

	// -- 1. Global API: Setup / EncryptString / DecryptString / Shutdown --
	if err := asherah.Setup(config); err != nil {
		log.Fatal(err)
	}

	ciphertext, err := asherah.EncryptString("sample-partition", "Hello, global API!")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Global encrypt OK:", ciphertext[:60]+"...")

	recovered, err := asherah.DecryptString("sample-partition", ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Global decrypt OK:", recovered)

	asherah.Shutdown()

	// -- 2. Factory/Session API: NewFactory / GetSession / Encrypt / Decrypt --
	factory, err := asherah.NewFactory(config)
	if err != nil {
		log.Fatal(err)
	}

	session, err := factory.GetSession("sample-partition")
	if err != nil {
		log.Fatal(err)
	}

	encrypted, err := session.Encrypt([]byte("Hello, session API!"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Session encrypt OK: %d bytes\n", len(encrypted))

	decrypted, err := session.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Session decrypt OK:", string(decrypted))

	session.Close()
	factory.Close()

	// -- 3. Concurrent example (Go uses goroutines instead of async) --
	if err := asherah.Setup(config); err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	partitions := []string{"user-1", "user-2", "user-3"}

	for _, pid := range partitions {
		wg.Add(1)
		go func(partition string) {
			defer wg.Done()
			ct, err := asherah.EncryptString(partition, "Hello from "+partition)
			if err != nil {
				log.Printf("encrypt %s: %v", partition, err)
				return
			}
			pt, err := asherah.DecryptString(partition, ct)
			if err != nil {
				log.Printf("decrypt %s: %v", partition, err)
				return
			}
			fmt.Printf("Goroutine %s OK: %s\n", partition, pt)
		}(pid)
	}
	wg.Wait()

	asherah.Shutdown()

	// -- 4. Log + metrics hooks: forward observability events to your stack --
	var logEvents, metricEvents int32
	// The simplest way: hand Asherah a *slog.Logger and let slog handle
	// dispatch, filtering, and formatting:
	//
	//   _ = asherah.SetSlogLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	//
	// Or pass a callback to read each record's structured fields directly:
	if err := asherah.SetLogHook(func(e asherah.LogEvent) {
		atomic.AddInt32(&logEvents, 1)
		// e.Level is a slog.Level — pass it straight to any slog.Handler,
		// or filter on slog.LevelInfo etc. with normal comparison.
		if e.Level >= slog.LevelInfo {
			fmt.Printf("[asherah-log %s] %s: %s\n", e.Level, e.Target, e.Message)
		}
	}); err != nil {
		log.Fatal(err)
	}
	if err := asherah.SetMetricsHook(func(e asherah.MetricsEvent) {
		atomic.AddInt32(&metricEvents, 1)
		// In real code, dispatch to your metrics library (statsd, prometheus, etc.).
		// Timing events have non-zero DurationNs and empty Name.
		// Cache events have non-empty Name and DurationNs == 0.
	}); err != nil {
		log.Fatal(err)
	}
	if err := asherah.Setup(config); err != nil {
		log.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ct, err := asherah.EncryptString("hooks-partition", fmt.Sprintf("hook-payload-%d", i))
		if err != nil {
			log.Fatal(err)
		}
		if _, err := asherah.DecryptString("hooks-partition", ct); err != nil {
			log.Fatal(err)
		}
	}
	asherah.Shutdown()
	_ = asherah.ClearLogHook()
	_ = asherah.ClearMetricsHook()
	fmt.Printf("Hooks observed %d log events and %d metric events\n",
		atomic.LoadInt32(&logEvents), atomic.LoadInt32(&metricEvents))
}

// -- 4. Production config (commented out) --
// region := "us-west-2"
// enableSuffix := true
// enableCache := true
// prodConfig := asherah.Config{
//     ServiceName:          "my-service",
//     ProductID:            "my-product",
//     Metastore:            "dynamodb",  // or "mysql", "postgres"
//     KMS:                  "aws",
//     RegionMap:            map[string]string{"us-west-2": "arn:aws:kms:us-west-2:..."},
//     PreferredRegion:      &region,
//     EnableRegionSuffix:   &enableSuffix,
//     EnableSessionCaching: &enableCache,
// }
