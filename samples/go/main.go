package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

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
