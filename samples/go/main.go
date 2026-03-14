package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	asherah "github.com/godaddy/asherah-go"
)

func main() {
	// A static master key for local development only.
	// In production, use KMS: "aws" with a proper region map.
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

	err := asherah.Setup(asherah.Config{
		ServiceName: "sample-service",
		ProductID:   "sample-product",
		Metastore:   "memory",
		KMS:         "static",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer asherah.Shutdown()

	// Encrypt
	plaintext := "Hello from Go!"
	ciphertext, err := asherah.EncryptString("sample-partition", plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Encrypted:", ciphertext[:80]+"...")

	// Decrypt
	recovered, err := asherah.DecryptString("sample-partition", ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted:", recovered)
}
