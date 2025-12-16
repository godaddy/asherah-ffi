// +build ignore

// This program generates test vectors using the original Go asherah-cobhan library.
// It produces JSON files that can be decrypted by both the Go and Rust implementations.
//
// Usage: go run generate_vectors.go

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

/*
#cgo LDFLAGS: -L. -lasherah_cobhan_go -ldl
#include <stdlib.h>
#include <stdint.h>

// Cobhan buffer structure
typedef struct {
    int32_t length;
    int32_t capacity;
    char data[];
} CobhanBuffer;

// Function declarations for the Go asherah-cobhan library
extern void Shutdown();
extern int32_t SetupJson(void* configJson);
extern int32_t EncryptToJson(void* partitionIdPtr, void* dataPtr, void* jsonPtr);
extern int32_t DecryptFromJson(void* partitionIdPtr, void* jsonPtr, void* dataPtr);
extern int32_t EstimateBuffer(int32_t dataLen, int32_t partitionLen);

// Helper to create a cobhan input buffer
static void* create_input_buffer(const char* data, int32_t len) {
    int32_t total = 8 + len;
    char* buf = (char*)malloc(total);
    if (!buf) return NULL;

    // Set length (little-endian)
    buf[0] = len & 0xFF;
    buf[1] = (len >> 8) & 0xFF;
    buf[2] = (len >> 16) & 0xFF;
    buf[3] = (len >> 24) & 0xFF;

    // Reserved bytes
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;

    // Copy data
    if (len > 0) {
        memcpy(buf + 8, data, len);
    }

    return buf;
}

// Helper to create a cobhan output buffer
static void* create_output_buffer(int32_t capacity) {
    int32_t total = 8 + capacity;
    char* buf = (char*)malloc(total);
    if (!buf) return NULL;

    // Set length to 0
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    // Set capacity (little-endian)
    buf[4] = capacity & 0xFF;
    buf[5] = (capacity >> 8) & 0xFF;
    buf[6] = (capacity >> 16) & 0xFF;
    buf[7] = (capacity >> 24) & 0xFF;

    return buf;
}

// Helper to get length from buffer
static int32_t get_buffer_length(void* buf) {
    char* b = (char*)buf;
    return (int32_t)(
        (unsigned char)b[0] |
        ((unsigned char)b[1] << 8) |
        ((unsigned char)b[2] << 16) |
        ((unsigned char)b[3] << 24)
    );
}

// Helper to get data from buffer
static char* get_buffer_data(void* buf) {
    return ((char*)buf) + 8;
}
*/
import "C"

// TestVector represents a single test case
type TestVector struct {
	Name        string `json:"name"`
	PartitionID string `json:"partition_id"`
	Plaintext   string `json:"plaintext"`
	PlaintextB64 string `json:"plaintext_b64,omitempty"` // For binary data
	Ciphertext  string `json:"ciphertext"` // The encrypted JSON
	IsBinary    bool   `json:"is_binary"`
}

// TestVectorFile represents the output file format
type TestVectorFile struct {
	Version     string       `json:"version"`
	Generator   string       `json:"generator"`
	Description string       `json:"description"`
	Config      ConfigInfo   `json:"config"`
	Vectors     []TestVector `json:"vectors"`
}

type ConfigInfo struct {
	ServiceName string `json:"service_name"`
	ProductID   string `json:"product_id"`
	Metastore   string `json:"metastore"`
	KMS         string `json:"kms"`
	MasterKey   string `json:"master_key_hex"`
}

func main() {
	// Set up master key for static KMS
	masterKey := strings.Repeat("41", 32) // 64 hex chars = 32 bytes
	os.Setenv("STATIC_MASTER_KEY_HEX", masterKey)

	// Configuration matching what we'll use in tests
	config := map[string]interface{}{
		"ServiceName":          "interop-test-service",
		"ProductID":            "interop-test-product",
		"Metastore":            "memory",
		"KMS":                  "static",
		"EnableSessionCaching": true,
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal config: %v\n", err)
		os.Exit(1)
	}

	// Initialize with SetupJson
	configBuf := C.create_input_buffer(C.CString(string(configJSON)), C.int32_t(len(configJSON)))
	if configBuf == nil {
		fmt.Fprintf(os.Stderr, "Failed to create config buffer\n")
		os.Exit(1)
	}
	defer C.free(configBuf)

	result := C.SetupJson(configBuf)
	if result != 0 {
		fmt.Fprintf(os.Stderr, "SetupJson failed with code: %d\n", result)
		os.Exit(1)
	}
	defer C.Shutdown()

	fmt.Println("Go asherah-cobhan initialized successfully")

	// Generate test vectors
	vectors := []TestVector{}

	// Test case 1: Simple ASCII text
	vectors = append(vectors, generateVector("simple_ascii", "test-partition-1", "Hello, World!"))

	// Test case 2: Empty string
	vectors = append(vectors, generateVector("empty_string", "test-partition-2", ""))

	// Test case 3: Unicode text
	vectors = append(vectors, generateVector("unicode_text", "test-partition-3", "Hello, \u4e16\u754c! \ud83e\udd80"))

	// Test case 4: JSON content
	vectors = append(vectors, generateVector("json_content", "test-partition-4", `{"key": "value", "number": 42}`))

	// Test case 5: Long text
	longText := strings.Repeat("This is a test message that will be repeated many times. ", 100)
	vectors = append(vectors, generateVector("long_text", "test-partition-5", longText))

	// Test case 6: Special characters
	vectors = append(vectors, generateVector("special_chars", "test-partition-6", "Special: \t\n\r\"'\\<>&"))

	// Test case 7: Numbers and symbols
	vectors = append(vectors, generateVector("numbers_symbols", "test-partition-7", "12345!@#$%^&*()_+-=[]{}|;':\",./<>?"))

	// Test case 8: Same partition, different data
	vectors = append(vectors, generateVector("same_partition_1", "shared-partition", "First message"))
	vectors = append(vectors, generateVector("same_partition_2", "shared-partition", "Second message"))

	// Test case 9: Whitespace only
	vectors = append(vectors, generateVector("whitespace", "test-partition-9", "   \t\n\r   "))

	// Test case 10: Single character
	vectors = append(vectors, generateVector("single_char", "test-partition-10", "X"))

	// Create output file
	output := TestVectorFile{
		Version:     "1.0",
		Generator:   "go-asherah-cobhan",
		Description: "Test vectors generated by the original Go asherah-cobhan implementation",
		Config: ConfigInfo{
			ServiceName: "interop-test-service",
			ProductID:   "interop-test-product",
			Metastore:   "memory",
			KMS:         "static",
			MasterKey:   masterKey,
		},
		Vectors: vectors,
	}

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	outputPath := filepath.Join(".", "test_vectors_go.json")
	if err := os.WriteFile(outputPath, outputJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %d test vectors to %s\n", len(vectors), outputPath)

	// Verify vectors can be decrypted
	fmt.Println("Verifying vectors...")
	for _, v := range vectors {
		if err := verifyVector(v); err != nil {
			fmt.Fprintf(os.Stderr, "Vector %s verification failed: %v\n", v.Name, err)
			os.Exit(1)
		}
	}
	fmt.Println("All vectors verified successfully")
}

func generateVector(name, partitionID, plaintext string) TestVector {
	// Create partition buffer
	partitionBuf := C.create_input_buffer(C.CString(partitionID), C.int32_t(len(partitionID)))
	defer C.free(partitionBuf)

	// Create data buffer
	dataBuf := C.create_input_buffer(C.CString(plaintext), C.int32_t(len(plaintext)))
	defer C.free(dataBuf)

	// Estimate output size
	estimate := C.EstimateBuffer(C.int32_t(len(plaintext)), C.int32_t(len(partitionID)))
	if estimate < 1024 {
		estimate = 1024
	}

	// Create output buffer
	outputBuf := C.create_output_buffer(estimate)
	defer C.free(outputBuf)

	// Encrypt
	result := C.EncryptToJson(partitionBuf, dataBuf, outputBuf)
	if result != 0 {
		panic(fmt.Sprintf("EncryptToJson failed for %s with code %d", name, result))
	}

	// Get ciphertext
	length := C.get_buffer_length(outputBuf)
	ciphertext := C.GoStringN(C.get_buffer_data(outputBuf), C.int(length))

	return TestVector{
		Name:        name,
		PartitionID: partitionID,
		Plaintext:   plaintext,
		Ciphertext:  ciphertext,
		IsBinary:    false,
	}
}

func verifyVector(v TestVector) error {
	// Create partition buffer
	partitionBuf := C.create_input_buffer(C.CString(v.PartitionID), C.int32_t(len(v.PartitionID)))
	defer C.free(partitionBuf)

	// Create ciphertext buffer
	ciphertextBuf := C.create_input_buffer(C.CString(v.Ciphertext), C.int32_t(len(v.Ciphertext)))
	defer C.free(ciphertextBuf)

	// Create output buffer
	outputBuf := C.create_output_buffer(C.int32_t(len(v.Plaintext) + 1024))
	defer C.free(outputBuf)

	// Decrypt
	result := C.DecryptFromJson(partitionBuf, ciphertextBuf, outputBuf)
	if result != 0 {
		return fmt.Errorf("DecryptFromJson failed with code %d", result)
	}

	// Get plaintext
	length := C.get_buffer_length(outputBuf)
	decrypted := C.GoStringN(C.get_buffer_data(outputBuf), C.int(length))

	if decrypted != v.Plaintext {
		return fmt.Errorf("decrypted text mismatch: expected %q, got %q", v.Plaintext, decrypted)
	}

	return nil
}
