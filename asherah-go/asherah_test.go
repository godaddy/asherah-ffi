package asherah_test

import (
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "testing"

    asherah "github.com/godaddy/asherah-go"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
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

    if !asherah.GetSetupStatus() {
        t.Fatalf("expected setup status to be true")
    }

    plaintext := "hello from go"
    ciphertext, err := asherah.EncryptString("partition", plaintext)
    if err != nil {
        t.Fatalf("EncryptString failed: %v", err)
    }
    if ciphertext == "" {
        t.Fatalf("ciphertext was empty")
    }

    recovered, err := asherah.DecryptString("partition", ciphertext)
    if err != nil {
        t.Fatalf("DecryptString failed: %v", err)
    }
    if recovered != plaintext {
        t.Fatalf("expected %q, got %q", plaintext, recovered)
    }
}

// --- FFI Boundary Tests ---

func setupForBoundary(t *testing.T) {
	t.Helper()
	ensureNativeLibrary(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))
	cfg := asherah.Config{
		ServiceName: "ffi-test",
		ProductID:   "prod",
		Metastore:   "memory",
		KMS:         "static",
	}
	if err := asherah.Setup(cfg); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
}

func TestUnicodeCJK(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	text := "你好世界こんにちは세계"
	ct, err := asherah.EncryptString("go-unicode", text)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	recovered, err := asherah.DecryptString("go-unicode", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != text {
		t.Fatalf("CJK mismatch: expected %q, got %q", text, recovered)
	}
}

func TestUnicodeEmoji(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	text := "🦀🔐🎉💾🌍"
	ct, err := asherah.EncryptString("go-unicode", text)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	recovered, err := asherah.DecryptString("go-unicode", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != text {
		t.Fatalf("emoji mismatch: expected %q, got %q", text, recovered)
	}
}

func TestUnicodeMixedScripts(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	text := "Hello 世界 مرحبا Привет 🌍"
	ct, err := asherah.EncryptString("go-unicode", text)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	recovered, err := asherah.DecryptString("go-unicode", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != text {
		t.Fatalf("mixed scripts mismatch: expected %q, got %q", text, recovered)
	}
}

func TestUnicodeCombiningCharacters(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	text := "e\u0301 n\u0303 a\u0308"
	ct, err := asherah.EncryptString("go-unicode", text)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	recovered, err := asherah.DecryptString("go-unicode", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != text {
		t.Fatalf("combining chars mismatch: expected %q, got %q", text, recovered)
	}
}

func TestUnicodeZWJSequence(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	text := "👨\u200D👩\u200D👧\u200D👦"
	ct, err := asherah.EncryptString("go-unicode", text)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	recovered, err := asherah.DecryptString("go-unicode", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != text {
		t.Fatalf("ZWJ mismatch: expected %q, got %q", text, recovered)
	}
}

func TestBinaryAllByteValues(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	payload := make([]byte, 256)
	for i := 0; i < 256; i++ {
		payload[i] = byte(i)
	}
	ct, err := asherah.Encrypt("go-binary", payload)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	recovered, err := asherah.Decrypt("go-binary", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(recovered) != len(payload) {
		t.Fatalf("length mismatch: expected %d, got %d", len(payload), len(recovered))
	}
	for i := range payload {
		if recovered[i] != payload[i] {
			t.Fatalf("byte %d mismatch: expected %d, got %d", i, payload[i], recovered[i])
		}
	}
}

func TestEmptyPayload(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	ct, err := asherah.Encrypt("go-empty", []byte{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	recovered, err := asherah.Decrypt("go-empty", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(recovered))
	}
}

func TestLargePayload1MB(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	size := 1024 * 1024
	payload := make([]byte, size)
	for i := 0; i < size; i++ {
		payload[i] = byte(i % 256)
	}
	ct, err := asherah.Encrypt("go-large", payload)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	recovered, err := asherah.Decrypt("go-large", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(recovered) != size {
		t.Fatalf("length mismatch: expected %d, got %d", size, len(recovered))
	}
	for i := range payload {
		if recovered[i] != payload[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestDecryptInvalidJSON(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	_, err := asherah.DecryptString("go-error", "not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDecryptWrongPartition(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	ct, err := asherah.EncryptString("partition-a", "secret")
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	_, err = asherah.DecryptString("partition-b", ct)
	if err == nil {
		t.Fatal("expected error for wrong partition")
	}
}

func TestSetupShutdownRepeatable(t *testing.T) {
    ensureNativeLibrary(t)

    os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

    cfg := asherah.Config{
        ServiceName: "svc",
        ProductID:   "prod",
        Metastore:   "memory",
        KMS:         "static",
    }

    if err := asherah.Setup(cfg); err != nil {
        t.Fatalf("initial Setup failed: %v", err)
    }
    asherah.Shutdown()

    if err := asherah.Setup(cfg); err != nil {
        t.Fatalf("second Setup failed: %v", err)
    }
    if !asherah.GetSetupStatus() {
        t.Fatalf("expected setup status to be true after second setup")
    }
    asherah.Shutdown()

    if asherah.GetSetupStatus() {
        t.Fatalf("expected setup status to be false after shutdown")
    }
}

func ensureNativeLibrary(t *testing.T) {
    t.Helper()
    _, file, _, ok := runtime.Caller(0)
    if !ok {
        t.Fatalf("unable to determine caller path")
    }
    moduleDir := filepath.Dir(file)
    repoRoot := filepath.Dir(moduleDir)
    targetDir := filepath.Join(repoRoot, "target", "debug")
    if _, err := os.Stat(targetDir); err == nil {
        os.Setenv("ASHERAH_GO_NATIVE", targetDir)
        return
    }
    // fallback to release directory
    releaseDir := filepath.Join(repoRoot, "target", "release")
    if _, err := os.Stat(releaseDir); err == nil {
        os.Setenv("ASHERAH_GO_NATIVE", releaseDir)
        return
    }
    // leave environment unchanged; loader will fall back to system paths.
}
