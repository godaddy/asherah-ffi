package asherah_test

import (
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "testing"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
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
	for i := range 256 {
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
	for i := range size {
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

func boolPtr(b bool) *bool { return &b }

// newTestFactory creates a Factory with static/memory config for tests.
func newTestFactory(t *testing.T) *asherah.Factory {
	t.Helper()
	ensureNativeLibrary(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))
	cfg := asherah.Config{
		ServiceName:          "factory-test",
		ProductID:            "prod",
		Metastore:            "memory",
		KMS:                  "static",
		EnableSessionCaching: boolPtr(false),
	}
	factory, err := asherah.NewFactory(cfg)
	if err != nil {
		t.Fatalf("NewFactory failed: %v", err)
	}
	return factory
}

// --- Factory / Session API Tests ---

func TestFactorySessionRoundTrip(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	session, err := factory.GetSession("round-trip")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	defer session.Close()

	plaintext := []byte("hello from factory/session")
	ct, err := session.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext was empty")
	}

	recovered, err := session.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, recovered)
	}
}

func TestFactoryMultipleSessions(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	sessA, err := factory.GetSession("partition-a")
	if err != nil {
		t.Fatalf("GetSession(partition-a) failed: %v", err)
	}
	defer sessA.Close()

	sessB, err := factory.GetSession("partition-b")
	if err != nil {
		t.Fatalf("GetSession(partition-b) failed: %v", err)
	}
	defer sessB.Close()

	// Encrypt with partition-a
	ctA, err := sessA.Encrypt([]byte("secret-a"))
	if err != nil {
		t.Fatalf("sessA.Encrypt failed: %v", err)
	}

	// Encrypt with partition-b
	ctB, err := sessB.Encrypt([]byte("secret-b"))
	if err != nil {
		t.Fatalf("sessB.Encrypt failed: %v", err)
	}

	// Each session decrypts its own data
	recoveredA, err := sessA.Decrypt(ctA)
	if err != nil {
		t.Fatalf("sessA.Decrypt failed: %v", err)
	}
	if string(recoveredA) != "secret-a" {
		t.Fatalf("partition-a: expected %q, got %q", "secret-a", recoveredA)
	}

	recoveredB, err := sessB.Decrypt(ctB)
	if err != nil {
		t.Fatalf("sessB.Decrypt failed: %v", err)
	}
	if string(recoveredB) != "secret-b" {
		t.Fatalf("partition-b: expected %q, got %q", "secret-b", recoveredB)
	}

	// Cross-partition decrypt should fail
	_, err = sessB.Decrypt(ctA)
	if err == nil {
		t.Fatal("expected error decrypting partition-a ciphertext with partition-b session")
	}
}

func TestSessionEncryptString(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	session, err := factory.GetSession("string-test")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	defer session.Close()

	plaintext := "hello string variant"
	ct, err := session.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}
	if ct == "" {
		t.Fatal("ciphertext string was empty")
	}

	recovered, err := session.DecryptString(ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, recovered)
	}
}

func TestSessionClosePreventsFurtherUse(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	session, err := factory.GetSession("close-test")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	session.Close()

	_, err = session.Encrypt([]byte("should fail"))
	if err == nil {
		t.Fatal("expected error encrypting on closed session")
	}

	_, err = session.Decrypt([]byte("should fail"))
	if err == nil {
		t.Fatal("expected error decrypting on closed session")
	}
}

func TestFactoryClosePreventsSessions(t *testing.T) {
	factory := newTestFactory(t)

	factory.Close()

	_, err := factory.GetSession("should-fail")
	if err == nil {
		t.Fatal("expected error getting session from closed factory")
	}
}

// --- Null and empty input handling ---
//
// Go's []byte has no real distinction between nil and []byte{} — most APIs
// treat them interchangeably. So the contract here is:
//   - empty partition string → error (programming error)
//   - nil or []byte{} plaintext → valid empty encrypt that round-trips
//   - empty string plaintext → valid empty encrypt that round-trips
//   - nil/empty/empty-string ciphertext → error (invalid DataRowRecord JSON)

func TestEncryptEmptyPartitionFails(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	if _, err := asherah.Encrypt("", []byte("x")); err == nil {
		t.Fatal("expected error for empty partition")
	}
	if _, err := asherah.EncryptString("", "x"); err == nil {
		t.Fatal("expected error for empty partition (EncryptString)")
	}
	if _, err := asherah.Decrypt("", []byte("{}")); err == nil {
		t.Fatal("expected error for empty partition (Decrypt)")
	}
	if _, err := asherah.DecryptString("", "{}"); err == nil {
		t.Fatal("expected error for empty partition (DecryptString)")
	}
}

func TestEncryptNilPlaintextRoundTrips(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	// In Go, nil []byte is conventionally equivalent to []byte{} — treat
	// it as a valid empty plaintext, not an error.
	ct, err := asherah.Encrypt("go-nil-pt", nil)
	if err != nil {
		t.Fatalf("Encrypt(nil) failed: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext was empty")
	}
	recovered, err := asherah.Decrypt("go-nil-pt", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("expected empty recovered, got %d bytes", len(recovered))
	}
}

func TestEmptyStringRoundTrip(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	ct, err := asherah.EncryptString("go-empty-str", "")
	if err != nil {
		t.Fatalf("EncryptString(\"\") failed: %v", err)
	}
	if ct == "" {
		t.Fatal("ciphertext was empty")
	}
	recovered, err := asherah.DecryptString("go-empty-str", ct)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if recovered != "" {
		t.Fatalf("expected empty string, got %q", recovered)
	}
}

func TestDecryptNilOrEmptyFails(t *testing.T) {
	setupForBoundary(t)
	defer asherah.Shutdown()

	// nil and zero-length byte slices must be rejected as invalid JSON,
	// not silently treated as empty plaintext.
	if _, err := asherah.Decrypt("go-empty-decrypt", nil); err == nil {
		t.Fatal("expected error for nil ciphertext")
	}
	if _, err := asherah.Decrypt("go-empty-decrypt", []byte{}); err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
	if _, err := asherah.DecryptString("go-empty-decrypt", ""); err == nil {
		t.Fatal("expected error for empty string ciphertext")
	}
}

func TestSessionNilAndEmptyInputs(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	// GetSession with empty partition must fail
	if _, err := factory.GetSession(""); err == nil {
		t.Fatal("expected error for GetSession(\"\")")
	}

	session, err := factory.GetSession("go-session-null-empty")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	defer session.Close()

	// nil plaintext is a valid empty encrypt
	ct, err := session.Encrypt(nil)
	if err != nil {
		t.Fatalf("session.Encrypt(nil) failed: %v", err)
	}
	recovered, err := session.Decrypt(ct)
	if err != nil {
		t.Fatalf("session.Decrypt failed: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(recovered))
	}

	// empty string round-trip
	ctStr, err := session.EncryptString("")
	if err != nil {
		t.Fatalf("session.EncryptString(\"\") failed: %v", err)
	}
	recoveredStr, err := session.DecryptString(ctStr)
	if err != nil {
		t.Fatalf("session.DecryptString failed: %v", err)
	}
	if recoveredStr != "" {
		t.Fatalf("expected empty string, got %q", recoveredStr)
	}

	// nil/empty ciphertext on decrypt must error
	if _, err := session.Decrypt(nil); err == nil {
		t.Fatal("expected error for session.Decrypt(nil)")
	}
	if _, err := session.Decrypt([]byte{}); err == nil {
		t.Fatal("expected error for session.Decrypt([]byte{})")
	}
	if _, err := session.DecryptString(""); err == nil {
		t.Fatal("expected error for session.DecryptString(\"\")")
	}
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	factory := newTestFactory(t)
	defer factory.Close()

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			session, sessErr := factory.GetSession(fmt.Sprintf("concurrent-%d", id))
			if sessErr != nil {
				errs <- fmt.Errorf("goroutine %d: GetSession failed: %w", id, sessErr)
				return
			}
			defer session.Close()

			plaintext := fmt.Sprintf("goroutine-%d-payload", id)
			ct, encErr := session.EncryptString(plaintext)
			if encErr != nil {
				errs <- fmt.Errorf("goroutine %d: EncryptString failed: %w", id, encErr)
				return
			}
			recovered, decErr := session.DecryptString(ct)
			if decErr != nil {
				errs <- fmt.Errorf("goroutine %d: DecryptString failed: %w", id, decErr)
				return
			}
			if recovered != plaintext {
				errs <- fmt.Errorf("goroutine %d: expected %q, got %q", id, plaintext, recovered)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
