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
