package asherah

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func compatEnsureLib(t *testing.T) {
	t.Helper()
	// Find native library relative to this file
	_, f, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(f), "..")
	for _, sub := range []string{"target/debug", "target/release"} {
		p := filepath.Join(root, sub)
		os.Setenv("ASHERAH_GO_NATIVE", p)
		break
	}
}

func TestCanonicalSessionFactoryRoundTrip(t *testing.T) {
	compatEnsureLib(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", "2222222222222222222222222222222222222222222222222222222222222222")

	config := &CanonicalConfig{
		Service: "compat-svc",
		Product: "compat-prod",
		Policy:  NewCryptoPolicy(),
	}

	factory := NewSessionFactory(config, &InMemoryMetastore{}, NewStaticKMS("thisIsAStaticMasterKeyForTesting"), nil)
	defer factory.Close()

	session, err := factory.GetSession("test-partition")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	defer session.Close()

	ctx := context.Background()
	plaintext := []byte("hello from canonical Go API")

	drr, err := session.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if drr == nil || drr.Key == nil {
		t.Fatal("DataRowRecord or Key is nil")
	}

	decrypted, err := session.Decrypt(ctx, *drr)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestCanonicalMultipleSessions(t *testing.T) {
	compatEnsureLib(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", "2222222222222222222222222222222222222222222222222222222222222222")

	config := &CanonicalConfig{
		Service: "compat-svc",
		Product: "compat-prod",
	}

	factory := NewSessionFactory(config, &InMemoryMetastore{}, NewStaticKMS("thisIsAStaticMasterKeyForTesting"), nil)
	defer factory.Close()

	ctx := context.Background()

	s1, _ := factory.GetSession("partition-1")
	defer s1.Close()
	s2, _ := factory.GetSession("partition-2")
	defer s2.Close()

	drr1, _ := s1.Encrypt(ctx, []byte("data1"))
	drr2, _ := s2.Encrypt(ctx, []byte("data2"))

	pt1, _ := s1.Decrypt(ctx, *drr1)
	pt2, _ := s2.Decrypt(ctx, *drr2)

	if string(pt1) != "data1" {
		t.Fatalf("expected data1, got %s", pt1)
	}
	if string(pt2) != "data2" {
		t.Fatalf("expected data2, got %s", pt2)
	}
}

func TestDataRowRecordStructure(t *testing.T) {
	compatEnsureLib(t)
	os.Setenv("STATIC_MASTER_KEY_HEX", "2222222222222222222222222222222222222222222222222222222222222222")

	config := &CanonicalConfig{
		Service: "compat-svc",
		Product: "compat-prod",
	}

	factory := NewSessionFactory(config, &InMemoryMetastore{}, NewStaticKMS("thisIsAStaticMasterKeyForTesting"), nil)
	defer factory.Close()

	session, _ := factory.GetSession("struct-test")
	defer session.Close()

	drr, err := session.Encrypt(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify the DataRowRecord has the expected structure
	if drr.Key == nil {
		t.Fatal("Key is nil")
	}
	if drr.Key.Created == 0 {
		t.Fatal("Key.Created should not be zero")
	}
	if len(drr.Key.EncryptedKey) == 0 {
		t.Fatal("Key.EncryptedKey is empty")
	}
	if len(drr.Data) == 0 {
		t.Fatal("Data is empty")
	}
	if drr.Key.ParentKeyMeta == nil {
		t.Fatal("ParentKeyMeta is nil")
	}
	if drr.Key.ParentKeyMeta.ID == "" {
		t.Fatal("ParentKeyMeta.ID is empty")
	}
}
