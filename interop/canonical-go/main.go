// Probe the canonical github.com/godaddy/asherah Go API to discover its actual
// behavior on null/empty inputs. Prints one line per case: PASS or the actual
// error returned. Used by the interop test runner — output is parsed
// line-by-line so it must remain stable.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	crypto := aead.NewAES256GCM()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x22
	}

	staticKMS, err := kms.NewStatic(string(masterKey), crypto)
	if err != nil {
		return fmt.Errorf("kms.NewStatic: %w", err)
	}

	metastore := persistence.NewMemoryMetastore()

	policy := appencryption.NewCryptoPolicy()

	factory := appencryption.NewSessionFactory(
		&appencryption.Config{
			Service: "service",
			Product: "product",
			Policy:  policy,
		},
		metastore,
		staticKMS,
		crypto,
	)
	defer factory.Close()

	// 1) GetSession with empty string — does canonical reject it?
	probe("GetSession_empty_partition", func() (string, error) {
		s, err := factory.GetSession("")
		if err != nil {
			return "", err
		}
		s.Close()
		return "accepted", nil
	})

	// 2) Encrypt with nil []byte
	probe("Encrypt_nil_data", func() (string, error) {
		s, err := factory.GetSession("p1")
		if err != nil {
			return "", err
		}
		defer s.Close()
		drr, err := s.Encrypt(ctx, nil)
		if err != nil {
			return "", err
		}
		dataLen := 0
		if drr.Data != nil {
			dataLen = len(drr.Data)
		}
		return fmt.Sprintf("accepted: ciphertext_data_len=%d", dataLen), nil
	})

	// 3) Encrypt with empty []byte
	probe("Encrypt_empty_data", func() (string, error) {
		s, err := factory.GetSession("p1")
		if err != nil {
			return "", err
		}
		defer s.Close()
		drr, err := s.Encrypt(ctx, []byte{})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("accepted: ciphertext_data_len=%d", len(drr.Data)), nil
	})

	// 4) Encrypt empty then Decrypt — round-trip
	probe("Roundtrip_empty", func() (string, error) {
		s, err := factory.GetSession("p1")
		if err != nil {
			return "", err
		}
		defer s.Close()
		drr, err := s.Encrypt(ctx, []byte{})
		if err != nil {
			return "", err
		}
		out, err := s.Decrypt(ctx, *drr)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("recovered_len=%d nil=%v", len(out), out == nil), nil
	})

	// 5) Decrypt with empty DataRowRecord
	probe("Decrypt_empty_drr", func() (string, error) {
		s, err := factory.GetSession("p1")
		if err != nil {
			return "", err
		}
		defer s.Close()
		out, err := s.Decrypt(ctx, appencryption.DataRowRecord{})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("accepted: out_len=%d", len(out)), nil
	})

	// 6) Decrypt with DRR whose Data is nil
	probe("Decrypt_nil_data_in_drr", func() (string, error) {
		s, err := factory.GetSession("p1")
		if err != nil {
			return "", err
		}
		defer s.Close()
		out, err := s.Decrypt(ctx, appencryption.DataRowRecord{
			Data: nil,
			Key:  &appencryption.EnvelopeKeyRecord{},
		})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("accepted: out_len=%d", len(out)), nil
	})

	return nil
}

func probe(name string, fn func() (string, error)) {
	result, err := fn()
	if err != nil {
		fmt.Printf("%s: ERROR: %s\n", name, err.Error())
		return
	}
	fmt.Printf("%s: %s\n", name, result)
}
