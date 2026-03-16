package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	appencryption "github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
	"github.com/godaddy/asherah/go/securememory"
	"github.com/godaddy/asherah/go/securememory/memguard"
	"github.com/godaddy/asherah/go/securememory/protectedmemory"
)

const benchStaticKey = "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"

var (
	mgFactory  *appencryption.SessionFactory
	mgSession  *appencryption.Session
	pmFactory  *appencryption.SessionFactory
	pmSession  *appencryption.Session
	sizes      = []int{64, 1024, 8192}
)

func makeFactory(sf securememory.SecretFactory) (*appencryption.SessionFactory, *appencryption.Session) {
	crypto := aead.NewAES256GCM()
	metastore := persistence.NewMemoryMetastore()
	kmsService, err := kms.NewStatic(benchStaticKey, crypto)
	if err != nil {
		panic(err)
	}
	cfg := &appencryption.Config{
		Service: "bench-svc",
		Product: "bench-prod",
		Policy:  appencryption.NewCryptoPolicy(),
	}
	factory := appencryption.NewSessionFactory(cfg, metastore, kmsService, crypto,
		appencryption.WithMetrics(false),
		appencryption.WithSecretFactory(sf))
	session, err := factory.GetSession("bench-partition")
	if err != nil {
		panic(err)
	}
	return factory, session
}

func verify(session *appencryption.Session, label string) {
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		drr, err := session.Encrypt(ctx, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s encrypt failed for %dB: %v\n", label, size, err)
			os.Exit(1)
		}
		pt, err := session.Decrypt(ctx, *drr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s decrypt failed for %dB: %v\n", label, size, err)
			os.Exit(1)
		}
		if !bytes.Equal(payload, pt) {
			fmt.Fprintf(os.Stderr, "%s round-trip verification failed for %dB\n", label, size)
			os.Exit(1)
		}
	}
}

func TestMain(m *testing.M) {
	mgFactory, mgSession = makeFactory(new(memguard.SecretFactory))
	pmFactory, pmSession = makeFactory(new(protectedmemory.SecretFactory))
	verify(mgSession, "memguard")
	verify(pmSession, "protectedmemory")

	code := m.Run()
	mgSession.Close()
	mgFactory.Close()
	pmSession.Close()
	pmFactory.Close()
	os.Exit(code)
}

func benchEncrypt(b *testing.B, session *appencryption.Session) {
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				drr, err := session.Encrypt(ctx, payload)
				if err != nil {
					b.Fatal(err)
				}
				_ = drr
			}
		})
	}
}

func benchDecrypt(b *testing.B, session *appencryption.Session) {
	ctx := context.Background()
	for _, size := range sizes {
		payload := make([]byte, size)
		rand.Read(payload)
		drr, err := session.Encrypt(ctx, payload)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pt, err := session.Decrypt(ctx, *drr)
				if err != nil {
					b.Fatal(err)
				}
				_ = pt
			}
		})
	}
}

func BenchmarkMemguardEncrypt(b *testing.B)        { benchEncrypt(b, mgSession) }
func BenchmarkMemguardDecrypt(b *testing.B)        { benchDecrypt(b, mgSession) }
func BenchmarkProtectedmemEncrypt(b *testing.B)    { benchEncrypt(b, pmSession) }
func BenchmarkProtectedmemDecrypt(b *testing.B)    { benchDecrypt(b, pmSession) }
