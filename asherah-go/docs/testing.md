# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode.

## In-memory + static-KMS test fixture

```go
package mypkg_test

import (
    "os"
    "strings"
    "testing"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

func newTestFactory(t *testing.T) *asherah.Factory {
    t.Helper()
    os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))
    factory, err := asherah.NewFactory(asherah.Config{
        ServiceName: "test-svc",
        ProductID:   "test-prod",
        Metastore:   "memory",
        KMS:         "static",
    })
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { factory.Close() })
    return factory
}

func TestRoundTrip(t *testing.T) {
    factory := newTestFactory(t)

    session, err := factory.GetSession("tenant-A")
    if err != nil { t.Fatal(err) }
    defer session.Close()

    ct, err := session.EncryptString("4242 4242 4242 4242")
    if err != nil { t.Fatal(err) }

    pt, err := session.DecryptString(ct)
    if err != nil { t.Fatal(err) }
    if pt != "4242 4242 4242 4242" {
        t.Errorf("got %q, want %q", pt, "4242 4242 4242 4242")
    }
}
```

`t.Cleanup` ensures the factory closes on test exit (success or
failure). Use `t.Helper()` so test failures point at the caller.

## Subtests for partition isolation

```go
func TestPartitionIsolation(t *testing.T) {
    factory := newTestFactory(t)

    for _, tenantID := range []string{"tenant-a", "tenant-b", "tenant-c"} {
        t.Run(tenantID, func(t *testing.T) {
            session, err := factory.GetSession(tenantID)
            if err != nil { t.Fatal(err) }
            defer session.Close()

            ct, _ := session.EncryptString("payload")
            pt, _ := session.DecryptString(ct)
            if pt != "payload" {
                t.Errorf("got %q, want %q", pt, "payload")
            }
        })
    }
}
```

## Concurrent test patterns

The factory and its sessions are goroutine-safe. Test concurrency
explicitly:

```go
func TestConcurrentAccess(t *testing.T) {
    factory := newTestFactory(t)

    var wg sync.WaitGroup
    errs := make(chan error, 100)

    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            session, err := factory.GetSession(fmt.Sprintf("tenant-%d", i%10))
            if err != nil { errs <- err; return }
            defer session.Close()
            ct, err := session.EncryptString("payload")
            if err != nil { errs <- err; return }
            if _, err := session.DecryptString(ct); err != nil {
                errs <- err
            }
        }(i)
    }
    wg.Wait()
    close(errs)
    for err := range errs {
        t.Error(err)
    }
}
```

## Mocking via interfaces

Go's testing pattern: define an interface in the package that uses
Asherah, accept it as a dependency, mock in tests. Don't try to mock
`*asherah.Factory` directly — it's a concrete struct with native
state.

```go
// protector.go
package protector

type Encryptor interface {
    Encrypt(partitionID, plaintext string) (string, error)
    Decrypt(partitionID, ciphertext string) (string, error)
}

type AsherahEncryptor struct {
    factory *asherah.Factory
}

func New(factory *asherah.Factory) *AsherahEncryptor {
    return &AsherahEncryptor{factory: factory}
}

func (a *AsherahEncryptor) Encrypt(partitionID, plaintext string) (string, error) {
    session, err := a.factory.GetSession(partitionID)
    if err != nil { return "", err }
    defer session.Close()
    return session.EncryptString(plaintext)
}

func (a *AsherahEncryptor) Decrypt(partitionID, ciphertext string) (string, error) {
    session, err := a.factory.GetSession(partitionID)
    if err != nil { return "", err }
    defer session.Close()
    return session.DecryptString(ciphertext)
}
```

```go
// orderservice_test.go
type fakeEncryptor struct {
    encrypted map[string]string
}

func (f *fakeEncryptor) Encrypt(_, plaintext string) (string, error) {
    return "ct-" + plaintext, nil
}
func (f *fakeEncryptor) Decrypt(_, ciphertext string) (string, error) {
    return strings.TrimPrefix(ciphertext, "ct-"), nil
}

func TestOrderServiceCallsEncrypt(t *testing.T) {
    enc := &fakeEncryptor{}
    svc := NewOrderService(enc)

    out, err := svc.Create("merchant-7", "card data")
    if err != nil { t.Fatal(err) }
    if out != "ct-card data" {
        t.Errorf("got %q, want %q", out, "ct-card data")
    }
}
```

The integration test of `AsherahEncryptor` itself uses the real
`newTestFactory`; unit tests of consumers mock the `Encryptor`
interface.

## httptest with Asherah

```go
func TestProtectHandler(t *testing.T) {
    factory := newTestFactory(t)
    srv := httptest.NewServer(NewServer(factory))
    defer srv.Close()

    body := strings.NewReader(`{"tenant_id":"t1","plaintext":"hello"}`)
    resp, err := http.Post(srv.URL+"/protect", "application/json", body)
    if err != nil { t.Fatal(err) }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Fatalf("status %d", resp.StatusCode)
    }
    var got struct{ Token string }
    json.NewDecoder(resp.Body).Decode(&got)
    if got.Token == "" { t.Fatal("empty token") }
}
```

## Asserting envelope shape

```go
import "encoding/json"

func TestEnvelopeShape(t *testing.T) {
    factory := newTestFactory(t)
    session, _ := factory.GetSession("partition-1")
    defer session.Close()

    raw, _ := session.EncryptString("hello")

    var env struct {
        Key  map[string]any `json:"Key"`
        Data string         `json:"Data"`
    }
    if err := json.Unmarshal([]byte(raw), &env); err != nil {
        t.Fatal(err)
    }
    if env.Key["ParentKeyMeta"] == nil { t.Error("missing ParentKeyMeta") }
    if env.Data == "" { t.Error("empty Data") }
}
```

## Hook tests run serially

Hooks are process-global. If your test suite uses `t.Parallel()`,
exclude hook tests from parallelization:

```go
func TestLogHookFires(t *testing.T) {
    // Don't call t.Parallel() — hook is process-global.
    var events []asherah.LogEvent
    var mu sync.Mutex
    _ = asherah.SetLogHook(func(e asherah.LogEvent) {
        mu.Lock()
        defer mu.Unlock()
        events = append(events, e)
    })
    defer asherah.ClearLogHook()

    factory := newTestFactory(t)
    session, _ := factory.GetSession("p")
    defer session.Close()
    _, _ = session.EncryptString("hello")

    // Allow async hook delivery to drain.
    time.Sleep(50 * time.Millisecond)

    mu.Lock()
    defer mu.Unlock()
    if len(events) == 0 { t.Error("no log events") }
}
```

For verbose tests, prefer `SetLogHookSync` so events are delivered
synchronously and the test doesn't need to sleep for delivery:

```go
_ = asherah.SetLogHookSync(func(e asherah.LogEvent) { /* ... */ }, slog.LevelDebug)
```

## Testing with the SQL metastore (Testcontainers)

Use the `testcontainers-go` package:

```go
import "github.com/testcontainers/testcontainers-go/modules/mysql"

func TestRoundTripAgainstMySQL(t *testing.T) {
    ctx := context.Background()
    container, err := mysql.Run(ctx, "mysql:8.0",
        mysql.WithDatabase("asherah"),
        mysql.WithUsername("root"),
        mysql.WithPassword("test"),
    )
    if err != nil { t.Fatal(err) }
    defer container.Terminate(ctx)

    dsn, _ := container.ConnectionString(ctx)
    os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))
    factory, err := asherah.NewFactory(asherah.Config{
        ServiceName:        "test-svc",
        ProductID:          "test-prod",
        Metastore:          "rdbms",
        ConnectionString:   dsn,
        SQLMetastoreDBType: "mysql",
        KMS:                "static",
    })
    if err != nil { t.Fatal(err) }
    defer factory.Close()

    session, _ := factory.GetSession("p")
    defer session.Close()
    ct, _ := session.EncryptString("hello")
    pt, _ := session.DecryptString(ct)
    if pt != "hello" { t.Errorf("got %q", pt) }
}
```

Asherah's RDBMS metastore creates the schema on first use; no
migration step required.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** Ciphertext is
  non-deterministic — `EncryptString("x")` produces a different
  envelope on every call. Don't compare ciphertext bytes; round-trip
  through `DecryptString` and compare plaintexts.
- **Session caching.** `factory.GetSession("p")` returns a cached
  session by default. Tests asserting per-call behaviour should set
  `EnableSessionCaching: ptr(false)`.
- **Hooks are process-global.** Don't `t.Parallel()` hook tests.
- **Static-master-key sharing.** All tests in one process use the
  same `STATIC_MASTER_KEY_HEX` — envelopes encrypted in one test
  can be decrypted by another. If a test depends on isolation, set
  a different key AND call `asherah.Shutdown()` between tests.

## Native library resolution in tests

The native library is downloaded by `install-native` to the working
directory. For tests:

- Run `go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest`
  in your repo before `go test`.
- For repo development against `cargo build`, set
  `ASHERAH_GO_NATIVE=$(pwd)/target/debug` before `go test`.
- CI: cache the native binary or download it as part of test setup;
  it's small (~20MB) and the SHA256 verification is fast.
