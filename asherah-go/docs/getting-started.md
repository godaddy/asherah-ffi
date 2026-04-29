# Getting started

Step-by-step walkthrough from `go get` to a round-trip encrypt/decrypt.
After this guide, see:

- [`framework-integration.md`](./framework-integration.md) — `net/http`,
  Gin, Echo, chi, gRPC, AWS Lambda integration.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS KMS + DynamoDB.
- [`testing.md`](./testing.md) — `testing` package patterns, `httptest`,
  Testcontainers, mocking.
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Add the module

```bash
go get github.com/godaddy/asherah-ffi/asherah-go
```

Then install the native library (no CGO required — uses
[purego](https://github.com/ebitengine/purego)):

```bash
go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest
```

This downloads the prebuilt binary for your OS/architecture from
[GitHub Releases](https://github.com/godaddy/asherah-ffi/releases),
verifies the SHA256, and places it in the working directory. The
loader finds it automatically.

For repo development against `cargo build` output, set
`ASHERAH_GO_NATIVE` to a directory containing the library you built.

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Entry points | Use when |
|---|---|---|
| Package-level | `asherah.Setup(config)`, `asherah.EncryptString(...)`, … | Configure once, encrypt/decrypt with a partition id. Drop-in compatible with the canonical `godaddy/asherah-go` API. |
| Factory / Session | `asherah.NewFactory(config)`, `factory.GetSession(id)`, `session.Encrypt(...)` | Explicit lifecycle, multi-tenant isolation visible in code. Idiomatic Go: `defer factory.Close()`, `defer session.Close()`. |

The package-level API is a thin convenience wrapper over the
factory/session API.

## 3. Configure

Both styles take an `asherah.Config` struct:

```go
import (
    "os"
    "strings"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

// Testing-only static master key. Production must use AWS KMS;
// see aws-production-setup.md.
os.Setenv("STATIC_MASTER_KEY_HEX", strings.Repeat("22", 32))

config := asherah.Config{
    ServiceName: "my-service",
    ProductID:   "my-product",
    Metastore:   "memory",   // testing only — use "rdbms" or "dynamodb" in production
    KMS:         "static",   // testing only — use "aws" in production
}
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable values — changing them later
orphans existing envelope keys.

For the complete struct field list, see the **Configuration** section
of the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — package-level API

```go
if err := asherah.Setup(config); err != nil {
    log.Fatal(err)
}
defer asherah.Shutdown()

ciphertext, err := asherah.EncryptString("user-42", "secret")
if err != nil { return err }

// Persist `ciphertext` (a JSON string) to your storage.

// Later, after reading it back:
plaintext, err := asherah.DecryptString("user-42", ciphertext)
if err != nil { return err }
fmt.Println(plaintext)   // "secret"
```

For binary payloads use `asherah.Encrypt(partitionID, []byte)` /
`asherah.Decrypt(partitionID, []byte)`.

## 5. Encrypt and decrypt — factory / session API

```go
factory, err := asherah.NewFactory(config)
if err != nil { return err }
defer factory.Close()

session, err := factory.GetSession("user-42")
if err != nil { return err }
defer session.Close()

encrypted, err := session.Encrypt([]byte("secret"))
if err != nil { return err }

decrypted, err := session.Decrypt(encrypted)
if err != nil { return err }
```

Use `defer` for guaranteed cleanup. The factory's session cache means
`factory.GetSession("u")` returns a cached session for the same
partition until LRU-evicted.

`asherah.NewFactoryFromEnv()` is also available when configuration
comes exclusively from environment variables.

## 6. Concurrency

Go's idiomatic concurrency story replaces async/await — sessions are
goroutine-safe, and the factory's session cache handles concurrent
`GetSession` calls correctly:

```go
var wg sync.WaitGroup
for _, partition := range partitions {
    wg.Add(1)
    go func(p string) {
        defer wg.Done()
        ct, _ := asherah.EncryptString(p, "payload")
        _, _ = asherah.DecryptString(p, ct)
    }(partition)
}
wg.Wait()
```

The native operation is sub-microsecond — no special async API is
needed. For HTTP servers using goroutine-per-request (the standard
`net/http` pattern), each request handler can use Asherah directly.

## 7. Wire up observability

The simplest hook: hand Asherah a `*slog.Logger`. It dispatches via
the supplied handler, including filtering by `slog.Level`:

```go
import (
    "log/slog"
    "os"
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
})
_ = asherah.SetSlogLogger(slog.New(handler))
```

For full callback control:

```go
_ = asherah.SetLogHook(func(e asherah.LogEvent) {
    // e.Level is slog.Level (-4 trace ... 8 error)
    // e.Target is "asherah::session" etc
    // e.Message is the record text
    if e.Level >= slog.LevelWarn {
        slog.Warn(e.Message, "target", e.Target)
    }
})

_ = asherah.SetMetricsHook(func(e asherah.MetricsEvent) {
    // e.Type is "encrypt"/"decrypt"/"store"/"load"/"cache_hit"/...
    // e.DurationNs nonzero for timing events
    // e.Name nonempty for cache events
    switch e.Type {
    case "encrypt", "decrypt":
        myHistogram.Observe(e.Type, float64(e.DurationNs) / 1e6)
    case "cache_hit", "cache_miss", "cache_stale":
        myCounter.Inc(e.Type, e.Name)
    }
})
```

Hooks are process-global. `asherah.ClearLogHook()` /
`asherah.ClearMetricsHook()` deregister.

## 8. Move to production

The example uses `Metastore: "memory"` and `KMS: "static"` — both
**testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah returns errors via the standard Go `error` return value.
Specific shapes and what to check first are in
[`troubleshooting.md`](./troubleshooting.md).

Common shapes:
- `asherah-go: partition ID cannot be empty` — empty partition string.
- `decrypt_from_json: ...` — malformed envelope on decrypt.
- `factory_from_config: ...` — invalid config or KMS/metastore
  unreachable.

Wrap with `errors.Is` / `errors.As` patterns where appropriate, or
match on the error string for the simpler cases.

## What's next

- [`framework-integration.md`](./framework-integration.md) —
  `net/http`, Gin, Echo, chi, gRPC, AWS Lambda.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/go/main.go) exercises every
  API style + concurrency + log hook + metrics hook.
