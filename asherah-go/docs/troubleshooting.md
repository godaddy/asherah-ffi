# Troubleshooting

Common errors when integrating the Go binding, what they mean, and
what to check first.

## Decrypt errors

### `decrypt_from_json: expected value at line 1 column 1`

You called `DecryptString("")`, `Decrypt(nil)`, or `Decrypt([]byte{})`
with empty input. Empty bytes can't be a valid DataRowRecord envelope
(smallest legitimate envelope is ~241 bytes).

> Note: Go's `[]byte` doesn't distinguish nil from empty. Asherah
> treats both as "valid empty plaintext" on the encrypt side
> (round-trips back to empty), but rejects empty on the decrypt side.

**Likely cause:** caller code is short-circuiting empty values:

```go
// Bug — encrypt produced an envelope, but storage layer dropped it.
if len(envelope) == 0 { return "", nil }
return session.DecryptString(string(envelope))
```

**Fix:** check for the empty case *before* decrypt, not by passing
empty input to it:

```go
envelope := repo.LoadEnvelope(id)
if envelope == "" { return "", nil }
return session.DecryptString(envelope)
```

### `decrypt_from_json: tag mismatch` / `authentication failed`

Envelope JSON parses but AES-GCM auth tag doesn't verify. Causes:
- Tampered envelope (security incident if unexpected).
- Decrypting under different `ServiceName`/`ProductID` than encrypted.
- Metastore wiped/rotated between encrypt and decrypt.

**Fix:** check `ServiceName`/`ProductID` parity. Inspect
`json.Unmarshal(envelope).Key.ParentKeyMeta.KeyId` and verify a row
with that ID exists in your metastore.

### `decrypt_from_json: ...` (other JSON errors)

Input is non-empty but not valid Asherah JSON. Likely:
- Storage layer applied additional encoding (base64, gzip) on write.
- Envelope was truncated.

## Configuration errors

### `factory_from_config: Unknown metastore kind 'X'`

`Config.Metastore` got a value that isn't `"memory"`, `"rdbms"`,
`"dynamodb"`, or `"sqlite"`.

### `factory_from_config: Unknown KMS type 'X'`

Same shape for `Config.KMS`. Accepted: `"static"`, `"aws"`,
`"secrets-manager"`, `"vault"`.

### `factory_from_config: connection string required`

`Config.Metastore: "rdbms"` without `Config.ConnectionString`.

### `factory_from_config: KmsKeyId or RegionMap required`

`Config.KMS: "aws"` without either `Config.KmsKeyId` or
`Config.RegionMap`.

## Lifecycle / programming errors

### `asherah-go: Setup called while already configured`

`asherah.Setup(config)` called twice. Package-level API has one
process-global instance.

**Fix:** call `asherah.Shutdown()` first. In production, look for
duplicate setup calls — e.g. multiple `init()` paths in different
packages, or a `main` that re-invokes setup on hot reload.

### `asherah-go: not configured; call Setup first`

Package-level API used before `Setup`. Check that `Setup` ran and
returned nil. The error wraps the underlying cause if `Setup` failed.

### `asherah-go: partition ID cannot be empty`

Empty string passed as partition ID. Asherah is stricter than the
canonical `godaddy/asherah-go` v0.x package (which silently accepts
empty IDs and writes degenerate `_IK__service_product` rows).

**Fix:** ensure the partition ID is non-empty before calling Asherah.

## Native library errors

### `failed to load native library asherah_ffi`

The native `.so` / `.dylib` / `.dll` wasn't found. The loader
searches:

1. `ASHERAH_GO_NATIVE` directory (if set).
2. The current working directory.
3. The directory of the running executable.
4. System library paths (`/usr/local/lib`, `/usr/lib`, `LD_LIBRARY_PATH`).

**Fix:** run
`go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest`
to download the binary into your working directory, OR set
`ASHERAH_GO_NATIVE=/path/to/dir` to a directory containing it.

### Wrong architecture loaded

Apple Silicon running Go x86_64 under Rosetta or vice versa:

```bash
file $(go env GOROOT)/bin/go     # check Go's actual arch
go env GOOS GOARCH               # what Go thinks
arch                             # shell arch
```

Reinstall Go for the matching architecture. The `install-native` tool
selects the binary by `runtime.GOOS`/`runtime.GOARCH` of the program
that runs it — make sure it's the same Go binary you'll deploy with.

### Alpine/musl LoadError

`install-native` selects `linux-musl-x64` / `linux-musl-arm64`
automatically based on `runtime.GOOS` — but that detection assumes
your test/build container matches your production target.

If you build on glibc and deploy to Alpine, run `install-native` from
inside an Alpine container so the right binary is shipped:

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go run github.com/godaddy/asherah-ffi/asherah-go/cmd/install-native@latest
RUN go build -o app .

FROM alpine:3.19
RUN apk add libgcc libstdc++
COPY --from=builder /app/app /app/libasherah_ffi.so /
ENTRYPOINT ["/app"]
```

### `cannot find -lasherah_ffi` at link time

You shouldn't see this — `purego` doesn't link against the library at
build time, it loads dynamically at runtime. If you do, you've
introduced a CGO import path; check your imports for `// #cgo` lines.

## AWS-specific errors

DynamoDB metastore errors (`Metastore: "dynamodb"`) carry the AWS
SDK's error chain, including the AWS message. Exceptions that
aws-sdk-dynamodb does not model, `AccessDeniedException` and
`ValidationException` among them, print as `service error: unhandled
error (<Code>)` followed by the AWS message:

- `service error: unhandled error (AccessDeniedException)` — IAM. The
  AWS message that follows usually names the missing `dynamodb:`
  action.
- `service error: unhandled error (ValidationException)` — for example
  a table schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number).
- A DNS failure may read `dispatch failure: io error: client error
  (Connect): dns error: …` (not reproduced in testing).

KMS errors (`KMS: "aws"`) never include the AWS message, which embeds
account ids and ARNs. They name the region, the step that failed and a
fixed label for the cause, plus the AWS request id when AWS answered
(look it up in CloudTrail):

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
KMS GenerateDataKey failed in region us-west-2: dispatch failure (other: no credentials available)
```

The returned error carries only the outermost context (`<op>
failed: …`). The full chain, with the KMS detail, is in the native
layer's warn-level `<op> failed: …` log event; a failed KMS decrypt also produces an error-level
`asherah::kms_aws_envelope` event and a failed KMS encrypt an
error-level `asherah::session` event.
The log hook receives all of these at its default level (warn).

- `service error <code>` — KMS answered. `AccessDeniedException`: the
  IAM or key policy does not allow the call. `DisabledException` /
  `KMSInvalidStateException` / `NotFoundException`: the key is
  disabled, pending deletion, or missing in that region.
  `ThrottlingException`: request rate; retry.
- `dispatch failure (other: <credentials label>)` — no usable AWS
  credentials, so the request never reached KMS:
  - `no credentials available` — no credentials source was found
    (environment, shared files, web identity, container, instance
    metadata). On EC2 it may also mean the instance metadata service
    could not be reached (aws-config reports that case the same way),
    where retrying can help.
  - `credentials provider error` — a configured source failed, for
    example a `credential_process` command that fails or a container
    credentials endpoint that answers HTTP 500.
  - `unexpected credentials provider failure` — for example a
    container credentials endpoint that refuses the connection or
    answers with a body that is not JSON.
  - `invalid credentials configuration` — for example an
    `AWS_CONTAINER_AUTHORIZATION_TOKEN` that is not a valid HTTP header
    value (one containing a newline).
  - A credentials source that never answers — for example a container
    credentials endpoint that accepts the connection and does not
    reply — shows as a bare `dispatch failure (other)`, with no
    credentials label, after a delay (about 6 s per call in testing).
- `not sent: no region configured`, `request construction failure
  (invalid endpoint parameters)` — no region is configured, or the
  configured region is not a region name (for example a key ARN where
  `RegionMap` expects a region). Retrying does not help.
- `dispatch failure (io: connection refused)` and other connection-level
  kinds — the KMS endpoint (or VPC endpoint / proxy) could not be
  reached. A DNS failure may also appear as `dispatch failure (io: …)`;
  which kind it names is not fixed.
- `dispatch failure (io: other error)` — commonly a TLS failure: a
  TLS-inspecting proxy, a VPC endpoint whose certificate comes from a
  private CA the client does not trust, or an endpoint that does not
  speak TLS. Retrying does not fix it.
- `dispatch failure (timeout)`, `dispatch failure (other: transient
  error)` — the connection attempt timed out, or the connection closed
  before a response arrived.

The `aws-sdk-go-v2` package's credential cache is **not** consulted
— Asherah uses the AWS SDK for Rust's chain.

## purego-specific quirks

### `runtime: split stack overflow` or stack-related crashes

Calling FFI through purego unwinds Go's stack into native code. The
binding allocates large stack temporaries appropriately, but if you
see stack overflow errors, file a repository issue with the GOOS,
GOARCH, and reproduction.

### `signal: SIGSEGV: segmentation violation` after long runs

Could be a use-after-close — calling methods on a closed
`*Session` or `*Factory`. The Close methods don't currently mark
the value as closed, so subsequent calls dereference freed memory.
Always `defer session.Close()` immediately after acquisition; don't
share session handles across goroutines without ensuring no one is
using them when Close runs.

## Lambda-specific

### Cold start downloads native binary

If your Lambda deployment package doesn't include `libasherah_ffi.so`,
the first cold start tries to fetch it via `install-native` which
fails (no internet from Lambda by default).

**Fix:** include the native library in your deployment package:
```
your-deployment.zip
├── bootstrap
└── libasherah_ffi.so
```

Or set `ASHERAH_GO_NATIVE=/var/task` to point at the Lambda runtime
root where your zip extracts.

## Diagnostic recipe

When a problem isn't covered above:

1. **Set verbose logging:**
   ```go
   handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
   _ = asherah.SetSlogLogger(slog.New(handler))
   config.Verbose = ptr(true)
   ```
   Trace records cover every metastore call, KMS call, and
   key-cache decision.

2. **Inspect the metastore directly.** RDBMS: query
   `encryption_key`. DynamoDB: scan `AsherahKeys`.

3. **Repro with `Metastore: "memory"` + `KMS: "static"`** to
   eliminate AWS as a variable.

4. **Static-master-key rotation** fails decrypt with a tag mismatch —
   by design.
