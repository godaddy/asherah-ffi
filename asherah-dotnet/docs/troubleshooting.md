# Troubleshooting

Common errors when integrating the .NET binding, what they mean, and
what to check first. Errors are organized by the C# exception type and
the message text — search this page for the exact phrase you're seeing.

## `AsherahException`

Wraps errors from the native Rust core. The message text starts with
the FFI entry-point name (e.g. `decrypt_from_json: ...`) followed by
the underlying error.

### `decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)`

You called `DecryptBytes(byte[0])`, `DecryptString("")`, or the async
variants with an empty input. Empty bytes can never be a valid Asherah
envelope — the smallest legitimate envelope is ~241 bytes of JSON.

**Likely cause:** caller code is short-circuiting empty values before
the read path:

```csharp
// Bug — encrypt produced an envelope, but storage layer dropped it.
if (envelope.Length == 0)
    return string.Empty;
return session.DecryptString(envelope);
```

**Fix:** always pass the envelope through `Decrypt`. If your storage
layer can return empty for "no value", check that *before* you reach
the decrypt call, not by passing `""` to it:

```csharp
var envelope = repository.LoadEnvelope(id);
return envelope is null ? null : session.DecryptString(envelope);
```

See [`docs/input-contract.md`](../../docs/input-contract.md) for the
full rationale on why empty input isn't silently accepted.

### `decrypt_from_json: expected value at line 1 column 1`

The C# layer's empty-input guard catches the most common form of this
error before it crosses the FFI boundary, so seeing this message means
the input is **not** empty but is also **not** valid JSON. Likely
causes:

- Your storage layer applied additional encoding (base64, gzip, …) on
  write that wasn't reversed on read.
- The envelope was truncated (column-length limit, transport mangling).
- You're decrypting raw bytes that were never produced by Asherah at
  all.

**Fix:** dump the failing input to logs and inspect it. Valid Asherah
envelopes start with `{"Key":{` and contain the four fields `Key`,
`Data`, `ParentKeyMeta`, and `Created`. If the input doesn't look like
that, the storage path is the bug, not the decrypt call.

### `decrypt_from_json: tag mismatch / authentication failed`

The envelope is structurally valid JSON but its AES-GCM authentication
tag doesn't verify. Likely causes:

- The envelope was tampered with after encryption (security incident
  if unexpected).
- You're decrypting under the wrong service/product — the intermediate
  key in the envelope's `ParentKeyMeta` doesn't match the configured
  `ServiceName` + `ProductId` of the factory you're using.
- The metastore was wiped or rotated between encrypt and decrypt — the
  intermediate key referenced by the envelope no longer exists.

**Fix:** check that the `ServiceName` / `ProductId` on the decrypting
factory match what was used to encrypt. If they're correct, look at
the `ParentKeyMeta.KeyId` in the envelope JSON and verify a row with
that ID exists in your metastore.

### `factory_from_config: ...` / `factory_from_env: ...`

The native core rejected the supplied configuration. Common subtypes:

- `Unknown metastore kind 'x'` — the native core rejected the metastore selector.
  Prefer `WithMetastore(MetastoreKind)` so only valid variants are compiled in.
- `Unknown KMS type 'x'` — same shape. Use `WithKms(KmsKind)`.
- `connection string required` — you set `WithMetastore(MetastoreKind.Rdbms)` but
  not `WithConnectionString`.
- `KmsKeyId or RegionMap required` — `WithKms(KmsKind.Aws)` needs at least
  one of the two.

## `ArgumentNullException`

Thrown for null arguments to any `AsherahApi.*`,
`AsherahFactory.*`, or `AsherahSession.*` method. This is a programming
error — Asherah never silently ignores nulls. Fix the caller.

For async methods: `DecryptBytesAsync(null!)` and
`EncryptBytesAsync(null!)` throw synchronously (before returning a
`Task`). `DecryptStringAsync(null!)` and `EncryptStringAsync(null!)`
return a faulted `Task` (the async-marked methods can't throw
synchronously through the state machine).

## `InvalidOperationException`

### `Asherah is already configured; call Shutdown() first`

You called `AsherahApi.Setup(config)` twice. The single-shot API has
exactly one process-global factory; reconfiguring requires
`Shutdown()` first.

**Fix:** if you're testing reconfiguration, call `AsherahApi.Shutdown()`
before the second `Setup()`. If you're seeing this in production, your
host is registering the lifecycle hook twice — check for duplicate
`AddHostedService<...>` calls or a misconfigured DI lifetime.

### `Asherah not configured; call Setup() first`

You called `AsherahApi.Encrypt` / `Decrypt` (or any other op) without
calling `Setup()` first. Could happen if your hosted service order is
wrong (the controller resolved before `IHostedService.StartAsync`),
or if `Setup` threw during host startup and was swallowed.

**Fix:** ensure your `AsherahApi.Setup(...)` call runs in
`IHostedService.StartAsync` and that the host actually starts before
request handling. Don't catch+swallow exceptions from `Setup`.

### `partition id cannot be empty`

You passed `""` (empty string) as the `partitionId` to
`GetSession(...)`, `Encrypt(...)`, or `Decrypt(...)`. Asherah is
deliberately stricter here than the canonical `GoDaddy.Asherah.AppEncryption`
v0.x SDK, which silently accepted empty IDs and persisted
`_IK__service_product` rows. **The .NET binding rejects them.**

**Fix:** ensure your partition ID is sourced from a non-empty value
before reaching Asherah. If your code's contract is "partition is
optional, fallback to a default," apply that fallback in your wrapper,
not by passing `""`.

## `ObjectDisposedException`

You called a method on a disposed `AsherahFactory` or `AsherahSession`.
Common causes:

- Passing a session out of a `using` block. The `using` disposes at
  end of scope; the session is unusable after that.
- Disposing the factory while sessions from it are still in use.
  Sessions hold a reference to the factory's native handle; dispose
  factories last.
- DI lifetime mismatch — registering `AsherahSession` as a singleton
  in a per-request scope.

## Native library not found

### `DllNotFoundException: Unable to load shared library 'asherah_ffi'`

The .NET runtime couldn't locate `libasherah_ffi.dylib` (macOS) /
`libasherah_ffi.so` (Linux) / `asherah_ffi.dll` (Windows).

**For NuGet consumers:** the package ships native binaries under
`runtimes/<rid>/native/`. The runtime resolves the right one by RID.
If that's failing:

- Check the resolved RID for your deployment (`dotnet --info` shows
  the runtime's RID). Common pitfall: Alpine-based containers have
  `linux-musl-x64` but resolve to `linux-x64` by default and load
  the glibc binary, which fails. Set
  `<RuntimeIdentifier>linux-musl-x64</RuntimeIdentifier>` in your
  publish profile.
- Check that the published output contains the `runtimes/` directory.
  If you're using `dotnet publish -p:PublishSingleFile=true`, ensure
  the native binary is included via `<None>` items or
  `<IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>`.

**For repo development:** the native library is built by `cargo build`
into `target/<profile>/`. Set `ASHERAH_DOTNET_NATIVE` to an absolute
path:

```bash
cargo build -p asherah-ffi
export ASHERAH_DOTNET_NATIVE="$(pwd)/target/debug"
dotnet test
```

A relative path (`target/debug`) is wrong — the binding resolves
relative to the test process's working directory, not the repo root.

### `DllNotFoundException` on Windows ARM64

The package ships `win-arm64` natives, but Windows on ARM64 sometimes
defaults to running .NET as `win-x64` under emulation. Check
`RuntimeInformation.OSArchitecture` at startup. Force the correct
architecture in your publish profile if needed.

## AWS-specific errors

DynamoDB metastore errors (`Metastore: "dynamodb"`) carry the AWS
SDK's error chain, including the AWS message. Exceptions that
aws-sdk-dynamodb does not model, `AccessDeniedException` and
`ValidationException` among them, print as `service error: unhandled
error (<Code>)` followed by the AWS message. Common shapes:

- `service error: unhandled error (AccessDeniedException)` — IAM. The
  AWS message that follows usually names the missing `dynamodb:`
  action; cross-reference against the policy in
  [`aws-production-setup.md`](./aws-production-setup.md#step-3-iam-policy-for-the-application).
- `service error: unhandled error (ValidationException)` — for example
  a table schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number); recreate the table with the
  correct schema if it was created manually with a different one.
- A DNS failure may read `dispatch failure: io error: client error
  (Connect): dns error: …` (not reproduced in testing). Check VPC
  endpoints / network ACLs / `AWS_REGION` agreement.

KMS errors (`KMS: "aws"`) never include the AWS message, which embeds
account ids and ARNs. They name the region, the step that failed and a
fixed label for the cause, plus the AWS request id when AWS answered
(look it up in CloudTrail):

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
KMS GenerateDataKey failed in region us-west-2: dispatch failure (other: no credentials available)
```

The exception carries only the outermost context. Synchronous calls
throw `<op>: <op> failed: …` and also log the full chain, with the KMS
detail, as a warn-level `<op> failed: …` event. So do the
`GoDaddy.Asherah.Encryption.Compat` package's `Session.EncryptAsync` /
`DecryptAsync`, which run the synchronous call with `Task.Run`.
`AsherahSession.EncryptBytesAsync` / `DecryptBytesAsync` and
`AsherahApi.EncryptAsync` / `DecryptAsync` use the native async calls:
their exception carries the outermost context alone, and the native
layer logs no warn-level event for them. For every call style, a failed
KMS decrypt also produces an error-level `asherah::kms_aws_envelope`
event and a failed KMS encrypt an error-level `asherah::session`
event. The log hook receives these at its default level (warn).

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
  which kind it names is not fixed. Check VPC
  endpoints / network ACLs / `AWS_REGION` agreement.
- `dispatch failure (io: other error)` — commonly a TLS failure: a
  TLS-inspecting proxy, a VPC endpoint whose certificate comes from a
  private CA the client does not trust, or an endpoint that does not
  speak TLS. Retrying does not fix it.
- `dispatch failure (timeout)`, `dispatch failure (other: transient
  error)` — the connection attempt timed out, or the connection closed
  before a response arrived.

## Diagnostic recipe

When a problem isn't covered above, this is the order of operations:

1. **Set verbose logging.** `WithVerbose(true)` on the config + sync
   log hook with `LogLevel.Trace`:

   ```csharp
   AsherahHooks.SetLogHookSync(myLogger, LogLevel.Trace);
   var config = AsherahConfig.CreateBuilder()
       .WithVerbose(true)
       // ...
       .Build();
   ```

   The Rust core logs every metastore call, KMS call, and key cache
   decision at `Trace` / `Debug`.

2. **Inspect the metastore directly.** For RDBMS, query the table
   `encryption_key`. For DynamoDB, scan `AsherahKeys`. Confirm rows
   exist for the system-key and intermediate-key IDs your envelope
   references.

3. **Repro with the static-KMS in-memory config.** Eliminates AWS as a
   variable. If the bug repros against in-memory + static, file a
   repository issue with the minimal repro.

4. **Check for static-master-key rotation.** If you set
   `STATIC_MASTER_KEY_HEX` to a different value than what was used to
   encrypt, decrypt fails with a tag mismatch — by design.
