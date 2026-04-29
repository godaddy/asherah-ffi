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

- `Unknown metastore kind 'x'` — `WithMetastore(string)` got a value
  that isn't `"memory"`, `"rdbms"`, `"dynamodb"`, or `"sqlite"`. Use
  the `WithMetastore(MetastoreKind)` overload to avoid this.
- `Unknown KMS type 'x'` — same shape. Use `WithKms(KmsKind)`.
- `connection string required` — you set `WithMetastore("rdbms")` but
  not `WithConnectionString`.
- `KmsKeyId or RegionMap required` — `WithKms("aws")` needs at least
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

Forwarded from the AWS SDK for Rust running in the native core. Common
shapes:

- `dispatch failure: unhandled error: ResolveError` — DNS resolution
  failed. Check VPC endpoints / network ACLs / `AWS_REGION` agreement.
- `service error: AccessDeniedException` — IAM. The error usually
  names the missing action; cross-reference against the policy in
  [`aws-production-setup.md`](./aws-production-setup.md#step-3-iam-policy-for-the-application).
- `service error: ValidationException: ...AttributeName...` — DynamoDB
  table schema doesn't match. Asherah expects partition key `Id`
  (string), sort key `Created` (number); recreate the table with the
  correct schema if it was created manually with a different one.
- `service error: KMSInvalidStateException` — the KMS key is
  `PendingDeletion` / `Disabled`. Re-enable or use a different key.

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
