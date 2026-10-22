# Troubleshooting

Common errors when integrating the Python binding, what they mean,
and what to check first.

## Decrypt errors

### `decrypt_from_json: expected value at line 1 column 1`

You called `decrypt_string("")`, `decrypt_bytes(b"")`, or the async
variants with empty input. Empty bytes can't be a valid DataRowRecord
envelope (smallest legitimate envelope is ~241 bytes of JSON).

**Likely cause:** caller code is short-circuiting empty values:

```python
# Bug — encrypt produced an envelope, but storage layer dropped it.
if not envelope:
    return ""
return session.decrypt_text(envelope)
```

**Fix:** check for the empty case *before* decrypt, not by passing
empty input:

```python
envelope = repo.load_envelope(id)
return session.decrypt_text(envelope) if envelope else None
```

### `decrypt_from_json: tag mismatch` / `authentication failed`

Envelope JSON parses but the AES-GCM auth tag doesn't verify. Causes:
- Tampered envelope (security incident if unexpected).
- Decrypting under different `ServiceName`/`ProductID` than encrypted.
- Metastore wiped or rotated between encrypt and decrypt.

**Fix:** check `ServiceName`/`ProductID` parity. Inspect
`json.loads(envelope)["Key"]["ParentKeyMeta"]["KeyId"]` and verify a
row with that ID exists in your metastore.

### `decrypt_from_json: ...` (other JSON errors)

Input is non-empty but not valid Asherah JSON. Likely:
- Storage applied additional encoding (base64, gzip) on write that
  wasn't reversed on read.
- Envelope was truncated (column-length limit, transport mangling).

## Configuration errors

### `factory_from_config: Unknown metastore kind 'X'`

`Metastore` got a value that isn't `"memory"`, `"rdbms"`, `"dynamodb"`,
or `"sqlite"`. Typos.

### `factory_from_config: Unknown KMS type 'X'`

Same shape for `KMS`. Accepted: `"static"`, `"aws"`,
`"secrets-manager"`, `"vault"`.

### `factory_from_config: connection string required`

`Metastore: "rdbms"` without `ConnectionString`. Set it to your DB DSN
(`"mysql://user:pass@host:3306/db"` or `"postgres://..."`).

### `factory_from_config: KmsKeyId or RegionMap required`

`KMS: "aws"` without either `KmsKeyId` (single-region) or `RegionMap`
(multi-region).

## Lifecycle / programming errors

### `RuntimeError: Asherah is already configured; call shutdown() first`

`asherah.setup(config)` called twice. The module-level API has one
process-global instance.

**Fix:** call `asherah.shutdown()` before reconfiguring. In
production, look for duplicate setup calls (often from import-time
side effects, or test fixtures forgetting to clean up).

### `RuntimeError: Asherah not configured; call setup() first`

Module-level API used before `setup()`. Check startup ordering;
ensure `setup()` ran and didn't throw.

### `ValueError: partition id cannot be empty`

You passed `""` as partition id. Asherah is stricter than the
canonical `godaddy/asherah-python` v0.x package (which silently
accepts empty IDs and writes degenerate `_IK__service_product` rows).

**Fix:** ensure your partition ID is non-empty before calling Asherah.

### `TypeError: ... missing X required positional argument` / `argument must be ..., not None`

`None` passed where a value was required. Usually means an upstream
value didn't arrive (missing dict key, missing query parameter, etc.).

## Native binary errors

### `ImportError: ... no module named asherah._native`

The native extension didn't load. Causes:

- Wrong wheel for your platform. Check
  `python -c "import platform; print(platform.machine(), platform.python_implementation())"`
  and verify `pip` resolved to a wheel matching your platform tags.
- musl/Alpine: ensure your wheel filename contains `musllinux`, not
  `manylinux`. Reinstall with
  `pip install --force-reinstall --no-cache-dir asherah`.
- Source install on a system without Rust toolchain. Either install
  Rust or pin to a version with a prebuilt wheel for your platform.

### `OSError: ... cannot open shared object file`

The `_native` extension is present but its dynamic-library
dependencies aren't. Most common on Alpine without `libgcc` /
`libstdc++`. Install
`apk add libgcc libstdc++` in your Dockerfile.

### Apple Silicon / Rosetta confusion

If `python` was installed for x86_64 but you're on arm64 (or vice
versa):
```bash
file $(which python)            # check actual arch
arch                            # check shell arch
```
Reinstall Python for the matching architecture and `pip install`.

## AWS-specific errors

### DynamoDB metastore

DynamoDB metastore errors (`Metastore: "dynamodb"`) carry the AWS
SDK's error chain, including the AWS message. Exceptions that
aws-sdk-dynamodb does not model, `AccessDeniedException` and
`ValidationException` among them, print as `service error: unhandled
error (<Code>)` followed by the AWS message:

- `service error: unhandled error (AccessDeniedException)` — IAM. The
  AWS message that follows usually names the missing `dynamodb:`
  action; cross-reference against
  [`aws-production-setup.md`](./aws-production-setup.md#step-3-iam-policy).
- `service error: unhandled error (ValidationException)` — for example
  a table schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number).
- A DNS failure may read `dispatch failure: io error: client error
  (Connect): dns error: …`. Check for a VPC endpoint / network
  ACL / `AWS_REGION` mismatch.

### KMS

KMS failures (`KMS: "aws"`) name the step that failed, the region and a
fixed label for the cause, plus the AWS request id when AWS answered:

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
```

Decrypt failures are logged as an `asherah::kms_aws_envelope` error
event, and both decrypt and encrypt failures appear in full in the
binding's `python binding operation failed: …` warn event; both reach
the log hook (`asherah.set_log_hook`) at the default `warn` level. The
`RuntimeError` message carries only the outermost context.

- Permissions or key state: `service error AccessDeniedException` (IAM
  or key policy), `DisabledException`, `KMSInvalidStateException`,
  `NotFoundException` (key disabled, pending deletion or missing).
- Credentials: `dispatch failure (other: no credentials available)` or
  another credentials label; the request never reached KMS.
- Region: `not sent: no region configured` — set `AWS_REGION` or
  `RegionMap`; `no matching regions found` — no configured region has
  a KEK in the stored envelope.
- Network: `dispatch failure (io: …)`, `(timeout)`, `(other: transient
  error)` — KMS could not be reached; `io: other error` can indicate TLS
  trouble. Check for a VPC endpoint / network ACL / `AWS_REGION` mismatch.
- Envelope: `data key failed envelope authentication` — the envelope
  is corrupt or the KEK was replaced out of band.

Unlike the DynamoDB errors above, KMS errors omit the AWS message,
which embeds ARNs and account ids; the request id lets AWS support (or
CloudTrail) find the call. Every label is explained in
[`docs/kms-errors.md`](../../docs/kms-errors.md).

## asyncio caveats

### `RuntimeError: Cannot run event loop while another loop is running`

You called the sync `setup()` / `encrypt_string()` from inside an
async context. The sync API is fine to call from sync code, and the
`*_async` API is fine from async code, but mixing them inside an
`asyncio.run()` block can confuse the tokio runtime.

**Fix:** use `*_async` consistently inside async code.

### `_native.AsherahError: shutdown_async called from inside event loop`

You called `await asherah.shutdown_async()` from inside a coroutine
that's still consuming Asherah resources. Ensure all in-flight encrypt
/ decrypt operations await before calling shutdown.

## Diagnostic recipe

When a problem isn't covered above:

1. **Install a log hook:**
   ```python
   def on_log(event):
       print(f"[asherah {event['level']}] {event['target']}: {event['message']}")
   asherah.set_log_hook(on_log)
   factory = asherah.SessionFactory.from_config(config)
   ```
   The hook receives `warn` and `error` events; `info`, `debug` and
   `trace` records are not delivered. An operation that fails in the
   Rust core logs a `python binding operation failed: …` warn event
   with the full error chain, and a failed KMS decrypt logs an
   `asherah::kms_aws_envelope` error event that lists every attempted
   region with its cause (see [KMS](#kms)).

2. **Inspect the metastore directly.** RDBMS: query
   `encryption_key`. DynamoDB: scan `AsherahKeys`. Confirm rows for
   the SK and IK IDs the failing envelope references.

3. **Repro with `Metastore: "memory"` + `KMS: "static"`.** Eliminates
   AWS as a variable. If the bug repros there, file a repository
   issue with the minimal repro.

4. **Static-master-key rotation.** Setting `STATIC_MASTER_KEY_HEX` to
   a different value than what was used to encrypt fails decrypt
   with a tag mismatch — by design.
