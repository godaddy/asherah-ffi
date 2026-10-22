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
  (Connect): dns error: …` (not reproduced in testing). Check for a VPC
  endpoint / network ACL / `AWS_REGION` mismatch.

### KMS

KMS failures (`KMS: "aws"`) name the region, the step that failed and
a fixed label for the cause, plus the AWS request id when AWS answered:

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
KMS GenerateDataKey failed in region us-west-2: dispatch failure (other: no credentials available)
```

The AWS error message is deliberately left out — it embeds account
ids and principal/key ARNs. Look the request id up in CloudTrail for
the full event. Decrypt failures are logged as an
`asherah::kms_aws_envelope` error event, and both decrypt and encrypt
failures appear in full in the binding's `python binding operation
failed: …` warn event; both reach the log hook at the default `warn`
level. The `RuntimeError` message carries only the outermost context.

KMS answered (`service error <code>`):

- `AccessDeniedException` — the IAM policy or key policy does not
  allow the call (`kms:Decrypt`, `kms:GenerateDataKey`, `kms:Encrypt`)
  for the calling principal.
- `DisabledException` / `KMSInvalidStateException` /
  `NotFoundException` — the key is disabled, pending deletion, or does
  not exist in that region.
- `IncorrectKeyException` / `InvalidCiphertextException` — the KEK was
  not encrypted under the configured key, or the stored KEK is damaged.
- `ThrottlingException` — request rate; transient.

Credentials — `dispatch failure (other: <label>)`; the request never
reached KMS:

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

Region — the request never left the client, so retrying does not help:

- `not sent: no region configured` — no region was resolved; set
  `AWS_REGION` or use `RegionMap` / `PreferredRegion`.
- `request construction failure (invalid endpoint parameters)` — the
  configured region is not a valid region name, for example a key ARN
  where `RegionMap` expects a region (`{"<region>": "<key ARN>"}`). The
  region itself prints as `<unrecognized region>`.

Network, TLS and endpoint:

- `dispatch failure (io: connection refused)` and other
  connection-level kinds — the KMS endpoint (or VPC endpoint / proxy)
  could not be reached. A DNS failure may also appear as `dispatch
  failure (io: …)`; which kind it names is not fixed. Check for a VPC
  endpoint / network ACL / `AWS_REGION` mismatch.
- `dispatch failure (io: other error)` — commonly a TLS failure: a
  TLS-inspecting proxy, a VPC endpoint whose certificate comes from a
  private CA the client does not trust, or an endpoint that does not
  speak TLS. Retrying does not fix it.
- `dispatch failure (timeout)` — the connection attempt timed out.
- `dispatch failure (other: transient error)` — the connection closed
  before a response arrived.
- `response error (HTTP …, unexpected end of file)` — the response was
  cut off.
- `service error (no error code, HTTP …)` — the answer was not a KMS
  error, for example an HTML page from a proxy.

Other:

- `Decrypt returned no plaintext` — KMS answered without a data key.
- `data key failed envelope authentication` — KMS decrypted the KEK
  but the result does not authenticate the stored key: the envelope
  is corrupt or the KEK was replaced out of band.
- `no matching regions found; configured regions: …; envelope
  regions: …` — none of the configured regions has a KEK in the
  stored envelope; KMS was not called.

`<unrecognized region>`, `<unrecognized error code>` and
`<unrecognized request id>` stand in for values that did not have the
expected shape (a region name, a KMS error code, a UUID request id).

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
