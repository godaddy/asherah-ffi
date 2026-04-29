# Troubleshooting

Common errors when integrating the Node.js binding, what they mean,
and what to check first. Search this page for the exact phrase you're
seeing.

## Decrypt errors

### `decrypt_from_json: expected value at line 1 column 1`

You called `decryptString("")` / `decrypt(Buffer.alloc(0))` or the
async variants with an empty input. Empty bytes can't be a valid
DataRowRecord envelope — the smallest legitimate envelope is ~241
bytes of JSON.

**Likely cause:** caller code is short-circuiting empty values:

```javascript
// Bug — encrypt produced an envelope, but storage layer dropped it.
if (envelope.length === 0) return "";
return session.decryptString(envelope);
```

**Fix:** check for the empty case *before* calling decrypt, not by
passing empty input:

```javascript
const envelope = await repo.loadEnvelope(id);
return envelope ? session.decryptString(envelope) : null;
```

### `decrypt_from_json: tag mismatch / authentication failed`

Envelope is valid JSON but its AES-GCM authentication tag doesn't
verify. Causes:
- Tampered envelope (security incident if unexpected).
- Decrypting under a different `serviceName`/`productId` than the one
  that encrypted (the IK referenced in `ParentKeyMeta` doesn't match).
- Metastore wiped or rotated between encrypt and decrypt.

**Fix:** check `serviceName`/`productId` parity. Inspect
`JSON.parse(envelope).Key.ParentKeyMeta.KeyId` and verify a row with
that ID exists in your metastore.

### `decrypt_from_json: ...` (other JSON errors)

Input is non-empty but not valid Asherah JSON. Likely:
- Storage layer applied additional encoding (base64, gzip) on write
  that wasn't reversed on read.
- Envelope was truncated.

**Fix:** dump the failing input. Valid envelopes start with `{"Key":{`
and contain `Key`, `Data`, `ParentKeyMeta`, `Created`.

## Configuration errors

### `factory_from_config: Unknown metastore kind 'X'`

`metastore` got a value that isn't `"memory"`, `"rdbms"`, `"dynamodb"`,
or `"sqlite"`. Typos are the usual cause.

### `factory_from_config: Unknown KMS type 'X'`

Same shape for `kms`. Accepted: `"static"`, `"aws"`,
`"secrets-manager"`, `"vault"`.

### `factory_from_config: connection string required`

`metastore: "rdbms"` without `connectionString`. Set it to your DB DSN
(e.g. `"mysql://user:pass@host:3306/db"` or
`"postgres://user:pass@host:5432/db"`).

### `factory_from_config: KmsKeyId or RegionMap required`

`kms: "aws"` without either `kmsKeyId` (single-region) or `regionMap`
(multi-region). Set one.

## Lifecycle / programming errors

### `Asherah is already configured; call shutdown() first`

`asherah.setup(config)` called twice. The static API has exactly one
process-global instance.

**Fix:** if you're testing reconfiguration, call `asherah.shutdown()`
first. In production, look for duplicate setup calls (often from
hot-reload tooling like nodemon / ts-node-dev re-executing the entry
point without resetting module state).

### `Asherah not configured; call setup() first`

Static API used before `setup()`. Could be a startup-order bug or
`setup()` threw and was swallowed.

### `partition id cannot be empty`

You passed `""` (empty string) as partition id. Asherah is stricter
than the canonical `godaddy/asherah-node` v0.x package, which silently
accepts empty IDs and writes degenerate `_IK__service_product` rows.

**Fix:** ensure your partition ID is sourced from a non-empty value.

### `TypeError: Cannot read properties of null/undefined`

Null/undefined passed where a value was required. Usually means an
upstream value didn't arrive when expected — check for missing
properties on JSON-decoded request bodies, missing tenant IDs, etc.

## Native binary errors

### `Error: Cannot find module 'asherah-linux-musl-x64'` (or similar)

The platform-specific native package wasn't installed. Causes:

- `npm install` ran in an environment with `--no-optional` or a
  package-lock that excluded the platform package.
- Package was installed on glibc Linux, then container moved to musl
  (or vice versa).
- M1/M2 Mac running Node under Rosetta — installs `darwin-x64` but
  runs as arm64 (or vice versa).

**Fix:** clear `node_modules/asherah` and `package-lock.json`'s
`asherah` entry, then `npm install asherah --include=optional`. For
musl: confirm `node -p "process.report.getReport().header.glibcVersionRuntime"`
returns `undefined`.

### `Error: dlopen ... no such file or directory`

The `index.<rid>.node` file is present but its dynamic-library
dependencies aren't. Most common on Alpine without `libgcc` /
`libstdc++`. Install `apk add libgcc libstdc++` in your Dockerfile.

### Apple Silicon / Rosetta confusion

If `node` was installed for x64 but you're on arm64 (or vice versa):
```bash
file $(which node)            # check actual arch
arch                          # check shell arch
```
Reinstall Node for the matching architecture and `npm install`.

## AWS-specific errors

Forwarded from the AWS SDK for Rust running in the native core:

- `dispatch failure: ResolveError` — DNS resolution failed. VPC
  endpoint / network ACL / `AWS_REGION` mismatch.
- `service error: AccessDeniedException` — IAM. The error names the
  missing action; cross-reference against
  [`aws-production-setup.md`](./aws-production-setup.md#step-3-iam-policy).
- `service error: ValidationException: ...AttributeName...` —
  DynamoDB schema mismatch. Asherah expects partition key `Id`
  (string), sort key `Created` (number).
- `service error: KMSInvalidStateException` — KMS key is
  `PendingDeletion`/`Disabled`. Re-enable or use a different key.

## Diagnostic recipe

When a problem isn't covered above:

1. **Set verbose logging:**
   ```javascript
   asherah.setLogHookSync((level, target, message) => {
     console.error(`[asherah ${level}] ${target}: ${message}`);
   });
   const factory = new SessionFactory({ ...config, verbose: true });
   ```
   Trace-level records cover every metastore call, KMS call, and
   key-cache decision.

2. **Inspect the metastore directly.** RDBMS: query
   `encryption_key`. DynamoDB: scan `AsherahKeys`. Confirm rows for
   the SK and IK IDs the failing envelope references.

3. **Repro with `metastore: "memory"` + `kms: "static"`.** Eliminates
   AWS as a variable. If the bug repros against in-memory + static,
   file a repository issue with the minimal repro.

4. **Static-master-key rotation.** If you set `STATIC_MASTER_KEY_HEX`
   to a different value than what was used to encrypt, decrypt fails
   with a tag mismatch — by design.
