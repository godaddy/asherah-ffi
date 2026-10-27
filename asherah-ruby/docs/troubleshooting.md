# Troubleshooting

Common errors when integrating the Ruby binding, what they mean, and
what to check first.

## Decrypt errors

### `decrypt_from_json: expected value at line 1 column 1`

You called `decrypt_string("")`, `decrypt_bytes("")`, or the async
variants with empty input. Empty bytes can't be a valid DataRowRecord
envelope (smallest legitimate envelope is ~241 bytes).

**Likely cause:** caller code is short-circuiting empty values:

```ruby
# Bug — encrypt produced an envelope, but storage layer dropped it.
return "" if envelope.empty?
session.decrypt_string(envelope)
```

**Fix:** check for the empty case *before* decrypt:

```ruby
envelope = repo.load_envelope(id)
envelope.present? ? session.decrypt_string(envelope) : nil
```

### `decrypt_from_json: tag mismatch` / `authentication failed`

Envelope JSON parses but AES-GCM auth tag doesn't verify. Causes:
- Tampered envelope (security incident if unexpected).
- Decrypting under different `ServiceName`/`ProductID` than
  encrypted.
- Metastore wiped/rotated between encrypt and decrypt.

**Fix:** check `ServiceName`/`ProductID` parity. Inspect
`JSON.parse(envelope)["Key"]["ParentKeyMeta"]["KeyId"]` and verify
a row with that ID exists in your metastore.

### `decrypt_from_json: ...` (other JSON errors)

Input is non-empty but not valid Asherah JSON. Likely:
- Storage layer applied additional encoding (base64, gzip).
- Envelope was truncated (column-length limit).

## Configuration errors

### `factory_from_config: Unknown metastore kind 'X'`

`Metastore` got a value that isn't `"memory"`, `"rdbms"`, `"dynamodb"`,
or `"sqlite"`. Typos.

### `factory_from_config: Unknown KMS type 'X'`

Same shape for `KMS`. Accepted: `"static"`, `"aws"`,
`"secrets-manager"`, `"vault"`.

### `factory_from_config: connection string required`

`Metastore => "rdbms"` without `ConnectionString`.

### `factory_from_config: KmsKeyId or RegionMap required`

`KMS => "aws"` without either `KmsKeyId` or `RegionMap`.

## Lifecycle / programming errors

### `Asherah::Error: Asherah is already configured; call shutdown first`

`Asherah.setup(config)` called twice. Module-level API has one
process-global instance.

**Fix:** if testing reconfiguration, call `Asherah.shutdown` first.
In production, look for duplicate setup calls — Rails initializers
running twice (Spring/Spork stalking) or factory rebuild on code
reload.

### `Asherah::Error: Asherah not configured; call setup first`

Module-level API used before `setup`. Check startup ordering;
ensure your initializer ran without raising.

### `ArgumentError: partition id cannot be empty`

You passed `""` or `nil` as partition id. Asherah is stricter than
the canonical `godaddy/asherah-ruby` v0.x gem (which silently
accepts empty IDs and writes degenerate `_IK__service_product`
rows).

**Fix:** ensure your partition ID is non-empty before calling
Asherah.

## Native library errors

### `LoadError: cannot load such file -- asherah/asherah.so`

The native extension didn't load. Causes:

- Wrong platform gem. Run `gem env` and check
  `INSTALLATION DIRECTORY` — the `asherah-x.y.z-<platform>/` should
  match your actual platform.
- musl/Alpine: the `asherah-*-linux-musl` gem should resolve
  automatically in Bundler. If not, run
  `bundle lock --add-platform x86_64-linux-musl` (or
  `aarch64-linux-musl`) and re-bundle.
- Source gem fallback selected but Rust toolchain isn't installed.
  Either install Rust (`curl --proto '=https' --tlsv1.2 -sSf
  https://sh.rustup.rs | sh`) or pin to a version with prebuilt
  binaries for your platform.

### `LoadError: cannot open shared object file: No such file or directory`

The `.so` is present but its dynamic-library dependencies aren't.
Most common on Alpine. Add `apk add libgcc libstdc++` to your
Dockerfile.

### Apple Silicon / Rosetta confusion

If `ruby` was installed for x86_64 but you're on arm64 (or vice
versa):

```bash
file $(which ruby)              # check actual arch
arch                            # check shell arch
```

Reinstall Ruby for the matching architecture (rbenv/asdf rebuild,
or Homebrew reinstall).

## Bundler pitfalls

### `Could not find asherah-x.y.z in any of the sources`

Ensure the gem is in your Gemfile:

```ruby
gem "asherah"
```

Then run `bundle install`.

### Lockfile resolves a different platform than your deploy target

Bundler resolves to the platform of `bundle install`. Deploying from
a Mac to Linux:

```bash
bundle lock --add-platform x86_64-linux        # glibc
bundle lock --add-platform aarch64-linux       # ARM64 glibc
bundle lock --add-platform x86_64-linux-musl   # Alpine
bundle lock --add-platform aarch64-linux-musl  # Alpine ARM64
```

Then commit `Gemfile.lock` so deploy `bundle install` picks the
right platform gem.

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

KMS errors (`KMS: "aws"`) name the step that failed, the region and a
fixed label for the cause, plus the AWS request id when AWS answered:

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-…])
```

The raised error carries only the outermost context. Synchronous
calls, and the module-level `Asherah.encrypt_async` /
`Asherah.decrypt_async` (which run the synchronous call in a `Thread`),
raise `<op> failed: …` and also log the full chain, with the KMS
detail, as a warn-level `<op> failed: …` event.
`Session#encrypt_bytes_async` / `#decrypt_bytes_async` use the native
async calls: their error carries the outermost context alone, and the
native layer logs no warn-level event for them. For every call style,
a failed KMS decrypt also produces an error-level
`asherah::kms_aws_envelope` event and a failed KMS encrypt an
error-level `asherah::session` event. The log hook
(`Asherah.set_log_hook`) receives these at its default level (warn).

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
  trouble. Check VPC endpoints / network ACLs / `AWS_REGION` agreement.
- Envelope: `data key failed envelope authentication` — the envelope
  is corrupt or the KEK was replaced out of band.

Unlike the DynamoDB errors above, KMS errors omit the AWS message,
which embeds ARNs and account ids; the request id lets AWS support (or
CloudTrail) find the call. Every label is explained in
[`docs/kms-errors.md`](../../docs/kms-errors.md).

The `aws-sdk-ruby` gem's credential cache is **not** consulted —
Asherah uses the AWS SDK for Rust's chain.

## Rails-specific

### Initializer runs in the wrong order

If `Rails.logger` isn't ready when the Asherah initializer runs,
move the hook setup into `Rails.application.config.after_initialize`:

```ruby
Rails.application.config.after_initialize do
  Asherah.set_log_hook(Rails.logger)
end
```

### Factory not closed across `bin/rails restart`

Rails' restart sends `at_exit`-aware signals; the
`at_exit { factory&.close }` from your initializer runs. If you're
seeing leaked factories across `spring stop` / `rake assets:precompile`,
your initializer is being loaded multiple times — guard with a
`Rails.application.config.respond_to?(:asherah_factory)` check.

## Diagnostic recipe

When a problem isn't covered above:

1. **Set verbose logging:**
   ```ruby
   Asherah.set_log_hook_sync do |evt|
     warn "[asherah #{evt[:level]}] #{evt[:target]}: #{evt[:message]}"
   end
   config = CONFIG.merge("Verbose" => true)
   ```
   Trace records cover every metastore call, KMS call, and
   key-cache decision.

2. **Inspect the metastore directly.** RDBMS: query
   `encryption_key`. DynamoDB: scan `AsherahKeys`.

3. **Repro with `Metastore => "memory"` + `KMS => "static"`** to
   eliminate AWS as a variable.

4. **Static-master-key rotation** fails decrypt with a tag mismatch —
   by design.
