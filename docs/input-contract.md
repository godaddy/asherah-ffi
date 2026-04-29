# Input contract: partition IDs vs. plaintext/ciphertext

This document specifies how every Asherah language binding handles
**null/nil/undefined arguments**, **empty strings**, and **empty byte
arrays** on the encrypt and decrypt entry points. The contract is
identical across bindings — only the language-native exception types
differ.

There are two distinct argument categories with different rules:

1. **Partition ID** — the tenancy/isolation identifier. `null`, `nil`,
   `undefined`, and the empty string `""` are **always programming
   errors**. There is no valid use case for an unidentified partition.

2. **Plaintext / ciphertext data** — the bytes you're encrypting or
   decrypting. `null`, `nil`, `undefined` are programming errors. Empty
   strings and empty byte arrays are **valid** for encrypt (and
   round-trip back to empty) but **invalid** for decrypt (not valid
   `DataRowRecord` JSON).

> **Do not short-circuit empty plaintext encryption in caller code.**
>
> A common (wrong) pattern is `if (input.length == 0) return input;` to
> "skip" encryption of empty values. **Don't do this.** Empty data is
> data: encrypting `""` produces a valid envelope (12-byte AES-GCM
> nonce + 16-byte authentication tag, wrapped in the normal
> `DataRowRecord` JSON). On decrypt the caller gets back exactly what
> was encrypted, so caller code never needs special-case logic.
>
> Skipping encryption for empty values:
>
> - leaks the *fact* that the value was empty (a side channel that an
>   adversary observing the ciphertext column can use),
> - defeats integrity guarantees — a tampered or substituted "empty"
>   record is indistinguishable from a real one,
> - silently diverges from the canonical Asherah behavior across all
>   languages.
>
> Always pass plaintext through `Encrypt` and ciphertext through
> `Decrypt` unchanged.

## Partition ID rules

The partition ID identifies a tenant, user, or other isolation unit
whose keys are kept separate. There is no defensible use case for an
empty or absent identifier — a request without an identifier is a
programming bug, not data.

| Input | Behavior |
|---|---|
| valid non-empty string | normal operation |
| `null` / `nil` / `undefined` | **error** (binding-native exception, before native call) |
| empty string `""` | **error** ("partition id cannot be empty") |
| string of only whitespace | accepted as a valid (if unusual) partition — whitespace is preserved verbatim, not collapsed |

This applies to every entry point that takes a partition ID:
`factory.GetSession(...)`, `AsherahApi.Encrypt(...)`,
`AsherahApi.Decrypt(...)`, the equivalent string variants, and the async
counterparts.

### Divergence from canonical

This binding is **stricter** than canonical asherah-csharp 0.11.0 and
canonical asherah-java 0.4.0, which accept `null` and `""` partition
IDs silently and write degenerate intermediate-key rows
(`_IK__service_product` for both null and empty in canonical C#;
`_IK_null_service_product` in canonical Java) to the metastore. This
binding rejects them at the API boundary so no row is ever written
under a degenerate ID. See `interop/tests/test_canonical_behavior.py`
for the pinned canonical behavior.

If you are migrating from canonical asherah-csharp or asherah-java and
have caller code that passes `null` partition IDs, that code has a
latent bug that this binding will surface as `ArgumentNullException` /
`NullPointerException`. Fix the caller; do not work around it.

## Plaintext rules (input to encrypt)

| Input | Behavior on encrypt |
|---|---|
| any non-empty string or byte array | normal operation |
| `null` / `nil` / `undefined` | **error** (binding-native exception, before native call) |
| empty string `""` | **valid** — produces a real `DataRowRecord` envelope; round-trips back to `""` on decrypt |
| empty byte array (`byte[0]` / `b""` / `[]byte{}` / `Buffer.alloc(0)`) | **valid** — produces a real `DataRowRecord` envelope; round-trips back to empty on decrypt |

**Empty plaintext is a real cryptographic operation, not a no-op.**
AES-256-GCM applied to empty plaintext produces 12 bytes of nonce + 0
bytes of ciphertext + 16 bytes of authentication tag = 28 bytes,
base64-encoded into the `Data` field of the `DataRowRecord`. The full
DRR envelope ends up around 241–252 bytes including the encrypted DRK
and the parent-key metadata. This wire format matches canonical Asherah
byte-for-byte.

### Go-specific note

Go's `[]byte` doesn't distinguish `nil` from an empty slice — both have
length 0, and idiomatic Go APIs treat them interchangeably. So:

- `asherah.Encrypt(partition, nil)` is **valid** and equivalent to
  `Encrypt(partition, []byte{})`. It round-trips back to a length-0
  slice.

This is the only place where the contract differs from the other
bindings, and only because the language itself doesn't distinguish the
cases.

## Ciphertext rules (input to decrypt)

| Input | Behavior on decrypt |
|---|---|
| valid `DataRowRecord` JSON (string or bytes) | normal operation |
| `null` / `nil` / `undefined` | **error** (binding-native exception, before native call) |
| empty string `""` or empty byte array | **error** (not valid JSON) |
| invalid JSON, truncated JSON, JSON of wrong shape | **error** (parse / structural error) |

Empty input cannot be a valid ciphertext — every legitimate
`DataRowRecord` has at minimum the `Key`, `Data`, and `ParentKeyMeta`
fields, which take ~241+ bytes. Decrypters that silently treat empty
ciphertext as empty plaintext would defeat integrity. We reject it at
the JSON parse step.

## Per-binding exception types

| Binding | partition ID null/empty | plaintext null | ciphertext null/empty |
|---|---|---|---|
| Rust core | `Err(anyhow::Error)` "partition id cannot be empty" | n/a (Rust has no null) | `Err(anyhow::Error)` from JSON parse |
| Rust FFI | C return code -1 with `LAST_ERROR` set | `ERR_NULL_PTR` if pointer null with len>0 | -1 with `LAST_ERROR` (JSON parse) |
| .NET | `ArgumentNullException` / `InvalidOperationException` | `ArgumentNullException` (sync); rejected `Task` (async) | `ArgumentNullException` (null); `AsherahException` wrapping JSON parse error (empty) |
| Java | `NullPointerException` from `Objects.requireNonNull` | `NullPointerException` (sync); rejected `CompletableFuture` (async) | `NullPointerException` (null); runtime exception from JSON parse (empty) |
| Node.js | `TypeError` from N-API marshalling, or sync `throw` / rejected `Promise` | same | `Error` from native layer |
| Python | `TypeError` from PyO3 type conversion | `TypeError` | `TypeError` (None); `Exception` from JSON parse (empty) |
| Ruby | `ArgumentError` from explicit guards | `ArgumentError` | `ArgumentError` (nil); `Asherah::Error::DecryptFailed` (empty) |
| Go | `error` `"asherah-go: partition ID cannot be empty"` | n/a — Go strings can't be nil; `nil []byte` is treated as empty (valid) | `error` from JSON parse |

## Per-binding empty-string AND empty-bytes coverage

Both empty string and empty byte array are tested as valid encrypt
plaintext on every binding that exposes a string API. Each row is
anchored by an automated regression test:

| Binding | empty `String` API | empty `byte[]` / bytes API |
|---|---|---|
| Rust core | n/a (bytes-only) | `encrypt_decrypt_empty_data`, `async_encrypt_decrypt_empty_data` |
| Rust FFI | n/a (bytes-only) | `encrypt_empty_then_decrypt_round_trip` |
| .NET | `Session_EmptyString_RoundTrip`, `Session_EmptyString_RoundTrip_StaticApi`, `Session_EmptyString_RoundTripAsync` | `Empty_Payload_RoundTrip`, `Session_EmptyBytes_RoundTrip_StaticApi`, `Session_EmptyBytes_RoundTripAsync` |
| Java | `sessionEmptyStringRoundTrip`, `staticEmptyStringRoundTrip`, `sessionEmptyStringRoundTripAsync` | `emptyPayloadRoundTrip`, `asyncEmptyPayload`, `sessionEmptyBytesRoundTrip`, `staticEmptyBytesRoundTrip` |
| Node.js | `testNullAndEmptyInputs` (string + Buffer), `testNullAndEmptyAsync` (string + Buffer) | same |
| Python | `test_module_empty_string_round_trip`, `test_session_empty_string_round_trip`, `test_module_async_empty_string_round_trip` | `test_empty_payload`, `test_async_empty_payload`, `test_session_async_empty_bytes_round_trip` |
| Ruby | `test_empty_string_round_trip` (module-level — session API is bytes-only by design) | `test_empty_payload`, `test_session_empty_payload_round_trip` |
| Go | `TestEmptyStringRoundTrip`, `TestSessionNilAndEmptyInputs` (string portion) | `TestEmptyPayload`, `TestEncryptNilPlaintextRoundTrips`, `TestSessionNilAndEmptyInputs` (bytes portion) |

## Wire-format compatibility with canonical

The empty-plaintext wire format matches canonical Asherah byte-for-byte
(canonical Go core, canonical asherah-csharp, canonical asherah-java,
canonical asherah-node) — verified by the cross-impl interop tests in
`interop/tests/test_canonical_mysql_interop.py` (8 bidirectional tests
covering empty, non-empty, unicode, and all-256-byte binary payloads).
Empty plaintext interop with canonical works exactly the same as any
other plaintext.
