# TODO

## Persist Metastore Configuration Drift Guards

Established Asherah repositories that have already been written to should persist
their safety-critical configuration invariants in the metastore. Values that are
relevant to metastore/key layout and cannot be safely changed after data exists,
such as region/extension suffix behavior, should be recorded once and used as a
configuration drift guard for future clients.

Implemented in `asherah/src/config_drift_guard.rs` using a backwards-compatible
TOFU (trust on first use) model. Existing repositories and metastores that do
not yet have a drift-check metadata record do not require a migration. If the
record is missing, the first correctly configured client inserts it using the
existing `encryption_key`/`KeyRecord` shape. Future clients compare their
resolved write-layout configuration against the persisted record.

The reserved row is scoped by service/product:

- `Id`: `__asherah_internal_config_drift_guard_v1__:<blake2b-base64url-scope>`
- `Created`: `946684800` (`2000-01-01T00:00:00Z`)
- `KeyRecord.Key`: base64 of compact JSON drift payload
- no TTL or expiration attribute

The JSON payload records the fields that define key/metastore write layout:

- schema version
- service name and product id
- effective region suffix and whether suffixing is enabled
- key id format version
- AEAD algorithm (`AES-256-GCM`)
- data row record format (`asherah-json-v1`)
- non-secret metastore identity
- non-secret KMS identity

Startup fails closed on mismatch before key writes. Two explicit repair levers
exist:

- `ASHERAH_CONFIG_DRIFT_FORCE_RUN=true`, or JSON `ConfigDriftForceRun`, runs
  despite a mismatch and does not rewrite the guard.
- `ASHERAH_CONFIG_DRIFT_FORCE_UPDATE=true`, or JSON `ConfigDriftForceUpdate`,
  replaces the reserved guard row with the current resolved configuration.

Both paths still perform the drift check and log loudly. The update path uses
an internal metastore replacement hook only for this reserved guard row; normal
key records remain insert-if-absent.
