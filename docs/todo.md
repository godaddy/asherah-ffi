# TODO

## Persist Metastore Configuration Drift Guards

Established Asherah repositories that have already been written to should persist
their safety-critical configuration invariants in the metastore. Values that are
relevant to metastore/key layout and cannot be safely changed after data exists,
such as region/extension suffix behavior, should be recorded once and used as a
configuration drift guard for future clients.

This must be implemented backwards compatibly. Existing repositories and
metastores that do not yet have a drift-check metadata record must not break on
upgrade. The design should support a safe first-run/adoption path that can
initialize the metadata record without changing existing key record semantics,
requiring destructive migrations, or preventing existing correctly configured
clients from continuing to operate.

On startup, Asherah clients should load this persisted drift-check record and
compare it with their resolved runtime configuration. If a mismatch is detected,
startup should fail closed before the client can write keys or data row records
that corrupt or fork the existing repository layout.

An explicit override flag or environment variable may be allowed for emergency
operation. Even when overridden, the client should still perform the drift check
and log loudly that a misconfiguration was detected and bypassed.

Open design points:

- Which configuration fields are safety-critical and immutable after first write.
- Where the drift-check record lives for each metastore without colliding with
  existing Asherah key records.
- How first-writer initialization is made atomic across concurrent clients.
- How legacy repositories without a drift-check record adopt the metadata
  without a breaking change.
- Exact override name, scope, and audit/logging behavior.
