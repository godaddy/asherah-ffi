# SQL Server Metastore Parity Notes

This documents parity between the upstream C# `AdoMetastoreImpl` and the Rust `MssqlMetastore` adapter.

## Upstream C# behavior (AppEncryption)
Source: `/tmp/asherah-upstream/csharp/AppEncryption/AppEncryption/Persistence/AdoMetastoreImpl.cs`
- Table: `encryption_key`
- Columns: `id`, `created`, `key_record`
- Load:
  - `SELECT key_record from encryption_key where id = @id and created = @created`
- LoadLatest:
  - `SELECT key_record from encryption_key where id = @id order by created DESC limit 1`
- Store:
  - `INSERT INTO encryption_key (id, created, key_record) VALUES (@id, @created, @key_record)`
  - On any `DbException`, returns `false` (no exception)
- Errors on load/loadLatest are caught and return `None` (no exception)

## Rust SQL Server adapter (current)
Source: `asherah/src/metastore_mssql.rs`
- Table: `encryption_key`
- Columns: `id` (NVARCHAR(512)), `created` (DATETIME2(3)), `key_record` (NVARCHAR(MAX))
- Load:
  - `SELECT key_record FROM encryption_key WHERE id = @P1 AND created = DATEADD(SECOND, @P2, '1970-01-01')`
- LoadLatest:
  - `SELECT TOP 1 key_record FROM encryption_key WHERE id = @P1 ORDER BY created DESC`
- Store:
  - `IF NOT EXISTS (...) INSERT ...`
  - Returns `false` on duplicates
  - Returns `false` on connection/query errors (matches C# error behavior)
- Errors in load/loadLatest return `None` (matches C# error behavior)

## Compatibility notes
- Query semantics match C# behavior; SQL Server uses `TOP 1` instead of `limit 1`.
- `created` is stored/read as UTC seconds using `DATEADD(SECOND, ...)`, matching C# truncation to epoch seconds.
- No schema migration is performed; the adapter only creates the table if missing.
- Duplicate insert returns `false` to match C# behavior.
