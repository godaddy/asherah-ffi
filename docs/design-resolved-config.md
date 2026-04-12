# Design: Replace Env Transport with ResolvedConfig

**Status:** Proposed  
**Date:** 2026-04-12  
**Scope:** `asherah/src/builders.rs`, `asherah-config/src/lib.rs`, metastore constructors

## Problem

`factory_from_config()` uses process-global environment variables as an
internal transport: `apply_env()` writes ~40 env vars, then `factory_from_env()`
reads them back. This causes side effects visible to the entire process, a
race condition in the async variant, and forces tests to serialize.

## Approach

1. Define a `ResolvedConfig` struct in `asherah/src/builders.rs`
2. Add `factory_from_resolved()` that builds directly from `ResolvedConfig`
3. Add metastore constructor variants that accept pool/TLS config as parameters
4. In `asherah-config`: add `ConfigOptions::resolve()` → `ResolvedConfig`
5. Rewrite `factory_from_config()` as: `resolve()` → `factory_from_resolved()`
6. Rewrite `factory_from_env()` as: parse env → `ResolvedConfig` → `factory_from_resolved()`
7. Remove `apply_env()` and the `FACTORY_BUILD_LOCK`

## Changes by file

### `asherah/src/builders.rs`
- Add `ResolvedConfig`, `MetastoreConfig`, `KmsConfig`, `PolicyConfig`, `PoolConfig` types
- Add `factory_from_resolved()` and `factory_from_resolved_async()`
- Refactor `factory_from_env()` to parse env → `ResolvedConfig` → `factory_from_resolved()`
- Same for async variant

### `asherah/src/pool_mysql.rs`
- Add `PoolConfig::from_resolved(pool: &PoolConfig)` constructor

### `asherah/src/metastore_mysql.rs`
- Add `connect_with(url, pool_config, tls_mode)` that accepts config directly
- `connect(url)` delegates to `connect_with()` reading env

### `asherah/src/metastore_postgres.rs`
- Add `connect_with(url, pool_config, replica_consistency)` 
- `connect(url)` delegates to `connect_with()` reading env

### `asherah/src/metastore_dynamodb.rs`
- Add `new_with(table, region, endpoint, region_suffix)` / async variant
- `new(table, region)` delegates to `new_with()` reading env

### `asherah-config/src/lib.rs`
- Add `ConfigOptions::resolve()` → `ResolvedConfig`
- Remove `apply_env()`, `set_env_opt_*` helpers, `FACTORY_BUILD_LOCK`
- `factory_from_config()` = `resolve()` → `factory_from_resolved()`
- `factory_from_config_async()` = `resolve()` → `factory_from_resolved_async()`
