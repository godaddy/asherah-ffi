# asherah

Ruby bindings for [Asherah](https://github.com/godaddy/asherah-ffi) envelope encryption with automatic key rotation.

Published to [GitHub Packages](https://github.com/godaddy/asherah-ffi/packages) with prebuilt native libraries for Linux x64/ARM64 and macOS x64/ARM64. A fallback source gem is available for other platforms (requires the Rust toolchain to compile).

## Installation

Configure the GitHub Packages gem source, then install:

```bash
gem sources --add https://rubygems.pkg.github.com/godaddy
gem install asherah
```

Or add to your Gemfile:

```ruby
source "https://rubygems.pkg.github.com/godaddy" do
  gem 'asherah'
end
```

The gem uses FFI to load the native Asherah library. Platform-specific gems ship the prebuilt library; the source gem builds it during installation.

## Quick Start

The simplest way to use Asherah is the static module API. Call `setup` once at startup and `shutdown` on exit:

```ruby
require "asherah"

Asherah.setup(
  "ServiceName" => "my-service",
  "ProductID"   => "my-product",
  "Metastore"   => "memory",   # testing only
  "KMS"         => "static"    # testing only
)

ciphertext = Asherah.encrypt_string("partition-id", "sensitive data")
plaintext  = Asherah.decrypt_string("partition-id", ciphertext)

Asherah.shutdown
```

The static API manages a session cache internally. Sessions are created on first use per partition and reused for subsequent calls.

### Block-style configuration

For an API compatible with the canonical GoDaddy Asherah Ruby gem, use `configure` with a block:

```ruby
Asherah.configure do |config|
  config.service_name = "my-service"
  config.product_id   = "my-product"
  config.kms          = "static"   # testing only
  config.metastore    = "memory"   # testing only
end

ciphertext = Asherah.encrypt_string("partition-id", "sensitive data")
plaintext  = Asherah.decrypt_string("partition-id", ciphertext)

Asherah.shutdown
```

## Session-Based API

For direct control over session lifecycle, use `SessionFactory` and `Session`:

```ruby
require "asherah"

Asherah.configure do |config|
  config.service_name = "my-service"
  config.product_id   = "my-product"
  config.kms          = "static"   # testing only
  config.metastore    = "memory"   # testing only
end

factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(config_json)
)
session = factory.get_session("partition-id")

ciphertext = session.encrypt_bytes("sensitive data")
plaintext  = session.decrypt_bytes(ciphertext)

session.close
factory.close
```

Or via the static API's internal factory (the typical pattern):

```ruby
Asherah.setup("ServiceName" => "my-service", "ProductID" => "my-product",
              "Metastore" => "memory", "KMS" => "static") # testing only

# The static API acquires and caches sessions automatically
ct = Asherah.encrypt("partition-id", "data")
pt = Asherah.decrypt("partition-id", ct)

Asherah.shutdown
```

## Async API

### Session-level async (true async via Rust tokio)

The session's async methods dispatch work to Rust's tokio runtime and receive results via FFI callbacks:

```ruby
session = factory.get_session("partition-id")

ct = session.encrypt_bytes_async(data)
pt = session.decrypt_bytes_async(ct)

session.close
```

### Static-level async (thread-based)

The static API's async methods run in a Ruby `Thread`:

```ruby
thread = Asherah.encrypt_async("partition-id", data) do |result|
  puts "Encrypted: #{result.bytesize} bytes"
end
thread.join
```

### Async Behavior

The session-level async methods (`encrypt_bytes_async`, `decrypt_bytes_async`) are true async. The encrypt/decrypt work runs on Rust's tokio worker threads and completes via an FFI callback. The Ruby interpreter is NOT blocked during the native call.

However, the implementation uses `Queue#pop` to synchronize the callback result back to the calling Ruby thread. This means `queue.pop` blocks the calling Ruby thread until the result arrives. True concurrency requires multiple Ruby threads or Ractors dispatching async calls in parallel.

The static-level async methods (`Asherah.encrypt_async`, `Asherah.decrypt_async`) simply run the sync operation in a new `Thread`.

## Migration from Canonical Ruby SDK

This replaces the original `asherah` gem which was built on Go via Cobhan FFI. The API is drop-in compatible:

| | Canonical (Go/Cobhan) | This binding (Rust/FFI) |
|---|---|---|
| Implementation | Go + Cobhan FFI | Rust + Ruby FFI gem |
| `Asherah.configure` | Supported | Supported (same API) |
| `Asherah.encrypt` / `decrypt` | Supported | Supported (same API) |
| `SessionFactory` | Supported | Supported (same API) |
| Memory protection | None | memguard (locked, wiped pages) |
| Async support | None | Session-level true async |

Migration steps:
1. Update the `asherah` gem version in your Gemfile
2. No code changes required -- the API is compatible
3. Both read the same metastore tables -- no data migration required

## Performance

Benchmarked on Apple M4 Max, 64-byte payload, hot session cache:

| Operation | Latency |
|---|---|
| Encrypt | ~1,170 ns |
| Decrypt | ~1,110 ns |

## Configuration

### `setup` (hash style)

Keys are PascalCase strings matching the Asherah configuration format:

| Key | Type | Required | Description |
|---|---|---|---|
| `ServiceName` | `String` | Yes | Service identifier for key hierarchy |
| `ProductID` | `String` | Yes | Product identifier for key hierarchy |
| `Metastore` | `String` | Yes | `"rdbms"`, `"dynamodb"`, `"memory"` (testing) |
| `KMS` | `String` | Yes | `"static"` or `"aws"` |
| `ConnectionString` | `String` | No | RDBMS connection string |
| `DynamoDBEndpoint` | `String` | No | Custom DynamoDB endpoint |
| `DynamoDBRegion` | `String` | No | DynamoDB region |
| `DynamoDBTableName` | `String` | No | DynamoDB table name |
| `RegionMap` | `Hash` | No | AWS KMS region-to-ARN map |
| `PreferredRegion` | `String` | No | Preferred AWS KMS region |
| `EnableRegionSuffix` | `Boolean` | No | Append region suffix to key IDs |
| `EnableSessionCaching` | `Boolean` | No | Enable session caching (default: true) |
| `SessionCacheMaxSize` | `Integer` | No | Max cached sessions |
| `SessionCacheDuration` | `Integer` | No | Cache TTL in milliseconds |
| `ExpireAfter` | `Integer` | No | Key expiration in seconds |
| `CheckInterval` | `Integer` | No | Key check interval in seconds |
| `Verbose` | `Boolean` | No | Enable verbose logging (default: false) |

### `configure` (block style)

Uses snake_case attribute accessors:

| Attribute | Maps to |
|---|---|
| `service_name` | `ServiceName` |
| `product_id` | `ProductID` |
| `metastore` | `Metastore` |
| `kms` | `KMS` |
| `connection_string` | `ConnectionString` |
| `dynamo_db_endpoint` | `DynamoDBEndpoint` |
| `dynamo_db_region` | `DynamoDBRegion` |
| `dynamo_db_table_name` | `DynamoDBTableName` |
| `region_map` | `RegionMap` |
| `preferred_region` | `PreferredRegion` |
| `enable_region_suffix` | `EnableRegionSuffix` |
| `enable_session_caching` | `EnableSessionCaching` |
| `session_cache_max_size` | `SessionCacheMaxSize` |
| `session_cache_duration` | `SessionCacheDuration` |
| `expire_after` | `ExpireAfter` |
| `check_interval` | `CheckInterval` |
| `verbose` | `Verbose` |

## API Reference

### `Asherah` (module-level static API)

| Method | Description |
|---|---|
| `setup(config_hash)` | Initialize with PascalCase config hash |
| `configure { \|c\| ... }` | Initialize with block-style snake_case config |
| `setup_async(config_hash, &block)` | Async `setup` in a Thread |
| `shutdown` | Release all resources and cached sessions |
| `shutdown_async(&block)` | Async `shutdown` in a Thread |
| `get_setup_status` | Returns `true` if initialized |
| `encrypt(partition, data)` | Encrypt bytes, returns DRR JSON bytes |
| `encrypt_string(partition, text)` | Encrypt string, returns DRR JSON string |
| `encrypt_async(partition, data, &block)` | Encrypt in a Thread |
| `decrypt(partition, drr)` | Decrypt DRR JSON bytes to plaintext |
| `decrypt_string(partition, drr)` | Decrypt DRR JSON string to plaintext string |
| `decrypt_async(partition, drr, &block)` | Decrypt in a Thread |
| `setenv(hash)` / `set_env(hash)` | Set environment variables |

### `Asherah::SessionFactory`

| Method | Description |
|---|---|
| `get_session(partition_id)` | Create a session for a partition |
| `close` | Release the factory |
| `closed?` | Returns `true` if closed |

### `Asherah::Session`

| Method | Description |
|---|---|
| `encrypt_bytes(data)` | Encrypt bytes, returns DRR JSON bytes |
| `decrypt_bytes(json)` | Decrypt DRR JSON bytes to plaintext bytes |
| `encrypt_bytes_async(data)` | True async encrypt via Rust tokio |
| `decrypt_bytes_async(json)` | True async decrypt via Rust tokio |
| `close` | Release the session |
| `closed?` | Returns `true` if closed |

## License

Licensed under the Apache License, Version 2.0.
