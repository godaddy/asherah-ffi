# Getting started

Step-by-step walkthrough from `gem install` to a round-trip
encrypt/decrypt. After this guide, see:

- [`framework-integration.md`](./framework-integration.md) — Rails,
  Sidekiq, Sinatra, Rack, AWS Lambda integration.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS KMS + DynamoDB.
- [`testing.md`](./testing.md) — Minitest/RSpec patterns,
  Testcontainers, mocking.
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Install the gem

Configure the GitHub Packages gem source, then install:

```bash
gem sources --add https://rubygems.pkg.github.com/godaddy
gem install asherah
```

Or in your Gemfile:

```ruby
source "https://rubygems.pkg.github.com/godaddy" do
  gem "asherah"
end
```

Platform-specific gems ship prebuilt native libraries for Linux
(x64/arm64, glibc and musl/Alpine) and macOS (x64/arm64). A fallback
source gem builds the native library at install time on other
platforms (requires the Rust toolchain).

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Entry points | Use when |
|---|---|---|
| Module-level | `Asherah.setup`, `Asherah.encrypt_string`, … | Configure once, encrypt/decrypt with a partition id. Drop-in compatible with the canonical `godaddy/asherah-ruby` API. |
| Factory / Session | `Asherah::SessionFactory`, `factory.get_session(id)`, `session.encrypt_bytes(...)` | Explicit lifecycle, multi-tenant isolation visible in code. |

The module-level API is a thin convenience wrapper over the
factory/session API. Pick by which one reads better at the call site.

## 3. Configure

Both styles take the same config hash (PascalCase keys to match the
canonical Ruby SDK):

```ruby
require "asherah"

# Testing-only static master key. Production must use AWS KMS;
# see aws-production-setup.md.
ENV["STATIC_MASTER_KEY_HEX"] = "22" * 32

CONFIG = {
  "ServiceName" => "my-service",
  "ProductID" => "my-product",
  "Metastore" => "memory",        # testing only — use "rdbms" or "dynamodb" in production
  "KMS" => "static",              # testing only — use "aws" in production
  "EnableSessionCaching" => true
}
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable values — changing them later
orphans existing envelope keys.

For the complete option table, see the **Configuration** section of
the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — module-level API

```ruby
Asherah.setup(CONFIG)
begin
  ciphertext = Asherah.encrypt_string("user-42", "secret")
  # Persist `ciphertext` (a JSON string) to your storage layer.

  # Later, after reading it back:
  plaintext = Asherah.decrypt_string("user-42", ciphertext)
  puts plaintext   # "secret"
ensure
  Asherah.shutdown
end
```

For binary payloads use `Asherah.encrypt_bytes(partition_id, bytes)` /
`Asherah.decrypt_bytes(partition_id, bytes)`.

## 5. Encrypt and decrypt — factory / session API

```ruby
require "asherah"
require "json"

factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
)
begin
  session = factory.get_session("user-42")
  begin
    encrypted = session.encrypt_bytes("secret")
    plaintext = session.decrypt_bytes(encrypted).force_encoding("UTF-8")
  ensure
    session.close
  end
ensure
  factory.close
end
```

Both factory and session need explicit `close` calls. The
`begin/ensure/end` idiom guarantees cleanup on exception.

## 6. Async API

Sync methods have `*_async` counterparts that release the GVL while
the native operation runs — other Ruby threads keep working:

```ruby
factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(CONFIG))
)
begin
  session = factory.get_session("user-42")
  begin
    encrypted = session.encrypt_bytes_async("hello")
    plaintext = session.decrypt_bytes_async(encrypted)
  ensure
    session.close
  end
ensure
  factory.close
end
```

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt
> paths. The native operation is sub-microsecond — async dispatch
> overhead is larger than the work itself for in-memory and warm
> cache scenarios. Use `*_async` from inside threaded servers
> (Puma, Falcon) where another Ruby thread can run while the
> metastore I/O is in flight.

## 7. Wire up observability

The simplest hook: hand Asherah a Ruby `Logger` (or any
Logger-compatible object — ActiveSupport::Logger, SemanticLogger,
Ougai). Asherah dispatches each record via `Logger#add` automatically.

```ruby
require "logger"

log = Logger.new($stdout)
log.level = Logger::WARN
Asherah.set_log_hook(log)
```

For full structured-event control, pass a block:

```ruby
Asherah.set_log_hook do |event|
  # event[:level]    => :trace | :debug | :info | :warn | :error
  # event[:severity] => Logger::Severity integer
  # event[:target]   => "asherah::session" etc
  # event[:message]  => "..."
  if event[:severity] >= Logger::WARN
    Rails.logger.warn("#{event[:target]}: #{event[:message]}")
  end
end

Asherah.set_metrics_hook do |event|
  # event[:type]        => :encrypt|:decrypt|:store|:load|:cache_hit|...
  # event[:duration_ns] => integer (nonzero for timing events)
  # event[:name]        => string (cache name) or nil
  case event[:type]
  when :encrypt, :decrypt
    StatsD.timing("asherah.#{event[:type]}", event[:duration_ns] / 1_000_000.0)
  when :cache_hit, :cache_miss, :cache_stale
    StatsD.increment("asherah.cache.#{event[:type]}", tags: ["cache:#{event[:name]}"])
  end
end
```

Hooks are process-global. `Asherah.clear_log_hook` /
`Asherah.clear_metrics_hook` deregister.

`Asherah.set_log_hook_sync` and `set_metrics_hook_sync` variants fire
on the encrypt/decrypt thread before the operation returns — pick
those if you need thread-local context (request IDs) intact in the
callback.

## 8. Move to production

The example uses `Metastore: "memory"` and `KMS: "static"` — both
**testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah surfaces errors via raised exceptions. Specific shapes and
what to check first are in
[`troubleshooting.md`](./troubleshooting.md).

Common shapes:
- `ArgumentError` — `nil` or empty where a value was required.
- `Asherah::Error` — wraps native errors (KMS failures, metastore
  errors, decrypt failures, malformed envelopes).

## What's next

- [`framework-integration.md`](./framework-integration.md) — Rails,
  Sidekiq, Sinatra, AWS Lambda.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/ruby/sample.rb) exercises
  every API style + async + log hook + metrics hook.
