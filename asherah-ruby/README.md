# Asherah Ruby

Ruby bindings for the Asherah envelope encryption and key rotation library.

Published to RubyGems with prebuilt native libraries for Linux (x86_64/aarch64)
and macOS (x86_64/arm64). Falls back to a source gem that requires the Rust
toolchain to compile.

## Features

- Envelope encryption with automatic key rotation
- Drop-in compatible API with the original GoDaddy Asherah Ruby SDK
- `Asherah.configure` block-style configuration
- `SessionFactory` for session management
- FFI-based native bindings via the `ffi` gem

## Quick Start

```ruby
require 'asherah'

Asherah.configure do |config|
  config.service_name = 'my-service'
  config.product_id = 'my-product'
  config.kms = 'static'
  config.metastore = 'memory'
end

factory = Asherah::SessionFactory.new
session = factory.get_session('partition')
encrypted = session.encrypt('hello world')
decrypted = session.decrypt(encrypted)
```

## Building

```bash
cd asherah-ruby
bundle install
ASHERAH_GEM_PLATFORM="x86_64-linux" gem build asherah.gemspec
```

## Testing

```bash
scripts/test.sh --bindings --platform=x64  # runs Ruby binding tests
```
