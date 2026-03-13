# Asherah Samples

Minimal encrypt/decrypt examples for each supported language.

All samples use an in-memory metastore with a static master key for simplicity.
**Do not use a static master key in production** — use `kms: "aws"` with a proper
region map instead.

## Rust

Uses path dependencies to the `asherah` and `asherah-config` crates in this repo.

```sh
cargo run --manifest-path samples/rust/Cargo.toml
```

## Go

Uses the `github.com/godaddy/asherah-go` module. The native library must be
available — either build it from this repo or install a prebuilt binary:

```sh
go run github.com/godaddy/asherah-go/cmd/install-native@latest
cd samples/go && go run .
```

## Node.js / TypeScript

Uses the [`asherah`](https://www.npmjs.com/package/asherah) npm package which
includes prebuilt native bindings for all platforms.

```sh
cd samples/node && npm install && node index.mjs
```

## Python

Requires the `asherah-py` package. Build and install from this repo using maturin:

```sh
pip install maturin
maturin develop --manifest-path asherah-py/Cargo.toml
python samples/python/sample.py
```

## Ruby

Requires the `ffi` gem and the `libasherah_ffi` native library. Build the native
library from this repo, then run with the local binding:

```sh
cargo build --release -p asherah-ffi
gem install ffi
ruby -Iasherah-ruby/lib samples/ruby/sample.rb
```
