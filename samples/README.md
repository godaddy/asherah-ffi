# Asherah Samples

Complete examples for each supported language, demonstrating:

1. **Static API** — simplest pattern (setup, encrypt, decrypt, shutdown)
2. **Factory/Session API** — recommended for applications (session reuse, partition isolation)
3. **Async API** — non-blocking patterns for event loops and concurrent applications
4. **Production config** — commented-out examples showing RDBMS + AWS KMS

All samples default to in-memory metastore with a static master key for local
development. **Do not use memory metastore or static KMS in production** — use
`rdbms`/`dynamodb` with `aws` KMS instead. Each sample includes a commented-out
production config example.

## Rust

```sh
cargo run --manifest-path samples/rust/Cargo.toml
```

Covers: Factory/Session API, JSON interop (DataRowRecord serialization), async
via tokio runtime.

## Node.js

```sh
cd samples/node && npm install && node index.mjs
```

Covers: Static API (string + Buffer), Session/Factory API with partition
isolation, async API (setupAsync/encryptStringAsync/decryptStringAsync).

## Python

```sh
pip install maturin
maturin develop --manifest-path asherah-py/Cargo.toml
python samples/python/sample.py
```

Covers: Static API (string + bytes), Session/Factory API with context managers,
async API via asyncio.

## C# / .NET

```sh
cargo build --release -p asherah-ffi
ASHERAH_DOTNET_NATIVE=target/release dotnet run --project samples/dotnet
```

Covers: Static API, Factory/Session API with `using` disposal, async API
(true async via Rust tokio — does not block .NET thread pool).

## Java

```sh
cargo build -p asherah-java
mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true package -DskipTests
javac -cp asherah-java/java/target/appencryption-*.jar samples/java/Sample.java
java -Dasherah.java.nativeLibraryPath=target/debug \
     -cp "asherah-java/java/target/appencryption-*.jar:samples/java" Sample
```

Covers: Static API, Factory/Session API (try-with-resources), async API
via CompletableFuture.

## Go

```sh
cargo build --release -p asherah-ffi
cd samples/go && go run .
```

Covers: Global API, Factory/Session API, concurrent goroutine example with
sync.WaitGroup (Go uses goroutines instead of async/await).

## Ruby

```sh
cargo build --release -p asherah-ffi
gem install ffi
ruby -Iasherah-ruby/lib samples/ruby/sample.rb
```

Covers: Static API, Session/Factory API, async API (tokio callback via FFI).
