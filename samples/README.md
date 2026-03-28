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

Uses a path reference to the `asherah-go` binding in this repo. The native
library must be built first:

```sh
cargo build --release -p asherah-ffi
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

## C# / .NET

Uses a project reference to the `GoDaddy.Asherah.AppEncryption` project in this repo. The native
library must be built first:

```sh
cargo build --release -p asherah-ffi
ASHERAH_DOTNET_NATIVE=target/release dotnet run --project samples/dotnet
```

## Java

Uses the `asherah-java` binding in this repo. Build the native library and the
Java jar, then compile and run:

```sh
cargo build -p asherah-java
mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true package -DskipTests
javac -cp asherah-java/java/target/asherah-java-0.1.0-SNAPSHOT.jar samples/java/Sample.java
java -Dasherah.java.nativeLibraryPath=target/debug \
     -cp asherah-java/java/target/asherah-java-0.1.0-SNAPSHOT.jar:samples/java Sample
```

## Ruby

Requires the `ffi` gem and the `libasherah_ffi` native library. Build the native
library from this repo, then run with the local binding:

```sh
cargo build --release -p asherah-ffi
gem install ffi
ruby -Iasherah-ruby/lib samples/ruby/sample.rb
```
