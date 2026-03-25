# Asherah Server

gRPC sidecar server for Asherah envelope encryption. Provides a language-agnostic
RPC interface over Unix domain sockets, compatible with the original GoDaddy
Asherah server protocol.

## Features

- gRPC API for encrypt/decrypt operations
- Unix domain socket transport
- Configurable via CLI flags or environment variables
- Session caching with configurable expiry
- All KMS and metastore backends supported (static, AWS KMS; memory, SQLite, MySQL, PostgreSQL, DynamoDB)

## Usage

```bash
cargo run -p asherah-server -- \
  --socket /tmp/asherah.sock \
  --service-name my-service \
  --product-id my-product \
  --metastore memory \
  --kms static
```

## Building

```bash
cargo build --release -p asherah-server
```

## Proto Definition

The gRPC service definition is at `proto/appencryption.proto`.
