# asherah-server

gRPC sidecar for Asherah envelope encryption. Runs as a Unix-domain-socket
gRPC server that any language with a gRPC client can drive — PHP, Python,
Ruby, Node.js, Java, .NET, Go, C++, Rust. The wire protocol is identical
to the canonical [`github.com/godaddy/asherah/server/go`](https://github.com/godaddy/asherah/tree/master/server/go)
reference server, so existing client code works against either binary.

Use this when:

* You need Asherah from a runtime without a maintained native binding
  (PHP is the canonical case), or
* You want one process per host owning the KMS / metastore connections
  with multiple language runtimes calling in over a unix socket.

If you're writing Go, Java, Node, Python, .NET, or Ruby and don't have
a sidecar requirement, prefer the in-process bindings:
[`asherah-go`](../asherah-go/), [`asherah-java`](../asherah-java/),
[`asherah-node`](../asherah-node/), [`asherah-py`](../asherah-py/),
[`asherah-dotnet`](../asherah-dotnet/), [`asherah-ruby`](../asherah-ruby/).
They give you a single-process call without the gRPC hop, and they
expose log hooks, metrics hooks, and observability that the gRPC API
cannot wire through.

## Documentation

| Guide | When to read |
|---|---|
| [gRPC client compatibility](./docs/grpc-client-compatibility.md) | Before connecting any non-Go client. Documents the one client-side option (`grpc.default_authority`) that PHP/Python/Ruby/Node/C++ callers must set. |
| [Migration from the Go reference server](#migration-from-the-go-reference-server) | Upgrading an existing deployment from `godaddy/asherah/server/go`. |
| [Observability](#observability) | Log levels, verbose mode, per-request lines, what reaches stderr at default verbosity. |
| [Drop-in compatibility ledger](../interop-grpc/README.md) | What `asherah-server` does identically to the Go reference, what it does deliberately differently, and why. Includes a Docker Compose harness that runs both servers side-by-side and asserts equivalence. |

## Quick start

### Docker

```bash
docker build -t asherah-server -f asherah-server/Dockerfile .
docker run --rm \
  -e ASHERAH_SERVICE_NAME=my-service \
  -e ASHERAH_PRODUCT_NAME=my-product \
  -e ASHERAH_METASTORE_MODE=memory \
  -e ASHERAH_KMS_MODE=static \
  -v /tmp/asherah-sock:/sock \
  asherah-server --socket-file=/sock/asherah.sock
```

For a non-trivial deployment with MySQL + AWS KMS, see
[the interop-grpc Docker Compose harness](../interop-grpc/docker-compose.yml).

### Binary

```bash
cargo build --release -p asherah-server
./target/release/asherah-server \
  --service my-service \
  --product my-product \
  --metastore memory \
  --kms static \
  --socket-file /tmp/asherah.sock
```

### Quick smoke test

In a second terminal, dial the socket from any gRPC client. Python:

```python
import grpc, appencryption_pb2, appencryption_pb2_grpc

# IMPORTANT: the grpc.default_authority option is required for tonic.
# See docs/grpc-client-compatibility.md.
channel = grpc.insecure_channel(
    "unix:/tmp/asherah.sock",
    options=[("grpc.default_authority", "localhost")],
)
stub = appencryption_pb2_grpc.AppEncryptionStub(channel)

def gen():
    yield appencryption_pb2.SessionRequest(
        get_session=appencryption_pb2.GetSession(partition_id="user-42"))
    yield appencryption_pb2.SessionRequest(
        encrypt=appencryption_pb2.Encrypt(data=b"secret"))

for resp in stub.Session(gen(), timeout=10):
    print(resp)
```

Generate `appencryption_pb2*.py` from
[`proto/appencryption.proto`](./proto/appencryption.proto) with
`python -m grpc_tools.protoc`.

## Configuration

`asherah-server` accepts the same env vars and CLI flags as the Go
reference server. Every flag has both a long form and an `ASHERAH_*` env
var; CLI takes precedence over env var.

### Required

| Env var | Flag | Description |
|---|---|---|
| `ASHERAH_SERVICE_NAME` | `--service` | Service name (becomes part of every key ID) |
| `ASHERAH_PRODUCT_NAME` | `--product`  | Product name (becomes part of every key ID) |
| `ASHERAH_METASTORE_MODE` | `--metastore` | `memory`, `rdbms`, or `dynamodb` |
| `ASHERAH_KMS_MODE` | `--kms` | `aws`, `static`, or `test-debug-static` |

### Socket

| Env var | Flag | Default | Description |
|---|---|---|---|
| `ASHERAH_SOCKET_FILE` | `-s`, `--socket-file` | `/tmp/appencryption.sock` | Filesystem path for the listening Unix socket. Same name as Go reference. |
| `ASHERAH_SOCKET` | `--socket` | (none) | Alias for `--socket-file`. asherah-ffi extension. Strips a leading `unix://` prefix so a gRPC client dial URI can be reused as a server bind value without errors. |
| `ASHERAH_SOCKET_MODE` | `--socket-mode` | (umask, typically `0666`) | Octal mode applied via `chmod` after bind. Set explicitly (e.g. `0660`) for multi-tenant hosts; default matches Go reference's `chmod`-free behavior. |

### Metastore

| Env var | Flag | Description |
|---|---|---|
| `ASHERAH_CONNECTION_STRING` | `--conn` | DSN for `--metastore=rdbms`. Accepts both Go MySQL DSN format (`user:pass@tcp(host:port)/db`) and standard `mysql://` / `postgres://` URLs. |
| `ASHERAH_DYNAMODB_ENDPOINT` | `--dynamodb-endpoint` | DynamoDB endpoint URL override (only with `--metastore=dynamodb`) |
| `ASHERAH_DYNAMODB_REGION` | `--dynamodb-region` | DynamoDB region (defaults to globally-configured region) |
| `ASHERAH_DYNAMODB_TABLE_NAME` | `--dynamodb-table-name` | DynamoDB table name (default `EncryptionKey`) |
| `ASHERAH_REPLICA_READ_CONSISTENCY` | `--replica-read-consistency` | `eventual`, `global`, `session` (Aurora write-forwarding only) |
| `ASHERAH_ENABLE_REGION_SUFFIX` | `--enable-region-suffix` | Append region to keys (DynamoDB only) |

The required schema for `--metastore=rdbms` is the same as the Go
reference's `metastore.sql`:

```sql
CREATE TABLE encryption_key (
  id          VARCHAR(255) NOT NULL,
  created     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  key_record  TEXT         NOT NULL,
  PRIMARY KEY (id, created),
  INDEX (created)
);
```

This works against MySQL 5.7+, MySQL 8.x, MariaDB, and Postgres
(replace `INDEX(created)` with `CREATE INDEX … ON encryption_key(created)`
on Postgres).

### KMS

| Env var | Flag | Description |
|---|---|---|
| `ASHERAH_REGION_MAP` | `--region-map` | `REGION1=ARN1,REGION2=ARN2` (required for `--kms=aws`) |
| `ASHERAH_PREFERRED_REGION` | `--preferred-region` | Preferred AWS region (required for `--kms=aws`) |
| `ASHERAH_AWS_PROFILE_NAME` | `--aws-profile-name` | AWS shared-credentials profile name |

`--kms=static` and `--kms=test-debug-static` are exact synonyms. Both
fall back to the canonical Asherah test key
(`thisIsAStaticMasterKeyForTesting`) when `StaticMasterKeyHex` is not
provided. For production you must use `--kms=aws`.

### Caching / lifecycle

| Env var | Flag | Default | Description |
|---|---|---|---|
| `ASHERAH_EXPIRE_AFTER` | `--expire-after` | (no expiry) | Key validity window (Go-style duration: `60m`, `2h`, `24h`) |
| `ASHERAH_CHECK_INTERVAL` | `--check-interval` | (no revalidation) | Cached key staleness check interval |
| `ASHERAH_ENABLE_SESSION_CACHING` | `--enable-session-caching` | `true` | Enable shared session cache |
| `ASHERAH_SESSION_CACHE_MAX_SIZE` | `--session-cache-max-size` | `1000` | Max sessions to cache |
| `ASHERAH_SESSION_CACHE_DURATION` | `--session-cache-duration` | `2h` | Session cache TTL |
| `ASHERAH_SHUTDOWN_DRAIN_TIMEOUT` | `--shutdown-drain-timeout` | `5s` | Drain deadline on SIGTERM/SIGINT |

### Logging

| Env var | Flag | Description |
|---|---|---|
| `ASHERAH_VERBOSE` | `-v`, `--verbose` | Forces filter `info,asherah=debug,asherah_server=debug`, overriding `RUST_LOG`. Mirrors the Go reference's verbose flag. |
| `RUST_LOG` | (env only) | Standard env_logger directive. Honored only when `--verbose` is unset. Default filter is `info`. |

See [Observability](#observability) below for what each level emits.

## Client integration

asherah-server speaks the canonical
[`appencryption.proto`](./proto/appencryption.proto). Generate clients
with `protoc` for your language and dial the socket with `unix:` URI
scheme. Every grpc-core-based language (PHP, Python, Ruby, Node.js,
C++) **must** pass `grpc.default_authority => "localhost"` as a channel
option — see [docs/grpc-client-compatibility.md](./docs/grpc-client-compatibility.md)
for the full explanation.

### PHP (`grpc/grpc-php`)

```php
use Grpc\ChannelCredentials;
use Asherah\Apps\Server\AppEncryptionClient;

$client = new AppEncryptionClient($socket, [
    'credentials' => ChannelCredentials::createInsecure(),
    'grpc.default_authority' => 'localhost',  // REQUIRED
]);

$call = $client->Session();
$call->write((new SessionRequest())->setGetSession(
    (new GetSession())->setPartitionId('user-42')));
$call->read();  // empty SessionResponse on success

$call->write((new SessionRequest())->setEncrypt(
    (new Encrypt())->setData('secret')));
$encResponse = $call->read();
$drr = $encResponse->getEncryptResponse()->getDataRowRecord();

$call->writesDone();
```

### Python (`grpcio`)

```python
import grpc
import appencryption_pb2 as pb
import appencryption_pb2_grpc as rpc

channel = grpc.insecure_channel(
    f"unix:{socket_path}",
    options=[("grpc.default_authority", "localhost")],  # REQUIRED
)
stub = rpc.AppEncryptionStub(channel)

def messages():
    yield pb.SessionRequest(get_session=pb.GetSession(partition_id="user-42"))
    yield pb.SessionRequest(encrypt=pb.Encrypt(data=b"secret"))

for resp in stub.Session(messages(), timeout=10):
    if resp.HasField("encrypt_response"):
        drr = resp.encrypt_response.data_row_record
```

### Ruby (`grpc` gem)

```ruby
require "appencryption_services_pb"

stub = Asherah::Apps::Server::AppEncryption::Stub.new(
  "unix:#{socket_path}",
  :this_channel_is_insecure,
  channel_args: { "grpc.default_authority" => "localhost" },  # REQUIRED
)

requests = Enumerator.new do |y|
  y << Asherah::Apps::Server::SessionRequest.new(
    get_session: Asherah::Apps::Server::GetSession.new(partition_id: "user-42"))
  y << Asherah::Apps::Server::SessionRequest.new(
    encrypt: Asherah::Apps::Server::Encrypt.new(data: "secret"))
end

stub.session(requests).each do |resp|
  # ...
end
```

### Node.js (`@grpc/grpc-js`)

```javascript
const grpc = require('@grpc/grpc-js');
const proto = require('./appencryption_pb.js');
const services = require('./appencryption_grpc_pb.js');

const client = new services.AppEncryptionClient(
  `unix:${socketPath}`,
  grpc.credentials.createInsecure(),
  { 'grpc.default_authority': 'localhost' },  // REQUIRED
);

const call = client.session();
call.write(new proto.SessionRequest().setGetSession(
  new proto.GetSession().setPartitionId('user-42')));
call.write(new proto.SessionRequest().setEncrypt(
  new proto.Encrypt().setData(Buffer.from('secret'))));
call.on('data', (resp) => { /* ... */ });
call.end();
```

### Go (`google.golang.org/grpc`) — no authority override needed

```go
import (
    pb "github.com/godaddy/asherah/server/go/api"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

conn, err := grpc.NewClient("unix:"+socketPath,
    grpc.WithTransportCredentials(insecure.NewCredentials()))
client := pb.NewAppEncryptionClient(conn)
stream, _ := client.Session(ctx)
stream.Send(&pb.SessionRequest{Request: &pb.SessionRequest_GetSession{
    GetSession: &pb.GetSession{PartitionId: "user-42"},
}})
resp, _ := stream.Recv()
```

The grpc-go HTTP/2 stack constructs an RFC-compliant default authority,
so no extra option is needed. See
[grpc-client-compatibility.md](./docs/grpc-client-compatibility.md) for
the explanation of why other languages need it.

### Java (`grpc-java`) — no authority override needed

```java
ManagedChannel channel = NettyChannelBuilder
    .forAddress(new DomainSocketAddress(socketPath))
    .eventLoopGroup(new EpollEventLoopGroup())
    .channelType(EpollDomainSocketChannel.class)
    .usePlaintext()
    .build();

AppEncryptionGrpc.AppEncryptionStub stub = AppEncryptionGrpc.newStub(channel);
StreamObserver<SessionRequest> requestObserver = stub.session(responseObserver);
requestObserver.onNext(SessionRequest.newBuilder()
    .setGetSession(GetSession.newBuilder().setPartitionId("user-42"))
    .build());
```

The Netty-based HTTP/2 layer that grpc-java uses sets a permissive
default authority; no override needed.

### .NET (`Grpc.Net.Client`) — no authority override needed

```csharp
using var channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
{
    HttpHandler = new SocketsHttpHandler
    {
        ConnectCallback = async (ctx, ct) =>
        {
            var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await sock.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct);
            return new NetworkStream(sock, ownsSocket: true);
        },
    },
});
var client = new AppEncryption.AppEncryptionClient(channel);
using var call = client.Session();
await call.RequestStream.WriteAsync(new SessionRequest { GetSession = new GetSession { PartitionId = "user-42" }});
```

## Migration from the Go reference server

`asherah-server` is wire-compatible with `godaddy/asherah/server/go`:
identical `appencryption.proto` definition, identical metastore schema,
identical KMS key derivation. Existing clients keep working *with the
caveat in the next paragraph*. Existing metastore data is portable
without re-encryption.

**Required client-side change for grpc-core languages**: PHP, Python,
Ruby, Node.js, and C++ clients must add `'grpc.default_authority' =>
'localhost'` to their channel options. This is a one-line constructor
change per binding language and is forward-compatible with the Go
reference. See
[docs/grpc-client-compatibility.md](./docs/grpc-client-compatibility.md).
Go, Java, and .NET clients work unchanged.

**Env var compatibility**: every `ASHERAH_*` env var the Go reference
reads is honored identically by `asherah-server`. The full list is in
[Configuration](#configuration) above.

**CLI flag compatibility**: every flag the Go reference exposes is
honored identically. Two extensions:

* `--socket` / `ASHERAH_SOCKET` is a courtesy alias for `--socket-file`
  that strips a leading `unix://` URI prefix. The Go reference does not
  read `ASHERAH_SOCKET`; clients commonly export it as a dial URI.
* `--socket-mode` / `ASHERAH_SOCKET_MODE` lets you set the listening
  socket's mode after bind (e.g. `0660`). The Go reference does not
  expose this.

**Behavioral divergences** (intentional, documented in
[interop-grpc/README.md](../interop-grpc/README.md)):

* Per-request `handling encrypt|decrypt|get-session for <partition>`
  log lines are emitted at **debug**, not info. Set
  `ASHERAH_VERBOSE=true` to see them. Rationale: partition IDs are
  tenant identifiers and should not log at default verbosity.
* `RUST_LOG` is honored when `--verbose` is unset. The Go reference
  has no `RUST_LOG` analog.

## Observability

asherah-server emits all logs to **stderr**. There is no built-in
metrics endpoint; for metrics use the in-process language bindings
instead.

### Log levels

| Filter | What's logged |
|---|---|
| Default (`info`) | Startup banner (`listening on …`), shutdown banner, asherah-crate WARN/ERROR (e.g. "Using static master key", cache policy warnings). No per-request lines. |
| `--verbose` / `ASHERAH_VERBOSE=true` | Adds: per-request lines (`handling encrypt|decrypt|get-session for <partition>`, `closing session for <partition>`), metastore load/store debug, KMS encrypt/decrypt debug. |
| Custom `RUST_LOG` | Any env_logger directive. Honored only when `--verbose` is unset. |

`--verbose` overrides any `RUST_LOG` setting unconditionally to ensure
the asherah-crate stream surfaces (matching the Go reference's posture
that verbose is the primary logging knob).

### Per-request log shape

```
[2026-05-07T13:53:54Z DEBUG asherah_server::service] handling get-session for user-42
[2026-05-07T13:53:54Z DEBUG asherah_server::service] handling encrypt for user-42
[2026-05-07T13:53:54Z DEBUG asherah_server::service] closing session for user-42
```

`<partition>` is the caller-supplied `partition_id` from `GetSession`.
Treat it as a tenant identifier in your log retention / access policy.

### "Listening on … then nothing" symptom

If you see the startup banner but no per-request lines under
`ASHERAH_VERBOSE=true`, the request isn't reaching the server's
handler. The most likely cause is HTTP/2 `:authority` strictness — see
[docs/grpc-client-compatibility.md](./docs/grpc-client-compatibility.md).

## Operational concerns

### Socket permissions

By default the socket inherits the process umask (typically `0666`) —
matches the Go reference. Set `--socket-mode=0660` on a multi-tenant
host where you don't want every local UID to be able to encrypt /
decrypt arbitrary records via the sidecar.

If the socket bind succeeds but clients get `EACCES`, check:

* The asherah-server process UID/GID and the client process UID/GID.
  They need a shared group (or the same UID) for `0660` to grant
  access.
* The path (e.g. `/sock/asherah.sock`) — the **directory** must be
  traversable (`x` bit) by the client UID, even if the socket itself
  is permissive.

### Graceful shutdown

asherah-server listens for `SIGTERM` and `SIGINT`. On signal:

1. Stops accepting new gRPC streams.
2. Waits up to `--shutdown-drain-timeout` (default `5s`) for in-flight
   sessions to finish their current operation. Increase for long-lived
   streaming clients.
3. Force-cancels stragglers and runs `Session::close()` on each
   session (frees memguard-locked pages, evicts the IK cache).
4. Removes the socket file.

### Container deployment

The image at [`asherah-server/Dockerfile`](./Dockerfile) is multi-stage
and produces a ~30 MB `debian:bookworm-slim`-based runtime image.
Cross-compilation for arm64 is configured; a single `docker buildx`
invocation produces both x86_64 and arm64 images.

The Docker Compose example at
[`interop-grpc/docker-compose.yml`](../interop-grpc/docker-compose.yml)
shows asherah-server running alongside MariaDB and the Go reference
server, with shared sockets via a volume. That harness is also the
side-by-side regression test suite for the canonical Go server's
behavior — see [`interop-grpc/README.md`](../interop-grpc/README.md).

## Building from source

```bash
cargo build --release -p asherah-server
```

Default features include `mysql`, `postgres`, `dynamodb`. Disable any
of them with `--no-default-features --features mysql,postgres` etc.

The proto file is at [`proto/appencryption.proto`](./proto/appencryption.proto)
and is byte-identical to the Go reference's
`server/protos/appencryption.proto` modulo trailing whitespace and
typo-fix comments.

## Reference

### Full CLI

Run `asherah-server --help` for the authoritative list of flags and env
vars.

A working gRPC client implementation in Rust (using tonic) lives at
[`interop-grpc/client/`](../interop-grpc/client/) and is what our
side-by-side regression suite drives. It mirrors the typical
session-stream lifecycle (GetSession → Encrypt → Decrypt) and is a
useful reference when porting to a new language.

### Proto

```protobuf
service AppEncryption {
  rpc Session (stream SessionRequest) returns (stream SessionResponse);
}
```

The `Session` RPC is bidirectional streaming. A client opens one
stream, sends a `GetSession` (with `partition_id`), then any number of
`Encrypt` and `Decrypt` requests interleaved on that stream. The
session is implicitly closed when the client `writesDone()` or the
underlying connection drops.

The full message types are in
[`proto/appencryption.proto`](./proto/appencryption.proto).

## License

Apache-2.0. See [`LICENSE`](../LICENSE) at the repo root.
