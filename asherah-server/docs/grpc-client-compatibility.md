# gRPC client compatibility notes

asherah-server is a Rust binary built on
[tonic](https://github.com/hyperium/tonic), which uses
[hyper](https://github.com/hyperium/hyper) and
[h2](https://github.com/hyperium/h2) for HTTP/2. This document captures
behavioral differences between asherah-server and the canonical
`github.com/godaddy/asherah/server/go` Go reference server that may
require **client-side** configuration changes when migrating.

asherah-server aims to be a drop-in replacement for the Go reference,
but the Rust HTTP/2 stack enforces RFC 9113 / RFC 3986 strictness in
places where Go's HTTP/2 implementation is permissive. Where the cost
of matching Go exactly would be a private fork of upstream crates, we
document the divergence here and ask consumers to make the small
client-side adjustment instead.

## `:authority` pseudo-header strictness

### Symptom

A previously-working consumer migrates the sidecar binary from the Go
reference to asherah-server and starts seeing a hang on the first gRPC
call followed by:

```
gRPC status code 13 (INTERNAL)
gRPC error message: "Received RST_STREAM with error code 1"
debug: UNKNOWN:Error received from peer
        {grpc_status:13, grpc_message:"Received RST_STREAM with error code 1"}
```

The asherah-server process logs the usual startup banner
(`listening on …` and any `asherah::*` warnings) but **emits zero
per-request log lines** even when `ASHERAH_VERBOSE=true` — the request
is rejected at the HTTP/2 framing layer before it reaches the gRPC
service code, so the per-request `handling get-session for X` debug
line never fires.

### Root cause

Every gRPC HTTP/2 request carries an `:authority` pseudo-header. For
TCP transports the authority is conventionally `host:port` and
everyone agrees. For Unix domain socket transports, gRPC C-Core (the
implementation underlying PHP, Python, Ruby, Node.js, and C++) defaults
the authority to a URL-encoded form of the socket path:

```
:authority   sockets%2Fproxy.sock
```

The Go reference server's HTTP/2 stack accepts any byte string here.
asherah-server's stack runs the value through
[`http::uri::Authority`](https://docs.rs/http/latest/http/uri/struct.Authority.html)
which enforces RFC 3986 with stricter rules than the spec's `reg-name`
production:

```
http::uri::Authority::from_str("sockets%2Fproxy.sock")
   -> Err(InvalidUri(InvalidAuthority))
http::uri::Authority::from_str("sockets/proxy.sock")
   -> Err(InvalidUri(InvalidUriChar))
http::uri::Authority::from_str("localhost")
   -> Ok(localhost)
```

When the parser rejects the value, h2 emits `RST_STREAM` with
`error_code = 1 (PROTOCOL_ERROR)` per RFC 9113 §8.3, and the request
never reaches the application. This is the same behavior every
tonic-based gRPC server exhibits — it's not asherah-specific. The
behavior is the same across h2 0.3 (tonic 0.12) and h2 0.4 (tonic 0.14),
so a tonic version downgrade is **not** a workaround.

The grpc-go client (used by Go callers) sends a different default
authority that happens to parse cleanly, which is why the issue did
not surface against the Go reference server.

### Fix

Pass an explicit `grpc.default_authority` option in the gRPC client
channel construction. Any RFC-compliant string works; `localhost` is
conventional and what we use in our own integration tests. The value
is opaque to asherah-server — it is not authenticated, validated
against the socket path, or otherwise consulted.

#### PHP (grpc/grpc-php)

```php
use Grpc\ChannelCredentials;
use Asherah\Apps\Server\AppEncryptionClient;

$client = new AppEncryptionClient($socket, [
    'credentials' => ChannelCredentials::createInsecure(),
    // Required for tonic/Rust asherah-server. Without this, the
    // PHP gRPC extension defaults :authority to the socket path,
    // which the Rust server rejects as PROTOCOL_ERROR.
    'grpc.default_authority' => 'localhost',
]);
```

#### Python (grpcio)

```python
import grpc

channel = grpc.insecure_channel(
    f"unix:{socket_path}",
    options=[("grpc.default_authority", "localhost")],
)
```

#### Ruby (grpc gem)

```ruby
stub = AppEncryptionService::Stub.new(
  "unix:#{socket_path}",
  :this_channel_is_insecure,
  channel_args: { "grpc.default_authority" => "localhost" },
)
```

#### Node.js (@grpc/grpc-js)

```javascript
const client = new AppEncryptionClient(
  `unix:${socketPath}`,
  grpc.credentials.createInsecure(),
  { 'grpc.default_authority': 'localhost' },
);
```

#### C++ (grpc++)

```cpp
grpc::ChannelArguments args;
args.SetString(GRPC_ARG_DEFAULT_AUTHORITY, "localhost");
auto channel = grpc::CreateCustomChannel(
    "unix:/sock/asherah.sock",
    grpc::InsecureChannelCredentials(),
    args);
```

#### Go (grpc-go) — already works

The grpc-go client constructs a different default authority that is
RFC-compliant. No change is required for Go consumers.

#### Java (grpc-java) — already works

grpc-java's HTTP/2 layer is built on Netty, which is permissive about
`:authority`. No change is required for Java consumers in our
integration tests, though if you migrate to a different gRPC client
implementation the same `defaultLoadBalancingPolicy`-style channel
override applies.

#### .NET (Grpc.Net.Client) — already works

Grpc.Net.Client uses the .NET HTTP stack, which sets
`:authority = host:port` for TCP and an RFC-clean placeholder for
UDS. No change is required.

### Why we don't fix this server-side

The validation lives in
[`http`](https://github.com/hyperium/http) and
[`h2`](https://github.com/hyperium/h2), upstream of tonic. There is no
configuration knob, feature flag, or tower middleware that can
intercept the rejection — RST_STREAM is emitted by h2 before the
request becomes a hyper or tonic request object. The only ways to
make asherah-server accept the C-Core default authority would be:

* Vendor a private fork of `h2` that loosens authority validation.
  Maintenance burden of keeping the fork rebased, and it diverges every
  tonic-based service in our workspace from the public crates.
* Insert a byte-level frame proxy between the listener and tonic that
  rewrites the `:authority` pseudo-header on incoming HEADERS frames.
  Doable but requires a careful HPACK-aware implementation.

We chose to document the divergence rather than carry either of those
costs. The client-side change is one constructor option, applied once
per binding language, and is forward-compatible with both the Go
reference server and asherah-server.

### Verifying the fix

After updating the client, the asherah-server stderr should show
per-request log lines on encrypt/decrypt traffic when run with
`ASHERAH_VERBOSE=true`:

```
[INFO  asherah_server] listening on /sock/asherah.sock (mode 0o660)
[DEBUG asherah_server::service] handling get-session for <partition>
[DEBUG asherah_server::service] handling encrypt for <partition>
[DEBUG asherah_server::service] closing session for <partition>
```

If the listening line appears but the per-request lines do not, the
client is still hitting the same `:authority` rejection. Confirm with
a packet trace via `socat -x -v UNIX-LISTEN:proxy.sock,fork
UNIX-CONNECT:asherah.sock` interposed between client and server: the
server's response to the first HEADERS frame should be a DATA/HEADERS
exchange, not `RST_STREAM error_code=1`.
