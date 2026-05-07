# asherah gRPC interop suite

End-to-end interoperability harness that proves (or disproves) drop-in
behavioral equivalence between the canonical Go reference asherah server
(`github.com/godaddy/asherah/server/go`) and our Rust implementation
(`asherah-server/`). Built because spec-by-vibe parity tests aren't
enough — every "drop-in compatible" claim should be backed by a test
that actually spawns both servers and compares observable behavior.

## What it tests

- **Wire-level assertion sweep**: connect, GetSession success, double-
  GetSession error, encrypt-before-session error, encrypt round-trip
  (DRR shape), decrypt round-trip (plaintext recovery). Run against
  both servers; the harness diffs the per-check pass/fail map.
- **Cross-decrypt**: encrypt with the Go server, decrypt with our
  Rust server (and vice versa) using a shared MySQL metastore + same
  static KMS key. The strongest possible cryptographic interop check.
- **Stderr capture**: both servers' stderr is captured and surfaced
  for diffing. Catches regressions in log line shape, level, and
  presence (the consumer's "no logs from gRPC server" complaint).

Not yet covered (planned follow-ups):
- TLS/socket-permission matrices
- Long-running stream and shutdown-drain timing
- Real KMS (LocalStack)

## Running

```bash
./run.sh
```

Requirements: `docker`, `docker compose`, `jq`. The driver builds three
images from source on first run, brings up MySQL, runs the suite, and
tears everything down. Exit 0 = behavior is equivalent on every
assertion, 1 = at least one divergence.

## What's in the box

```
interop-grpc/
├── README.md                # this file
├── go-ref-version.txt       # pinned godaddy/asherah commit SHA
├── Dockerfile.go-ref        # builds the Go server from a pinned commit
├── docker-compose.yml       # mysql + go-server + rust-server + client
├── run.sh                   # one-command driver
└── client/                  # Rust gRPC test client
    ├── Cargo.toml
    ├── build.rs
    ├── Dockerfile
    ├── proto/appencryption.proto
    └── src/main.rs
```

## Updating the Go reference pin

Edit `go-ref-version.txt` to a different SHA from
`github.com/godaddy/asherah` and re-run `./run.sh`. The Dockerfile
re-clones at build time; no submodule bookkeeping. We pin to a SHA
(not a moving branch) so divergence detection is reproducible.

## Blessed incompatibilities

A "drop-in" claim with zero divergences would be ideal but isn't
realistic. We track explicit deviations here:

| Behavior | Go reference | Rust server | Reason |
|---|---|---|---|
| Per-request log lines (`handling encrypt for X` etc.) | info, unconditional | debug, requires `--verbose` | Tenant identifier exposure (review 2026-05-05) |
| `ASHERAH_SOCKET` env var | not read | alias for `ASHERAH_SOCKET_FILE`, strips `unix://` | Consumer convenience; eliminates `unix://` URI mis-bind |
| `ASHERAH_SOCKET_MODE` env var | not read | optional; if unset, inherits umask (matches Go) | Hardening opt-in only — was a regression as a default |
| `RUST_LOG` env var | not read | honored when `--verbose` is unset | Power-user knob; verbose remains the canonical knob |

Every entry must point to a test in this suite that pins the divergence
so we can't accidentally regress *toward* parity by removing a
deliberate deviation.
