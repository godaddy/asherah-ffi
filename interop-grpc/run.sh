#!/usr/bin/env bash
# Drives the asherah gRPC interop suite.
#
# Builds the canonical Go reference server, our Rust server, and the
# interop client into local docker images; spins up MySQL + both servers;
# runs the client's assertion sweep against each in turn; diffs the JSON
# results; runs cross-decrypt (encrypt with one server, decrypt with the
# other via shared MySQL metastore + same KMS key); reports pass/fail.
#
# Exit code: 0 if behavior is equivalent in every assertion, 1 otherwise.
#
# Required: docker, docker compose, jq.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
ASHERAH_GO_REF="$(<"$HERE/go-ref-version.txt")"
COMPOSE_FILE="$HERE/docker-compose.yml"
PROJECT_NAME="asherah-interop"

# Use a fixed asherah env that matches the canonical Go server's accepted
# vars. ASHERAH_SOCKET_MODE=0666 here is a deliberate parity setting so
# the client (running as root in its container) can connect to either
# server's socket; production callers should set their own mode based on
# trust model.
export ASHERAH_SERVICE_NAME="${ASHERAH_SERVICE_NAME:-interop_service}"
export ASHERAH_PRODUCT_NAME="${ASHERAH_PRODUCT_NAME:-interop_product}"
export ASHERAH_METASTORE_MODE="${ASHERAH_METASTORE_MODE:-rdbms}"
export ASHERAH_CONNECTION_STRING="${ASHERAH_CONNECTION_STRING:-testuser:testpass@tcp(mysql:3306)/asherah}"
# Both servers default to KMS=static. The Go reference uses the hardcoded
# test key "thisIsAStaticMasterKeyForTesting"; our Rust binary falls back
# to the same 32 bytes (TEST_DEBUG_STATIC_MASTER_KEY_HEX is exactly the
# hex of that string) when StaticMasterKeyHex is unset, after the
# KMS=static / KMS=test-debug-static synonym fix. Cross-decrypt works
# end-to-end because both servers derive identical key material.
export ASHERAH_KMS_MODE="${ASHERAH_KMS_MODE:-static}"
export ASHERAH_VERBOSE="${ASHERAH_VERBOSE:-true}"
export ASHERAH_SOCKET_MODE="${ASHERAH_SOCKET_MODE:-0666}"

dc() {
  docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" "$@"
}

cleanup() {
  echo "--- cleanup ---"
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1" >&2
    exit 2
  }
}

step() {
  echo
  echo "==================== $* ===================="
}

require docker
require jq

step "build images"
docker build \
  --build-arg "ASHERAH_GO_REF=$ASHERAH_GO_REF" \
  -f "$HERE/Dockerfile.go-ref" \
  -t asherah-server-go-ref:interop \
  "$HERE"

# The asherah-server Dockerfile expects the workspace as build context.
docker build \
  -f "$REPO_ROOT/asherah-server/Dockerfile" \
  -t asherah-server-rust:interop \
  "$REPO_ROOT"

docker build \
  -f "$HERE/client/Dockerfile" \
  -t asherah-server-interop-client:interop \
  "$HERE/client"

step "bring up stack"
# `--wait` blocks until each container is running and (where defined)
# healthy. Without it, `docker compose up -d` returns mid-recreate and
# subsequent `dc run` calls race against half-replaced containers,
# producing "No such container: <sha>" daemon errors.
dc up -d --wait mysql go-server rust-server

# Wait for both sockets to be ready end-to-end (a successful encrypt
# implies metastore + KMS + bind are all working). We poll from inside
# the client image so it sees the same socket-volume bind. The first
# encrypt against either server is slow because it has to create the
# system key in the metastore and warm the KMS+MySQL pools — empirically
# 30-90s on the Go reference, much faster on subsequent calls — so the
# deadline has to be generous (180s here).
step "wait for sockets"
deadline=$(( $(date +%s) + 240 ))
for path in /sockets/go.sock /sockets/rust.sock; do
  attempt=0
  while :; do
    attempt=$((attempt+1))
    echo "  probe $path attempt=$attempt"
    # Per-attempt timeout (75s) is essential — without it, a single hung
    # `dc run` (e.g. tonic-client unable to negotiate h2c) blocks the
    # whole loop and the bash deadline check never fires. Empirically the
    # first encrypt against either server takes 30–90s for KMS+MySQL
    # warmup; subsequent attempts are sub-second.
    if timeout 75 dc run --rm -T --no-deps client \
        --socket "$path" --partition probe --payload probe encrypt \
        >/dev/null 2>&1; then
      echo "  $path ready"
      break
    fi
    if (( $(date +%s) > deadline )); then
      echo "timed out waiting for $path after $attempt attempts" >&2
      step "server logs (failure)"
      dc logs go-server || true
      dc logs rust-server || true
      exit 1
    fi
    sleep 2
  done
done

run_client() {
  local label="$1"; shift
  # Stdin is fed via the `<` redirect in cross-decrypt invocations; tonic
  # blocks on stdin EOF if we don't pass `-T` (no TTY) and a stdin source.
  dc run --rm -T --no-deps client "$@" \
    > "/tmp/${PROJECT_NAME}-${label}.json" \
    2> "/tmp/${PROJECT_NAME}-${label}.stderr" \
  && rc=0 || rc=$?
  echo "$rc" > "/tmp/${PROJECT_NAME}-${label}.rc"
  return 0
}

diff_results() {
  local a="$1" b="$2"
  # Strip the `detail` field — it carries lengths/text that may legitimately
  # differ (timestamps, ID formats). We diff the per-check pass/fail map only.
  jq -s '
    (.[0] | map({check, pass})) as $a
    | (.[1] | map({check, pass})) as $b
    | {a:$a, b:$b, equivalent: ($a == $b)}
  ' "/tmp/${PROJECT_NAME}-${a}.json.lines" "/tmp/${PROJECT_NAME}-${b}.json.lines"
}

to_jq_array() {
  # The client emits one JSON object per line; jq -s 'inputs' would also
  # work but `--slurp` wraps in an array which is what we want.
  jq -s '.' "/tmp/${PROJECT_NAME}-${1}.json" \
    > "/tmp/${PROJECT_NAME}-${1}.json.lines"
}

step "run assertion suite vs Go server"
run_client go --socket /sockets/go.sock --partition interop-partition --payload "hello, asherah" suite
to_jq_array go

step "run assertion suite vs Rust server"
run_client rust --socket /sockets/rust.sock --partition interop-partition --payload "hello, asherah" suite
to_jq_array rust

step "compare suite results"
diff_results go rust | tee "/tmp/${PROJECT_NAME}-compare.json"
equivalent=$(jq -r '.equivalent' "/tmp/${PROJECT_NAME}-compare.json")

step "cross-decrypt: encrypt-with-Go decrypt-with-Rust"
run_client encgo --socket /sockets/go.sock --partition cross --payload "cross-decrypt-payload" encrypt
run_client decrust --socket /sockets/rust.sock --partition cross --payload "cross-decrypt-payload" decrypt < "/tmp/${PROJECT_NAME}-encgo.json"
go_to_rust=$(jq -r '.plaintext_match // false' "/tmp/${PROJECT_NAME}-decrust.json")

step "cross-decrypt: encrypt-with-Rust decrypt-with-Go"
run_client encrust --socket /sockets/rust.sock --partition cross --payload "cross-decrypt-payload" encrypt
run_client decgo --socket /sockets/go.sock --partition cross --payload "cross-decrypt-payload" decrypt < "/tmp/${PROJECT_NAME}-encrust.json"
rust_to_go=$(jq -r '.plaintext_match // false' "/tmp/${PROJECT_NAME}-decgo.json")

step "stderr divergence (informational)"
echo "--- go stderr ---"; cat "/tmp/${PROJECT_NAME}-go.stderr" || true
echo "--- rust stderr ---"; cat "/tmp/${PROJECT_NAME}-rust.stderr" || true

step "result"
echo "suite-equivalent: $equivalent"
echo "go-encrypt -> rust-decrypt: $go_to_rust"
echo "rust-encrypt -> go-decrypt: $rust_to_go"

if [[ "$equivalent" == "true" && "$go_to_rust" == "true" && "$rust_to_go" == "true" ]]; then
  echo "INTEROP: PASS"
  exit 0
else
  echo "INTEROP: FAIL"
  exit 1
fi
