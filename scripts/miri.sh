#!/usr/bin/env bash
# Run Miri tests for undefined behavior detection.
#
# Miri requires nightly Rust. On systems where Homebrew rustc/cargo are first
# in PATH, we need to point CARGO at the nightly toolchain binary directly.
#
# Usage:
#   ./scripts/miri.sh          # run all Miri-compatible tests
#   ./scripts/miri.sh <filter> # run tests matching filter

set -euo pipefail

NIGHTLY_DIR="$HOME/.rustup/toolchains/nightly-$(rustc -vV | awk '/^host:/ {print $2}')/bin"

if [[ ! -x "$NIGHTLY_DIR/cargo-miri" ]]; then
    echo "Installing miri component for nightly toolchain..."
    rustup +nightly component add miri rust-src
fi

CARGO_MIRI="$NIGHTLY_DIR/cargo-miri"
export CARGO="$NIGHTLY_DIR/cargo"

FILTER="${1:-}"

echo "=== Miri: asherah (memguard pointer arithmetic, pure functions) ==="
"$CARGO_MIRI" miri test -p asherah --test miri $FILTER

echo ""
echo "=== Miri: asherah unit tests (partition, types, builders, kms) ==="
# Exclude memcall tests — they use mmap/mlock/mprotect FFI that Miri can't run
"$CARGO_MIRI" miri test -p asherah --lib -- --skip memcall $FILTER

echo ""
echo "=== Miri: asherah-cobhan unit tests (buffer pointer ops) ==="
"$CARGO_MIRI" miri test -p asherah-cobhan --lib $FILTER

echo ""
echo "All Miri tests passed."
