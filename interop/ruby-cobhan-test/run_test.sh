#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RUBY="${RUBY:-$(command -v ruby)}"
BUNDLE="${BUNDLE:-$(dirname "$RUBY")/bundle}"
NODE="${NODE:-$(command -v node)}"

export STATIC_MASTER_KEY_HEX="2222222222222222222222222222222222222222222222222222222222222222"

echo "=== Building asherah-cobhan ==="
cargo build --release -p asherah-cobhan --manifest-path "$ROOT_DIR/Cargo.toml"

echo "=== Installing gem dependencies ==="
cd "$SCRIPT_DIR"
"$BUNDLE" install --quiet

# Determine platform-specific library name
case "$(uname -s)" in
  Darwin) EXT="dylib" ;;
  Linux)  EXT="so" ;;
  *)      echo "Unsupported OS"; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="x64" ;;
  *)             echo "Unsupported arch"; exit 1 ;;
esac

NATIVE_DIR="$("$BUNDLE" info asherah --path)/lib/asherah/native"
CANONICAL_LIB="$NATIVE_DIR/libasherah-${ARCH}.${EXT}"
OUR_LIB="$ROOT_DIR/target/release/libasherah_cobhan.${EXT}"

if [ ! -f "$OUR_LIB" ]; then
  echo "Error: $OUR_LIB not found"
  exit 1
fi

# Back up the canonical library
if [ -f "$CANONICAL_LIB" ] && [ ! -f "$CANONICAL_LIB.orig" ]; then
  cp "$CANONICAL_LIB" "$CANONICAL_LIB.orig"
fi

TMPDIR="$(mktemp -d)"

cleanup() {
  if [ -f "$CANONICAL_LIB.orig" ]; then
    mv "$CANONICAL_LIB.orig" "$CANONICAL_LIB"
  fi
  rm -rf "$TMPDIR" 2>/dev/null
}
trap cleanup EXIT

STATUS=0

# ── Part 1: Drop-in replacement test (Rust cobhan + canonical Ruby gem) ──

echo
echo "=== Part 1: Drop-in replacement (Rust cobhan + canonical asherah-ruby gem) ==="

cp "$OUR_LIB" "$CANONICAL_LIB"
"$BUNDLE" exec "$RUBY" "$SCRIPT_DIR/test_interop.rb" || STATUS=1

# ── Part 2: Cross-language Ruby ↔ Node.js (both using our Rust core) ──

echo
echo "=== Part 2: Cross-language interop (Ruby ↔ Node.js via shared SQLite) ==="

export ASHERAH_SQLITE_PATH="$TMPDIR/asherah_keys.db"

# Ensure Rust cobhan is active for Ruby
cp "$OUR_LIB" "$CANONICAL_LIB"

# 2a: Ruby encrypts → Node.js decrypts
echo
echo "--- Ruby encrypts ---"
IMPL_LABEL="Ruby" "$BUNDLE" exec "$RUBY" "$SCRIPT_DIR/cross_language_encrypt.rb" "$TMPDIR/ruby_encrypted.json" || STATUS=1

echo
echo "--- Node.js decrypts Ruby ciphertexts ---"
"$NODE" "$SCRIPT_DIR/node_decrypt.js" "$TMPDIR/ruby_encrypted.json" || STATUS=1

# 2b: Node.js encrypts → Ruby decrypts
echo
echo "--- Node.js encrypts ---"
"$NODE" "$SCRIPT_DIR/node_encrypt.js" "$TMPDIR/node_encrypted.json" || STATUS=1

echo
echo "--- Ruby decrypts Node.js ciphertexts ---"
IMPL_LABEL="Ruby" "$BUNDLE" exec "$RUBY" "$SCRIPT_DIR/cross_language_decrypt.rb" "$TMPDIR/node_encrypted.json" || STATUS=1

echo
if [ $STATUS -eq 0 ]; then
  echo "=== ALL TESTS PASSED ==="
else
  echo "=== SOME TESTS FAILED ==="
fi

exit $STATUS
