#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ARTIFACTS_DIR="${BINDING_ARTIFACTS_DIR:?BINDING_ARTIFACTS_DIR must be set}"
ARCH="$(uname -m)"

case "$ARCH" in
  aarch64)
    TARGET_TRIPLE="aarch64-unknown-linux-gnu"
    ;;
  x86_64)
    TARGET_TRIPLE="x86_64-unknown-linux-gnu"
    ;;
  *)
    echo "[binding-tests] unsupported architecture: $ARCH" >&2
    exit 1
    ;;
 esac

TARGET_DIR="$ROOT_DIR/target/$TARGET_TRIPLE"
RELEASE_DIR="$TARGET_DIR/release"
mkdir -p "$RELEASE_DIR"

if compgen -G "$ARTIFACTS_DIR/ffi/libasherah_ffi.*" >/dev/null; then
  cp "$ARTIFACTS_DIR"/ffi/libasherah_ffi.* "$RELEASE_DIR/"
fi

export CARGO_TARGET_DIR="$TARGET_DIR"
export ASHERAH_DOTNET_NATIVE="$RELEASE_DIR"
export ASHERAH_RUBY_NATIVE="$RELEASE_DIR"
export ASHERAH_GO_NATIVE="$RELEASE_DIR"
export SERVICE_NAME="svc"
export PRODUCT_ID="prod"
export KMS="static"
export STATIC_MASTER_KEY_HEX="2222222222222222222222222222222222222222222222222222222222222222"

if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "$ROOT_DIR" 2>/dev/null || true
fi

echo "[binding-tests] Node.js"
if [ -d "$ARTIFACTS_DIR/node/npm" ]; then
  rm -rf "$ROOT_DIR/asherah-node/npm"
  cp -R "$ARTIFACTS_DIR/node/npm" "$ROOT_DIR/asherah-node/npm"
  if ! [ -f "$ROOT_DIR/asherah-node/npm/asherah.node" ]; then
    candidate=$(find "$ROOT_DIR/asherah-node/npm" -maxdepth 2 -name '*.node' -print | head -n1 || true)
    if [ -n "$candidate" ]; then
      cp "$candidate" "$ROOT_DIR/asherah-node/npm/asherah.node"
    fi
  fi
fi
pushd "$ROOT_DIR/asherah-node" >/dev/null
npm ci
npm test
if command -v bun >/dev/null 2>&1; then
  bun run test
else
  echo "[binding-tests] bun not found, skipping bun test"
fi
popd >/dev/null

echo "[binding-tests] Python"
python3 -m venv "$ROOT_DIR/.venv"
# shellcheck source=/dev/null
source "$ROOT_DIR/.venv/bin/activate"
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip uninstall -y asherah-py >/dev/null 2>&1 || true
if compgen -G "$ARTIFACTS_DIR/python/*.whl" >/dev/null; then
  python3 -m pip install "$ARTIFACTS_DIR"/python/*.whl
else
  python3 -m pip install -e "$ROOT_DIR/asherah-py"
fi
python3 -m pytest "$ROOT_DIR/asherah-py/tests" -vv

if [ "${BINDING_TESTS_FAST_ONLY:-}" = "1" ]; then
  echo "[binding-tests] Fast-only mode enabled, skipping Ruby/Go/Interop/.NET/Java"
  deactivate >/dev/null 2>&1 || true
  chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
  chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
  chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true
  echo "[binding-tests] complete (fast mode)"
  exit 0
fi

echo "[binding-tests] Ruby"
ruby -Iasherah-ruby/lib -Iasherah-ruby/test asherah-ruby/test/round_trip_test.rb

echo "[binding-tests] Go"
pushd "$ROOT_DIR/asherah-go" >/dev/null
go test ./...
popd >/dev/null

echo "[binding-tests] Interop"
python3 -m pytest "$ROOT_DIR/interop/tests"

echo "[binding-tests] .NET"
dotnet test "$ROOT_DIR/asherah-dotnet/AsherahDotNet.sln" --nologo

echo "[binding-tests] Java"
mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" -Dnative.build.skip=true test

chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true

echo "[binding-tests] complete"
