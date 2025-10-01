#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)
    DOTNET_RID="linux-x64"
    ;;
  aarch64)
    DOTNET_RID="linux-arm64"
    ;;
  *)
    echo "[build-bindings] Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

TARGET_DIR="$ROOT_DIR/target/$ARCH"
OUT_DIR="$ROOT_DIR/artifacts/$ARCH"

echo "[build-bindings] Preparing directories for $ARCH"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

export CARGO_TARGET_DIR="$TARGET_DIR"
export SERVICE_NAME="svc"
export PRODUCT_ID="prod"
export KMS="static"
export STATIC_MASTER_KEY_HEX="2222222222222222222222222222222222222222222222222222222222222222"
export ASHERAH_DOTNET_NATIVE="$CARGO_TARGET_DIR/release"
export ASHERAH_RUBY_NATIVE="$CARGO_TARGET_DIR/release"
export ASHERAH_GO_NATIVE="$CARGO_TARGET_DIR/release"
export NAPI_RS_CARGO_TARGET_DIR="$CARGO_TARGET_DIR"
export NAPI_TYPE_DEF_TMP_FOLDER="$CARGO_TARGET_DIR/napi-types"

mkdir -p "$NAPI_TYPE_DEF_TMP_FOLDER"

if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "$ROOT_DIR" 2>/dev/null || true
fi

echo "[build-bindings] Building core FFI library (release)"
cargo build --release -p asherah-ffi

echo "[build-bindings] Building Node.js addon"
pushd "$ROOT_DIR/asherah-node" >/dev/null
npm ci
npm run build:release
npm run prepublishOnly
mkdir -p "$OUT_DIR/node"
rm -rf "$OUT_DIR/node/npm"
cp -R npm "$OUT_DIR/node/npm"
rm -rf node_modules
popd >/dev/null

echo "[build-bindings] Building Python wheel"
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip install --upgrade maturin==1.9.4 >/dev/null
rm -rf "$ROOT_DIR/target/wheels"
maturin build --release --manifest-path "$ROOT_DIR/asherah-py/Cargo.toml"
mkdir -p "$OUT_DIR/python"
shopt -s nullglob
for wheel in "$ROOT_DIR"/target/wheels/*.whl; do
  cp "$wheel" "$OUT_DIR/python/"
done
shopt -u nullglob

echo "[build-bindings] Capturing native FFI artifacts"
mkdir -p "$OUT_DIR/ffi"
mkdir -p "$OUT_DIR/ruby"
shopt -s nullglob
for lib in "$CARGO_TARGET_DIR"/release/libasherah_ffi.*; do
  cp "$lib" "$OUT_DIR/ffi/"
  cp "$lib" "$OUT_DIR/ruby/"
done
shopt -u nullglob

echo "[build-bindings] Validating Go module"
pushd "$ROOT_DIR/asherah-go" >/dev/null
GOOS=linux GOARCH="$(go env GOARCH)" go test ./...
popd >/dev/null

echo "[build-bindings] Packing .NET library"
dotnet restore "$ROOT_DIR/asherah-dotnet/AsherahDotNet.sln"
dotnet pack "$ROOT_DIR/asherah-dotnet/AsherahDotNet/AsherahDotNet.csproj" \
  -c Release \
  -p:ContinuousIntegrationBuild=true \
  -p:RuntimeIdentifier="$DOTNET_RID" \
  -o "$OUT_DIR/dotnet"

echo "[build-bindings] Capturing Java artifacts"
mkdir -p "$OUT_DIR/java"
cargo build --release -p asherah-java
mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" -Dnative.build.skip=true -DskipTests package
cp "$ROOT_DIR"/asherah-java/java/target/*.jar "$OUT_DIR/java/"

echo "[build-bindings] Binding artifacts prepared in $OUT_DIR"

chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true
