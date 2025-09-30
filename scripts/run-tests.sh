#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_NAME="$(uname -m)"
DEFAULT_TARGET_DIR="$ROOT_DIR/target/${OS_NAME}-${ARCH_NAME}"

export PATH="/usr/local/cargo/bin:$PATH"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$DEFAULT_TARGET_DIR}"

export SERVICE_NAME="${SERVICE_NAME:-svc}"
export PRODUCT_ID="${PRODUCT_ID:-prod}"
export KMS="${KMS:-static}"
export STATIC_MASTER_KEY_HEX="${STATIC_MASTER_KEY_HEX:-2222222222222222222222222222222222222222222222222222222222222222}"
export ASHERAH_DOTNET_NATIVE="${ASHERAH_DOTNET_NATIVE:-$CARGO_TARGET_DIR/debug}"
export ASHERAH_RUBY_NATIVE="${ASHERAH_RUBY_NATIVE:-$CARGO_TARGET_DIR/debug}"
export ASHERAH_GO_NATIVE="${ASHERAH_GO_NATIVE:-$CARGO_TARGET_DIR/debug}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export NAPI_RS_CARGO_TARGET_DIR="${NAPI_RS_CARGO_TARGET_DIR:-$CARGO_TARGET_DIR}"
export NAPI_TYPE_DEF_TMP_FOLDER="${NAPI_TYPE_DEF_TMP_FOLDER:-$CARGO_TARGET_DIR/napi-types}"
export MATURIN_BIN="${MATURIN_BIN:-maturin}"
export CGO_ENABLED=1
mkdir -p "$NAPI_TYPE_DEF_TMP_FOLDER"

if command -v ld.lld >/dev/null 2>&1; then
  export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-fuse-ld=lld"
fi

echo "[tests] cargo fmt --check"
cargo fmt --all -- --check

echo "[tests] cargo clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "[tests] cargo test"
cargo test --workspace --exclude asherah-node

# Ensure language bindings can locate build artifacts using conventional paths
mkdir -p "$ROOT_DIR/target"
if [ -d "$CARGO_TARGET_DIR/debug" ]; then
  ln -snf "$CARGO_TARGET_DIR/debug" "$ROOT_DIR/target/debug"
fi
if [ -d "$CARGO_TARGET_DIR/release" ]; then
  ln -snf "$CARGO_TARGET_DIR/release" "$ROOT_DIR/target/release"
fi

echo "[tests] python bindings"
if [ ! -d "$ROOT_DIR/.venv" ]; then
  python3 -m venv "$ROOT_DIR/.venv"
fi
# shellcheck source=/dev/null
source "$ROOT_DIR/.venv/bin/activate"
python3 -m pip uninstall -y asherah-py >/dev/null 2>&1 || true
IFS=' ' read -r -a _maturin_cmd <<< "$MATURIN_BIN"
python3 -m pip --version
python3 -c 'import importlib.util; spec = importlib.util.find_spec("maturin"); print("maturin spec:", spec)' || true
which maturin || true
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip install maturin pytest >/dev/null
"${_maturin_cmd[@]}" develop --manifest-path asherah-py/Cargo.toml
python3 -m pytest asherah-py/tests -vv

echo "[tests] node addon"
(cd asherah-node && rm -rf target && npm install && npm run build && npm test)

echo "[tests] ruby bindings"
ruby -Iasherah-ruby/lib -Iasherah-ruby/test asherah-ruby/test/round_trip_test.rb

echo "[tests] go bindings"
(cd asherah-go && go test ./...)

echo "[tests] interop"
python3 -m pytest interop/tests

echo "[tests] rust JNI bindings"
cargo test -p asherah-java

echo "[tests] java integration"
cargo build -p asherah-java
(cd asherah-java/java && CARGO_TARGET_DIR="$CARGO_TARGET_DIR" mvn -B -Dnative.build.skip=true test)

echo "[tests] dotnet bindings"
dotnet test asherah-dotnet/AsherahDotNet.sln --nologo

echo "[tests] complete"
