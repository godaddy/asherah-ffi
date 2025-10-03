#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ARTIFACTS_DIR="${BINDING_ARTIFACTS_DIR:?BINDING_ARTIFACTS_DIR must be set}"
# Some artifact uploads include a nested artifacts/aarch64 prefix; normalize if present.
if [ -d "$ARTIFACTS_DIR/artifacts/aarch64" ]; then
  ARTIFACTS_DIR="$ARTIFACTS_DIR/artifacts/aarch64"
fi
ARCH="$(uname -m)"
BINDING_SELECTOR="${BINDING_TESTS_BINDING:-all}"
BINDING_SELECTOR="${BINDING_SELECTOR,,}"

should_run() {
  local target="$1"
  if [ "$BINDING_SELECTOR" = "all" ]; then
    return 0
  fi
  [ "$BINDING_SELECTOR" = "$target" ]
}

ensure_bun() {
  if command -v bun >/dev/null 2>&1; then
    return
  fi

  if [ -x /root/.bun/bin/bun ]; then
    ln -sf /root/.bun/bin/bun /usr/local/bin/bun
  fi

  if command -v bun >/dev/null 2>&1; then
    return
  fi

  echo "[binding-tests] Installing bun runtime"
  curl -fsSL https://bun.sh/install | bash >/dev/null
  ln -sf /root/.bun/bin/bun /usr/local/bin/bun
}

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
export NAPI_RS_CARGO_TARGET_DIR="$CARGO_TARGET_DIR"
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

# On arm64 tests container, rebuild the FFI library locally to ensure
# glibc compatibility with the container runtime (e.g., glibc 2.31).
ensure_local_ffi() {
  echo "[binding-tests] Building local FFI (release) for container"
  cargo build -p asherah-ffi --release
}

if should_run ffi || should_run dotnet || should_run java; then
  ensure_local_ffi
fi

if should_run node; then
  echo "[binding-tests] Node.js"
  if [ -d "$ARTIFACTS_DIR/node/npm" ]; then
    rm -rf "$ROOT_DIR/asherah-node/npm"
    cp -R "$ARTIFACTS_DIR/node/npm" "$ROOT_DIR/asherah-node/npm"
    if ! [ -f "$ROOT_DIR/asherah-node/npm/asherah.node" ]; then
      # Search deeper to handle platform-specific subfolders produced by napi prepublish
      candidate=$(find "$ROOT_DIR/asherah-node/npm" -maxdepth 6 -name '*.node' -print | head -n1 || true)
      if [ -n "$candidate" ]; then
        cp "$candidate" "$ROOT_DIR/asherah-node/npm/asherah.node"
      fi
    fi
  fi
  pushd "$ROOT_DIR/asherah-node" >/dev/null
  rm -f index.node
  npm install --ignore-scripts >/dev/null
  # Ensure native addon is compatible with the container's glibc by building locally
  if ! [ -f "$ROOT_DIR/asherah-node/npm/asherah.node" ]; then
    echo "[binding-tests] Building Node addon locally for test container"
    npx @napi-rs/cli build --release || npm run build || true
    candidate=$(find "$ROOT_DIR/asherah-node/npm" -maxdepth 6 -name '*.node' -print | head -n1 || true)
    if [ -n "$candidate" ]; then
      cp "$candidate" "$ROOT_DIR/asherah-node/npm/asherah.node" || true
    fi
  fi
  export LD_LIBRARY_PATH="$RELEASE_DIR:${LD_LIBRARY_PATH:-}"
  npm test
  ensure_bun
  if command -v bun >/dev/null 2>&1; then
    bun run test
  else
    echo "[binding-tests] bun not found, skipping bun test"
  fi
  popd >/dev/null
fi

PYTHON_VENV_ACTIVE=0
if should_run python; then
  echo "[binding-tests] Python"
  python3 -m venv "$ROOT_DIR/.venv"
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.venv/bin/activate"
  PYTHON_VENV_ACTIVE=1
  python3 -m pip install --upgrade pip >/dev/null
  python3 -m pip install -U pytest maturin >/dev/null
  python3 -m pip uninstall -y asherah-py >/dev/null 2>&1 || true
  if compgen -G "$ARTIFACTS_DIR/python/*.whl" >/dev/null; then
    if ! python3 -m pip install "$ARTIFACTS_DIR"/python/*.whl; then
      echo "[binding-tests] Wheel install failed, falling back to maturin develop"
      python3 -m maturin develop --manifest-path "$ROOT_DIR/asherah-py/Cargo.toml"
    fi
  else
    python3 -m maturin develop --manifest-path "$ROOT_DIR/asherah-py/Cargo.toml"
  fi
  python3 -m pytest "$ROOT_DIR/asherah-py/tests" -vv

  echo "[binding-tests] Interop"
  python3 -m pytest "$ROOT_DIR/interop/tests"
fi

if [ "${BINDING_TESTS_FAST_ONLY:-}" = "1" ] && [ "$BINDING_SELECTOR" = "all" ]; then
  echo "[binding-tests] Fast-only mode enabled, skipping Ruby/Go/Interop/.NET/Java"
  if [ $PYTHON_VENV_ACTIVE -eq 1 ]; then
    deactivate >/dev/null 2>&1 || true
  fi
  chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
  chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
  chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true
  echo "[binding-tests] complete (fast mode)"
  exit 0
fi

if should_run ffi; then
  echo "[binding-tests] Ruby"
  export LD_LIBRARY_PATH="$RELEASE_DIR:${LD_LIBRARY_PATH:-}"
  ruby -Iasherah-ruby/lib -Iasherah-ruby/test asherah-ruby/test/round_trip_test.rb

  echo "[binding-tests] Go"
  pushd "$ROOT_DIR/asherah-go" >/dev/null
  go test ./...
  popd >/dev/null
fi

if should_run dotnet; then
  echo "[binding-tests] .NET"
  dotnet test "$ROOT_DIR/asherah-dotnet/AsherahDotNet.sln" --nologo
fi

if should_run java; then
  echo "[binding-tests] Java"
  mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" -Dnative.build.skip=true test
fi

if [ $PYTHON_VENV_ACTIVE -eq 1 ]; then
  deactivate >/dev/null 2>&1 || true
fi

chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true

echo "[binding-tests] complete"
