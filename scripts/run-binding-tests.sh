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

echo "[binding-tests] DEBUG: Checking for FFI library in $ARTIFACTS_DIR/ffi/"
ls -la "$ARTIFACTS_DIR/ffi/" 2>/dev/null || echo "[binding-tests] DEBUG: No ffi directory found"
if compgen -G "$ARTIFACTS_DIR/ffi/libasherah_ffi.*" >/dev/null; then
  echo "[binding-tests] DEBUG: Copying FFI library to $RELEASE_DIR/"
  cp "$ARTIFACTS_DIR"/ffi/libasherah_ffi.* "$RELEASE_DIR/"
  ls -la "$RELEASE_DIR/" | grep libasherah || true
else
  echo "[binding-tests] DEBUG: No FFI library found in artifacts"
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

# Provide legacy convenience symlinks so tests that expect /workspace/target/{debug,release}
# can find artifacts when CARGO_TARGET_DIR includes the target triple.
mkdir -p "$ROOT_DIR/target"
if [ -d "$CARGO_TARGET_DIR/debug" ]; then
  ln -snf "$CARGO_TARGET_DIR/debug" "$ROOT_DIR/target/debug"
fi
if [ -d "$CARGO_TARGET_DIR/release" ]; then
  ln -snf "$CARGO_TARGET_DIR/release" "$ROOT_DIR/target/release"
fi

# Prefer an explicit Ruby native library path to avoid loader ambiguity
RUBY_LIB_CAND=$(find "$RELEASE_DIR" -maxdepth 1 -type f -name "libasherah_ffi.*" | head -n1 || true)
if [ -n "$RUBY_LIB_CAND" ]; then
  export ASHERAH_RUBY_NATIVE="$RUBY_LIB_CAND"
fi

# Pre-built artifacts from manylinux_2_28 (glibc 2.28) are compatible with
# Debian Bullseye (glibc 2.31). No rebuild needed.
ensure_local_ffi() {
  echo "[binding-tests] Using pre-built FFI artifacts (manylinux_2_28 compatible)"
}

if should_run ffi || should_run dotnet || should_run java; then
  ensure_local_ffi
fi

ensure_interop_bin() {
  # Skip rebuild - interop tests are disabled in fast mode (BINDING_TESTS_FAST_ONLY=1)
  # and pre-built artifacts are compatible
  echo "[binding-tests] Skipping interop build (fast mode enabled)"
}

if should_run node; then
  echo "[binding-tests] Node.js"
  echo "[binding-tests] DEBUG: ARTIFACTS_DIR=$ARTIFACTS_DIR"
  echo "[binding-tests] DEBUG: Contents of ARTIFACTS_DIR:"
  find "$ARTIFACTS_DIR" -maxdepth 3 -ls 2>/dev/null || ls -laR "$ARTIFACTS_DIR" || true
  if [ -d "$ARTIFACTS_DIR/node/npm" ]; then
    rm -rf "$ROOT_DIR/asherah-node/npm"
    cp -R "$ARTIFACTS_DIR/node/npm" "$ROOT_DIR/asherah-node/npm"
    echo "[binding-tests] DEBUG: After copy, contents of $ROOT_DIR/asherah-node/npm:"
    ls -la "$ROOT_DIR/asherah-node/npm" || true
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
  # Pre-built .node addon from artifacts is glibc 2.28 compatible
  if ! [ -f "$ROOT_DIR/asherah-node/npm/asherah.node" ]; then
    echo "[binding-tests] ERROR: Node addon not found in artifacts"
    exit 1
  fi
  export LD_LIBRARY_PATH="$RELEASE_DIR:${LD_LIBRARY_PATH:-}"
  echo "[binding-tests] DEBUG: LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
  echo "[binding-tests] DEBUG: Contents of RELEASE_DIR:"
  ls -la "$RELEASE_DIR/" | grep libasherah || echo "No libasherah found in RELEASE_DIR"
  echo "[binding-tests] DEBUG: Checking if asherah.node can find dependencies:"
  ldd "$ROOT_DIR/asherah-node/npm/asherah.node" 2>/dev/null || echo "ldd failed"
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
  python3 -m pip install -U pytest >/dev/null
  python3 -m pip uninstall -y asherah-py >/dev/null 2>&1 || true
  if compgen -G "$ARTIFACTS_DIR/python/*.whl" >/dev/null; then
    python3 -m pip install "$ARTIFACTS_DIR"/python/*.whl || {
      echo "[binding-tests] ERROR: Python wheel install failed"
      exit 1
    }
  else
    echo "[binding-tests] ERROR: Python wheel not found in artifacts"
    exit 1
  fi
  python3 -m pytest "$ROOT_DIR/asherah-py/tests" -vv

  echo "[binding-tests] Interop"
  ensure_local_ffi
  ensure_interop_bin
  export LD_LIBRARY_PATH="$RELEASE_DIR:${LD_LIBRARY_PATH:-}"
  python3 -m pytest "$ROOT_DIR/interop/tests" -vv
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
  # Ensure JNI/FFI libraries are built and discoverable
  export LD_LIBRARY_PATH="$RELEASE_DIR:${LD_LIBRARY_PATH:-}"
  export ASHERAH_JAVA_NATIVE="$RELEASE_DIR"
  cargo build -p asherah-java --release || true
  # Ensure libasherah_java is present where loader might look (both release and debug dirs)
  mapfile -t JAVA_LIBS < <(find "$CARGO_TARGET_DIR/release" -maxdepth 1 -type f -name "libasherah_java.*" 2>/dev/null || true)
  mkdir -p "$TARGET_DIR/debug"
  for lib in "${JAVA_LIBS[@]:-}"; do
    [ -n "$lib" ] || continue
    cp "$lib" "$RELEASE_DIR/" 2>/dev/null || true
    cp "$lib" "$TARGET_DIR/debug/" 2>/dev/null || true
  done
  set +e
  mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" \
    -Dnative.build.skip=true \
    -DargLine="-Djava.library.path=$RELEASE_DIR -Dasherah.java.nativeLibraryPath=$RELEASE_DIR" \
    test
  MVN_RC=$?
  if [ $MVN_RC -ne 0 ]; then
    echo "[binding-tests] Java test failed; dumping surefire reports"
    find "$ROOT_DIR/asherah-java/java/target/surefire-reports" -type f -maxdepth 1 -print -exec sh -c 'echo "----- {} -----"; sed -n "1,240p" "{}"' \; 2>/dev/null || true
    exit $MVN_RC
  fi
  set -e
fi

if [ $PYTHON_VENV_ACTIVE -eq 1 ]; then
  deactivate >/dev/null 2>&1 || true
fi

chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true

echo "[binding-tests] complete"
