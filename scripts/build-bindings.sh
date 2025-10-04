#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ARCH="${TARGET_ARCH:-$(uname -m)}"

COMPONENTS_SPEC="${BINDING_COMPONENTS:-all}"
COMPONENTS_SPEC="$(printf '%s' "$COMPONENTS_SPEC" | tr '[:upper:]' '[:lower:]')"
IFS=' ,'
read -r -a COMPONENT_LIST <<< "$COMPONENTS_SPEC"
unset IFS

should_build() {
  local target="$1"
  if [ "$COMPONENTS_SPEC" = "all" ] || [ "$COMPONENTS_SPEC" = "*" ]; then
    return 0
  fi
  for entry in "${COMPONENT_LIST[@]}"; do
    if [ "$entry" = "$target" ]; then
      return 0
    fi
  done
  return 1
}

requires_core_build() {
  if should_build all; then
    return 0
  fi
  local comp
  for comp in ffi python ruby dotnet java go; do
    if should_build "$comp"; then
      return 0
    fi
  done
  return 1
}

ROOT_OUT_DIR_DEFAULT="$ROOT_DIR/artifacts/$ARCH"
OUT_DIR="${BINDING_OUTPUT_DIR:-$ROOT_OUT_DIR_DEFAULT}"

case "$ARCH" in
  x86_64|amd64)
    DOTNET_RID="linux-x64"
    CARGO_TRIPLE="x86_64-unknown-linux-gnu"
    NAPI_PLATFORM="linux-x64-gnu"
    ;;
  aarch64|arm64)
    DOTNET_RID="linux-arm64"
    CARGO_TRIPLE="aarch64-unknown-linux-gnu"
    NAPI_PLATFORM="linux-arm64-gnu"
    ;;
  *)
    echo "[build-bindings] Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

if [ "$CARGO_TRIPLE" = "aarch64-unknown-linux-gnu" ]; then
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR:-aarch64-linux-gnu-ar}"
  export CC_aarch64_unknown_linux_gnu="${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}"
  export CXX_aarch64_unknown_linux_gnu="${CXX_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-g++}"
  export AR_aarch64_unknown_linux_gnu="${AR_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-ar}"
  export PKG_CONFIG_ALLOW_CROSS="${PKG_CONFIG_ALLOW_CROSS:-1}"
fi

TARGET_DIR="$ROOT_DIR/target/$CARGO_TRIPLE"

CARGO_RELEASE_DIR="$TARGET_DIR/release"
if [ ! -d "$CARGO_RELEASE_DIR" ]; then
  CARGO_RELEASE_DIR="$TARGET_DIR/$CARGO_TRIPLE/release"
fi

echo "[build-bindings] Preparing directories for $ARCH (components: ${COMPONENTS_SPEC})"
mkdir -p "$TARGET_DIR"
if [ "$COMPONENTS_SPEC" = "all" ] || [ "$COMPONENTS_SPEC" = "*" ]; then
  rm -rf "$OUT_DIR"
  mkdir -p "$OUT_DIR"
else
  mkdir -p "$OUT_DIR"
  for comp in "${COMPONENT_LIST[@]}"; do
    case "$comp" in
      ffi)
        rm -rf "$OUT_DIR/ffi" "$OUT_DIR/ruby"
        ;;
      node)
        rm -rf "$OUT_DIR/node"
        ;;
      python)
        rm -rf "$OUT_DIR/python"
        ;;
      dotnet)
        rm -rf "$OUT_DIR/dotnet"
        ;;
      java)
        rm -rf "$OUT_DIR/java"
        ;;
      go)
        rm -rf "$OUT_DIR/go"
        ;;
    esac
  done
fi

export CARGO_TARGET_DIR="$TARGET_DIR"
export SERVICE_NAME="svc"
export PRODUCT_ID="prod"
export KMS="static"
export STATIC_MASTER_KEY_HEX="2222222222222222222222222222222222222222222222222222222222222222"
export ASHERAH_DOTNET_NATIVE="$CARGO_RELEASE_DIR"
export ASHERAH_RUBY_NATIVE="$CARGO_RELEASE_DIR"
export ASHERAH_GO_NATIVE="$CARGO_RELEASE_DIR"
export NAPI_RS_CARGO_TARGET_DIR="$CARGO_TARGET_DIR"
export NAPI_TYPE_DEF_TMP_FOLDER="$CARGO_TARGET_DIR/napi-types"

mkdir -p "$NAPI_TYPE_DEF_TMP_FOLDER"

if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "$ROOT_DIR" 2>/dev/null || true
fi

RELEASE_DIR="$ROOT_DIR/target/release"
mkdir -p "$RELEASE_DIR"

SKIP_CORE_BUILD="${SKIP_CORE_BUILD:-0}"

if requires_core_build; then
  if [ "$SKIP_CORE_BUILD" = "1" ]; then
    echo "[build-bindings] Skipping core build; reusing cached artifacts"
  else
    echo "[build-bindings] Building core FFI library (release)"
    cargo build --release -p asherah-ffi --target "$CARGO_TRIPLE"
    echo "[build-bindings] Built artifacts in $CARGO_RELEASE_DIR:"
    find "$CARGO_RELEASE_DIR" -maxdepth 2 -mindepth 1 -print || true
    echo "[build-bindings] Searching for asherah_ffi artifacts under $TARGET_DIR:"
    find "$TARGET_DIR" -maxdepth 4 -name '*asherah_ffi*' -print || true
  fi

mapfile -d '' ffi_release_files < <(find "$CARGO_RELEASE_DIR" \( -type f -o -type l \) -name 'libasherah_ffi.*' -print0)

if [ ${#ffi_release_files[@]} -eq 0 ]; then
  ALT_RELEASE_DIR="$TARGET_DIR/$CARGO_TRIPLE/release"
  if [ -d "$ALT_RELEASE_DIR" ]; then
    mapfile -d '' ffi_release_files < <(find "$ALT_RELEASE_DIR" \( -type f -o -type l \) -name 'libasherah_ffi.*' -print0)
  fi
fi

if [ ${#ffi_release_files[@]} -eq 0 ]; then
  mapfile -d '' ffi_release_files < <(find "$TARGET_DIR" -maxdepth 4 -type f \( -name 'libasherah_ffi.*' -o -name 'asherah_ffi.dll' \) ! -path '*/deps/*' -print0)
fi

if [ ${#ffi_release_files[@]} -eq 0 ]; then
  echo "[build-bindings] Error: no libasherah_ffi artifacts available under $TARGET_DIR"
  exit 1
fi

for lib in "${ffi_release_files[@]}"; do
    base="$(basename "$lib")"
    ext="${base##*.}"
    if [ "$ext" = "d" ]; then
      continue
    fi
      normalized="$base"
      case "$base" in
        libasherah_ffi-*.so) normalized="libasherah_ffi.so" ;;
        libasherah_ffi-*.a) normalized="libasherah_ffi.a" ;;
        libasherah_ffi-*.dylib) normalized="libasherah_ffi.dylib" ;;
        asherah_ffi-*.dll) normalized="asherah_ffi.dll" ;;
      esac
    echo "[build-bindings] Copying core artifact $base to $RELEASE_DIR/$normalized"
    cp "$lib" "$RELEASE_DIR/$normalized"
  done
fi

if should_build node || should_build all; then
  echo "[build-bindings] Building Node.js addon"
  pushd "$ROOT_DIR/asherah-node" >/dev/null
  npm ci
  # Build the Node addon for the explicit Rust target to ensure
  # cross-compilation produces the correct architecture binary.
  npx @napi-rs/cli build --release --platform "$NAPI_PLATFORM" --target "$CARGO_TRIPLE"
  npm run prepublishOnly
  # Ensure top-level asherah.node exists for test loader convenience
  if [ ! -f npm/asherah.node ]; then
    candidate=$(find npm -maxdepth 6 -name '*.node' -print | head -n1 || true)
    if [ -n "$candidate" ]; then
      cp "$candidate" npm/asherah.node
    fi
  fi
  mkdir -p "$OUT_DIR/node"
  rm -rf "$OUT_DIR/node/npm"
  cp -R npm "$OUT_DIR/node/npm"
  rm -rf node_modules
  popd >/dev/null
fi

if should_build python || should_build all; then
  echo "[build-bindings] Building Python wheel"
  python3 -m pip install --upgrade pip >/dev/null
  python3 -m pip install --upgrade maturin==1.9.4 >/dev/null
  rm -rf "$ROOT_DIR/target/wheels" "$ROOT_DIR/target/$CARGO_TRIPLE/wheels"
  # Build manylinux-compatible wheel (glibc 2.28)
  maturin build --release --manifest-path "$ROOT_DIR/asherah-py/Cargo.toml" --target "$CARGO_TRIPLE" --compatibility manylinux_2_28
  mkdir -p "$OUT_DIR/python"
  PY_WHEEL_DIR="$ROOT_DIR/target/wheels"
  if ! compgen -G "$PY_WHEEL_DIR/*.whl" >/dev/null 2>&1; then
    PY_WHEEL_DIR="$ROOT_DIR/target/$CARGO_TRIPLE/wheels"
  fi
  if compgen -G "$PY_WHEEL_DIR/*.whl" >/dev/null 2>&1; then
    for wheel in "$PY_WHEEL_DIR"/*.whl; do
      echo "[build-bindings] Packaging $(basename "$wheel")"
      cp "$wheel" "$OUT_DIR/python/"
    done
  else
    echo "[build-bindings] Warning: no wheels found in $PY_WHEEL_DIR"
  fi
fi

if should_build ffi || should_build ruby || should_build all; then
  echo "[build-bindings] Capturing native FFI artifacts"
  mkdir -p "$OUT_DIR/ffi"
  mkdir -p "$OUT_DIR/ruby"
  mapfile -d '' ffi_files < <(find "$CARGO_RELEASE_DIR" \( -type f -o -type l \) -name 'libasherah_ffi.*' -print0)

  if [ ${#ffi_files[@]} -eq 0 ]; then
    ALT_RELEASE_DIR="$TARGET_DIR/$CARGO_TRIPLE/release"
    if [ -d "$ALT_RELEASE_DIR" ]; then
      mapfile -d '' ffi_files < <(find "$ALT_RELEASE_DIR" \( -type f -o -type l \) -name 'libasherah_ffi.*' -print0)
    fi
  fi

  if [ ${#ffi_files[@]} -eq 0 ]; then
    mapfile -d '' ffi_files < <(find "$TARGET_DIR" -maxdepth 4 -type f \( -name 'libasherah_ffi.*' -o -name 'asherah_ffi.dll' \) ! -path '*/deps/*' -print0)
  fi

  if [ ${#ffi_files[@]} -eq 0 ]; then
    echo "[build-bindings] Error: no libasherah_ffi artifacts found for packaging"
    exit 1
  fi

  for lib in "${ffi_files[@]}"; do
    base="$(basename "$lib")"
    ext="${base##*.}"
    if [ "$ext" = "d" ]; then
      continue
    fi
    normalized="$base"
    case "$base" in
      libasherah_ffi-*.so) normalized="libasherah_ffi.so" ;;
      libasherah_ffi-*.a) normalized="libasherah_ffi.a" ;;
      libasherah_ffi-*.dylib) normalized="libasherah_ffi.dylib" ;;
      asherah_ffi-*.dll) normalized="asherah_ffi.dll" ;;
    esac
    echo "[build-bindings] Packaging $base as $normalized"
    cp "$lib" "$OUT_DIR/ffi/$normalized"
    cp "$lib" "$OUT_DIR/ruby/$normalized"
  done
fi

if should_build go || should_build all; then
  echo "[build-bindings] Go module"
  pushd "$ROOT_DIR/asherah-go" >/dev/null
  GOOS=linux GOARCH=$(if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then go env GOARCH; else echo arm64; fi) go build ./...
  popd >/dev/null
fi

if should_build dotnet || should_build all; then
  echo "[build-bindings] Packing .NET library"
  dotnet restore "$ROOT_DIR/asherah-dotnet/AsherahDotNet.sln"
  dotnet pack "$ROOT_DIR/asherah-dotnet/AsherahDotNet/AsherahDotNet.csproj" \
    -c Release \
    -p:ContinuousIntegrationBuild=true \
    -p:RuntimeIdentifier="$DOTNET_RID" \
    -o "$OUT_DIR/dotnet"
fi

if should_build java || should_build all; then
  echo "[build-bindings] Capturing Java artifacts"
  mkdir -p "$OUT_DIR/java"
  cargo build --release -p asherah-java --target "$CARGO_TRIPLE"
  mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" -Dnative.build.skip=true -DskipTests package
  cp "$ROOT_DIR"/asherah-java/java/target/*.jar "$OUT_DIR/java/"
fi

echo "[build-bindings] Binding artifacts prepared in $OUT_DIR"

if [ -d "$OUT_DIR" ]; then
  echo "[build-bindings] Artifacts directory layout:"
  find "$OUT_DIR" -maxdepth 3 -mindepth 1 -print || true
else
  echo "[build-bindings] Warning: expected output directory $OUT_DIR does not exist"
fi

chmod -R a+rwX "$ROOT_DIR/.cache" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/target" 2>/dev/null || true
chmod -R a+rwX "$ROOT_DIR/artifacts" 2>/dev/null || true
