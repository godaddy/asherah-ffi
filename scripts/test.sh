#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

########################################################################
# Help / Usage
########################################################################

show_help() {
    cat >&2 <<EOF
Usage: $(basename "$0") <mode> [options]

Modes:
  --unit          Rust unit tests (cargo test --workspace)
  --integration   Integration tests with MySQL, Postgres, DynamoDB (Docker required)
  --bindings      All language binding tests (Python, Node, Ruby, Go, Java, .NET)
  --interop       Cross-language interop tests
  --fuzz          Fuzz tests (requires cargo-fuzz + nightly)
  --sanitizers    Miri + AddressSanitizer + Valgrind
  --lint          Format check + clippy
  --e2e           E2E tests against published packages
  --all           Run everything (unit + integration + bindings + interop + lint)

Options:
  --binding=NAME    Run only a specific binding test (python, node, ruby, go, java, dotnet)
  --platform=ARCH   Target platform: x64, arm64 (default: auto-detect from uname -m)
  --fuzz-time=N     Fuzz duration per target in seconds (default: 30)

Environment:
  BINDING_ARTIFACTS_DIR   Path to pre-built CI artifacts (skips local builds)

Examples:
  $(basename "$0") --unit
  $(basename "$0") --bindings --binding=python
  $(basename "$0") --all
  $(basename "$0") --fuzz --fuzz-time=60
EOF
    exit 1
}

########################################################################
# Utilities
########################################################################

PASS=0
FAIL=0
SKIP=0
RESULTS=()

log()  { echo ">>> $1" >&2; }
pass() { PASS=$((PASS + 1)); RESULTS+=("PASS: $1"); log "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); RESULTS+=("FAIL: $1"); log "FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); RESULTS+=("SKIP: $1"); log "SKIP: $1"; }

run_test() {
    local name="$1"
    shift
    log "Running: $name"
    if "$@"; then
        pass "$name"
    else
        fail "$name"
        summary
    fi
}

summary() {
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    for r in "${RESULTS[@]}"; do
        echo "  $r"
    done
    echo "----------------------------------------"
    echo "  PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
    echo "========================================"
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}

########################################################################
# CI artifact staging
########################################################################

# When BINDING_ARTIFACTS_DIR is set (CI), stage pre-built binaries
# instead of building from source.
setup_ci_artifacts() {
    local ad="$BINDING_ARTIFACTS_DIR"
    log "Using pre-built CI artifacts from $ad"

    # Determine Rust target triple from platform
    local target_triple
    case "$PLATFORM" in
        x86_64)   target_triple="x86_64-unknown-linux-gnu" ;;
        aarch64)  target_triple="aarch64-unknown-linux-gnu" ;;
    esac

    # Set up target directories matching what cargo would produce
    local release_dir="$ROOT_DIR/target/release"
    if [ -n "$target_triple" ]; then
        release_dir="$ROOT_DIR/target/$target_triple/release"
    fi
    mkdir -p "$release_dir" "$ROOT_DIR/target/release" "$ROOT_DIR/target/debug"

    # Stage FFI shared library
    for f in "$ad"/ffi/libasherah_ffi.*; do
        [ -e "$f" ] && cp "$f" "$release_dir/"
    done

    # Stage Java JNI library
    for f in "$ad"/java/libasherah_java.*; do
        [ -e "$f" ] && cp "$f" "$release_dir/" && cp "$f" "$ROOT_DIR/target/debug/"
    done

    # Stage Node.js addon
    if [ -d "$ad/node/npm" ]; then
        rm -rf "$ROOT_DIR/asherah-node/npm"
        cp -R "$ad/node/npm" "$ROOT_DIR/asherah-node/npm"
        if ! [ -f "$ROOT_DIR/asherah-node/npm/asherah.node" ]; then
            local candidate
            candidate=$(find "$ROOT_DIR/asherah-node/npm" -maxdepth 6 -name '*.node' -print | head -n1 || true)
            [ -n "$candidate" ] && cp "$candidate" "$ROOT_DIR/asherah-node/npm/asherah.node"
        fi
    fi

    # Symlink triple-specific dir to target/release for tools that look there
    if [ -n "$target_triple" ] && [ "$release_dir" != "$ROOT_DIR/target/release" ]; then
        ln -snf "$release_dir" "$ROOT_DIR/target/release"
    fi

    # For safe.directory in CI containers
    if command -v git >/dev/null 2>&1; then
        git config --global --add safe.directory "$ROOT_DIR" 2>/dev/null || true
    fi

    export CARGO_TARGET_DIR="$ROOT_DIR/target${target_triple:+/$target_triple}"
    export ASHERAH_DOTNET_NATIVE="$release_dir"
    export ASHERAH_RUBY_NATIVE="$release_dir"
    export ASHERAH_GO_NATIVE="$release_dir"
    export LD_LIBRARY_PATH="$release_dir:${LD_LIBRARY_PATH:-}"
}

########################################################################
# Test functions
########################################################################

do_lint() {
    log "=== Lint ==="
    run_test "cargo fmt" cargo fmt --all -- --check
    run_test "cargo clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings
}

do_unit() {
    log "=== Unit Tests ==="
    # The asherah crate is tested separately to avoid running integration_containers
    # (104 tests needing Docker + --test-threads=1) during the unit test phase.
    # Workspace feature unification enables mysql/postgres/dynamodb from binding
    # crates, which causes cargo to compile and include integration_containers.
    run_test "cargo test (workspace, excl. asherah core)" \
        cargo test --workspace --exclude asherah --exclude asherah-node

    # Run asherah crate unit tests: lib tests + all test files except
    # integration_containers (Docker) and cucumber (BDD framework).
    local asherah_test_args=(
        cargo test -p asherah --features sqlite,mysql,postgres,dynamodb --lib
    )
    for f in asherah/tests/*.rs; do
        local name
        name="$(basename "$f" .rs)"
        case "$name" in
            integration_containers|cucumber) continue ;;
        esac
        asherah_test_args+=(--test "$name")
    done
    run_test "cargo test (asherah unit)" "${asherah_test_args[@]}"
}

do_integration() {
    log "=== Integration Tests (Docker required) ==="
    if ! docker info >/dev/null 2>&1; then
        skip "integration tests (Docker not running)"
        return
    fi
    run_test "integration (MySQL, Postgres, DynamoDB)" \
        cargo test -p asherah --features mysql,postgres,dynamodb \
        --test integration_containers -- --test-threads=1
}

do_bindings() {
    local binding="${BINDING_FILTER:-all}"
    log "=== Binding Tests (${binding}) ==="

    export STATIC_MASTER_KEY_HEX="746869734973415374617469634d61737465724b6579466f7254657374696e67"

    if [ -n "${BINDING_ARTIFACTS_DIR:-}" ]; then
        setup_ci_artifacts
    else
        # Local: build FFI libs from source
        log "Building Rust FFI libraries..."
        cargo build --release -p asherah-ffi -p asherah-java -p asherah-cobhan 2>&1 | tail -1
        export ASHERAH_DOTNET_NATIVE="$ROOT_DIR/target/release"
        export ASHERAH_RUBY_NATIVE="$ROOT_DIR/target/release"
        export ASHERAH_GO_NATIVE="$ROOT_DIR/target/release"
    fi

    # Python
    if [ "$binding" = "all" ] || [ "$binding" = "python" ]; then
        if command -v python3 >/dev/null 2>&1; then
            if [ -n "${BINDING_ARTIFACTS_DIR:-}" ]; then
                # CI: install pre-built wheel
                python3 -m pip install --break-system-packages -U pytest 2>&1 | tail -1 || true
                python3 -m pip install --break-system-packages --force-reinstall --no-deps "$BINDING_ARTIFACTS_DIR"/python/*.whl 2>&1 | tail -1
            elif ! python3 -c "import asherah" 2>/dev/null; then
                log "Installing Python binding (maturin develop)..."
                if command -v maturin >/dev/null 2>&1; then
                    maturin develop --release --manifest-path asherah-py/Cargo.toml 2>&1 | tail -1
                else
                    pip3 install maturin 2>&1 | tail -1
                    maturin develop --release --manifest-path asherah-py/Cargo.toml 2>&1 | tail -1
                fi
            fi
            run_test "Python (pytest)" python3 -m pytest asherah-py/tests -vv
        else
            skip "Python tests (python3 not installed)"
        fi
    fi

    # Node.js
    if [ "$binding" = "all" ] || [ "$binding" = "node" ]; then
        if command -v node >/dev/null 2>&1; then
            if [ -n "${BINDING_ARTIFACTS_DIR:-}" ]; then
                # CI: addon staged by setup_ci_artifacts, just install deps
                (cd asherah-node && npm install --ignore-scripts 2>&1 | tail -1)
            elif [ ! -f asherah-node/index.node ]; then
                log "Building Node.js addon..."
                (cd asherah-node && npm install 2>&1 | tail -1 && npx @napi-rs/cli build --release 2>&1 | tail -1)
                # Copy to platform dir
                local plat_dir=""
                case "$(uname -s)-$(uname -m)" in
                    Darwin-arm64)  plat_dir="asherah-node/npm/darwin-arm64" ;;
                    Darwin-x86_64) plat_dir="asherah-node/npm/darwin-x64" ;;
                    Linux-x86_64)  plat_dir="asherah-node/npm/linux-x64-gnu" ;;
                    Linux-aarch64) plat_dir="asherah-node/npm/linux-arm64-gnu" ;;
                esac
                if [ -n "$plat_dir" ] && [ -f asherah-node/index.node ]; then
                    mkdir -p "$plat_dir"
                    local existing
                    existing=$(ls "$plat_dir"/*.node 2>/dev/null | head -1)
                    if [ -n "$existing" ]; then
                        cp asherah-node/index.node "$existing"
                    else
                        cp asherah-node/index.node "$plat_dir/index.node"
                    fi
                fi
            fi
            run_test "Node.js" bash -c "cd asherah-node && npm test"
        else
            skip "Node.js tests (node not installed)"
        fi
    fi

    # Ruby
    if [ "$binding" = "all" ] || [ "$binding" = "ruby" ]; then
        RUBY_CMD="ruby"
        if [ -x "/opt/homebrew/opt/ruby/bin/ruby" ]; then
            RUBY_CMD="/opt/homebrew/opt/ruby/bin/ruby"
            export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH"
        fi
        if ! $RUBY_CMD -e 'require "ffi"' 2>/dev/null; then
            log "Installing Ruby ffi gem..."
            if gem install ffi --no-document 2>&1 | tail -1; then
                true
            elif command -v sudo >/dev/null 2>&1; then
                sudo gem install ffi --no-document 2>&1 | tail -1
            fi
        fi
        run_test "Ruby" $RUBY_CMD -I asherah-ruby/lib -I asherah-ruby/test asherah-ruby/test/round_trip_test.rb
    fi

    # Go
    if [ "$binding" = "all" ] || [ "$binding" = "go" ]; then
        if command -v go >/dev/null 2>&1; then
            (cd asherah-go && go mod tidy 2>&1) || true
            run_test "Go" bash -c "cd asherah-go && CGO_ENABLED=0 go test ./..."
        else
            skip "Go tests (go not installed)"
        fi
    fi

    # Java
    if [ "$binding" = "all" ] || [ "$binding" = "java" ]; then
        if command -v mvn >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
            log "Building Java JAR..."
            local java_native="${ASHERAH_DOTNET_NATIVE:-$ROOT_DIR/target/release}"
            # --enable-native-access requires JDK 16+; skip on older JDKs
            local java_ver
            java_ver=$(java -version 2>&1 | head -1 | sed 's/.*version "\([0-9]*\).*/\1/')
            local native_access_flag=""
            if [ "${java_ver:-0}" -ge 16 ] 2>/dev/null; then
                native_access_flag="--enable-native-access=ALL-UNNAMED "
            fi
            mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true -DskipTests package -q 2>&1 | tail -1
            run_test "Java (JUnit)" mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true \
                -Dasherah.java.nativeLibraryPath="$java_native" \
                -DargLine="${native_access_flag}-Djava.library.path=$java_native" test
        else
            skip "Java tests (maven/java not installed)"
        fi
    fi

    # .NET
    if [ "$binding" = "all" ] || [ "$binding" = "dotnet" ]; then
        if command -v dotnet >/dev/null 2>&1; then
            run_test ".NET (xUnit)" dotnet test asherah-dotnet/AsherahDotNet.slnx --nologo
        else
            skip ".NET tests (dotnet not installed)"
        fi
    fi
}

do_interop() {
    log "=== Interop Tests ==="
    if command -v python3 >/dev/null 2>&1 && [ -d interop/tests ]; then
        run_test "Cross-language interop (Python/Node/Rust/Ruby)" \
            python3 -m pytest interop/tests -vv
    else
        skip "Interop tests (pytest or interop/ directory not available)"
    fi
}

do_fuzz() {
    local fuzz_time="${FUZZ_TIME:-30}"
    log "=== Fuzz Tests (${fuzz_time}s per target) ==="
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        log "Installing cargo-fuzz..."
        cargo install cargo-fuzz 2>&1 | tail -1
    fi
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        skip "Fuzz tests (cargo-fuzz install failed)"
        return
    fi
    if command -v rustup >/dev/null 2>&1; then
        if ! RUSTUP_TOOLCHAIN=nightly rustc --version >/dev/null 2>&1; then
            log "Installing nightly toolchain for fuzz..."
            rustup install nightly 2>&1 | tail -1
        fi
    fi
    if ! RUSTUP_TOOLCHAIN=nightly rustc --version >/dev/null 2>&1; then
        skip "Fuzz tests (nightly toolchain not available)"
        return
    fi

    # Resolve nightly bin dir so sub-processes (cargo-fuzz spawns cargo build)
    # also use the nightly compiler, even when system cargo isn't the rustup proxy.
    local nightly_bin
    nightly_bin="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)")"

    local targets
    targets=$(cd fuzz && PATH="$nightly_bin:$PATH" cargo fuzz list 2>/dev/null)
    if [ -z "$targets" ]; then
        skip "Fuzz tests (no fuzz targets found)"
        return
    fi

    for target in $targets; do
        run_test "fuzz: $target (${fuzz_time}s)" \
            bash -c "cd fuzz && PATH=\"$nightly_bin:\$PATH\" cargo fuzz run $target -- -max_total_time=$fuzz_time"
    done
}

SANITIZER_IMAGE="asherah-sanitizers:latest"

# Build or reuse a Docker image with nightly Rust, clang, valgrind.
ensure_sanitizer_image() {
    if docker image inspect "$SANITIZER_IMAGE" >/dev/null 2>&1; then
        return
    fi
    log "Building sanitizer Docker image (one-time)..."
    docker build -t "$SANITIZER_IMAGE" -f - "$ROOT_DIR" <<'DOCKERFILE'
FROM rust:1.91-bullseye
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm valgrind pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN rustup install nightly \
    && rustup component add --toolchain nightly miri rust-src \
    && rustup target add --toolchain nightly x86_64-unknown-linux-gnu
WORKDIR /workspace
DOCKERFILE
}

# Run a command inside the sanitizer container, mounting the workspace.
# Uses a persistent volume for the cargo registry so deps aren't re-downloaded,
# and a separate target dir so ASAN-instrumented builds don't clobber host builds.
run_in_sanitizer_container() {
    mkdir -p "$ROOT_DIR/.cache/sanitizer-target"
    docker run --rm \
        --memory=8g \
        -v "$ROOT_DIR:/workspace" \
        -v "$ROOT_DIR/.cache/sanitizer-target:/workspace/sanitizer-target" \
        -w /workspace \
        -e CARGO_TARGET_DIR=/workspace/sanitizer-target \
        "$SANITIZER_IMAGE" \
        bash -c "$1"
}

do_sanitizers() {
    log "=== Sanitizer Tests ==="

    # Ensure nightly toolchain is available (required for miri and ASAN)
    local has_nightly=false
    if command -v rustup >/dev/null 2>&1; then
        if ! RUSTUP_TOOLCHAIN=nightly rustc --version >/dev/null 2>&1; then
            log "Installing nightly toolchain..."
            rustup install nightly 2>&1 | tail -1
        fi
        if RUSTUP_TOOLCHAIN=nightly rustc --version >/dev/null 2>&1; then
            has_nightly=true
        fi
    fi

    # Resolve nightly bin dir for sub-processes
    local nightly_bin=""
    if [ "$has_nightly" = true ]; then
        nightly_bin="$(dirname "$(rustup which --toolchain nightly cargo 2>/dev/null)")"
    fi

    # Miri — run on all crates with Miri-compatible tests.
    # Miri can't emulate syscalls (mprotect/mlock), so skip memcall/memguard.
    if [ "$has_nightly" = true ]; then
        if ! PATH="$nightly_bin:$PATH" cargo miri --version >/dev/null 2>&1; then
            log "Installing miri component..."
            rustup component add --toolchain nightly miri rust-src 2>&1 | tail -1
        fi
        if PATH="$nightly_bin:$PATH" cargo miri --version >/dev/null 2>&1; then
            run_test "Miri (asherah core lib)" \
                bash -c "PATH=\"$nightly_bin:\$PATH\" cargo miri test -p asherah --lib -- --skip memcall --skip memguard"
            run_test "Miri (asherah types + json)" \
                bash -c "PATH=\"$nightly_bin:\$PATH\" cargo miri test -p asherah --test types_tests --test json_shape"
            run_test "Miri (cobhan)" \
                bash -c "PATH=\"$nightly_bin:\$PATH\" cargo miri test -p asherah-cobhan --lib"
            run_test "Miri (server)" \
                bash -c "PATH=\"$nightly_bin:\$PATH\" cargo miri test -p asherah-server --lib"
        else
            skip "Miri (miri component install failed)"
        fi
    else
        skip "Miri (rustup not available)"
    fi

    # AddressSanitizer — needs Linux + nightly. Use Docker on macOS.
    if [ "$(uname)" = "Linux" ] && [ "$has_nightly" = true ]; then
        local asan_target="${PLATFORM}-unknown-linux-gnu"
        run_test "AddressSanitizer (asherah core)" bash -c \
            "PATH=\"$nightly_bin:\$PATH\" RUSTFLAGS=\"-Zsanitizer=address\" ASAN_OPTIONS=\"detect_leaks=1\" cargo -Zbuild-std test -p asherah --lib --target $asan_target -- --test-threads=1"
        run_test "AddressSanitizer (cobhan)" bash -c \
            "PATH=\"$nightly_bin:\$PATH\" RUSTFLAGS=\"-Zsanitizer=address\" ASAN_OPTIONS=\"detect_leaks=1\" cargo -Zbuild-std test -p asherah-cobhan --lib --target $asan_target -- --test-threads=1"
    elif docker info >/dev/null 2>&1; then
        ensure_sanitizer_image
        # --target must be explicit so cargo separates host (proc-macro) from
        # target (ASAN-instrumented) builds. Without it, RUSTFLAGS applies to
        # proc-macros too, breaking futures_macro/tokio_macros. Use the
        # container's native triple, not a hardcoded x86_64 target.
        run_test "AddressSanitizer (asherah core, via Docker)" \
            run_in_sanitizer_container \
            'TARGET=$(rustc +nightly -vV | grep host | cut -d" " -f2) && RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS="detect_leaks=1" cargo +nightly -Zbuild-std test -p asherah --lib --target "$TARGET" -- --test-threads=1'
        run_test "AddressSanitizer (cobhan, via Docker)" \
            run_in_sanitizer_container \
            'TARGET=$(rustc +nightly -vV | grep host | cut -d" " -f2) && RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS="detect_leaks=1" cargo +nightly -Zbuild-std test -p asherah-cobhan --lib --target "$TARGET" -- --test-threads=1'
    else
        skip "AddressSanitizer (requires Linux or Docker)"
    fi

    # Valgrind — needs Linux. Use Docker on macOS.
    if command -v valgrind >/dev/null 2>&1; then
        run_test "Valgrind (asherah core)" valgrind --error-exitcode=1 \
            --leak-check=full --suppressions="$ROOT_DIR/valgrind.supp" \
            cargo test -p asherah --lib -- --test-threads=1
        run_test "Valgrind (cobhan)" valgrind --error-exitcode=1 \
            --leak-check=full --suppressions="$ROOT_DIR/valgrind.supp" \
            cargo test -p asherah-cobhan --lib -- --test-threads=1
    elif docker info >/dev/null 2>&1; then
        ensure_sanitizer_image
        # Compile first, then run test binary under Valgrind (not cargo).
        run_test "Valgrind (asherah core, via Docker)" \
            run_in_sanitizer_container \
            'set -eo pipefail && cargo test -p asherah --lib --no-run 2>&1 && BIN=$(cargo test -p asherah --lib --no-run 2>&1 | grep -oP "Executable.*\(\K[^)]+") && valgrind --error-exitcode=1 --leak-check=full --suppressions=/workspace/valgrind.supp "$BIN" --test-threads=1'
        run_test "Valgrind (cobhan, via Docker)" \
            run_in_sanitizer_container \
            'set -eo pipefail && cargo test -p asherah-cobhan --lib --no-run 2>&1 && BIN=$(cargo test -p asherah-cobhan --lib --no-run 2>&1 | grep -oP "Executable.*\(\K[^)]+") && valgrind --error-exitcode=1 --leak-check=full --suppressions=/workspace/valgrind.supp "$BIN" --test-threads=1'
    else
        skip "Valgrind (not installed and Docker not available)"
    fi
}

do_e2e() {
    log "=== E2E Tests ==="

    # npm package
    if [ -d e2e-npm-test ] && command -v node >/dev/null 2>&1; then
        run_test "E2E npm" bash -c "cd e2e-npm-test && npm install && node test.js"
    else
        skip "E2E npm (directory or node not available)"
    fi

    # PyPI package
    if [ -d e2e-pypi-test ] && command -v python3 >/dev/null 2>&1; then
        run_test "E2E PyPI" bash -c "cd e2e-pypi-test && python3 -m pytest -vv"
    else
        skip "E2E PyPI (directory or python3 not available)"
    fi
}

do_all() {
    do_lint
    do_unit
    do_integration
    do_bindings
    do_interop
    do_fuzz
    do_sanitizers
}

########################################################################
# Argument parsing
########################################################################

if [ $# -eq 0 ]; then
    show_help
fi

MODE=""
BINDING_FILTER="all"
FUZZ_TIME=30
PLATFORM=""

while [ $# -gt 0 ]; do
    case "$1" in
        --unit)         MODE="unit" ;;
        --integration)  MODE="integration" ;;
        --bindings)     MODE="bindings" ;;
        --interop)      MODE="interop" ;;
        --fuzz)         MODE="fuzz" ;;
        --sanitizers)   MODE="sanitizers" ;;
        --lint)         MODE="lint" ;;
        --e2e)          MODE="e2e" ;;
        --all)          MODE="all" ;;
        --binding=*)    BINDING_FILTER="${1#--binding=}" ;;
        --platform=*)   PLATFORM="${1#--platform=}" ;;
        --fuzz-time=*)  FUZZ_TIME="${1#--fuzz-time=}" ;;
        --help|-h)      show_help ;;
        *)
            echo "Unknown option: $1" >&2
            show_help
            ;;
    esac
    shift
done

if [ -z "$MODE" ]; then
    show_help
fi

# Normalize platform: accept common aliases, default to native arch
if [ -z "$PLATFORM" ] || [ "$PLATFORM" = "auto" ] || [ "$PLATFORM" = "native" ]; then
    PLATFORM=$(uname -m)
fi
case "$PLATFORM" in
    x86_64|amd64|x64)    PLATFORM="x86_64" ;;
    aarch64|arm64)        PLATFORM="aarch64" ;;
    *)
        echo "Unknown platform: $PLATFORM (expected x64, arm64, auto, native)" >&2
        exit 1
        ;;
esac

export BINDING_FILTER
export FUZZ_TIME
# Note: PLATFORM is intentionally NOT exported — MSBuild interprets it as
# the build platform, breaking .NET builds on arm64.

case "$MODE" in
    unit)         do_unit ;;
    integration)  do_integration ;;
    bindings)     do_bindings ;;
    interop)      do_interop ;;
    fuzz)         do_fuzz ;;
    sanitizers)   do_sanitizers ;;
    lint)         do_lint ;;
    e2e)          do_e2e ;;
    all)          do_all ;;
esac

summary
