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
  --binding=NAME  Run only a specific binding test (python, node, ruby, go, java, dotnet)
  --fuzz-time=N   Fuzz duration per target in seconds (default: 30)

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
# Test functions
########################################################################

do_lint() {
    log "=== Lint ==="
    run_test "cargo fmt" cargo fmt --check
    run_test "cargo clippy" cargo clippy --workspace --all-targets -- -D warnings
}

do_unit() {
    log "=== Unit Tests ==="
    run_test "cargo test (workspace)" cargo test --workspace --exclude asherah-node
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

    # Build FFI libs
    log "Building Rust FFI libraries..."
    cargo build --release -p asherah-ffi -p asherah-java -p asherah-cobhan 2>&1 | tail -1
    export ASHERAH_DOTNET_NATIVE="$ROOT_DIR/target/release"
    export ASHERAH_RUBY_NATIVE="$ROOT_DIR/target/release"
    export ASHERAH_GO_NATIVE="$ROOT_DIR/target/release"
    export STATIC_MASTER_KEY_HEX="746869734973415374617469634d61737465724b6579466f7254657374696e67"

    # Python
    if [ "$binding" = "all" ] || [ "$binding" = "python" ]; then
        if command -v python3 >/dev/null 2>&1; then
            if ! python3 -c "import asherah" 2>/dev/null; then
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
            if [ ! -f asherah-node/index.node ]; then
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
            gem install ffi --no-document 2>&1 | tail -1
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
            mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true -DskipTests package -q 2>&1 | tail -1
            run_test "Java (JUnit)" mvn -B -f asherah-java/java/pom.xml -Dnative.build.skip=true test
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
        skip "Fuzz tests (cargo-fuzz not installed — run: cargo install cargo-fuzz)"
        return
    fi
    if ! rustup run nightly rustc --version >/dev/null 2>&1; then
        skip "Fuzz tests (nightly toolchain not installed — run: rustup install nightly)"
        return
    fi

    local targets
    targets=$(cd fuzz && cargo +nightly fuzz list 2>/dev/null)
    if [ -z "$targets" ]; then
        skip "Fuzz tests (no fuzz targets found)"
        return
    fi

    for target in $targets; do
        run_test "fuzz: $target (${fuzz_time}s)" \
            bash -c "cd fuzz && cargo +nightly fuzz run $target -- -max_total_time=$fuzz_time"
    done
}

do_sanitizers() {
    log "=== Sanitizer Tests ==="

    # Miri
    if rustup run nightly miri --version >/dev/null 2>&1; then
        run_test "Miri (undefined behavior)" \
            cargo +nightly miri test -p asherah-ffi --lib
    else
        skip "Miri (not installed — run: rustup +nightly component add miri)"
    fi

    # AddressSanitizer (Linux only)
    if [ "$(uname)" = "Linux" ]; then
        run_test "AddressSanitizer" bash -c \
            'RUSTFLAGS="-Zsanitizer=address" ASAN_OPTIONS="detect_leaks=1" cargo +nightly test -p asherah-ffi --target x86_64-unknown-linux-gnu -- --test-threads=1'
    else
        skip "AddressSanitizer (Linux only)"
    fi

    # Valgrind (Linux only)
    if command -v valgrind >/dev/null 2>&1; then
        run_test "Valgrind" valgrind --error-exitcode=1 \
            cargo test -p asherah-ffi --lib -- --test-threads=1
    else
        skip "Valgrind (not installed)"
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

export BINDING_FILTER
export FUZZ_TIME

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
