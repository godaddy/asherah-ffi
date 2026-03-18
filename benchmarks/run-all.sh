#!/usr/bin/env bash
set -uo pipefail
# NOTE: not using set -e — individual benchmark failures should not abort
# the entire run. Each section handles its own errors.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BENCH_DIR="$ROOT_DIR/benchmarks"

########################################################################
# Argument handling
########################################################################

show_help() {
    cat >&2 <<EOF
Usage: $(basename "$0") <mode>

Modes:
  --hot         In-memory metastore, all caches hot (baseline)
  --warm        MySQL metastore, caches active (steady-state)
  --cold        MySQL metastore, caches disabled (every op hits MySQL)
  --setup       Install runtime dependencies (gems, npm packages, etc.)
  --clean       Remove fetched canonical assets and build artifacts
  --cleanup     Alias for --clean

All three benchmark modes produce the same multi-language comparison table.
Warm and cold require Docker (starts a MySQL 8.1 container automatically).
EOF
    exit 1
}

do_clean() {
    echo "Cleaning benchmark artifacts..."
    rm -rf /tmp/asherah-canonical
    rm -rf "$BENCH_DIR/dotnet-bench-newmetastore/asherah-upstream"
    # Fetched npm packages
    rm -rf "$BENCH_DIR"/*/node_modules
    # .NET build output
    rm -rf "$BENCH_DIR"/dotnet-bench*/obj "$BENCH_DIR"/dotnet-bench*/bin
    # Java shade output (JARs rebuilt quickly)
    rm -rf "$BENCH_DIR"/java-bench*/target
    # BenchmarkDotNet artifacts
    rm -rf "$ROOT_DIR/BenchmarkDotNet.Artifacts"
    # NOTE: We intentionally preserve benchmarks/asherah-bench/target (Criterion
    # Rust build cache) and benchmarks/native-bench/*/target — these take minutes
    # to rebuild and contain only our own compiled code, not fetched assets.
    echo "Done."
    exit 0
}

do_setup() {
    echo "Installing benchmark dependencies..."

    # Node.js
    if command -v node >/dev/null 2>&1; then
        (cd "$BENCH_DIR/asherah-node-bench" && npm install 2>&1 | tail -1)
        (cd "$BENCH_DIR/node-bench-canonical" && npm install 2>&1 | tail -1)
    fi

    # Ruby
    RUBY_CMD="ruby"
    if [ -x "/opt/homebrew/opt/ruby/bin/ruby" ]; then
        RUBY_CMD="/opt/homebrew/opt/ruby/bin/ruby"
        GEM_CMD="/opt/homebrew/opt/ruby/bin/gem"
    else
        GEM_CMD="gem"
    fi
    if command -v "$RUBY_CMD" >/dev/null 2>&1; then
        $GEM_CMD install ffi benchmark-ips kalibera asherah --no-document 2>&1 | tail -1
    fi

    # Python
    if command -v python3 >/dev/null 2>&1; then
        pip3 install asherah 2>&1 | tail -1
    fi

    # Java canonical (clone + install to local maven repo)
    if command -v mvn >/dev/null 2>&1; then
        if [ ! -d /tmp/asherah-canonical/java ]; then
            git clone --depth 1 https://github.com/godaddy/asherah.git /tmp/asherah-canonical 2>&1 | tail -1
        fi
        mvn -B -f /tmp/asherah-canonical/java/app-encryption/pom.xml install -DskipTests -q 2>&1
    fi

    echo "Done. Run $0 --hot to execute benchmarks."
    exit 0
}

MODE="${1:-}"
case "$MODE" in
    --clean|--cleanup) do_clean ;;
    --setup)           do_setup ;;
    --hot)             ;; # fall through to hot benchmarks below
    --warm|--cold)     ;; # handled after prerequisites
    *)                 show_help ;;
esac

RESULTS_DIR=$(mktemp -d)
trap 'rm -rf "$RESULTS_DIR"' EXIT

# Unset CC if set to bare 'gcc' — it breaks Rust's ring/openssl-sys builds on macOS
# where the system 'gcc' is actually clang and may not behave as expected.
if [ "${CC:-}" = "gcc" ]; then
    unset CC
fi

log() { echo ">>> $1" >&2; }
skip() { echo "    SKIP: $1" >&2; }

# Write result: file per implementation, format: enc_64 enc_1024 enc_8192 dec_64 dec_1024 dec_8192
write_result() {
    local name="$1"
    shift
    echo "$@" > "$RESULTS_DIR/$name"
}

# Pre-create all result files with zeros so every implementation always
# appears in the table (dashes for failures/skips instead of hidden rows).
init_all_results() {
    local zeros="0 0 0 0 0 0"
    for f in \
        "01_Rust_native" \
        "02_.NET_FFI" \
        "03_Go_FFI" \
        "04_Python_FFI" \
        "05_Java_FFI" \
        "06_Ruby_FFI" \
        "07_Node.js_FFI" \
        "90_Canonical_C#_v0.2.10" \
        "91_Canon._Go_(protectedmem)" \
        "93_Canonical_Java" \
        "94_Canon._Go_(memguard)" \
        "95_Canon._Ruby_(Cobhan)" \
        "96_Canon._Node.js_(Cobhan)" \
    ; do
        echo "$zeros" > "$RESULTS_DIR/$f"
    done
}
init_all_results

########################################################################
# Prerequisites
########################################################################

log "Checking prerequisites..."

HAVE_RUST=0; command -v cargo >/dev/null 2>&1 && HAVE_RUST=1
HAVE_DOTNET=0; command -v dotnet >/dev/null 2>&1 && HAVE_DOTNET=1
if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || echo /opt/homebrew/opt/openjdk@21)"
    export JAVA_HOME
fi
HAVE_JAVA=0; command -v java >/dev/null 2>&1 && "$JAVA_HOME/bin/java" --version >/dev/null 2>&1 && HAVE_JAVA=1
HAVE_GO=0; command -v go >/dev/null 2>&1 && HAVE_GO=1
HAVE_PYTHON=0; python3 -c "import asherah" 2>/dev/null && HAVE_PYTHON=1
HAVE_NODE=0; command -v node >/dev/null 2>&1 && HAVE_NODE=1

RUBY_CMD="ruby"
if [ -x "/opt/homebrew/opt/ruby/bin/ruby" ]; then
    export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH"
fi
HAVE_RUBY=0; $RUBY_CMD -e 'require "benchmark/ips"; require "ffi"' 2>/dev/null && HAVE_RUBY=1
HAVE_RUBY_CANONICAL=0; $RUBY_CMD -e 'require "asherah"; require "benchmark/ips"' 2>/dev/null && HAVE_RUBY_CANONICAL=1

# Use the hex encoding of Go's hardcoded "thisIsAStaticMasterKeyForTesting" so
# Rust FFI and canonical Go cobhan bindings use the same master key.
export STATIC_MASTER_KEY_HEX="${STATIC_MASTER_KEY_HEX:-746869734973415374617469634d61737465724b6579466f7254657374696e67}"

########################################################################
# Build
########################################################################

FFI_LIB_DIR="$ROOT_DIR/target/release"
FFI_LIB_EXISTS=0
if [ -f "$FFI_LIB_DIR/libasherah_ffi.dylib" ] || [ -f "$FFI_LIB_DIR/libasherah_ffi.so" ]; then
    FFI_LIB_EXISTS=1
fi

NEED_MYSQL=0
if [ "$MODE" = "--warm" ] || [ "$MODE" = "--cold" ]; then
    NEED_MYSQL=1
fi

# Check if a shared library has MySQL support compiled in
has_mysql() {
    strings "$1" 2>/dev/null | grep -q 'asherah::metastore_mysql' 2>/dev/null
}

ffi_has_mysql() {
    local lib=""
    if [ -f "$FFI_LIB_DIR/libasherah_ffi.dylib" ]; then lib="$FFI_LIB_DIR/libasherah_ffi.dylib"
    elif [ -f "$FFI_LIB_DIR/libasherah_ffi.so" ]; then lib="$FFI_LIB_DIR/libasherah_ffi.so"
    else return 1; fi
    has_mysql "$lib"
}

if [ "$HAVE_RUST" = 1 ]; then
    if [ "$FFI_LIB_EXISTS" = 0 ] || { [ "$NEED_MYSQL" = 1 ] && ! ffi_has_mysql; }; then
        log "Building Rust FFI library (with MySQL support)..."
        cargo build --release -p asherah-ffi -p asherah-java --manifest-path "$ROOT_DIR/Cargo.toml" -q 2>&1
        FFI_LIB_EXISTS=1
    else
        log "Using existing Rust FFI library in $FFI_LIB_DIR"
    fi
fi
export ASHERAH_DOTNET_NATIVE="$FFI_LIB_DIR"
export ASHERAH_RUBY_NATIVE="$FFI_LIB_DIR"
export ASHERAH_GO_NATIVE="$FFI_LIB_DIR"

# Ensure Node.js addon is built and in the right place
if [ "$HAVE_NODE" = 1 ] && [ "$HAVE_RUST" = 1 ]; then
    NODE_ADDON="$ROOT_DIR/asherah-node/npm/darwin-arm64/index.darwin-arm64.node"
    # Detect platform-specific addon path
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) NODE_ADDON_DIR="$ROOT_DIR/asherah-node/npm/darwin-arm64" ;;
        Darwin-x86_64) NODE_ADDON_DIR="$ROOT_DIR/asherah-node/npm/darwin-x64" ;;
        Linux-x86_64) NODE_ADDON_DIR="$ROOT_DIR/asherah-node/npm/linux-x64-gnu" ;;
        Linux-aarch64) NODE_ADDON_DIR="$ROOT_DIR/asherah-node/npm/linux-arm64-gnu" ;;
        *) NODE_ADDON_DIR="" ;;
    esac

    NEED_NODE_REBUILD=0
    if [ -n "$NODE_ADDON_DIR" ]; then
        NODE_ADDON=$(ls "$NODE_ADDON_DIR"/*.node 2>/dev/null | head -1)
        if [ -z "$NODE_ADDON" ]; then
            NEED_NODE_REBUILD=1
        elif [ "$NEED_MYSQL" = 1 ] && ! has_mysql "$NODE_ADDON"; then
            NEED_NODE_REBUILD=1
        fi
    fi

    if [ "$NEED_NODE_REBUILD" = 1 ]; then
        log "Building Node.js addon (with MySQL support)..."
        (cd "$ROOT_DIR/asherah-node" && cargo clean -p asherah-node 2>/dev/null; npx @napi-rs/cli build --release 2>&1 | tail -1)
        # Copy built addon to platform directory
        if [ -n "$NODE_ADDON_DIR" ]; then
            mkdir -p "$NODE_ADDON_DIR"
            BUILT="$ROOT_DIR/asherah-node/index.node"
            if [ -f "$BUILT" ]; then
                # Overwrite whatever .node file exists in the platform dir
                EXISTING=$(ls "$NODE_ADDON_DIR"/*.node 2>/dev/null | head -1)
                if [ -n "$EXISTING" ]; then
                    cp "$BUILT" "$EXISTING"
                else
                    cp "$BUILT" "$NODE_ADDON_DIR/index.node"
                fi
                log "Copied Node.js addon to $NODE_ADDON_DIR"
            fi
        fi
    fi
fi

# Ensure Python binding is installed and has MySQL support
if [ "$HAVE_PYTHON" = 1 ] && [ "$HAVE_RUST" = 1 ] && [ "$NEED_MYSQL" = 1 ]; then
    if ! python3 -c "
import asherah, os
os.environ['STATIC_MASTER_KEY_HEX'] = '22' * 32
try:
    asherah.setup({'ServiceName':'t','ProductID':'t','Metastore':'rdbms','KMS':'static','ConnectionString':'mysql://invalid:0/x'})
except Exception as e:
    if 'feature' in str(e).lower(): raise
    pass  # connection error is fine — means mysql feature is compiled in
" 2>/dev/null; then
        log "Rebuilding Python binding with MySQL support..."
        (cd "$ROOT_DIR" && maturin develop --release --manifest-path asherah-py/Cargo.toml 2>&1 | tail -1)
        HAVE_PYTHON=0; python3 -c "import asherah" 2>/dev/null && HAVE_PYTHON=1
    fi
fi

# JAVA_HOME already set above in prerequisites

########################################################################
# MySQL container management (--warm / --cold)
########################################################################

MYSQL_CONTAINER=""
start_mysql() {
    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: Docker is not running. Start Docker and try again." >&2
        exit 1
    fi
    log "Starting MySQL 8.1 container..."
    MYSQL_CONTAINER="asherah-bench-mysql-$$"
    if ! docker run -d --name "$MYSQL_CONTAINER" \
        -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=test \
        -p 13306:3306 mysql:8.1 >/dev/null 2>&1; then
        echo "ERROR: Failed to start MySQL container. Is port 13306 in use?" >&2
        echo "  Try: docker rm -f \$(docker ps -q --filter name=asherah-bench-mysql)" >&2
        exit 1
    fi
    # Wait for MySQL to accept connections
    log "Waiting for MySQL to be ready..."
    local ready=0
    for i in $(seq 1 60); do
        if docker exec "$MYSQL_CONTAINER" mysql -u root -e "SELECT 1" test >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" = 0 ]; then
        echo "ERROR: MySQL did not become ready after 60 seconds" >&2
        docker logs "$MYSQL_CONTAINER" 2>&1 | tail -10 >&2
        exit 1
    fi
    if ! docker exec "$MYSQL_CONTAINER" mysql -u root -e \
        "CREATE TABLE IF NOT EXISTS encryption_key (
            id VARCHAR(255) NOT NULL,
            created TIMESTAMP NOT NULL,
            key_record JSON NOT NULL,
            PRIMARY KEY(id, created)
        ) ENGINE=InnoDB" test 2>&1; then
        echo "ERROR: Failed to create encryption_key table" >&2
        exit 1
    fi
    log "MySQL ready on port 13306"
    # Rust FFI bindings use URL-style connection string
    export BENCH_METASTORE="rdbms"
    export BENCH_CONNECTION_STRING="mysql://root@127.0.0.1:13306/test"
    export MYSQL_URL="mysql://root@127.0.0.1:13306/test"
    # Cobhan/Go-based bindings use Go MySQL DSN format
    export BENCH_CONNECTION_STRING_GO="root@tcp(127.0.0.1:13306)/test?parseTime=true"
    # For cobhan env var path
    export Metastore="rdbms"
    export ConnectionString="root@tcp(127.0.0.1:13306)/test?parseTime=true"
}

stop_mysql() {
    if [ -n "$MYSQL_CONTAINER" ]; then
        log "Stopping MySQL container..."
        docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
    fi
}

if [ "$MODE" = "--warm" ] || [ "$MODE" = "--cold" ]; then
    start_mysql
    trap 'stop_mysql; rm -rf "$RESULTS_DIR"' EXIT
    if [ "$MODE" = "--cold" ]; then
        # Cold: IK cache size 1 + rotate partitions = every op is a cache miss
        export BENCH_COLD=1
        # Set directly so all implementations pick it up via env, including
        # Rust factory_from_env() and cobhan bindings
        export INTERMEDIATE_KEY_CACHE_MAX_SIZE=1
    fi
    # Fall through to run the same language benchmarks as --hot, but against MySQL
fi

########################################################################
# Hot (in-memory) benchmarks — all languages
########################################################################

########################################################################
# Rust native (Criterion)
########################################################################

if [ "$HAVE_RUST" = 1 ]; then
    log "Running Rust native benchmark (Criterion)..."
    CRITERION_EXTRA=""
    if [ "${BENCH_COLD:-}" = "1" ]; then
        CRITERION_EXTRA="-- --sample-size 20 --warm-up-time 1"
    fi
    cargo bench --manifest-path "$BENCH_DIR/asherah-bench/Cargo.toml" --bench native $CRITERION_EXTRA 2>&1 \
        > "$RESULTS_DIR/criterion_native.log"
    # Parse: extract "group/rust_native/SIZE\n...\ntime:   [low mid high]"
    python3 -c "
import re, sys
text = open('$RESULTS_DIR/criterion_native.log').read()
enc, dec = {}, {}
for m in re.finditer(r'native_(encrypt|decrypt)/rust_native/(\d+)\s.*?time:\s+\[[\d.]+ \w+ ([\d.]+) (ns|µs|ms)', text, re.S):
    op, size, val, unit = m.group(1), int(m.group(2)), float(m.group(3)), m.group(4)
    if 'µ' in unit: val *= 1000
    elif unit == 'ms': val *= 1_000_000
    d = enc if op == 'encrypt' else dec
    d[size] = int(val)
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
" > "$RESULTS_DIR/01_Rust_native"
fi

########################################################################
# .NET FFI + Canonical (BenchmarkDotNet)
########################################################################

if [ "$HAVE_DOTNET" = 1 ] && [ "$FFI_LIB_EXISTS" = 1 ]; then
    log "Running .NET benchmark (BenchmarkDotNet)..."
    if dotnet run --project "$BENCH_DIR/dotnet-bench" -c Release > "$RESULTS_DIR/bdn.log" 2>&1; then
        python3 -c "
import re, sys
results = {}
for line in open('$RESULTS_DIR/bdn.log'):
    if '|' not in line or 'Method' in line or '---' in line: continue
    parts = [p.strip() for p in line.split('|')]
    if len(parts) < 6: continue
    name_field = parts[1]
    cat_field = parts[2]
    size_field = parts[3]
    mean_field = parts[4]
    if not size_field.strip().isdigit(): continue
    for impl_name in ['Rust FFI', 'Canonical C# v0.2.10']:
        if impl_name in name_field:
            size = int(size_field)
            m = re.search(r'([\d,]+\.?\d*)\s*(ns|us|µs|ms)', mean_field)
            if m:
                val = float(m.group(1).replace(',', ''))
                unit = m.group(2)
                if unit in ('us', 'µs'): val *= 1000
                elif unit == 'ms': val *= 1_000_000
                results.setdefault(impl_name, {}).setdefault(cat_field, {})[size] = int(val)
if not results:
    print('BDN produced no results. Log tail:', file=sys.stderr)
    lines = open('$RESULTS_DIR/bdn.log').readlines()
    for line in lines[-30:]:
        print('  ' + line.rstrip(), file=sys.stderr)
for name, fname in [('Rust FFI', '02_.NET_FFI'), ('Canonical C# v0.2.10', '90_Canonical_C#_v0.2.10')]:
    d = results.get(name, {})
    e, dc = d.get('Encrypt', {}), d.get('Decrypt', {})
    with open('$RESULTS_DIR/' + fname, 'w') as f:
        f.write(f\"{e.get(64,0)} {e.get(1024,0)} {e.get(8192,0)} {dc.get(64,0)} {dc.get(1024,0)} {dc.get(8192,0)}\n\")
"
    else
        skip ".NET benchmark failed. Log tail:"
        tail -20 "$RESULTS_DIR/bdn.log" 2>/dev/null >&2
    fi
else
    skip ".NET SDK or Rust FFI lib not available"
fi

########################################################################
# Java FFI (JMH)
########################################################################

if [ "$HAVE_JAVA" = 1 ] && [ "$FFI_LIB_EXISTS" = 1 ]; then
    log "Building Java FFI benchmark (JMH)..."
    # Build the asherah-java JAR and install to local Maven repo
    mvn -B -f "$ROOT_DIR/asherah-java/java/pom.xml" -Dnative.build.skip=true -DskipTests package -q 2>&1
    JAR_FILE=$(ls "$ROOT_DIR"/asherah-java/java/target/asherah-java-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -1)
    JAR_VERSION=$(echo "$JAR_FILE" | sed 's/.*asherah-java-\(.*\)\.jar/\1/')
    mvn -B install:install-file -Dfile="$JAR_FILE" \
        -DgroupId=com.godaddy.asherah -DartifactId=asherah-java -Dversion="${JAR_VERSION}" -Dpackaging=jar -q 2>&1
    mvn -B -U -f "$BENCH_DIR/java-bench/pom.xml" clean package -q -Dasherah.java.version="${JAR_VERSION}" 2>&1

    log "Running Java FFI benchmark (JMH)..."
    java -Djava.library.path="$FFI_LIB_DIR" -Dasherah.java.nativeLibraryPath="$FFI_LIB_DIR" \
        -jar "$BENCH_DIR/java-bench/target/java-bench-1.0-SNAPSHOT.jar" > "$RESULTS_DIR/jmh_ffi.log" 2>&1
    python3 -c "
import re
enc, dec = {}, {}
for line in open('$RESULTS_DIR/jmh_ffi.log'):
    m = re.search(r'Benchmark\.(encrypt|decrypt)\s+(\d+)\s+avgt\s+\d+\s+([\d.]+)', line)
    if m:
        op, size, val = m.group(1), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size] = int(val)
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
" > "$RESULTS_DIR/05_Java_FFI"
else
    skip "Java or Rust FFI lib not available"
fi

########################################################################
# Java Canonical (JMH)
########################################################################

if [ "$HAVE_JAVA" = 1 ]; then
    if [ ! -d /tmp/asherah-canonical/java ]; then
        log "Cloning canonical asherah repo (run --setup to pre-fetch)..."
        git clone --depth 1 https://github.com/godaddy/asherah.git /tmp/asherah-canonical 2>&1 | tail -1
        mvn -B -f /tmp/asherah-canonical/java/app-encryption/pom.xml install -DskipTests -q 2>&1
    fi
    log "Building Java Canonical benchmark (JMH)..."
    mvn -B -f /tmp/asherah-canonical/java/app-encryption/pom.xml install -DskipTests -q 2>&1
    mvn -B -f "$BENCH_DIR/java-bench-canonical/pom.xml" clean package -q 2>&1

    log "Running Java Canonical benchmark (JMH)..."
    java -jar "$BENCH_DIR/java-bench-canonical/target/java-bench-canonical-1.0-SNAPSHOT.jar" > "$RESULTS_DIR/jmh_canon.log" 2>&1
    python3 -c "
import re
enc, dec = {}, {}
for line in open('$RESULTS_DIR/jmh_canon.log'):
    m = re.search(r'Benchmark\.(encrypt|decrypt)\s+(\d+)\s+avgt\s+\d+\s+([\d.]+)', line)
    if m:
        op, size, val = m.group(1), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size] = int(val)
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
" > "$RESULTS_DIR/93_Canonical_Java"
fi

########################################################################
# Go FFI (testing.B)
########################################################################

if [ "$HAVE_GO" = 1 ] && [ "$FFI_LIB_EXISTS" = 1 ]; then
    log "Running Go FFI benchmark (testing.B)..."
    (cd "$BENCH_DIR/go-bench" && go mod tidy 2>&1) || true
    GO_BENCH_ARGS="-bench=. -benchmem -count=3 -benchtime=3s"
    if [ "${BENCH_COLD:-}" = "1" ]; then
        GO_BENCH_ARGS="-bench=. -benchmem -count=1 -benchtime=100x -timeout=120s"
    fi
    if (cd "$BENCH_DIR/go-bench" && CGO_ENABLED=0 ASHERAH_GO_NATIVE="$FFI_LIB_DIR" \
        go test $GO_BENCH_ARGS ./... 2>&1) \
        > "$RESULTS_DIR/go_ffi.log"; then
        python3 -c "
import re, collections
enc, dec = collections.defaultdict(list), collections.defaultdict(list)
for line in open('$RESULTS_DIR/go_ffi.log'):
    m = re.match(r'Benchmark(Encrypt|Decrypt)/(\d+)B-\d+\s+\d+\s+([\d.]+)\s+ns/op', line)
    if m:
        op, size, val = m.group(1).lower(), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size].append(val)
def avg(d, s): vals = d.get(s, []); return int(sum(vals)/len(vals)) if vals else 0
print(avg(enc,64), avg(enc,1024), avg(enc,8192), avg(dec,64), avg(dec,1024), avg(dec,8192))
" > "$RESULTS_DIR/03_Go_FFI"
    else
        skip "Go FFI benchmark failed (see log): $(tail -5 "$RESULTS_DIR/go_ffi.log" 2>/dev/null)"
    fi
else
    skip "Go or Rust FFI lib not available"
fi

########################################################################
# Go Canonical (testing.B)
########################################################################

if [ "$HAVE_GO" = 1 ]; then
    log "Running Go Canonical benchmark (testing.B)..."
    (cd "$BENCH_DIR/native-bench/go-bench" && go mod tidy 2>&1) || true
    (cd "$BENCH_DIR/native-bench/go-bench" && go test -bench=. -benchmem -count=3 -benchtime=3s ./... 2>&1) \
        > "$RESULTS_DIR/go_canon.log"

    for backend in Memguard Protectedmem; do
        python3 -c "
import re, collections
enc, dec = collections.defaultdict(list), collections.defaultdict(list)
for line in open('$RESULTS_DIR/go_canon.log'):
    m = re.match(r'Benchmark${backend}(Encrypt|Decrypt)/(\d+)B-\d+\s+\d+\s+([\d.]+)\s+ns/op', line)
    if m:
        op, size, val = m.group(1).lower(), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size].append(val)
def avg(d, s): vals = d.get(s, []); return int(sum(vals)/len(vals)) if vals else 0
print(avg(enc,64), avg(enc,1024), avg(enc,8192), avg(dec,64), avg(dec,1024), avg(dec,8192))
"
    done > /dev/null  # just to check
    # protectedmem
    python3 -c "
import re, collections
enc, dec = collections.defaultdict(list), collections.defaultdict(list)
for line in open('$RESULTS_DIR/go_canon.log'):
    m = re.match(r'BenchmarkProtectedmem(Encrypt|Decrypt)/(\d+)B-\d+\s+\d+\s+([\d.]+)\s+ns/op', line)
    if m:
        op, size, val = m.group(1).lower(), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size].append(val)
def avg(d, s): vals = d.get(s, []); return int(sum(vals)/len(vals)) if vals else 0
print(avg(enc,64), avg(enc,1024), avg(enc,8192), avg(dec,64), avg(dec,1024), avg(dec,8192))
" > "$RESULTS_DIR/91_Canon._Go_(protectedmem)"
    # memguard
    python3 -c "
import re, collections
enc, dec = collections.defaultdict(list), collections.defaultdict(list)
for line in open('$RESULTS_DIR/go_canon.log'):
    m = re.match(r'BenchmarkMemguard(Encrypt|Decrypt)/(\d+)B-\d+\s+\d+\s+([\d.]+)\s+ns/op', line)
    if m:
        op, size, val = m.group(1).lower(), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size].append(val)
def avg(d, s): vals = d.get(s, []); return int(sum(vals)/len(vals)) if vals else 0
print(avg(enc,64), avg(enc,1024), avg(enc,8192), avg(dec,64), avg(dec,1024), avg(dec,8192))
" > "$RESULTS_DIR/94_Canon._Go_(memguard)"
fi

########################################################################
# Python FFI (timeit)
########################################################################

if [ "$HAVE_PYTHON" = 1 ]; then
    log "Running Python FFI benchmark (timeit)..."
    python3 "$BENCH_DIR/python-bench/bench.py" > "$RESULTS_DIR/python.log" 2>&1
    python3 -c "
import re
enc, dec = {}, {}
for line in open('$RESULTS_DIR/python.log'):
    m = re.match(r'\s+(\d+)B\s+(\d+)\s+ns\s+\d+\s+ns\s+(\d+)\s+ns', line)
    if m:
        enc[int(m.group(1))] = int(m.group(2))
        dec[int(m.group(1))] = int(m.group(3))
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
" > "$RESULTS_DIR/04_Python_FFI"
else
    skip "Python Python asherah not installed"
fi

########################################################################
# Ruby FFI (benchmark-ips)
########################################################################

parse_ruby_ips() {
    python3 -c "
import re
enc, dec = {}, {}
for line in open('$1'):
    m = re.search(r'(encrypt|decrypt) (\d+)B.*\(([\d.]+) .s/i\)', line)
    if m:
        op, size, us = m.group(1), int(m.group(2)), float(m.group(3))
        (enc if op == 'encrypt' else dec)[size] = int(us * 1000)
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
"
}

if [ "$HAVE_RUBY" = 1 ]; then
    log "Running Ruby FFI benchmark (benchmark-ips)..."
    ASHERAH_RUBY_NATIVE="$FFI_LIB_DIR" $RUBY_CMD -I "$ROOT_DIR/asherah-ruby/lib" \
        "$BENCH_DIR/ruby-bench/bench_ffi.rb" > "$RESULTS_DIR/ruby_ffi.log"
    parse_ruby_ips "$RESULTS_DIR/ruby_ffi.log" > "$RESULTS_DIR/06_Ruby_FFI"
else
    skip "Ruby benchmark-ips or ffi gem not available"
fi

########################################################################
# Ruby Canonical (benchmark-ips)
########################################################################

if [ "$HAVE_RUBY_CANONICAL" = 1 ]; then
    log "Running Ruby Canonical benchmark (benchmark-ips)..."
    $RUBY_CMD "$BENCH_DIR/ruby-bench/bench_canonical.rb" > "$RESULTS_DIR/ruby_canon.log" 2>/dev/null
    parse_ruby_ips "$RESULTS_DIR/ruby_canon.log" > "$RESULTS_DIR/95_Canon._Ruby_(Cobhan)"
fi

########################################################################
# Node.js FFI (tinybench)
########################################################################

run_node_bench() {
    local pkg=$1 config=$2
    node -e "
const { Bench } = require('tinybench');
const asherah = require('$pkg');
asherah.setup($config);
const cold = process.env.BENCH_COLD === '1';
async function run() {
  for (const size of [64, 1024, 8192]) {
    const payload = Buffer.alloc(size, 0x41);
    if (cold) {
      // Cold: pre-encrypt on 2 partitions, alternate to force IK cache miss
      const ct0 = asherah.encrypt('cold-0', payload);
      const ct1 = asherah.encrypt('cold-1', payload);
      asherah.decrypt('cold-0', ct0); // warm SK cache
      let ei = 0, di = 0;
      const bench = new Bench({ warmupIterations: 10, iterations: 500 });
      bench.add('encrypt ' + size, () => { asherah.encrypt('cold-enc-' + (ei++), payload); });
      bench.add('decrypt ' + size, () => {
        const i = di++ % 2;
        asherah.decrypt('cold-' + i, i === 0 ? ct0 : ct1);
      });
      await bench.run();
      for (const t of bench.tasks) {
        console.log(t.name + ' ' + Math.round(t.result.latency.mean * 1e6));
      }
    } else {
      const p = 'bench-partition';
      const ct = asherah.encrypt(p, payload);
      const pt = asherah.decrypt(p, ct);
      if (!payload.equals(pt)) throw new Error('verify failed ' + size);
      const bench = new Bench({ warmupIterations: 1000, iterations: 5000 });
      bench.add('encrypt ' + size, () => { asherah.encrypt(p, payload); });
      bench.add('decrypt ' + size, () => { asherah.decrypt(p, ct); });
      await bench.run();
      for (const t of bench.tasks) {
        console.log(t.name + ' ' + Math.round(t.result.latency.mean * 1e6));
      }
    }
  }
  asherah.shutdown();
}
run();
"
}

parse_node_bench() {
    python3 -c "
enc, dec = {}, {}
for line in open('$1'):
    parts = line.strip().split()
    if len(parts) == 3:
        op, size, val = parts[0], int(parts[1]), int(parts[2])
        (enc if op == 'encrypt' else dec)[size] = val
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
"
}

NODE_METASTORE="${BENCH_METASTORE:-memory}"
NODE_CONN="${BENCH_CONNECTION_STRING:-}"
NODE_CONN_GO="${BENCH_CONNECTION_STRING_GO:-}"
NODE_CHECK="${BENCH_CHECK_INTERVAL:-}"
NODE_FFI_EXTRA=""
NODE_CANON_EXTRA=""
if [ -n "$NODE_CONN" ]; then
    NODE_FFI_EXTRA=", connectionString: '$NODE_CONN'"
fi
if [ -n "$NODE_CONN_GO" ]; then
    NODE_CANON_EXTRA=", ConnectionString: '$NODE_CONN_GO'"
fi
if [ "${BENCH_COLD:-}" = "1" ]; then
    NODE_FFI_EXTRA="$NODE_FFI_EXTRA, intermediateKeyCacheMaxSize: 1"
    NODE_CANON_EXTRA="$NODE_CANON_EXTRA, IntermediateKeyCacheMaxSize: 1"
fi
if [ -n "$NODE_CHECK" ]; then
    NODE_FFI_EXTRA="$NODE_FFI_EXTRA, checkInterval: $NODE_CHECK"
    NODE_CANON_EXTRA="$NODE_CANON_EXTRA, CheckInterval: $NODE_CHECK"
fi

if [ "$HAVE_NODE" = 1 ] && [ -d "$BENCH_DIR/asherah-node-bench/node_modules/tinybench" ]; then
    log "Running Node.js FFI benchmark (tinybench)..."
    (cd "$BENCH_DIR/asherah-node-bench" && run_node_bench "asherah-node" \
        "{ serviceName: 'bench-svc', productId: 'bench-prod', metastore: '$NODE_METASTORE', kms: 'static', enableSessionCaching: true${NODE_FFI_EXTRA} }") \
        > "$RESULTS_DIR/node_ffi.log"
    parse_node_bench "$RESULTS_DIR/node_ffi.log" > "$RESULTS_DIR/07_Node.js_FFI"
else
    skip "Node.js FFI not available (run: cd benchmarks/asherah-node-bench && npm install tinybench)"
fi

########################################################################
# Node.js Canonical (tinybench)
########################################################################

if [ "$HAVE_NODE" = 1 ] && [ -d "$BENCH_DIR/node-bench-canonical/node_modules/tinybench" ]; then
    log "Running Node.js Canonical benchmark (tinybench)..."
    # Canonical cobhan package accepts the same config keys as our FFI
    (cd "$BENCH_DIR/node-bench-canonical" && run_node_bench "asherah" \
        "{ ServiceName: 'bench-svc', ProductID: 'bench-prod', Metastore: '$NODE_METASTORE', KMS: 'static', EnableSessionCaching: true, SQLMetastoreDBType: 'mysql'${NODE_CANON_EXTRA} }") \
        > "$RESULTS_DIR/node_canon.log" 2>/dev/null
    parse_node_bench "$RESULTS_DIR/node_canon.log" > "$RESULTS_DIR/96_Canon._Node.js_(Cobhan)"
fi

########################################################################
# Output table
########################################################################

python3 -c "
import os, sys

mode = '$MODE'
results_dir = '$RESULTS_DIR'
rows = []
for fname in sorted(os.listdir(results_dir)):
    fpath = os.path.join(results_dir, fname)
    if fname.endswith('.log') or not os.path.isfile(fpath):
        continue
    content = open(fpath).read().strip()
    if not content:
        continue
    vals = content.split()
    if len(vals) != 6:
        continue
    # Strip sort prefix (e.g. '01_')
    name = fname.split('_', 1)[1] if '_' in fname else fname
    name = name.replace('_', ' ')
    nums = [int(v) for v in vals]
    rows.append((name, nums))

def fmt(n):
    if n == 0: return '       -'
    return f'{n:>8,}'

N = 26  # name column inner width
# Data row inner: ' ' + 8 + ' ' + 8 + ' ' + 8 + ' ' = 28 chars
D = 28  # data column inner width

hdr = '─' * (N + 2)
dat = '─' * D
top = f'┌{hdr}┬{dat}┬{dat}┐'
mid = f'├{hdr}┼{dat}┼{dat}┤'
bot = f'└{hdr}┴{dat}┴{dat}┘'

def row(name, e64, e1k, e8k, d64, d1k, d8k):
    return f'│ {name:<{N}} │ {fmt(e64)} {fmt(e1k)} {fmt(e8k)} │ {fmt(d64)} {fmt(d1k)} {fmt(d8k)} │'

mode_label = {'--hot': 'Hot (in-memory)', '--warm': 'Warm (MySQL, cached)', '--cold': 'Cold (MySQL, no cache)'}.get(mode, mode)
print()
print(f'  Mode: {mode_label}')
print()
print(top)
print(f'│ {\"\":<{N}} │ {\"ENCRYPT (ns/op)\":^{D-2}} │ {\"DECRYPT (ns/op)\":^{D-2}} │')
print(f'│ {\"Implementation\":<{N}} │ {\"64B\":>8} {\"1KB\":>8} {\"8KB\":>8} │ {\"64B\":>8} {\"1KB\":>8} {\"8KB\":>8} │')
print(mid)

printed_sep = False
for name, nums in rows:
    if name.startswith('Canon') and not printed_sep:
        print(mid)
        printed_sep = True
    e64, e1k, e8k, d64, d1k, d8k = nums
    print(row(name, e64, e1k, e8k, d64, d1k, d8k))

print(bot)
print()
import platform, subprocess
cpu = 'unknown'
try:
    cpu = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip()
except Exception:
    try:
        for line in open('/proc/cpuinfo'):
            if 'model name' in line: cpu = line.split(':',1)[1].strip(); break
    except Exception: pass
print(f'Platform: {platform.system()} {platform.machine()}, {cpu}')
print('All numbers in nanoseconds (ns). Lower is better.')
"
