#!/usr/bin/env bash
set -uo pipefail
# NOTE: not using set -e — individual benchmark failures should not abort
# the entire run. Each section handles its own errors.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BENCH_DIR="$ROOT_DIR/benchmarks"

########################################################################
# --clean: remove all fetched canonical assets and build artifacts
########################################################################

if [ "${1:-}" = "--clean" ]; then
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
fi

########################################################################
# --setup: install runtime dependencies only (no benchmarks)
########################################################################

if [ "${1:-}" = "--setup" ]; then
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

    echo "Done. Run $0 to execute benchmarks."
    exit 0
fi

########################################################################
# Mode flags
########################################################################

BENCH_MODE="${BENCH_MODE:-memory}"
BENCH_MYSQL_URL="${BENCH_MYSQL_URL:-${MYSQL_URL:-}}"
BENCH_MYSQL_IMAGE="${BENCH_MYSQL_IMAGE:-mysql:8.1}"
MYSQL_CONTAINER_ID=""
MYSQL_STARTED_BY_SCRIPT=0
log() { echo ">>> $1" >&2; }
skip() { echo "    SKIP: $1" >&2; }

compute_mysql_dsn() {
    # Canonical Go/Cobhan bindings expect go-sql-driver DSN:
    #   user[:pass]@tcp(host:port)/db[?params]
    # Rust FFI bindings use URL form:
    #   mysql://user[:pass]@host:port/db
    # Keep BENCH_MYSQL_URL for FFI and derive BENCH_MYSQL_DSN for canonical.
    if [ -z "${BENCH_MYSQL_URL:-}" ]; then
        BENCH_MYSQL_DSN=""
        return
    fi

    if [[ "$BENCH_MYSQL_URL" != mysql://* ]]; then
        BENCH_MYSQL_DSN="$BENCH_MYSQL_URL"
        return
    fi

    BENCH_MYSQL_DSN="$(
        python3 - "$BENCH_MYSQL_URL" <<'PY'
import sys
from urllib.parse import urlparse, unquote

url = sys.argv[1]
u = urlparse(url)
if u.scheme != "mysql":
    print(url)
    raise SystemExit(0)

user = unquote(u.username or "root")
password = unquote(u.password or "")
host = u.hostname or "127.0.0.1"
port = u.port or 3306
db = (u.path or "/test").lstrip("/") or "test"
auth = user if not password else f"{user}:{password}"
dsn = f"{auth}@tcp({host}:{port})/{db}"
if u.query:
    dsn += f"?{u.query}"
print(dsn)
PY
    )"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --memory)
            BENCH_MODE="memory"
            ;;
        --hot)
            BENCH_MODE="hot"
            ;;
        --warm)
            BENCH_MODE="warm"
            ;;
        --cold)
            BENCH_MODE="cold"
            ;;
        --mysql-url)
            shift
            if [ $# -eq 0 ]; then
                echo "ERROR: --mysql-url requires a value" >&2
                exit 2
            fi
            BENCH_MYSQL_URL="$1"
            ;;
        --mysql-url=*)
            BENCH_MYSQL_URL="${1#--mysql-url=}"
            ;;
        "")
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--memory|--hot|--warm|--cold] [--mysql-url <url>] [--setup|--clean]" >&2
            exit 2
            ;;
    esac
    shift
done

start_mysql_container() {
    log "No MySQL URL provided; starting ephemeral Docker MySQL (${BENCH_MYSQL_IMAGE})..."

    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: docker is required for --$BENCH_MODE when MySQL URL is not provided" >&2
        exit 2
    fi

    MYSQL_CONTAINER_ID="$(docker run -d --rm \
        -e MYSQL_DATABASE=test \
        -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
        -p 127.0.0.1::3306 \
        "$BENCH_MYSQL_IMAGE" 2>/dev/null || true)"
    if [ -z "$MYSQL_CONTAINER_ID" ]; then
        echo "ERROR: failed to start MySQL container from image $BENCH_MYSQL_IMAGE" >&2
        exit 2
    fi
    MYSQL_STARTED_BY_SCRIPT=1

    local host_port=""
    for _ in $(seq 1 60); do
        local port_line
        port_line="$(docker port "$MYSQL_CONTAINER_ID" 3306/tcp 2>/dev/null | head -1 || true)"
        host_port="${port_line##*:}"
        if [ -n "$host_port" ]; then
            break
        fi
        sleep 1
    done
    if [ -z "$host_port" ]; then
        echo "ERROR: failed to determine mapped MySQL host port" >&2
        docker logs "$MYSQL_CONTAINER_ID" 2>/dev/null | tail -20 >&2 || true
        exit 2
    fi

    for _ in $(seq 1 90); do
        if docker exec "$MYSQL_CONTAINER_ID" mysqladmin -h 127.0.0.1 -u root ping --silent >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! docker exec "$MYSQL_CONTAINER_ID" mysqladmin -h 127.0.0.1 -u root ping --silent >/dev/null 2>&1; then
        echo "ERROR: MySQL container did not become ready in time" >&2
        docker logs "$MYSQL_CONTAINER_ID" 2>/dev/null | tail -20 >&2 || true
        exit 2
    fi

    if ! docker exec "$MYSQL_CONTAINER_ID" mysql -h 127.0.0.1 -u root test -e \
        "DROP TABLE IF EXISTS encryption_key; CREATE TABLE encryption_key (id VARCHAR(255) NOT NULL, created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, key_record JSON NOT NULL, PRIMARY KEY(id, created), INDEX(created)) ENGINE=InnoDB" \
        >/dev/null; then
        echo "ERROR: failed to create encryption_key table in ephemeral MySQL" >&2
        docker logs "$MYSQL_CONTAINER_ID" 2>/dev/null | tail -20 >&2 || true
        exit 2
    fi

    BENCH_MYSQL_URL="mysql://root@127.0.0.1:${host_port}/test"
    compute_mysql_dsn
    log "Using ephemeral MySQL at ${BENCH_MYSQL_URL}"
}

mysql_exec_url() {
    # Execute SQL against BENCH_MYSQL_URL using the mysql CLI client.
    # Parses mysql://user[:pass]@host:port/db URL format.
    local sql="$1"
    local url="${BENCH_MYSQL_URL:-}"
    if [ -z "$url" ]; then return 1; fi
    local parts
    parts="$(python3 -c "
from urllib.parse import urlparse, unquote
import sys
u = urlparse(sys.argv[1])
print(unquote(u.username or 'root'))
print(unquote(u.password or ''))
print(u.hostname or '127.0.0.1')
print(u.port or 3306)
print((u.path or '/test').lstrip('/') or 'test')
" "$url" 2>/dev/null)" || return 1
    local user host port db
    user="$(echo "$parts" | sed -n '1p')"
    local pass
    pass="$(echo "$parts" | sed -n '2p')"
    host="$(echo "$parts" | sed -n '3p')"
    port="$(echo "$parts" | sed -n '4p')"
    db="$(echo "$parts" | sed -n '5p')"
    local pass_arg=""
    if [ -n "$pass" ]; then pass_arg="-p$pass"; fi
    mysql -h "$host" -P "$port" -u "$user" $pass_arg "$db" -e "$sql" 2>/dev/null
}

reset_mysql() {
    if [ "$BENCH_MODE" = "memory" ]; then
        return
    fi
    if [ "$MYSQL_STARTED_BY_SCRIPT" != "1" ]; then
        # External MySQL: drop and recreate the table for clean state
        # Safety: only drop+recreate if the database name contains 'test' or 'bench'
        # to avoid accidentally nuking production encryption_key tables.
        local db_name
        db_name="$(python3 -c "from urllib.parse import urlparse; print((urlparse('$BENCH_MYSQL_URL').path or '/').lstrip('/') or 'unknown')" 2>/dev/null)"
        case "$db_name" in
            *test*|*bench*|*tmp*)
                mysql_exec_url "DROP TABLE IF EXISTS encryption_key; CREATE TABLE encryption_key (id VARCHAR(255) NOT NULL, created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, key_record JSON NOT NULL, PRIMARY KEY(id, created), INDEX(created)) ENGINE=InnoDB" \
                    || log "WARNING: could not reset external MySQL table (ensure the mysql CLI is installed)"
                ;;
            *)
                echo "ERROR: refusing to modify encryption_key in database '$db_name' — name must contain 'test', 'bench', or 'tmp'" >&2
                exit 2
                ;;
        esac
        return
    fi
    # Ephemeral MySQL: nuke and restart for clean buffer pool state
    log "Resetting MySQL container for clean state..."
    if [ -n "$MYSQL_CONTAINER_ID" ]; then
        docker rm -f "$MYSQL_CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    MYSQL_CONTAINER_ID=""
    BENCH_MYSQL_URL=""
    BENCH_MYSQL_DSN=""
    start_mysql_container
    export BENCH_MYSQL_URL
    export BENCH_MYSQL_DSN
    if [ -n "$BENCH_MYSQL_URL" ]; then
        export MYSQL_URL="$BENCH_MYSQL_URL"
    else
        unset MYSQL_URL 2>/dev/null || true
    fi
}

if [ "$BENCH_MODE" != "memory" ] && [ -z "$BENCH_MYSQL_URL" ]; then
    start_mysql_container
fi

export BENCH_MODE
export BENCH_MYSQL_URL
compute_mysql_dsn
export BENCH_MYSQL_DSN
if [ -n "$BENCH_MYSQL_URL" ]; then
    export MYSQL_URL="$BENCH_MYSQL_URL"
else
    unset MYSQL_URL 2>/dev/null || true
fi

# Warm mode: set IK cache to 100 with LRU so ~95% of 2048 partitions miss
# Cold mode: set IK cache to 1 so every partition access misses
if [ "$BENCH_MODE" = "warm" ]; then
    export INTERMEDIATE_KEY_CACHE_MAX_SIZE=100
elif [ "$BENCH_MODE" = "cold" ]; then
    export INTERMEDIATE_KEY_CACHE_MAX_SIZE=1
fi

RESULTS_DIR=$(mktemp -d)
cleanup() {
    if [ "$MYSQL_STARTED_BY_SCRIPT" = "1" ] && [ -n "$MYSQL_CONTAINER_ID" ]; then
        docker rm -f "$MYSQL_CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$RESULTS_DIR"
}
trap cleanup EXIT

# Unset CC if set to bare 'gcc' — it breaks Rust's ring/openssl-sys builds on macOS
# where the system 'gcc' is actually clang and may not behave as expected.
if [ "${CC:-}" = "gcc" ]; then
    unset CC
fi

# Write result: file per implementation, format: enc_64 enc_1024 enc_8192 dec_64 dec_1024 dec_8192
write_result() {
    local name="$1"
    shift
    echo "$@" > "$RESULTS_DIR/$name"
}

########################################################################
# Prerequisites
########################################################################

log "Checking prerequisites..."
case "$BENCH_MODE" in
    memory) log "Benchmark mode: memory (in-memory hot-cache)" ;;
    hot) log "Benchmark mode: hot (MySQL hot-cache)" ;;
    warm) log "Benchmark mode: warm (MySQL, SK cached + IK miss)" ;;
    cold) log "Benchmark mode: cold (MySQL, SK-only cache)" ;;
esac

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
# Auto-fix stale gem extensions that produce "Ignoring" warnings which corrupt benchmark output
$RUBY_CMD -e 'exit' 2>&1 | grep -q 'Ignoring' && gem pristine --all --no-extensions 2>/dev/null
HAVE_RUBY=0; $RUBY_CMD -e 'require "benchmark/ips"; require "ffi"' 2>/dev/null && HAVE_RUBY=1
HAVE_RUBY_CANONICAL=0; $RUBY_CMD -e 'require "asherah"; require "benchmark/ips"' 2>/dev/null && HAVE_RUBY_CANONICAL=1

export STATIC_MASTER_KEY_HEX="${STATIC_MASTER_KEY_HEX:-$(printf '22%.0s' {1..32})}"

########################################################################
# Build
########################################################################

FFI_LIB_DIR="$ROOT_DIR/target/release"
FFI_LIB_EXISTS=0
if [ -f "$FFI_LIB_DIR/libasherah_ffi.dylib" ] || [ -f "$FFI_LIB_DIR/libasherah_ffi.so" ]; then
    FFI_LIB_EXISTS=1
fi

if [ "$HAVE_RUST" = 1 ] && [ "$FFI_LIB_EXISTS" = 0 ]; then
    log "Building Rust FFI library..."
    cargo build --release -p asherah-ffi --manifest-path "$ROOT_DIR/Cargo.toml" -q 2>&1
    FFI_LIB_EXISTS=1
elif [ "$FFI_LIB_EXISTS" = 1 ]; then
    log "Using existing Rust FFI library in $FFI_LIB_DIR"
fi
export ASHERAH_DOTNET_NATIVE="$FFI_LIB_DIR"
export ASHERAH_RUBY_NATIVE="$FFI_LIB_DIR"
export ASHERAH_GO_NATIVE="$FFI_LIB_DIR"

# JAVA_HOME already set above in prerequisites

########################################################################
# Rust native (Criterion)
########################################################################

if [ "$HAVE_RUST" = 1 ]; then
    reset_mysql
    log "Running Rust native benchmark (Criterion)..."
    CRITERION_EXTRA=""
    if [ "$BENCH_MODE" = "cold" ]; then
        CRITERION_EXTRA="-- --sample-size 20 --warm-up-time 1"
    fi
    if cargo bench --manifest-path "$BENCH_DIR/asherah-bench/Cargo.toml" --bench native $CRITERION_EXTRA 2>&1 \
        > "$RESULTS_DIR/criterion_native.log"; then
        python3 -c "
import re, sys
text = open('$RESULTS_DIR/criterion_native.log').read()
enc, dec = {}, {}
for m in re.finditer(r'native_(encrypt|decrypt)/rust_native/(\d+)\s.*?time:\s+\[[\d.]+ \w+ ([\d.]+) (ns|µs|us|ms)', text, re.S):
    op, size, val, unit = m.group(1), int(m.group(2)), float(m.group(3)), m.group(4)
    if unit in ('µs', 'us'): val *= 1000
    elif unit == 'ms': val *= 1_000_000
    d = enc if op == 'encrypt' else dec
    d[size] = int(val)
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
" > "$RESULTS_DIR/01_Rust_native"
    else
        skip "Rust native benchmark failed (see log): $(tail -5 "$RESULTS_DIR/criterion_native.log" 2>/dev/null)"
    fi
fi

########################################################################
# .NET FFI + Canonical (BenchmarkDotNet)
########################################################################

if [ "$HAVE_DOTNET" = 1 ] && [ "$FFI_LIB_EXISTS" = 1 ]; then
    reset_mysql
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
canon_pairs = [('Canonical C# v0.2.10', '90_Canonical_C#_v0.2.10')] if '$BENCH_MODE' in ('memory', 'hot') else []
for name, fname in [('Rust FFI', '02_.NET_FFI')] + canon_pairs:
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
    reset_mysql
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

if [ "$HAVE_JAVA" = 1 ] && [ "$BENCH_MODE" != "cold" ] && [ "$BENCH_MODE" != "warm" ]; then
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
    reset_mysql
    log "Running Go FFI benchmark (testing.B)..."
    (cd "$BENCH_DIR/go-bench" && go mod tidy 2>&1) || true
    if (cd "$BENCH_DIR/go-bench" && CGO_ENABLED=0 ASHERAH_GO_NATIVE="$FFI_LIB_DIR" \
        go test -bench=. -benchmem -count=3 -benchtime=3s ./... 2>&1) \
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

if [ "$HAVE_GO" = 1 ] && [ "$BENCH_MODE" != "cold" ] && [ "$BENCH_MODE" != "warm" ]; then
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
    # Ensure release build is installed (interop tests may have installed a debug build)
    if command -v maturin >/dev/null 2>&1; then
        log "Building Python binding (release)..."
        maturin develop --release --manifest-path "$ROOT_DIR/asherah-py/Cargo.toml" 2>&1 | tail -1
    fi
    reset_mysql
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
# Read entire file and normalize: remove any non-benchmark text that may have
# been injected mid-line (e.g. Ruby gem warnings on stderr leaking into stdout).
text = open('$1').read()
# Match only the result lines with i/s and (time/i) — not warmup lines
for m in re.finditer(r'(encrypt|decrypt) (\d+)B\s+[\d.]+k?\s+\([^)]+\)\s+i/s\s+\(([\d.]+)\s+(.)s/i\)', text):
    op, size, val, unit = m.group(1), int(m.group(2)), float(m.group(3)), m.group(4)
    if unit == 'm':
        ns = int(val * 1_000_000)
    else:
        ns = int(val * 1000)
    (enc if op == 'encrypt' else dec)[size] = ns
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
"
}

if [ "$HAVE_RUBY" = 1 ]; then
    reset_mysql
    log "Running Ruby FFI benchmark (benchmark-ips)..."
    if ASHERAH_RUBY_NATIVE="$FFI_LIB_DIR" $RUBY_CMD -I "$ROOT_DIR/asherah-ruby/lib" \
        "$BENCH_DIR/ruby-bench/bench_ffi.rb" > "$RESULTS_DIR/ruby_ffi.log" 2>/dev/null; then
        parse_ruby_ips "$RESULTS_DIR/ruby_ffi.log" > "$RESULTS_DIR/06_Ruby_FFI"
    else
        skip "Ruby FFI benchmark failed (see log): $(tail -5 "$RESULTS_DIR/ruby_ffi.log" 2>/dev/null)"
    fi
else
    skip "Ruby benchmark-ips or ffi gem not available"
fi

########################################################################
# Ruby Canonical (benchmark-ips)
########################################################################

if [ "$HAVE_RUBY_CANONICAL" = 1 ] && [ "$BENCH_MODE" != "cold" ] && [ "$BENCH_MODE" != "warm" ]; then
    reset_mysql
    log "Running Ruby Canonical benchmark (benchmark-ips)..."
    if BENCH_MYSQL_URL="$BENCH_MYSQL_DSN" MYSQL_URL="$BENCH_MYSQL_DSN" \
        $RUBY_CMD "$BENCH_DIR/ruby-bench/bench_canonical.rb" > "$RESULTS_DIR/ruby_canon.log" 2>&1; then
        parse_ruby_ips "$RESULTS_DIR/ruby_canon.log" > "$RESULTS_DIR/95_Canon._Ruby_(Cobhan)"
    else
        skip "Ruby Canonical benchmark failed (see log): $(tail -5 "$RESULTS_DIR/ruby_canon.log" 2>/dev/null)"
    fi
fi

########################################################################
# Node.js FFI (tinybench)
########################################################################

run_node_bench() {
    local pkg=$1 flavor=$2
    node -e "
const { Bench } = require('tinybench');
const asherah = require('$pkg');
const mode = (process.env.BENCH_MODE || 'memory').toLowerCase();
const mysqlUrl = process.env.BENCH_MYSQL_URL || process.env.MYSQL_URL || '';
const partitionPoolSize = Number.parseInt(process.env.BENCH_PARTITION_POOL || '2048', 10);
const warmSessionCacheMax = Number.parseInt(process.env.BENCH_WARM_SESSION_CACHE_MAX || '4096', 10);
if (!Number.isFinite(partitionPoolSize) || partitionPoolSize < 1) {
  throw new Error('BENCH_PARTITION_POOL must be a positive integer');
}
if (!Number.isFinite(warmSessionCacheMax) || warmSessionCacheMax < 1) {
  throw new Error('BENCH_WARM_SESSION_CACHE_MAX must be a positive integer');
}
const isFfi = '$flavor' === 'ffi';
const serviceName = isFfi ? 'bench-svc' : 'bench-canon-svc';
const productId = isFfi ? 'bench-prod' : 'bench-canon-prod';
const partitionPrefix = isFfi ? 'bench' : 'bench-canon';
const config = isFfi
  ? { serviceName, productId, kms: 'static', enableSessionCaching: true }
  : { ServiceName: serviceName, ProductID: productId, KMS: 'static', EnableSessionCaching: true };
if (!['memory', 'hot', 'warm', 'cold'].includes(mode)) {
  throw new Error('invalid BENCH_MODE=' + mode + ' (expected memory/hot/warm/cold)');
}
if (mode !== 'memory') {
  if (!mysqlUrl) throw new Error(mode + ' mode requires BENCH_MYSQL_URL/MYSQL_URL');
  if (isFfi) {
    config.metastore = 'rdbms';
    config.connectionString = mysqlUrl;
    if (mode === 'warm') config.sessionCacheMaxSize = warmSessionCacheMax;
    if (mode === 'cold') config.enableSessionCaching = false;
  } else {
    config.Metastore = 'rdbms';
    config.ConnectionString = mysqlUrl;
    if (mode === 'warm') config.SessionCacheMaxSize = warmSessionCacheMax;
    if (mode === 'cold') config.EnableSessionCaching = false;
  }
} else {
  if (isFfi) config.metastore = 'memory';
  else config.Metastore = 'memory';
}
asherah.setup(config);
async function run() {
  for (const size of [64, 1024, 8192]) {
    const payload = Buffer.alloc(size, 0x41);
    const bench = new Bench({ warmupIterations: 1000, iterations: 5000 });
    if (mode === 'memory' || mode === 'hot') {
      const partition = partitionPrefix + '-partition';
      const ct = asherah.encrypt(partition, payload);
      const pt = asherah.decrypt(partition, ct);
      if (!payload.equals(pt)) throw new Error('verify failed ' + size);
      bench.add('encrypt ' + size, () => { asherah.encrypt(partition, payload); });
      bench.add('decrypt ' + size, () => { asherah.decrypt(partition, ct); });
    } else {
      const partitions = Array.from({ length: partitionPoolSize }, (_, i) => partitionPrefix + '-' + mode + '-' + size + '-' + i);
      const ciphertexts = partitions.map((partition) => asherah.encrypt(partition, payload));
      const pt = asherah.decrypt(partitions[0], ciphertexts[0]);
      if (!payload.equals(pt)) throw new Error('verify failed ' + size);
      let encIdx = 0;
      let decIdx = 0;
      bench.add('encrypt ' + size, () => {
        const idx = encIdx % partitions.length;
        encIdx += 1;
        asherah.encrypt(partitions[idx], payload);
      });
      bench.add('decrypt ' + size, () => {
        const idx = decIdx % partitions.length;
        decIdx += 1;
        asherah.decrypt(partitions[idx], ciphertexts[idx]);
      });
    }
    await bench.run();
    for (const t of bench.tasks) {
      console.log(t.name + ' ' + Math.round(t.result.latency.mean * 1e6));
    }
  }
  asherah.shutdown();
}
run();
"
}

parse_node_bench() {
    python3 -c "
import re
enc, dec = {}, {}
for line in open('$1'):
    m = re.match(r'^(encrypt|decrypt)\s+(\d+)\s+(\d+)\s*$', line.strip())
    if m:
        op, size, val = m.group(1), int(m.group(2)), int(m.group(3))
        (enc if op == 'encrypt' else dec)[size] = val
print(enc.get(64,0), enc.get(1024,0), enc.get(8192,0), dec.get(64,0), dec.get(1024,0), dec.get(8192,0))
"
}

if [ "$HAVE_NODE" = 1 ] && [ -d "$BENCH_DIR/asherah-node-bench/node_modules/tinybench" ]; then
    # Ensure release addon is built (interop tests may have built debug)
    if [ -f "$ROOT_DIR/asherah-node/package.json" ] && command -v npx >/dev/null 2>&1; then
        log "Building Node.js addon (release)..."
        (cd "$ROOT_DIR/asherah-node" && npx @napi-rs/cli build --release 2>&1 | tail -1) || true
    fi
    reset_mysql
    log "Running Node.js FFI benchmark (tinybench)..."
    if (cd "$BENCH_DIR/asherah-node-bench" && run_node_bench "asherah-node" "ffi") \
        > "$RESULTS_DIR/node_ffi.log" 2>&1; then
        parse_node_bench "$RESULTS_DIR/node_ffi.log" > "$RESULTS_DIR/07_Node.js_FFI"
    else
        skip "Node.js FFI benchmark failed (see log): $(tail -5 "$RESULTS_DIR/node_ffi.log" 2>/dev/null)"
    fi
else
    skip "Node.js FFI not available (run: cd benchmarks/asherah-node-bench && npm install tinybench)"
fi

########################################################################
# Node.js Canonical (tinybench)
########################################################################

if [ "$HAVE_NODE" = 1 ] && [ -d "$BENCH_DIR/node-bench-canonical/node_modules/tinybench" ] && [ "$BENCH_MODE" != "cold" ] && [ "$BENCH_MODE" != "warm" ]; then
    reset_mysql
    log "Running Node.js Canonical benchmark (tinybench)..."
    if (cd "$BENCH_DIR/node-bench-canonical" && BENCH_MYSQL_URL="$BENCH_MYSQL_DSN" MYSQL_URL="$BENCH_MYSQL_DSN" \
        run_node_bench "asherah" "canonical") > "$RESULTS_DIR/node_canon.log" 2>&1; then
        parse_node_bench "$RESULTS_DIR/node_canon.log" > "$RESULTS_DIR/96_Canon._Node.js_(Cobhan)"
    else
        skip "Node.js Canonical benchmark failed (see log): $(tail -5 "$RESULTS_DIR/node_canon.log" 2>/dev/null)"
    fi
fi

########################################################################
# Output table
########################################################################

python3 -c "
import os, sys

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

print()
print(top)
print(f'│ {\"\":<{N}} │ {\"ENCRYPT (ns/op)\":^{D-2}} │ {\"DECRYPT (ns/op)\":^{D-2}} │')
print(f'│ {\"Implementation\":<{N}} │ {\"64B\":>8} {\"1KB\":>8} {\"8KB\":>8} │ {\"64B\":>8} {\"1KB\":>8} {\"8KB\":>8} │')
print(mid)

# Split into FFI and canonical groups, sort each by 64B encrypt
ffi_rows = [(n, v) for n, v in rows if not n.startswith('Canon')]
canon_rows = [(n, v) for n, v in rows if n.startswith('Canon')]
# Sort by encrypt 64B (index 0), putting zeros (missing data) at the end
def sort_key(pair): return (pair[1][0] == 0, pair[1][0])
ffi_rows.sort(key=sort_key)
canon_rows.sort(key=sort_key)

for name, nums in ffi_rows:
    e64, e1k, e8k, d64, d1k, d8k = nums
    print(row(name, e64, e1k, e8k, d64, d1k, d8k))
if canon_rows:
    print(mid)
    for name, nums in canon_rows:
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
