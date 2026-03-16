#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BENCH_DIR="$ROOT_DIR/benchmarks"

########################################################################
# --clean: remove all fetched canonical assets and build artifacts
########################################################################

if [ "${1:-}" = "--clean" ]; then
    echo "Cleaning benchmark artifacts..."
    rm -rf /tmp/asherah-canonical
    rm -rf /tmp/asherah-go-wip
    rm -rf "$BENCH_DIR/dotnet-bench-newmetastore/asherah-upstream"
    # Build output (covered by .gitignore but clean anyway)
    for d in "$BENCH_DIR"/*/target "$BENCH_DIR"/*/bin "$BENCH_DIR"/*/obj \
             "$BENCH_DIR"/*/node_modules "$BENCH_DIR"/asherah-bench/target \
             "$ROOT_DIR/BenchmarkDotNet.Artifacts"; do
        rm -rf "$d" 2>/dev/null || true
    done
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
        pip3 install asherah-py 2>&1 | tail -1
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
HAVE_PYTHON=0; python3 -c "import asherah_py" 2>/dev/null && HAVE_PYTHON=1
HAVE_NODE=0; command -v node >/dev/null 2>&1 && HAVE_NODE=1

RUBY_CMD="ruby"
if [ -x "/opt/homebrew/opt/ruby/bin/ruby" ]; then
    export PATH="/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH"
fi
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
    log "Running Rust native benchmark (Criterion)..."
    cargo bench --manifest-path "$BENCH_DIR/asherah-bench/Cargo.toml" --bench native 2>&1 \
        > "$RESULTS_DIR/criterion_native.log"
    # Parse: extract "group/rust_native/SIZE\n...\ntime:   [low mid high]"
    python3 -c "
import re, sys
text = open('$RESULTS_DIR/criterion_native.log').read()
enc, dec = {}, {}
for m in re.finditer(r'native_(encrypt|decrypt)/rust_native/(\d+)\s.*?time:\s+\[[\d.]+ \w+ ([\d.]+) (ns|µs)', text, re.S):
    op, size, val, unit = m.group(1), int(m.group(2)), float(m.group(3)), m.group(4)
    if 'µ' in unit: val *= 1000
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
    dotnet run --project "$BENCH_DIR/dotnet-bench" -c Release > "$RESULTS_DIR/bdn.log" 2>&1
    python3 -c "
import re
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
            # Mean field looks like '18,947.7 ns' or '652.6 ns'
            m = re.search(r'([\d,]+\.?\d*)\s*ns', mean_field)
            if m:
                val = float(m.group(1).replace(',', ''))
                results.setdefault(impl_name, {}).setdefault(cat_field, {})[size] = int(val)
for name, fname in [('Rust FFI', '02_.NET_FFI'), ('Canonical C# v0.2.10', '90_Canonical_C#_v0.2.10')]:
    d = results.get(name, {})
    e, dc = d.get('Encrypt', {}), d.get('Decrypt', {})
    with open('$RESULTS_DIR/' + fname, 'w') as f:
        f.write(f\"{e.get(64,0)} {e.get(1024,0)} {e.get(8192,0)} {dc.get(64,0)} {dc.get(1024,0)} {dc.get(8192,0)}\n\")
"
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
    GO_WIP_MOVED=0
    if [ -f "$ROOT_DIR/asherah-go/ffi.go" ]; then
        mkdir -p /tmp/asherah-go-wip
        mv "$ROOT_DIR"/asherah-go/ffi.go "$ROOT_DIR"/asherah-go/ffi_unix.go "$ROOT_DIR"/asherah-go/ffi_windows.go /tmp/asherah-go-wip/ 2>/dev/null || true
        GO_WIP_MOVED=1
    fi

    log "Running Go FFI benchmark (testing.B)..."
    (cd "$BENCH_DIR/go-bench" && CGO_ENABLED=1 go test -bench=. -benchmem -count=3 -benchtime=3s ./... 2>&1) \
        > "$RESULTS_DIR/go_ffi.log"

    if [ "$GO_WIP_MOVED" = 1 ]; then
        mv /tmp/asherah-go-wip/* "$ROOT_DIR/asherah-go/" 2>/dev/null || true
        rmdir /tmp/asherah-go-wip 2>/dev/null || true
    fi

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
    skip "Go or Rust FFI lib not available"
fi

########################################################################
# Go Canonical (testing.B)
########################################################################

if [ "$HAVE_GO" = 1 ]; then
    log "Running Go Canonical benchmark (testing.B)..."
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
    skip "Python asherah_py not installed"
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
    $RUBY_CMD "$BENCH_DIR/ruby-bench/bench_canonical.rb" 2>&1 | grep -v 'asherah-cobhan:' \
        > "$RESULTS_DIR/ruby_canon.log"
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
const p = 'bench-partition';
async function run() {
  for (const size of [64, 1024, 8192]) {
    const payload = Buffer.alloc(size, 0x41);
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

if [ "$HAVE_NODE" = 1 ] && [ -d "$BENCH_DIR/asherah-node-bench/node_modules/tinybench" ]; then
    log "Running Node.js FFI benchmark (tinybench)..."
    (cd "$BENCH_DIR/asherah-node-bench" && run_node_bench "asherah-node" \
        "{ serviceName: 'bench-svc', productId: 'bench-prod', metastore: 'memory', kms: 'static', enableSessionCaching: false }") \
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
    (cd "$BENCH_DIR/node-bench-canonical" && run_node_bench "asherah" \
        "{ ServiceName: 'bench-svc', ProductID: 'bench-prod', Metastore: 'memory', KMS: 'static', EnableSessionCaching: false }") \
        2>&1 | grep -v 'asherah-cobhan:' > "$RESULTS_DIR/node_canon.log"
    parse_node_bench "$RESULTS_DIR/node_canon.log" > "$RESULTS_DIR/96_Canon._Node.js_(Cobhan)"
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
