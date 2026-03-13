#!/usr/bin/env bash
set -euo pipefail

RUBY="${RUBY:-/opt/homebrew/opt/ruby/bin/ruby}"
ITERATIONS="${ITERATIONS:-50000}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Ruby: $($RUBY --version)"
echo "Iterations: $ITERATIONS"
echo ""

echo "=== Go cobhan (canonical asherah gem) ==="
ITERATIONS=$ITERATIONS $RUBY "$DIR/bench_go.rb" 2>/dev/null
echo ""

echo "=== Rust cobhan (canonical gem + Rust native lib) ==="
ITERATIONS=$ITERATIONS $RUBY "$DIR/bench_hybrid.rb" 2>/dev/null
echo ""

echo "=== Rust FFI (asherah-ruby binding) ==="
ITERATIONS=$ITERATIONS $RUBY "$DIR/bench_rust.rb" 2>/dev/null
echo ""
