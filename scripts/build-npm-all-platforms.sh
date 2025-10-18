#!/bin/bash
set -e

# Build asherah-node for all platforms locally
# This script builds all possible platforms from the current host

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT/asherah-node"

echo "Building asherah-node for all platforms..."
echo

# Determine current platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Install dependencies once
echo "Installing dependencies..."
npm ci --ignore-scripts

# Clean previous builds
rm -f *.node
rm -f *.tgz

if [ "$PLATFORM" = "darwin" ]; then
  echo
  echo "==> Building for macOS (both architectures)"
  echo

  # macOS ARM64
  echo "Building for aarch64-apple-darwin..."
  npm run build:release -- --target aarch64-apple-darwin
  mv index.node index.darwin-arm64.node
  echo "✓ Built index.darwin-arm64.node"

  # macOS x64
  echo "Building for x86_64-apple-darwin..."
  npm run build:release -- --target x86_64-apple-darwin
  mv index.node index.darwin-x64.node
  echo "✓ Built index.darwin-x64.node"

  echo
  echo "macOS builds complete!"

  # Also build Linux if Docker is available
  if command -v docker >/dev/null 2>&1; then
  echo
  echo "==> Building Linux binaries using Docker"
  echo

  # Build Linux x64
  echo "Building for x86_64-unknown-linux-gnu in Docker..."
  docker run --rm \
    -v "$PROJECT_ROOT:/work" \
    -w /work/asherah-node \
    --platform linux/amd64 \
    rust:latest \
    bash -c "
      set -ex
      apt-get update -qq && apt-get install -y -qq nodejs npm > /dev/null 2>&1
      rustup target add x86_64-unknown-linux-gnu
      npm ci --ignore-scripts
      cargo build --release --target x86_64-unknown-linux-gnu
      ls -la ../target/x86_64-unknown-linux-gnu/release/ | grep asherah
      strip ../target/x86_64-unknown-linux-gnu/release/libasherah_node.so
      cp ../target/x86_64-unknown-linux-gnu/release/libasherah_node.so index.linux-x64-gnu.node
    "
  echo "✓ Built index.linux-x64-gnu.node"

  # Build Linux ARM64
  echo "Building for aarch64-unknown-linux-gnu in Docker..."
  docker run --rm \
    -v "$PROJECT_ROOT:/work" \
    -w /work/asherah-node \
    --platform linux/amd64 \
    rust:latest \
    bash -c "
      set -ex
      apt-get update -qq && apt-get install -y -qq nodejs npm gcc-aarch64-linux-gnu g++-aarch64-linux-gnu > /dev/null 2>&1
      npm ci --ignore-scripts
      rustup target add aarch64-unknown-linux-gnu
      export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
      export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
      cargo build --release --target aarch64-unknown-linux-gnu
      ls -la ../target/aarch64-unknown-linux-gnu/release/ | grep asherah
      aarch64-linux-gnu-strip ../target/aarch64-unknown-linux-gnu/release/libasherah_node.so
      cp ../target/aarch64-unknown-linux-gnu/release/libasherah_node.so index.linux-arm64-gnu.node
    "
  echo "✓ Built index.linux-arm64-gnu.node"

  echo
  echo "Linux builds complete (via Docker)!"
  fi

elif [ "$PLATFORM" = "linux" ]; then
  echo
  echo "==> Building for Linux (both architectures)"
  echo

  # Linux x64
  echo "Building for x86_64-unknown-linux-gnu..."
  npm run build:release -- --target x86_64-unknown-linux-gnu
  mv index.node index.linux-x64-gnu.node
  strip -x index.linux-x64-gnu.node
  echo "✓ Built index.linux-x64-gnu.node"

  # Linux ARM64 (requires cross-compilation tools)
  if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "Building for aarch64-unknown-linux-gnu..."
    npm run build:release -- --target aarch64-unknown-linux-gnu
    mv index.node index.linux-arm64-gnu.node
    aarch64-linux-gnu-strip index.linux-arm64-gnu.node
    echo "✓ Built index.linux-arm64-gnu.node"
  else
    echo "⚠️  Skipping ARM64 build - aarch64-linux-gnu-gcc not found"
    echo "   Install with: sudo apt-get install gcc-aarch64-linux-gnu"
  fi

  echo
  echo "Linux builds complete!"

else
  echo "Unsupported platform: $PLATFORM"
  exit 1
fi

# Show what we built
echo
echo "Built binaries:"
ls -lh *.node

# Create universal package structure
echo
echo "==> Creating universal package with all binaries"
node create-universal-package.js

# Create the package
npm pack

echo
echo "✅ Package created successfully!"
ls -lh *.tgz

echo
echo "To test before publishing:"
echo "  npm install ./$(ls -t *.tgz | head -1)"
echo "  node test/roundtrip.js"
echo
echo "To publish:"
echo "  npm publish --access public"
