#!/bin/bash
set -e

# Build asherah-node package for all platforms locally
# This is a workaround for when GitHub Actions is unavailable due to billing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT/asherah-node"

echo "Building asherah-node package..."

# Determine current platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$PLATFORM-$ARCH" in
  darwin-arm64)
    TARGET="aarch64-apple-darwin"
    ;;
  darwin-x86_64)
    TARGET="x86_64-apple-darwin"
    ;;
  linux-x86_64)
    TARGET="x86_64-unknown-linux-gnu"
    ;;
  linux-aarch64)
    TARGET="aarch64-unknown-linux-gnu"
    ;;
  *)
    echo "Unsupported platform: $PLATFORM-$ARCH"
    exit 1
    ;;
esac

echo "Detected platform: $PLATFORM-$ARCH (Rust target: $TARGET)"

# Install dependencies (ignore optionalDependencies that don't exist yet)
npm install --ignore-scripts

# Build for current platform
echo "Building for $TARGET..."
npx @napi-rs/cli build --release --target "$TARGET"

# Copy binary to npm directory (napi puts it in project root as index.node)
if [ -f "$PROJECT_ROOT/asherah-node/index.node" ]; then
  echo "Copying binary to npm/asherah.node..."
  cp "$PROJECT_ROOT/asherah-node/index.node" "$PROJECT_ROOT/asherah-node/npm/asherah.node"
fi

echo ""
echo "✓ Build complete for current platform ($PLATFORM-$ARCH)"
echo "✓ Binary copied to npm/asherah.node"
echo ""
echo "To test and publish:"
echo "  cd asherah-node"
echo "  node test/roundtrip.js    # Test the build"
echo "  npm pack                  # Create tarball (dry run)"
echo "  npm publish --access public  # Publish to npm"
echo ""
echo "Note: This builds a single-platform package for $PLATFORM-$ARCH only."
echo "Users on other platforms will need platform-specific builds."
echo "To support all platforms, fix the GitHub Actions billing issue."
