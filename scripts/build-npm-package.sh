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

echo ""
echo "✓ Build complete for current platform"
echo ""
echo "Note: This script only builds for your current platform ($PLATFORM-$ARCH)."
echo "To publish a complete package with all platforms, you need:"
echo ""
echo "  1. Build on macOS (ARM64 + x86_64)"
echo "  2. Build on Linux (x86_64 + ARM64 via cross-compilation)"
echo "  3. Build on Windows (x86_64)"
echo "  4. Combine all bindings into npm/ directory"
echo "  5. Run: npm publish --access public"
echo ""
echo "Or fix the GitHub Actions billing issue to use the automated workflow."
