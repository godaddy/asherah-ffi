#!/usr/bin/env bash
# Generate architecture-specific build info
# Usage: source scripts/arch-info.sh <x86_64|aarch64>

set -euo pipefail

ARCH="${1:-$(uname -m)}"

case "$ARCH" in
  x86_64)
    export ARCH_SHORT="x86_64"
    export ARCH_RUST_TRIPLE="x86_64-unknown-linux-gnu"
    export ARCH_MANYLINUX="manylinux_2_28_x86_64"
    export ARCH_CROSS_GCC="aarch64-linux-gnu-gcc"
    export ARCH_CROSS_GXX="aarch64-linux-gnu-g++"
    export ARCH_CROSS_AR="aarch64-linux-gnu-ar"
    ;;
  aarch64|arm64)
    export ARCH_SHORT="aarch64"
    export ARCH_RUST_TRIPLE="aarch64-unknown-linux-gnu"
    export ARCH_MANYLINUX="manylinux_2_28_aarch64"
    export ARCH_CROSS_GCC="x86_64-linux-gnu-gcc"
    export ARCH_CROSS_GXX="x86_64-linux-gnu-g++"
    export ARCH_CROSS_AR="x86_64-linux-gnu-ar"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Compute cross-arch values
if [ "$ARCH_SHORT" = "x86_64" ]; then
  export CROSS_ARCH_SHORT="aarch64"
  export CROSS_ARCH_RUST_TRIPLE="aarch64-unknown-linux-gnu"
  export CROSS_ARCH_MANYLINUX="manylinux_2_28_aarch64"
else
  export CROSS_ARCH_SHORT="x86_64"
  export CROSS_ARCH_RUST_TRIPLE="x86_64-unknown-linux-gnu"
  export CROSS_ARCH_MANYLINUX="manylinux_2_28_x86_64"
fi
