#!/bin/bash
# Shared before-script-linux for maturin-action builds.
# Used by both publish-pypi.yml and CI dry-run jobs.
# ANY change here affects all PyPI builds — test via CI dry-runs first.
set -euo pipefail

if command -v yum &>/dev/null; then
  # manylinux native (CentOS/RHEL based) — system OpenSSL for target arch
  yum install -y cmake3 perl-IPC-Cmd openssl-devel pkgconfig 2>/dev/null || \
  yum install -y cmake perl-IPC-Cmd openssl-devel pkgconfig 2>/dev/null || true
  [ -x /usr/bin/cmake3 ] && ln -sf /usr/bin/cmake3 /usr/local/bin/cmake 2>/dev/null || true
  export OPENSSL_NO_VENDOR=1
elif command -v apk &>/dev/null; then
  # musllinux native (Alpine based)
  apk add --no-cache cmake make perl openssl-dev openssl-libs-static pkgconf musl-dev
  export OPENSSL_NO_VENDOR=1
elif command -v apt-get &>/dev/null; then
  # Cross-compile container (Debian based)
  apt-get update && apt-get install -y cmake perl pkg-config curl
  if ls /usr/bin/*musl* 2>/dev/null; then
    # rust-musl-cross: download musl OpenSSL from Alpine via shared script
    MUSL_ARCH=$(uname -m)
    case "$MUSL_ARCH" in
      x86_64)       ARCH=x86_64 ;;
      aarch64|arm64) ARCH=aarch64 ;;
      *) echo "ERROR: Unsupported musl architecture '$MUSL_ARCH'" >&2; exit 1 ;;
    esac
    DOWNLOAD_SCRIPT="${GITHUB_WORKSPACE:-$(pwd)}/scripts/download-musl-openssl.sh"
    if [ ! -f "$DOWNLOAD_SCRIPT" ]; then
      echo "ERROR: Expected helper script not found: $DOWNLOAD_SCRIPT" >&2
      exit 1
    fi
    source "$DOWNLOAD_SCRIPT"
  fi
  # glibc cross-compile (manylinux-cross): openssl-sys vendors OpenSSL
fi
pkg-config --libs openssl 2>/dev/null || echo "INFO: pkg-config openssl not found, will vendor or use OPENSSL_DIR"
