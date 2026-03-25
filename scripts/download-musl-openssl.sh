#!/bin/bash
# Download musl-compatible OpenSSL headers and static libraries from Alpine Linux.
# Used by npm musl builds in ci.yml and publish-npm.yml.
#
# Usage: ARCH=x86_64 source scripts/download-musl-openssl.sh
#   Sets OPENSSL_DIR, OPENSSL_STATIC, OPENSSL_NO_VENDOR in the environment.
set -euo pipefail

ARCH="${ARCH:?ARCH must be set (x86_64 or aarch64)}"
ALPINE_VERSION="${ALPINE_VERSION:-v3.20}"

mkdir -p /tmp/musl-ssl
(cd /tmp/musl-ssl && \
  OPENSSL_DEV=$(curl -sL "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}/" | grep -o "openssl-dev-[^\"]*\\.apk" | head -1) && \
  OPENSSL_STATIC=$(curl -sL "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}/" | grep -o "openssl-libs-static-[^\"]*\\.apk" | head -1) && \
  echo "Downloading ${OPENSSL_DEV} and ${OPENSSL_STATIC}" && \
  curl -sLO "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}/${OPENSSL_DEV}" && \
  curl -sLO "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}/${OPENSSL_STATIC}" && \
  for f in *.apk; do tar xf "$f" 2>/dev/null || true; done)

ls /tmp/musl-ssl/usr/include/openssl/ssl.h || { echo "ERROR: OpenSSL headers not found"; exit 1; }
ls /tmp/musl-ssl/usr/lib/libssl.a || { echo "ERROR: OpenSSL static lib not found"; exit 1; }

export OPENSSL_DIR=/tmp/musl-ssl/usr
export OPENSSL_STATIC=1
export OPENSSL_NO_VENDOR=1
