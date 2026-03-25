#!/bin/bash
# Install sccache in container environments where taiki-e/install-action is unavailable.
# Used by arm64 container jobs in ci.yml.
set -euo pipefail

SCCACHE_VERSION="${SCCACHE_VERSION:-0.8.1}"

curl -fL --retry 5 --retry-delay 5 \
  "https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz" | tar xz
mv sccache-*/sccache /usr/local/bin/
chmod +x /usr/local/bin/sccache
rm -rf sccache-*
