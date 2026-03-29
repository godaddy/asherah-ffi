#!/bin/bash
# Install sccache in container environments where taiki-e/install-action is unavailable.
# Used by arm64 container jobs in ci.yml and maturin Docker containers.
set -euo pipefail

SCCACHE_VERSION="${SCCACHE_VERSION:-0.8.1}"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        TARGET="x86_64-unknown-linux-musl" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "ERROR: unsupported architecture '$ARCH'" >&2; exit 1 ;;
esac

URL="https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-${TARGET}.tar.gz"
TMPFILE="/tmp/sccache-${SCCACHE_VERSION}.tar.gz"

for attempt in 1 2 3; do
  echo "Downloading sccache v${SCCACHE_VERSION} (attempt ${attempt})..."
  if curl -fSL --retry 3 --retry-delay 5 -o "$TMPFILE" "$URL"; then
    # Validate it's actually a gzip file, not an HTML error page
    if file "$TMPFILE" | grep -q gzip; then
      tar xzf "$TMPFILE"
      mv sccache-*/sccache /usr/local/bin/
      chmod +x /usr/local/bin/sccache
      rm -rf sccache-* "$TMPFILE"
      echo "sccache v${SCCACHE_VERSION} installed"
      exit 0
    else
      echo "WARNING: downloaded file is not gzip (attempt ${attempt})" >&2
      head -c 200 "$TMPFILE" >&2
      echo >&2
      rm -f "$TMPFILE"
    fi
  else
    echo "WARNING: curl failed (attempt ${attempt})" >&2
    rm -f "$TMPFILE"
  fi
  [ "$attempt" -lt 3 ] && sleep 5
done

echo "ERROR: failed to download sccache after 3 attempts" >&2
exit 1
