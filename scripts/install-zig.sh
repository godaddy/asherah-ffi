#!/usr/bin/env bash
# Install Zig with retry-on-failure semantics.
#
# Replaces `mlugg/setup-zig@v2`, which has no built-in retry — its single
# fetch failure (`##[error]fetch failed`) was blocking PR CI on transient
# ziglang.org / GitHub-release flakes. This script wraps curl with
# `--retry 10 --retry-connrefused`, falls back across two mirrors, and
# pins a known-good Zig version compatible with cargo-zigbuild.
#
# Used by:
#   - .github/workflows/ci.yml         (4 call sites: node-musl-x64,
#                                       node-musl-arm64, cobhan-musl-x64,
#                                       cobhan-musl-arm64)
#   - .github/workflows/publish-npm.yml
#   - .github/workflows/release-cobhan.yml
#
# Both the publish workflows and their dry-run mirrors call this script
# so they cannot drift on the Zig install path.
#
# Inputs (env):
#   ZIG_VERSION   — Zig version to install (default: 0.14.1)
#   ZIG_INSTALL_DIR — install prefix (default: $RUNNER_TEMP/zig or /opt/zig)
#
# Outputs:
#   - Zig binary on $PATH (via $GITHUB_PATH)
#   - `zig version` printed to stdout for verification
set -euo pipefail

ZIG_VERSION="${ZIG_VERSION:-0.14.1}"

case "$(uname -m)" in
    x86_64|amd64) ZIG_ARCH=x86_64 ;;
    aarch64|arm64) ZIG_ARCH=aarch64 ;;
    *)
        echo "::error::install-zig.sh: unsupported host arch $(uname -m)"
        exit 1
        ;;
esac

case "$(uname -s)" in
    Linux) ZIG_OS=linux ;;
    Darwin) ZIG_OS=macos ;;
    *)
        echo "::error::install-zig.sh: unsupported host OS $(uname -s)"
        exit 1
        ;;
esac

ZIG_TARBALL="zig-${ZIG_ARCH}-${ZIG_OS}-${ZIG_VERSION}.tar.xz"
# Primary + two community mirrors. ziglang.org occasionally rejects
# CI egress with `SSL_read: Connection reset by peer`; the community
# mirrors (listed at https://ziglang.org/download/community-mirrors/)
# serve the same payload from independent infrastructure.
URLS=(
    "https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TARBALL}"
    "https://zigmirror.hryx.net/zig/${ZIG_TARBALL}"
    "https://pkg.machengine.org/zig/${ZIG_TARBALL}"
)

INSTALL_DIR="${ZIG_INSTALL_DIR:-${RUNNER_TEMP:-/tmp}/zig}"
mkdir -p "$INSTALL_DIR"
TARBALL_PATH="${INSTALL_DIR}/${ZIG_TARBALL}"

download() {
    local url="$1"
    # --retry 10 --retry-connrefused covers transient connection /
    # 5xx failures. --max-time 600 bounds runaway hangs but is loose
    # enough that a slow link can complete the ~46 MB tarball; CI
    # runners usually finish in seconds.
    curl --retry 10 \
        --retry-connrefused \
        --retry-delay 5 \
        --connect-timeout 30 \
        --max-time 600 \
        --fail \
        --silent \
        --show-error \
        --location \
        -o "$TARBALL_PATH" \
        "$url"
}

echo ">>> Installing Zig ${ZIG_VERSION} for ${ZIG_OS}-${ZIG_ARCH}"
# Try each URL with 2 attempts. curl --retry handles connect-level
# transients within a single invocation; the outer attempt covers
# mid-body resets (SSL_read EAGAIN, etc.). On exhaustion, fall through
# to the next mirror. With 3 URLs × 2 attempts = 6 chances against
# 3 independent infrastructures.
download_ok=0
for url in "${URLS[@]}"; do
    for attempt in 1 2; do
        echo ">>> Download attempt $attempt from $url"
        if download "$url"; then
            download_ok=1
            break 2
        fi
        echo "::warning::install-zig.sh: $url attempt $attempt failed"
        sleep $((attempt * 3))
    done
done
if [[ $download_ok -ne 1 ]]; then
    echo "::error::install-zig.sh: all mirrors failed (tried ${#URLS[@]} URLs × 2 attempts)"
    exit 1
fi

# Extract into INSTALL_DIR; the tarball contains a top-level
# `zig-${ZIG_OS}-${ZIG_ARCH}-${ZIG_VERSION}/` directory.
tar -xf "$TARBALL_PATH" -C "$INSTALL_DIR"
ZIG_BIN_DIR="${INSTALL_DIR}/zig-${ZIG_ARCH}-${ZIG_OS}-${ZIG_VERSION}"
if [[ ! -x "${ZIG_BIN_DIR}/zig" ]]; then
    echo "::error::install-zig.sh: zig binary not found at ${ZIG_BIN_DIR}/zig after extraction"
    ls -la "$INSTALL_DIR"
    exit 1
fi

# Persist on PATH for subsequent steps.
if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$ZIG_BIN_DIR" >>"$GITHUB_PATH"
fi
export PATH="${ZIG_BIN_DIR}:$PATH"

echo ">>> Installed:"
zig version
