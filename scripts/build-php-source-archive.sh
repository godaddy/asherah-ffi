#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/tmp/asherah-php-dist}"
if [[ "$OUT_DIR" != /* ]]; then
    OUT_DIR="$PWD/$OUT_DIR"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_SRC="$ROOT_DIR/asherah-php"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/asherah-php-archive.XXXXXX")"
PACKAGE_WORK="$TMP_ROOT/asherah-php"
trap 'rm -rf "$TMP_ROOT"' EXIT
export COMPOSER_CACHE_DIR="$TMP_ROOT/composer-cache"
if [ -z "${COMPOSER_ROOT_VERSION:-}" ]; then
    if VERSION="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null)"; then
        export COMPOSER_ROOT_VERSION="$VERSION"
    elif BRANCH="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null)" && [ -n "$BRANCH" ] && [ "$BRANCH" != "HEAD" ]; then
        export COMPOSER_ROOT_VERSION="dev-$BRANCH"
    else
        export COMPOSER_ROOT_VERSION="dev-main"
    fi
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

cp -a "$PACKAGE_SRC" "$PACKAGE_WORK"
rm -rf "$PACKAGE_WORK/vendor" \
    "$PACKAGE_WORK/native" \
    "$PACKAGE_WORK/composer.lock" \
    "$PACKAGE_WORK/.php-cs-fixer.cache" \
    "$PACKAGE_WORK/.phpunit.cache"

cd "$PACKAGE_WORK"
rm -f composer.lock
composer install --prefer-dist --no-progress
composer validate --strict
composer archive --format=zip --dir="$OUT_DIR" >/dev/null

ARCHIVE="$(find "$OUT_DIR" -maxdepth 1 -type f -name '*.zip' | head -n 1)"
if [ -z "$ARCHIVE" ]; then
    echo "ERROR: composer archive did not produce a zip" >&2
    exit 1
fi

unzip -l "$ARCHIVE" | tee "$OUT_DIR/archive.txt"
! grep -E " vendor/| native/| composer.lock" "$OUT_DIR/archive.txt"
grep -q "src/Asherah.php" "$OUT_DIR/archive.txt"

printf '%s\n' "$ARCHIVE"
