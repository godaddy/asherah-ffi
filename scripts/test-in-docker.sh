#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
IMAGE_TAG="asherah-tests:latest"
CACHE_DIR="$ROOT_DIR/.cache"

mkdir -p \
  "$CACHE_DIR/cargo" \
  "$CACHE_DIR/pip" \
  "$CACHE_DIR/npm" \
  "$CACHE_DIR/maven" \
  "$CACHE_DIR/dotnet"

COMMON_MOUNTS=(
  -v "$ROOT_DIR:/workspace"
  -w /workspace
  -v "$CACHE_DIR/cargo:/root/.cargo"
  -v "$CACHE_DIR/pip:/root/.cache/pip"
  -v "$CACHE_DIR/npm:/root/.npm"
  -v "$CACHE_DIR/maven:/root/.m2"
  -v "$CACHE_DIR/dotnet:/root/.nuget/packages"
)

if [ -n "${DOCKER_PLATFORM:-}" ]; then
  docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --file "$ROOT_DIR/docker/tests.Dockerfile" \
    --tag "$IMAGE_TAG" \
    --load \
    "$ROOT_DIR"

  docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    "${COMMON_MOUNTS[@]}" \
    "$IMAGE_TAG" \
    /workspace/scripts/run-tests.sh
else
  docker build -f "$ROOT_DIR/docker/tests.Dockerfile" -t "$IMAGE_TAG" "$ROOT_DIR"

  docker run --rm \
    "${COMMON_MOUNTS[@]}" \
    "$IMAGE_TAG" \
    /workspace/scripts/run-tests.sh
fi
