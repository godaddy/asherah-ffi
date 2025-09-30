#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
TAG_SUFFIX="${PLATFORM//\//-}"
IMAGE_TAG="asherah-bindings:${TAG_SUFFIX}"
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

echo "[build-bindings-docker] Building image for platform ${PLATFORM}"
docker buildx build \
  --platform "$PLATFORM" \
  --file "$ROOT_DIR/docker/tests.Dockerfile" \
  --tag "$IMAGE_TAG" \
  --load \
  "$ROOT_DIR"

echo "[build-bindings-docker] Running bindings build script for ${PLATFORM}"
docker run --rm \
  --platform "$PLATFORM" \
  "${COMMON_MOUNTS[@]}" \
  "$IMAGE_TAG" \
  /workspace/scripts/build-bindings.sh
