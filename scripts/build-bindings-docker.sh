#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
TAG_SUFFIX="${PLATFORM//\//-}"
IMAGE_TAG="asherah-bindings:${TAG_SUFFIX}"

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
  -v "$ROOT_DIR:/workspace" \
  -w /workspace \
  "$IMAGE_TAG" \
  /workspace/scripts/build-bindings.sh
