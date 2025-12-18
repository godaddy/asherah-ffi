#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
TAG_SUFFIX="${PLATFORM//\//-}"
IMAGE_TAG="asherah-bindings:${TAG_SUFFIX}"
CACHE_DIR="$ROOT_DIR/.cache"
APT_ALLOW_INSECURE_ARG=()
APT_MINIMAL_ARG=()
DOTNET_SKIP_ARG=()

mkdir -p \
  "$CACHE_DIR/cargo" \
  "$CACHE_DIR/rustup" \
  "$CACHE_DIR/pip" \
  "$CACHE_DIR/npm" \
  "$CACHE_DIR/maven" \
  "$CACHE_DIR/dotnet"

COMMON_MOUNTS=(
  -v "$ROOT_DIR:/workspace"
  -w /workspace
  -v "$CACHE_DIR/cargo:/root/.cargo"
  -v "$CACHE_DIR/rustup:/root/.rustup"
  -v "$CACHE_DIR/pip:/root/.cache/pip"
  -v "$CACHE_DIR/npm:/root/.npm"
  -v "$CACHE_DIR/maven:/root/.m2"
  -v "$CACHE_DIR/dotnet:/root/.nuget/packages"
)

ENV_ARGS=()
ENV_ARGS+=("-e" "CARGO_HOME=/root/.cargo")
ENV_ARGS+=("-e" "RUSTUP_HOME=/root/.rustup")
for var in BINDING_COMPONENTS BINDING_OUTPUT_DIR SKIP_CORE_BUILD TARGET_ARCH; do
  if [ -n "${!var:-}" ]; then
    ENV_ARGS+=("-e" "$var=${!var}")
  fi
done

if [ -n "${DOCKER_APT_ALLOW_INSECURE:-}" ]; then
  APT_ALLOW_INSECURE_ARG=(--build-arg "APT_ALLOW_INSECURE=${DOCKER_APT_ALLOW_INSECURE}")
fi
if [ -n "${DOCKER_APT_MINIMAL:-}" ]; then
  APT_MINIMAL_ARG=(--build-arg "APT_MINIMAL=${DOCKER_APT_MINIMAL}")
fi
if [ -n "${DOCKER_DOTNET_SKIP:-}" ]; then
  DOTNET_SKIP_ARG=(--build-arg "DOTNET_SKIP=${DOCKER_DOTNET_SKIP}")
fi

echo "[build-bindings-docker] Building image for platform ${PLATFORM}"
BUILD_ARGS=(
  --platform "$PLATFORM"
  --file "$ROOT_DIR/docker/tests.Dockerfile"
  --tag "$IMAGE_TAG"
)
if [ ${#APT_ALLOW_INSECURE_ARG[@]} -gt 0 ]; then
  BUILD_ARGS+=("${APT_ALLOW_INSECURE_ARG[@]}")
fi
if [ ${#APT_MINIMAL_ARG[@]} -gt 0 ]; then
  BUILD_ARGS+=("${APT_MINIMAL_ARG[@]}")
fi
if [ ${#DOTNET_SKIP_ARG[@]} -gt 0 ]; then
  BUILD_ARGS+=("${DOTNET_SKIP_ARG[@]}")
fi
BUILD_ARGS+=(--load "$ROOT_DIR")
docker buildx build "${BUILD_ARGS[@]}"

echo "[build-bindings-docker] Running bindings build script for ${PLATFORM}"
docker run --rm \
  --platform "$PLATFORM" \
  "${COMMON_MOUNTS[@]}" \
  "${ENV_ARGS[@]}" \
  "$IMAGE_TAG" \
  /workspace/scripts/build-bindings.sh
