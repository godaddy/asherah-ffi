# syntax=docker/dockerfile:1
# Pin builder to the build host platform so we never compile under QEMU.
# Cross-compilation is handled by Rust/GCC toolchains instead.
FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder

ARG TARGETARCH

WORKDIR /src

# Install build dependencies + cross-compilation toolchain for arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config perl make protobuf-compiler \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu && \
    rm -rf /var/lib/apt/lists/*

# Configure cross-compilation for arm64
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    PKG_CONFIG_ALLOW_CROSS=1

# Copy entire workspace (filtered by .dockerignore)
COPY . .

# Install the toolchain + targets specified in rust-toolchain.toml,
# then build release binary, cross-compiling if target is arm64
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      TARGET=aarch64-unknown-linux-gnu; \
    else \
      TARGET=x86_64-unknown-linux-gnu; \
    fi && \
    rustup target add $TARGET && \
    cargo build --release -p asherah-server --target $TARGET && \
    mkdir -p /out && \
    cp target/$TARGET/release/asherah-server /out/asherah-server && \
    if [ "$TARGETARCH" = "arm64" ]; then \
      aarch64-linux-gnu-strip /out/asherah-server; \
    else \
      strip /out/asherah-server; \
    fi

# Final image uses the TARGET platform (matches the binary we cross-compiled)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/asherah-server /usr/local/bin/asherah-server

ENTRYPOINT ["asherah-server"]
CMD ["--help"]
