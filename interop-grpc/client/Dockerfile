# Builds the interop test client into a slim image. The harness mounts
# the shared socket volume into this container and invokes the binary
# against each server in turn.
ARG RUSTVERSION=1.91
FROM rust:${RUSTVERSION}-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml build.rs ./
COPY proto/ proto/
COPY src/ src/

RUN cargo build --release --bin interop-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/interop-client /usr/local/bin/interop-client
ENTRYPOINT ["/usr/local/bin/interop-client"]
