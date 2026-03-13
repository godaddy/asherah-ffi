FROM rust:1.88-bookworm AS builder

WORKDIR /src

# Install build dependencies for vendored OpenSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config perl make protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# Copy entire workspace (filtered by .dockerignore)
COPY . .

# Build release binary with all features (mysql, postgres, dynamodb)
RUN cargo build --release -p asherah-server && \
    strip target/release/asherah-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/asherah-server /usr/local/bin/asherah-server

ENTRYPOINT ["asherah-server"]
CMD ["--help"]
