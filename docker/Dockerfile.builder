# Shared builder stage. Each runtime image FROM this layer for cargo build.
FROM rust:1.88-bookworm AS builder

WORKDIR /work

# Install system deps (boringtun is pure Rust; only build-essential needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Cache deps separately from sources for fast rebuilds.
COPY Cargo.toml Cargo.lock* ./
COPY rust-toolchain.toml ./
COPY crates ./crates
COPY tests ./tests
COPY fhe-helper ./fhe-helper

RUN cargo build --release --workspace
