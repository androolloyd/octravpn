# Shared builder stage. Each runtime image FROM this layer for cargo build.
#
# Build context: PARENT of the octra repo, so both `octra/` and the
# sibling `octra-foundry/` (which owns the `octraforge` +
# `octra-mock-rpc` crates that octra/ path-deps into) are visible.
# `docker-compose.yml` already sets `context: ..` for this.
#
# Build performance: ~3 min cold; current iteration story is "edit
# source → docker compose build → ~3 min". Faster incremental
# rebuilds require either a long-lived dev container with a bind-
# mounted target volume, or building the binaries on the host and
# mounting them into the runtime images. Both are tracked as
# follow-ups.
FROM rust:1.96.0-bookworm AS builder

WORKDIR /work

# Install system deps. boringtun is pure Rust; `protobuf-compiler` is
# needed by the path-depped `headscale-api` build script (prost-build).
# Mirrors the GH-Actions `setup-rust` composite action that we wired
# the same way for ci.yml + demo.yml + proof.yml + fuzz.yml.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates protobuf-compiler libprotobuf-dev && \
    rm -rf /var/lib/apt/lists/*

# Mirror the host layout: /work/octra + /work/octra-foundry +
# /work/headscale-rs side-by-side. The two sibling repos own crates
# that octra/ path-deps into (octra-foundry → mock-rpc + octraforge;
# headscale-rs → headscale-api + headscale-cli for the wire/admin
# layer), so the Cargo workspace cannot resolve without them.
COPY octra-foundry ./octra-foundry
COPY headscale-rs ./headscale-rs
COPY octra/Cargo.toml octra/Cargo.lock* ./octra/
COPY octra/rust-toolchain.toml* ./octra/
COPY octra/crates ./octra/crates
COPY octra/vendor ./octra/vendor
COPY octra/tests ./octra/tests
COPY octra/program ./octra/program
# pvac-sidecar/ipc-tests is a workspace member referenced from the
# root Cargo.toml; cargo errors out at workspace-load time if absent.
# We only need the manifest + the (tiny) src/ for cargo to be happy
# — the binaries this builder produces don't link it.
COPY octra/pvac-sidecar ./octra/pvac-sidecar

WORKDIR /work/octra
# The mock is a dev-only path dependency, so release builds select it via
# Foundry's own locked manifest. Share the output directory used by runtime images.
RUN cargo build --locked --release -p octravpn-node -p octravpn-client && \
    CARGO_TARGET_DIR=/work/octra/target cargo build --locked --release \
        --manifest-path /work/octra-foundry/Cargo.toml -p octra-mock-rpc -p octra-cli
