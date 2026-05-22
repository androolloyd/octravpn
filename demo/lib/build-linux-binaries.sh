#!/usr/bin/env bash
# build-linux-binaries.sh
#
# Build all the Linux binaries the demo harnesses need, from a macOS
# (or any) dev host, using docker as the cross-compile runtime. We
# don't actually cross-compile in the cargo sense — we run cargo
# inside `rust:1.88-bookworm`, so the toolchain IS Linux and the
# emitted ELF binaries match the debian:bookworm-slim containers the
# bringups mount them into.
#
# Mirrors the build path the 3node-mesh-bringup uses (`target/linux-debug/`),
# so a single warm cargo cache services every fixture.
#
# Binaries built (under target/linux-debug/debug/):
#   - octravpn            (crates/octravpn-client, [[bin]] name "octravpn")
#   - octravpn-node       (crates/octravpn-node)
#   - octravpn-analytics  (crates/octravpn-analytics)
#   - octra-mock-rpc      (sibling repo ../octra-foundry, crates/octra-mock-rpc)
#
# Exit codes:
#   0   READY — every requested binary is present and fresh.
#   10  cargo build inside docker failed.
#   20  docker not available on host.
#   30  required sibling repo missing (../octra-foundry, ../headscale-rs).
#
# Idempotency: each binary is checked against its crate's main.rs
# mtime. If the binary is newer than the source entry-point, the
# build is skipped. A warm-cache run (nothing changed) is sub-second.
#
# Measured on this repo, Apple M-series host (rust:1.88-bookworm
# pre-pulled, target/linux-debug wiped, host cargo cache untouched):
#   cold (`rm -rf target/linux-debug && time bash …`): ~103 s real
#     (octravpn workspace 1m15s in cargo, mock-rpc 10s, plus the apt
#     protobuf-compiler libprotobuf-dev install). Linker is the long pole; `dev`
#     profile keeps it bearable.
#   warm (every binary fresh): ~0.2 s real — pure stat() and shell.
# Subsequent cold rebuilds (target wiped, cargo-registry preserved)
# typically come in under 60 s because crates.io fetch is skipped.
#
# Env overrides:
#   OCTRA_BUILDER_IMAGE  Override the docker image (default
#                        octravpn-builder:latest if present, else
#                        rust:1.88-bookworm).
#   OCTRA_FOUNDRY_PATH   Path to ../octra-foundry sibling (default
#                        ${REPO_ROOT}/../octra-foundry).
#   HEADSCALE_RS_PATH    Path to ../headscale-rs sibling (default
#                        ${REPO_ROOT}/../headscale-rs).
#   BUILD_LINUX_FORCE    If set to 1, rebuild every binary regardless
#                        of freshness.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
LINUX_TARGET_DIR="${REPO_ROOT}/target/linux-debug"
DEBUG_DIR="${LINUX_TARGET_DIR}/debug"
FOUNDRY_DEBUG_DIR="${LINUX_TARGET_DIR}/foundry-debug"

# Sibling repos required by the workspace's transitive deps (headscale-rs
# is a path dep via the mesh crate's protobuf bridge, octra-foundry hosts
# the mock-rpc crate).
OCTRA_FOUNDRY="${OCTRA_FOUNDRY_PATH:-${REPO_ROOT}/../octra-foundry}"
HEADSCALE_RS="${HEADSCALE_RS_PATH:-${REPO_ROOT}/../headscale-rs}"

if ! command -v docker >/dev/null 2>&1; then
    echo "build-linux-binaries: docker not on PATH" >&2
    exit 20
fi
if ! docker info >/dev/null 2>&1; then
    echo "build-linux-binaries: docker daemon not reachable" >&2
    exit 20
fi

if [[ ! -d "${OCTRA_FOUNDRY}" ]]; then
    echo "build-linux-binaries: sibling repo missing at ${OCTRA_FOUNDRY}" >&2
    exit 30
fi
if [[ ! -d "${HEADSCALE_RS}" ]]; then
    echo "build-linux-binaries: sibling repo missing at ${HEADSCALE_RS}" >&2
    exit 30
fi

mkdir -p "${DEBUG_DIR}" \
         "${FOUNDRY_DEBUG_DIR}" \
         "${LINUX_TARGET_DIR}/cargo-registry" \
         "${LINUX_TARGET_DIR}/cargo-git"

# Pick the builder image. The prebuilt octravpn-builder:latest (if
# present) already has protoc + build deps baked in; fall back to the
# vanilla rust image with an inline apt-install preamble.
BUILDER_IMAGE="${OCTRA_BUILDER_IMAGE:-}"
if [[ -z "${BUILDER_IMAGE}" ]]; then
    if docker image inspect octravpn-builder:latest >/dev/null 2>&1; then
        BUILDER_IMAGE="octravpn-builder:latest"
    else
        BUILDER_IMAGE="rust:1.88-bookworm"
    fi
fi

# headscale-api's build.rs (prost-build) shells out to protoc; the
# prebuilt builder image already has it, the vanilla rust image needs
# the apt step.
BUILD_PREAMBLE=""
if [[ "${BUILDER_IMAGE}" == "rust:1.88-bookworm" ]]; then
    BUILD_PREAMBLE="apt-get update >/dev/null 2>&1 && \
        apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev >/dev/null 2>&1 && "
fi

# ---------------------------------------------------------------------------
# Freshness helper: a binary is "fresh" iff it exists AND is newer than
# the source main.rs (and the crate's Cargo.toml). This catches both
# missing binaries and out-of-date ones without invoking cargo, which
# is what makes warm-cache runs sub-second.
# ---------------------------------------------------------------------------
is_fresh() {
    local bin_path="$1"; shift
    local force="${BUILD_LINUX_FORCE:-0}"
    if [[ "${force}" == "1" ]]; then
        return 1
    fi
    if [[ ! -x "${bin_path}" ]]; then
        return 1
    fi
    local src
    for src in "$@"; do
        if [[ ! -e "${src}" ]]; then
            # Source missing — treat as not fresh; caller will fail with
            # a clear cargo error.
            return 1
        fi
        if [[ "${src}" -nt "${bin_path}" ]]; then
            return 1
        fi
    done
    return 0
}

human_size() {
    local path="$1"
    if [[ ! -e "${path}" ]]; then
        echo "0 B"
        return
    fi
    # macOS stat is BSD-flavored; linux is GNU. Try both.
    local bytes
    bytes=$(stat -f '%z' "${path}" 2>/dev/null || stat -c '%s' "${path}" 2>/dev/null || echo 0)
    awk -v b="${bytes}" 'BEGIN {
        if (b >= 1048576)      { printf "%.1f MB", b/1048576 }
        else if (b >= 1024)    { printf "%.1f KB", b/1024 }
        else                   { printf "%d B",   b }
    }'
}

# ---------------------------------------------------------------------------
# Docker invocation shape. We share the cargo registry + git caches
# across all builds, which is the whole point of routing through a
# single target dir. The octravpn workspace + sibling repos are
# bind-mounted at the same paths the mesh-bringup uses, so cargo's
# path-dep resolution sees the same layout it would on CI.
# ---------------------------------------------------------------------------
#
# Identity passthrough: when CI / a non-root host invokes this script,
# we still want the emitted ELF files to be owned by the invoking
# user — otherwise subsequent `git add`, `cp`, or `docker compose up`
# steps fail with EACCES on the root-owned target dir.
#
# We used to drop to the caller's uid via `--user`, but the
# BUILD_PREAMBLE (apt-get install protobuf-compiler libprotobuf-dev when falling back
# to vanilla rust:1.88-bookworm) needs root inside the container. The
# robust fix: build as root inside, then chown the output tree to
# the caller after — the bind mount preserves the chown.
DOCKER_USER_ARGS=""
# Captured here so the post-build chown matches.
CALLER_UID="$(id -u)"
CALLER_GID="$(id -g)"

# Post-build hook to fix ownership of the bind-mounted target dir.
# Called after every successful run_in_builder invocation. No-op when
# already owned by the caller (warm cache).
fixup_ownership() {
    if [[ "${CALLER_UID}" == "0" ]]; then
        return 0  # root caller: nothing to fix
    fi
    # Use a tiny `chown` container to do this — it runs as root
    # inside, has access to the bind mount, and exits in <100ms.
    docker run --rm \
        -v "${LINUX_TARGET_DIR}":/work/target \
        -v "${FOUNDRY_DEBUG_DIR}":/work/foundry-target \
        alpine:3 sh -c "chown -R ${CALLER_UID}:${CALLER_GID} /work/target /work/foundry-target" >/dev/null 2>&1 || true
}

run_in_builder() {
    local cmd="$1"
    # shellcheck disable=SC2086
    docker run --rm \
        ${DOCKER_USER_ARGS} \
        -v "${REPO_ROOT}":/work/octra \
        -v "${OCTRA_FOUNDRY}":/work/octra-foundry \
        -v "${HEADSCALE_RS}":/work/headscale-rs \
        -v "${LINUX_TARGET_DIR}":/work/octra/target \
        -v "${FOUNDRY_DEBUG_DIR}":/work/octra-foundry/target \
        -v "${LINUX_TARGET_DIR}/cargo-registry":/usr/local/cargo/registry \
        -v "${LINUX_TARGET_DIR}/cargo-git":/usr/local/cargo/git \
        -w /work/octra \
        "${BUILDER_IMAGE}" \
        bash -c "${BUILD_PREAMBLE}${cmd}"
}

# ---------------------------------------------------------------------------
# Plan: collect the set of octravpn-workspace binaries that need
# building into a single cargo invocation (cheaper than 3 separate
# invocations because cargo gets to share its lock-pass / metadata
# scan). The foundry mock-rpc lives in a different workspace, so it's
# a separate docker run.
# ---------------------------------------------------------------------------
declare -a OCTRAVPN_NEEDED=()
declare -A OCTRAVPN_SOURCES=(
    [octravpn]="crates/octravpn-client/src/main.rs:crates/octravpn-client/Cargo.toml"
    [octravpn-node]="crates/octravpn-node/src/main.rs:crates/octravpn-node/Cargo.toml"
    [octravpn-analytics]="crates/octravpn-analytics/src/main.rs:crates/octravpn-analytics/Cargo.toml"
)

for bin in octravpn octravpn-node octravpn-analytics; do
    bin_path="${DEBUG_DIR}/${bin}"
    sources_csv="${OCTRAVPN_SOURCES[$bin]}"
    IFS=':' read -r -a sources <<<"${sources_csv}"
    src_full=()
    for s in "${sources[@]}"; do
        src_full+=("${REPO_ROOT}/${s}")
    done
    if is_fresh "${bin_path}" "${src_full[@]}"; then
        echo "FRESH: target/linux-debug/debug/${bin} ($(human_size "${bin_path}"))" >&2
    else
        OCTRAVPN_NEEDED+=("${bin}")
    fi
done

if (( ${#OCTRAVPN_NEEDED[@]} > 0 )); then
    echo "building (in ${BUILDER_IMAGE}): ${OCTRAVPN_NEEDED[*]}" >&2
    cargo_args=""
    for b in "${OCTRAVPN_NEEDED[@]}"; do
        cargo_args+=" --bin ${b}"
    done
    if ! run_in_builder "cargo build${cargo_args}" >&2; then
        echo "BUILD FAIL: cargo build${cargo_args} (octravpn workspace)" >&2
        exit 10
    fi
    fixup_ownership
fi

# Emit BUILT lines for the octravpn-workspace binaries.
for bin in octravpn octravpn-node octravpn-analytics; do
    bin_path="${DEBUG_DIR}/${bin}"
    if [[ ! -x "${bin_path}" ]]; then
        echo "BUILD FAIL: ${bin_path} missing after cargo build" >&2
        exit 10
    fi
    echo "BUILT: target/linux-debug/debug/${bin} ($(human_size "${bin_path}"))"
done

# ---------------------------------------------------------------------------
# octra-mock-rpc lives in the sibling foundry workspace. It's a
# separate cargo invocation against a separate target dir.
# ---------------------------------------------------------------------------
MOCK_RPC_SRC_MAIN="${OCTRA_FOUNDRY}/crates/octra-mock-rpc/src/main.rs"
MOCK_RPC_SRC_TOML="${OCTRA_FOUNDRY}/crates/octra-mock-rpc/Cargo.toml"
MOCK_RPC_BIN_FOUNDRY="${FOUNDRY_DEBUG_DIR}/debug/octra-mock-rpc"
MOCK_RPC_BIN_LOCAL="${DEBUG_DIR}/octra-mock-rpc"

if is_fresh "${MOCK_RPC_BIN_LOCAL}" "${MOCK_RPC_SRC_MAIN}" "${MOCK_RPC_SRC_TOML}"; then
    echo "FRESH: target/linux-debug/debug/octra-mock-rpc ($(human_size "${MOCK_RPC_BIN_LOCAL}"))" >&2
else
    echo "building (in ${BUILDER_IMAGE}): octra-mock-rpc (sibling foundry)" >&2
    # shellcheck disable=SC2086
    if ! docker run --rm \
        ${DOCKER_USER_ARGS} \
        -v "${OCTRA_FOUNDRY}":/work/octra-foundry \
        -v "${FOUNDRY_DEBUG_DIR}":/work/octra-foundry/target \
        -v "${LINUX_TARGET_DIR}/cargo-registry":/usr/local/cargo/registry \
        -v "${LINUX_TARGET_DIR}/cargo-git":/usr/local/cargo/git \
        -w /work/octra-foundry \
        "${BUILDER_IMAGE}" \
        bash -c "${BUILD_PREAMBLE}cargo build --bin octra-mock-rpc" >&2; then
        echo "BUILD FAIL: cargo build --bin octra-mock-rpc (foundry workspace)" >&2
        exit 10
    fi
    fixup_ownership
    if [[ ! -x "${MOCK_RPC_BIN_FOUNDRY}" ]]; then
        echo "BUILD FAIL: ${MOCK_RPC_BIN_FOUNDRY} missing after cargo build" >&2
        exit 10
    fi
    # Copy into our linux-debug/debug/ so callers can mount it from one
    # consistent path regardless of which workspace it came from.
    cp -f "${MOCK_RPC_BIN_FOUNDRY}" "${MOCK_RPC_BIN_LOCAL}"
fi

if [[ -x "${MOCK_RPC_BIN_LOCAL}" ]]; then
    echo "BUILT: target/linux-debug/debug/octra-mock-rpc ($(human_size "${MOCK_RPC_BIN_LOCAL}"))"
fi

echo "READY"
exit 0
