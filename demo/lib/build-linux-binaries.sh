#!/usr/bin/env bash
# build-linux-binaries.sh
#
# Build all the Linux binaries the demo harnesses need, from a macOS
# (or any) dev host, using docker as the cross-compile runtime. We
# don't actually cross-compile in the cargo sense — we run cargo
# inside `rust:1.96.0-bookworm`, so the toolchain IS Linux and the
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
# Idempotency: Cargo checks the complete dependency graph on every run,
# including library modules, build inputs and the mounted sibling repos.
# Existing target directories retain incremental artifacts for warm builds.
#
# Env overrides:
#   OCTRA_BUILDER_IMAGE  Override the docker image (default
#                        octravpn-builder:latest if present, else
#                        rust:1.96.0-bookworm).
#   OCTRA_FOUNDRY_PATH   Path to ../octra-foundry sibling (default
#                        ${REPO_ROOT}/../octra-foundry).
#   HEADSCALE_RS_PATH    Path to ../headscale-rs sibling (default
#                        ${REPO_ROOT}/../headscale-rs).
#   BUILD_LINUX_FORCE    Retained for callers; Cargo now checks every
#                        binary regardless of this setting.

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
        BUILDER_IMAGE="rust:1.96.0-bookworm"
    fi
fi

# headscale-api's build.rs (prost-build) shells out to protoc; the
# prebuilt builder image already has it, the vanilla rust image needs
# the apt step.
BUILD_PREAMBLE=""
if [[ "${BUILDER_IMAGE}" == "rust:1.96.0-bookworm" ]]; then
    BUILD_PREAMBLE="apt-get update >/dev/null 2>&1 && \
        apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev >/dev/null 2>&1 && "
fi

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
# to vanilla rust:1.96.0-bookworm) needs root inside the container. The
# robust fix: build as root inside, then chown the output tree to
# the caller after — the bind mount preserves the chown.
DOCKER_USER_ARGS=""
# Captured here so the post-build chown matches.
CALLER_UID="$(id -u)"
CALLER_GID="$(id -g)"

# Post-build hook to fix ownership of the bind-mounted target dir.
# Called after successful Cargo invocations so any updated artifacts belong
# to the caller.
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
# Check all three workspace binaries in one incremental Cargo invocation.
# Cargo owns freshness for modules and transitive path dependencies; a
# main.rs timestamp cannot establish that a library-backed binary is current.
# The foundry mock-rpc uses a separate workspace and target directory.
# ---------------------------------------------------------------------------
echo "building (in ${BUILDER_IMAGE}): octravpn octravpn-node octravpn-analytics" >&2
if ! run_in_builder "cargo build --locked --bin octravpn --bin octravpn-node --bin octravpn-analytics" >&2; then
    echo "BUILD FAIL: cargo build (octravpn workspace)" >&2
    exit 10
fi
fixup_ownership

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
MOCK_RPC_BIN_FOUNDRY="${FOUNDRY_DEBUG_DIR}/debug/octra-mock-rpc"
MOCK_RPC_BIN_LOCAL="${DEBUG_DIR}/octra-mock-rpc"

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
    bash -c "${BUILD_PREAMBLE}cargo build --locked --bin octra-mock-rpc" >&2; then
    echo "BUILD FAIL: cargo build --bin octra-mock-rpc (foundry workspace)" >&2
    exit 10
fi
fixup_ownership
if [[ ! -x "${MOCK_RPC_BIN_FOUNDRY}" ]]; then
    echo "BUILD FAIL: ${MOCK_RPC_BIN_FOUNDRY} missing after cargo build" >&2
    exit 10
fi
# Copy the artifact Cargo just checked into the common fixture directory.
cp -f "${MOCK_RPC_BIN_FOUNDRY}" "${MOCK_RPC_BIN_LOCAL}"

if [[ -x "${MOCK_RPC_BIN_LOCAL}" ]]; then
    echo "BUILT: target/linux-debug/debug/octra-mock-rpc ($(human_size "${MOCK_RPC_BIN_LOCAL}"))"
fi

echo "READY"
exit 0
