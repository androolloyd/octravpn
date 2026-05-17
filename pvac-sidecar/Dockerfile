# PVAC sidecar build image.
#
# Builds the JSON-over-stdio daemon `octra-pvac-sidecar` from the
# vendored GPL-2+ PVAC fork under vendor/pvac/. The result is a
# single statically-linked-ish binary (libstdc++/libgcc remain shared,
# but those are provided by debian:bookworm-slim).
#
# Build:
#   docker build -t octra-pvac-sidecar -f pvac-sidecar/Dockerfile pvac-sidecar
#
# Run interactively (stdin/stdout):
#   docker run -i --rm octra-pvac-sidecar
#
# License: GPL-2+ (with OpenSSL exemption — though we don't link OpenSSL).
# See LICENSE for the full text and LICENSE.NOTICE.md for the boundary
# statement between this GPL'd binary and the surrounding MIT/Apache
# Rust workspace.

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        make \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile ./
COPY src ./src
COPY vendor ./vendor

# Use an arch-portable compile target. The intrinsics in PVAC require
# at least SSE2 / NEON; -march=x86-64-v2 is widely available on modern
# x86 servers (Westmere+) and avoids needing AES-NI specifically.
RUN if [ "$(uname -m)" = "aarch64" ]; then \
        make CXX=g++ ARCH="-march=armv8-a+crypto" ; \
    else \
        make CXX=g++ ARCH="-march=x86-64-v2 -maes" ; \
    fi

# --- runtime image -----------------------------------------------------

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/octra-pvac-sidecar /usr/local/bin/octra-pvac-sidecar
COPY LICENSE /usr/share/doc/octra-pvac-sidecar/LICENSE

# Disable buffering on the runtime side too. The daemon flushes stdout
# explicitly, but Docker may attach a non-tty stdin/stdout that buffers.
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/local/bin/octra-pvac-sidecar"]
