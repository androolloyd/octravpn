# Build context is the parent containing octra/, octra-foundry/, headscale-rs/.
# The existing builder provides the pinned toolchain and sibling dependencies.
ARG BUILDER_IMAGE=octravpn-builder:latest
FROM ${BUILDER_IMAGE} AS tests
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /work/octra
RUN rm -rf crates program vendor tests pvac-sidecar /work/octra-foundry /work/headscale-rs
COPY octra-foundry /work/octra-foundry
COPY headscale-rs /work/headscale-rs
COPY octra/Cargo.toml octra/Cargo.lock ./
COPY octra/rust-toolchain.toml ./
COPY octra/crates ./crates
COPY octra/program ./program
COPY octra/vendor ./vendor
COPY octra/tests ./tests
COPY octra/pvac-sidecar ./pvac-sidecar
COPY octra/docker/vpn-transport ./docker/vpn-transport
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    find crates /work/octra-foundry /work/headscale-rs -name '*.rs' -type f -exec touch {} + && \
    cargo test --locked -p octravpn-client --lib --no-run --message-format=json > /tmp/vpn-build.json && \
    python3 -c 'import json, pathlib, shutil; rows=[json.loads(s) for s in pathlib.Path("/tmp/vpn-build.json").read_text().splitlines()]; paths=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="octravpn_client" and "lib" in r.get("target",{}).get("kind",[]) and r.get("profile",{}).get("test") and r.get("executable")]; assert len(paths)==1, paths; shutil.copyfile(paths[0], "/tmp/vpn-transport-tests")' && \
    python3 docker/vpn-transport/source-manifest.py > /tmp/vpn-transport-source.json

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 libssl3 libgcc-s1 && rm -rf /var/lib/apt/lists/*
COPY --from=tests --chmod=0755 /tmp/vpn-transport-tests /usr/local/bin/vpn-transport-tests
COPY --from=tests /tmp/vpn-transport-source.json /usr/local/share/vpn-transport-source.json
COPY --chmod=0755 octra/docker/vpn-transport/entry.sh /usr/local/bin/qualify-vpn
ENTRYPOINT ["/usr/local/bin/qualify-vpn"]
