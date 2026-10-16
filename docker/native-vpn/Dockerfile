ARG BUILDER_IMAGE=octravpn-builder:latest
FROM ${BUILDER_IMAGE} AS binaries
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /work/octra
RUN rm -rf crates program vendor tests pvac-sidecar /work/octra-foundry /work/headscale-rs
COPY octra-foundry /work/octra-foundry
COPY headscale-rs /work/headscale-rs
COPY octra/Cargo.toml octra/Cargo.lock octra/rust-toolchain.toml ./
RUN rustup show active-toolchain
COPY octra/crates ./crates
COPY octra/program ./program
COPY octra/vendor ./vendor
COPY octra/tests ./tests
COPY octra/pvac-sidecar ./pvac-sidecar
COPY octra/docs/rust-node/source-map.json ./docs/rust-node/source-map.json
COPY octra/scripts/node-port/octb-oracle.ml octra/scripts/node-port/native-oracle.py octra/scripts/node-port/octb-fixtures.py ./scripts/node-port/
COPY octra/scripts/node-port/snapshot-service-oracle.ml octra/scripts/node-port/snapshot-service-fixtures.py ./scripts/node-port/
COPY octra/scripts/node-port/finality-query-oracle.ml ./scripts/node-port/
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    find crates /work/octra-foundry /work/headscale-rs -name '*.rs' -type f -exec touch {} + && \
    cargo build --locked -p octra-node -p octravpn-node -p octravpn-client && \
    mkdir /tmp/native-binaries && \
    cp target/debug/octra-node target/debug/octravpn-node target/debug/octravpn /tmp/native-binaries/
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo build --locked --release -p octravpn-private-admin && \
    cp target/release/octravpn-private-admin /tmp/native-binaries/
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo test --locked -p octra-node-protocol --lib isolated_tests && \
    cargo test --locked -p octra-node-runtime --lib canonical::storage_tests && \
    cargo test --locked -p octravpn-core --lib identifier::tests && \
    cargo test --locked -p octravpn-core --lib rpc::asset_tests && \
    cargo test --locked -p octravpn-client --bin octravpn settlement_guards && \
    cargo test --locked -p octravpn-client --bin octravpn receipt_context_tests && \
    cargo test --locked -p octravpn-client --bin octravpn recovery::tests && \
    cargo test --locked -p octravpn-client --bin octravpn reconnect_real_wireguard && \
    cargo test --locked -p octravpn-node --lib native_receipt_freezes && \
    cargo test --locked -p octravpn-node --lib v3_boot::publication::tests && \
    cargo test --locked -p octra-node --lib vpn::settlement::tests && \
    cargo test --locked -p octra-node --lib native_vpn_directories && \
    cargo test --locked -p octra-node --lib snapshot_export && \
    cargo test --locked -p octra-node --lib explicit_observer_preserves_native_role_order && \
    cargo test --locked -p octra-node --test snapshot_service_parity && \
    cargo test --locked -p octra-node --test services http_join_deadline_preserves_committed_prefix_before_next_record
RUN --mount=type=cache,id=octra-foundry-qualification-target,target=/work/octra-foundry/target \
    cargo build --locked --manifest-path /work/octra-foundry/Cargo.toml -p octra-cli --bin octra && \
    cp /work/octra-foundry/target/debug/octra /tmp/native-binaries/
COPY octra/docker/native-vpn ./docker/native-vpn
COPY octra/licenses ./licenses
RUN python3 docker/native-vpn/manifest.py > /tmp/native-source.json

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables python3 libssl3 libgcc-s1 && rm -rf /var/lib/apt/lists/*
COPY --from=binaries /tmp/native-binaries/ /usr/local/bin/
COPY --from=binaries /tmp/native-source.json /usr/local/share/native-source.json
COPY --from=binaries /work/octra/licenses /usr/local/share/licenses/octra
COPY octra/program/main-v5.aml octra/program/private-admin-factory.aml /usr/local/share/aml/
COPY octra/docker/native-vpn/qualify.py /usr/local/bin/qualify.py
COPY octra/docker/native-vpn/tun_gate.py /usr/local/bin/tun_gate.py
COPY octra/docker/native-vpn/packet_target.py /usr/local/bin/packet_target.py
ENTRYPOINT ["python3", "-u", "/usr/local/bin/qualify.py"]
