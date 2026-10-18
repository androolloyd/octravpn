ARG BUILDER_IMAGE=octravpn-builder:latest
FROM ${BUILDER_IMAGE} AS binaries
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /work/octra
RUN rm -rf crates program vendor tests pvac-sidecar scripts/node-port /work/octra-foundry /work/headscale-rs
COPY octra-foundry /work/octra-foundry
COPY headscale-rs /work/headscale-rs
COPY octra/Cargo.toml octra/Cargo.lock octra/rust-toolchain.toml ./
COPY octra/.cargo/config.toml ./.cargo/config.toml
RUN rustup show active-toolchain
COPY octra/crates ./crates
COPY octra/program ./program
COPY octra/vendor ./vendor
COPY octra/tests ./tests
COPY octra/pvac-sidecar ./pvac-sidecar
COPY octra/docs/rust-node/source-map.json octra/docs/rust-node/upstream.json octra/docs/rust-node/network-authority.json ./docs/rust-node/
COPY octra/scripts/node-port ./scripts/node-port
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
    cargo test --locked -p octra-node-runtime --lib state_batch::storage::tests && \
    cargo test --locked -p octra-node-runtime --lib account_summary::tests && \
    cargo test --locked -p octra-node --lib rpc::account_tests && \
    cargo test --locked -p octra-node --lib rpc::native::status::tests && \
    cargo test --locked -p octra-node --lib executor::proofs::tests && \
    cargo test --locked -p octra-node --lib captured_ && \
    cargo test --locked -p octra-node-runtime --lib canonical::reader::paths && \
    cargo test --locked -p octra-node-runtime --test canonical_assets -- --skip browser_fixture && \
    cargo test --locked -p octra-node-runtime --test live_consensus resource_gossip_reaches_actor_without_enabling_optional_committees && \
    cargo test --locked -p octra-node-protocol --test optional_resource_parity --test resource_lanes_parity && \
    cargo test --locked -p octra-node-protocol --test vpn_compiler_parity && \
    cargo test --locked -p octra-browser --lib --tests && \
    cargo test --locked -p octravpn-core --lib identifier::tests && \
    cargo test --locked -p octravpn-core --lib rpc::asset_tests && \
    cargo test --locked -p octravpn-core --lib create_personal_tailnet && \
    cargo test --locked -p octravpn-client --lib paid_routes::linux::tests && \
    cargo test --locked -p octravpn-client --lib onboarding::tests && \
    cargo test --locked -p octravpn-client --lib settlement_guards && \
    cargo test --locked -p octravpn-client --lib receipt_context_tests && \
    cargo test --locked -p octravpn-client --lib recovery::tests && \
    cargo test --locked -p octravpn-client --lib reconnect_real_wireguard && \
    cargo test --locked -p octravpn-node --lib native_receipt_freezes && \
    cargo test --locked -p octravpn-node --lib personal_ && \
    cargo test --locked -p octravpn-node --lib anchored_mesh_boots_with_deny_all_before_sync && \
    cargo test --locked -p octravpn-node --lib v3_boot::publication::tests && \
    cargo test --locked -p octra-node --lib vpn::settlement::tests && \
    cargo test --locked -p octra-node --lib native_vpn_directories && \
    cargo test --locked -p octra-node --lib snapshot_export && \
    cargo test --locked -p octra-node --lib retained_gateway_cache && \
    cargo test --locked -p octra-node --test services canonical_gateway_keeps && \
    cargo test --locked -p octra-node --lib explicit_observer_preserves_native_role_order && \
    cargo test --locked -p octra-node --test snapshot_service_parity && \
    cargo test --locked -p octra-node --test services http_join_deadline_preserves_committed_prefix_before_next_record
RUN --mount=type=cache,id=octra-foundry-qualification-target,target=/work/octra-foundry/target \
    cargo build --locked --manifest-path /work/octra-foundry/Cargo.toml -p octra-cli --bin octra && \
    cp /work/octra-foundry/target/debug/octra /tmp/native-binaries/
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo test --locked -p octra-node --lib single::facade::publication::tests && \
    cargo test --locked -p octra-node --lib single::network::tests && \
    cargo test --locked -p octra-node --test single_native facade:: && \
    cargo test --locked -p octra-node --test single_native --no-run --message-format=json > /tmp/single-fixture-build.json && \
    python3 -c 'import json,shutil; rows=[json.loads(line) for line in open("/tmp/single-fixture-build.json") if line.startswith("{")]; bins=[row["executable"] for row in rows if row.get("reason")=="compiler-artifact" and row.get("target",{}).get("name")=="single_native" and row.get("executable")]; assert len(bins)==1; shutil.copy2(bins[0],"/tmp/native-binaries/octra-single-fixture")'
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo test --locked --release -p octra-node-runtime --features test-helpers \
      --test crypto_process --test private_isolation --test private_admission --test pvac_status_service && \
    cargo test --locked -p octravpn-node --lib native_derp && \
    cargo test --locked -p octra-node --lib mesh::
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo build --locked --release -p octra-node && \
    cp target/release/octra-node /tmp/native-binaries/octra-node
RUN --mount=type=cache,id=octra-vpn-qualification-target,target=/work/octra/target \
    cargo test --locked --release -p octra-node --lib vpn::payments && \
    cargo test --locked -p octravpn-client --lib payments:: && \
    cargo test --locked -p octravpn-client --lib payment_runner:: && \
    cargo test --locked -p octravpn-node --lib payment_meter:: && \
    cargo test --locked -p octravpn-node --lib payments:: && \
    cargo test --locked -p octra-node-runtime --test octranet_payments
COPY octra/docker/native-vpn ./docker/native-vpn
RUN PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s docker/native-vpn -p 'test_payments_qualify.py'
COPY octra/licenses ./licenses
RUN python3 docker/native-vpn/manifest.py > /tmp/native-source.json

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables python3 libssl3 libgcc-s1 && rm -rf /var/lib/apt/lists/*
COPY --from=binaries /tmp/native-binaries/ /usr/local/bin/
COPY --from=binaries /tmp/native-source.json /usr/local/share/native-source.json
COPY --from=binaries /work/octra/licenses /usr/local/share/licenses/octra
COPY octra/program/main-v5.aml octra/program/private-admin-factory.aml /usr/local/share/aml/
COPY octra/program/octranet-payments.aml octra/program/octranet-payments-factory.aml /usr/local/share/aml/
COPY octra/docker/native-vpn/qualify.py /usr/local/bin/qualify.py
COPY octra/docker/native-vpn/payments_qualify.py /usr/local/bin/payments_qualify.py
COPY octra/docker/native-vpn/json_snapshot.py /usr/local/bin/json_snapshot.py
COPY octra/docker/native-vpn/payment_control.py /usr/local/bin/payment_control.py
COPY octra/docker/native-vpn/single_qualify.py /usr/local/bin/single_qualify.py
COPY octra/docker/native-vpn/tun_gate.py /usr/local/bin/tun_gate.py
COPY octra/docker/native-vpn/packet_target.py /usr/local/bin/packet_target.py
ENTRYPOINT ["python3", "-u", "/usr/local/bin/qualify.py"]
