ARG NODE_IMAGE=octra-native-vpn-qualification:local
FROM ${NODE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools nftables curl ca-certificates util-linux procps && rm -rf /var/lib/apt/lists/*
COPY octra/scripts/devnet-relay/node_namespace.py /app/node_namespace.py
ENTRYPOINT ["python3", "/app/node_namespace.py"]
