ARG TAILSCALE_IMAGE=tailscale/tailscale@sha256:87c55d6be56ad85b3d8bceca5f87f73de288c609131460dd1be1874c250cc41d
ARG NODE_IMAGE=octranet-qualification:20261017
FROM ${TAILSCALE_IMAGE} AS tailscale
FROM ${NODE_IMAGE}
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/
ENTRYPOINT []
