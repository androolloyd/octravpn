#!/usr/bin/env bash
# Render node + client configs for the devnet docker overlay.
#
# Reads docker/devnet/.env, the per-node host info from
# docker/devnet/hosts.env, and writes:
#   $HOST_DEVNET_DIR/node{1,2,3}/node.toml
#   $HOST_DEVNET_DIR/client/client.toml
#
# Wallet + WG key files must already exist under $HOST_DEVNET_DIR
# (see docker/devnet/README.md for how to generate them).
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ ! -f docker/devnet/.env ]]; then
  echo "error: docker/devnet/.env not found" >&2
  echo "       cp docker/devnet/.env.example docker/devnet/.env" >&2
  exit 1
fi
set -a
# shellcheck source=/dev/null
source docker/devnet/.env
[[ -f docker/devnet/hosts.env ]] && source docker/devnet/hosts.env
set +a

: "${OCTRA_RPC_URL:?set OCTRA_RPC_URL in docker/devnet/.env}"
: "${PROGRAM_ADDR:?set PROGRAM_ADDR after deploying program/main.aml}"

HOST_DIR="${HOST_DEVNET_DIR:-./docker/devnet/state}"
mkdir -p "$HOST_DIR"/{node1,node2,node3,client}

render_node() {
  local n=$1
  local addr_var=NODE${n}_VALIDATOR_ADDR
  local ep_var=NODE${n}_PUBLIC_ENDPOINT
  local price_var=NODE${n}_PRICE_PER_MB
  local region_var=NODE${n}_REGION

  : "${!addr_var:?set $addr_var in docker/devnet/hosts.env (validator wallet addr)}"
  : "${!ep_var:?set $ep_var in docker/devnet/hosts.env (e.g. node$n.example.com:51820)}"

  VALIDATOR_ADDR="${!addr_var}" \
  PUBLIC_ENDPOINT="${!ep_var}" \
  PRICE_PER_MB="${!price_var:-100}" \
  REGION="${!region_var:-test}" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  envsubst < docker/conf/devnet/node.toml.template \
    > "$HOST_DIR/node$n/node.toml"
  echo "wrote $HOST_DIR/node$n/node.toml"
}

render_client() {
  : "${CLIENT_ADDR:?set CLIENT_ADDR in docker/devnet/hosts.env}"
  CLIENT_ADDR="$CLIENT_ADDR" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  envsubst < docker/conf/devnet/client.toml.template \
    > "$HOST_DIR/client/client.toml"
  echo "wrote $HOST_DIR/client/client.toml"
}

render_node 1
render_node 2
render_node 3
render_client

echo
echo "Next: verify each $HOST_DIR/node{1,2,3}/wallet.key and wg.key exist"
echo "      (32-byte hex, chmod 0600). See docker/devnet/README.md."
