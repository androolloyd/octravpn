#!/usr/bin/env bash
# Render node + client configs for the testnet docker overlay.
#
# Reads docker/testnet/.env, the per-node host info from
# docker/testnet/hosts.env, and writes:
#   $HOST_TESTNET_DIR/node{1,2,3}/node.toml
#   $HOST_TESTNET_DIR/client/client.toml
#
# Wallet + WG key files must already exist under $HOST_TESTNET_DIR
# (see docker/testnet/README.md for how to generate them).
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ ! -f docker/testnet/.env ]]; then
  echo "error: docker/testnet/.env not found" >&2
  echo "       cp docker/testnet/.env.example docker/testnet/.env" >&2
  exit 1
fi
set -a
# shellcheck source=/dev/null
source docker/testnet/.env
[[ -f docker/testnet/hosts.env ]] && source docker/testnet/hosts.env
set +a

: "${OCTRA_RPC_URL:?set OCTRA_RPC_URL in docker/testnet/.env}"
: "${PROGRAM_ADDR:?set PROGRAM_ADDR after deploying program/main.aml}"

HOST_DIR="${HOST_TESTNET_DIR:-./docker/testnet/state}"
mkdir -p "$HOST_DIR"/{node1,node2,node3,client}

render_node() {
  local n=$1
  local addr_var=NODE${n}_VALIDATOR_ADDR
  local ep_var=NODE${n}_PUBLIC_ENDPOINT
  local price_var=NODE${n}_PRICE_PER_MB
  local region_var=NODE${n}_REGION

  : "${!addr_var:?set $addr_var in docker/testnet/hosts.env (validator wallet addr)}"
  : "${!ep_var:?set $ep_var in docker/testnet/hosts.env (e.g. node$n.example.com:51820)}"

  VALIDATOR_ADDR="${!addr_var}" \
  PUBLIC_ENDPOINT="${!ep_var}" \
  PRICE_PER_MB="${!price_var:-100}" \
  REGION="${!region_var:-test}" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  envsubst < docker/conf/testnet/node.toml.template \
    > "$HOST_DIR/node$n/node.toml"
  echo "wrote $HOST_DIR/node$n/node.toml"
}

render_client() {
  : "${CLIENT_ADDR:?set CLIENT_ADDR in docker/testnet/hosts.env}"
  CLIENT_ADDR="$CLIENT_ADDR" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  envsubst < docker/conf/testnet/client.toml.template \
    > "$HOST_DIR/client/client.toml"
  echo "wrote $HOST_DIR/client/client.toml"
}

render_node 1
render_node 2
render_node 3
render_client

echo
echo "Next: verify each $HOST_DIR/node{1,2,3}/wallet.key and wg.key exist"
echo "      (32-byte hex, chmod 0600). See docker/testnet/README.md."
