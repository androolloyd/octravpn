#!/usr/bin/env bash
# OctraVPN testnet bootstrap driver.
#
# Usage:
#   scripts/testnet/bootstrap.sh [--dry-run] [--allow-mainnet] [PARAMS_FILE]
#
# Steps (each idempotent):
#   1. Parse testnet-params.toml.
#   2. Verify .env.testnet exists + no PLACEHOLDER values remain.
#   3. Materialize per-validator config dirs from templates.
#   4. Render prometheus.yml + targets.json.
#   5. `docker compose config` sanity check.
#   6. Pull / build images.
#   7. Start mesh-control first; wait for /v1/health.
#   8. Start validators.
#   9. Start DERP.
#  10. Start observability.
#  11. Print next-step pointers (health-check, join URL).
#
# Dry-run prints every step it would take but never invokes docker.
set -euo pipefail

# ---------------------------------------------------------------------
# Locate repo root (this script lives at scripts/testnet/bootstrap.sh)
# ---------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------
DRY_RUN=0
ALLOW_MAINNET=0
PARAMS_FILE="deploy/testnet/testnet-params.toml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)        DRY_RUN=1; shift ;;
    --allow-mainnet)  ALLOW_MAINNET=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      PARAMS_FILE="$1"; shift
      ;;
  esac
done

step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
maybe(){ if (( DRY_RUN )); then printf '    [dry-run] %s\n' "$*"; else "$@"; fi; }

# ---------------------------------------------------------------------
# Step 1 — parse params (same dumb parser as ceremony/mainnet-deploy)
# ---------------------------------------------------------------------
step "Step 1/11: parse $PARAMS_FILE"
[[ -f "$PARAMS_FILE" ]] || die "params file not found: $PARAMS_FILE
  hint: cp deploy/testnet/testnet-params.toml.example $PARAMS_FILE"

parse_scalar() {
  # parse_scalar KEY FILE -> stdout value (or empty)
  grep -E "^[[:space:]]*$1[[:space:]]*=" "$2" 2>/dev/null \
    | head -n1 \
    | sed -E 's/^[^=]+=[[:space:]]*//; s/[[:space:]]*(#.*)?$//; s/^"(.*)"$/\1/'
}

TIER=$(parse_scalar tier "$PARAMS_FILE")
[[ "$TIER" == "testnet" ]] || die "params tier='$TIER' — bootstrap.sh refuses any tier other than 'testnet'"

NETWORK_NAME=$(parse_scalar network_name "$PARAMS_FILE")
RPC_URL=$(parse_scalar rpc_url "$PARAMS_FILE")
CHAIN_ID=$(parse_scalar chain_id "$PARAMS_FILE")
PROGRAM_ADDR=$(parse_scalar program_addr "$PARAMS_FILE")
CONFIG_DIR=$(parse_scalar config_dir "$PARAMS_FILE")
CONFIG_DIR="${CONFIG_DIR:-./deploy/testnet/state}"
GENESIS_DIR=$(parse_scalar genesis_dir "$PARAMS_FILE")
GENESIS_DIR="${GENESIS_DIR:-$CONFIG_DIR/genesis}"

note "tier         = $TIER"
note "network_name = $NETWORK_NAME"
note "rpc_url      = $RPC_URL"
note "chain_id     = $CHAIN_ID"
note "program_addr = ${PROGRAM_ADDR:-<empty — must be set>}"
note "config_dir   = $CONFIG_DIR"

case "$RPC_URL" in
  *octra.network*)
    if [[ "$RPC_URL" != *devnet* && "$RPC_URL" != *testnet* ]]; then
      (( ALLOW_MAINNET )) || die "rpc_url looks like mainnet ($RPC_URL).
  Pass --allow-mainnet to override (rehearsal only)."
    fi
    ;;
esac

[[ -n "$PROGRAM_ADDR" ]] || die "program_addr is empty in $PARAMS_FILE.
  Deploy program/main-v3.aml against $RPC_URL first (see deploy/testnet/README.md §Bootstrap),
  then paste the address into the params file."

# ---------------------------------------------------------------------
# Step 2 — .env.testnet exists, no PLACEHOLDER left
# ---------------------------------------------------------------------
step "Step 2/11: validate .env.testnet"
ENV_FILE="deploy/testnet/.env.testnet"
if [[ ! -f "$ENV_FILE" ]]; then
  die "$ENV_FILE not found.
  hint: cp deploy/testnet/.env.testnet.example $ENV_FILE && edit it"
fi
if grep -q '^[A-Z0-9_]*=PLACEHOLDER' "$ENV_FILE"; then
  echo "remaining PLACEHOLDERs:" >&2
  grep -nE '^[A-Z0-9_]*=PLACEHOLDER' "$ENV_FILE" >&2 || true
  die "$ENV_FILE still has PLACEHOLDER values; fill them before bootstrapping"
fi
note "OK — $ENV_FILE has no PLACEHOLDERs"

# Load env so we can render templates. Use `set -a` so every var
# becomes exported for envsubst.
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a
export NETWORK_NAME

# ---------------------------------------------------------------------
# Step 3 — render per-validator + mesh-control configs
# ---------------------------------------------------------------------
step "Step 3/11: render configs"
command -v envsubst >/dev/null || die "envsubst not found (install gettext)"

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/prometheus" "$CONFIG_DIR/derp/certs"

render_validator() {
  local idx="$1" name="validator$1"
  local addr_var="VALIDATOR${idx}_ADDR"
  local ep_var="VALIDATOR${idx}_PUBLIC_ENDPOINT"
  local price_var="VALIDATOR${idx}_PRICE_PER_MB"
  local region_var="VALIDATOR${idx}_REGION"

  : "${!addr_var:?$addr_var unset in $ENV_FILE}"
  : "${!ep_var:?$ep_var unset in $ENV_FILE}"

  mkdir -p "$CONFIG_DIR/$name"
  local role="signer,observer"
  [[ "$idx" == "3" ]] && role="signer,observer,relay"

  VALIDATOR_ADDR="${!addr_var}" \
  PUBLIC_ENDPOINT="${!ep_var}" \
  PRICE_PER_MB="${!price_var:-100}" \
  REGION="${!region_var:-test}" \
  NODE_NAME="$name" \
  NODE_ROLE="$role" \
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  CHAIN_ID="$CHAIN_ID" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  MESH_CONTROL_URL="$MESH_CONTROL_URL" \
  DERP_URL="$DERP_URL" \
  envsubst < deploy/testnet/templates/node.toml.template \
    > "$CONFIG_DIR/$name/node.toml"
  note "rendered $CONFIG_DIR/$name/node.toml (role=$role)"
}

if (( DRY_RUN )); then
  note "[dry-run] would render validator1, validator2, validator3 + mesh-control configs"
else
  render_validator 1
  render_validator 2
  render_validator 3

  mkdir -p "$CONFIG_DIR/mesh-control"
  OCTRA_RPC_URL="$OCTRA_RPC_URL" \
  CHAIN_ID="$CHAIN_ID" \
  PROGRAM_ADDR="$PROGRAM_ADDR" \
  OPERATOR_MULTISIG_ADDR="$OPERATOR_MULTISIG_ADDR" \
  OPERATOR_MULTISIG_THRESHOLD="${OPERATOR_MULTISIG_THRESHOLD:-2}" \
  envsubst < deploy/testnet/templates/mesh-control.toml.template \
    > "$CONFIG_DIR/mesh-control/mesh-control.toml"
  note "rendered $CONFIG_DIR/mesh-control/mesh-control.toml"
fi

# ---------------------------------------------------------------------
# Step 4 — prometheus.yml + targets.json
# ---------------------------------------------------------------------
step "Step 4/11: render prometheus targets"
if (( DRY_RUN )); then
  note "[dry-run] would render $CONFIG_DIR/prometheus/{prometheus.yml,targets.json}"
else
  NETWORK_NAME="$NETWORK_NAME" \
    envsubst < deploy/testnet/templates/prometheus.yml.template \
    > "$CONFIG_DIR/prometheus/prometheus.yml"
  envsubst < deploy/testnet/templates/targets.json.template \
    > "$CONFIG_DIR/prometheus/targets.json"
  note "rendered prometheus.yml + targets.json"
fi

# ---------------------------------------------------------------------
# Step 5 — verify the compose file parses with this env
# ---------------------------------------------------------------------
step "Step 5/11: docker compose config sanity check"
if (( DRY_RUN )); then
  note "[dry-run] would run: docker compose --env-file $ENV_FILE -f docker-compose.testnet.yml config -q"
else
  docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml config -q \
    || die "compose config failed — see error above"
  note "compose config OK"
fi

# ---------------------------------------------------------------------
# Step 6 — pull / build images
# ---------------------------------------------------------------------
step "Step 6/11: build / pull images"
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet build
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet pull --ignore-buildable

# ---------------------------------------------------------------------
# Step 7 — mesh-control first
# ---------------------------------------------------------------------
step "Step 7/11: start mesh-control"
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet up -d mesh-control
if ! (( DRY_RUN )); then
  note "waiting for mesh-control /v1/health …"
  for i in {1..30}; do
    if docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml ps mesh-control 2>/dev/null \
        | grep -q '(healthy)'; then
      note "mesh-control healthy"
      break
    fi
    sleep 2
    [[ $i -eq 30 ]] && die "mesh-control did not become healthy in 60s — check 'docker compose logs mesh-control'"
  done
fi

# ---------------------------------------------------------------------
# Step 8 — validators
# ---------------------------------------------------------------------
step "Step 8/11: start validators"
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet up -d validator1 validator2 validator3

# ---------------------------------------------------------------------
# Step 9 — DERP relay
# ---------------------------------------------------------------------
step "Step 9/11: start DERP relay"
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet up -d derp

# ---------------------------------------------------------------------
# Step 10 — observability
# ---------------------------------------------------------------------
step "Step 10/11: start observability"
maybe docker compose --env-file "$ENV_FILE" -f docker-compose.testnet.yml --profile testnet up -d prometheus grafana

# ---------------------------------------------------------------------
# Step 11 — next steps
# ---------------------------------------------------------------------
step "Step 11/11: done"
cat <<EOF

  Verify the stack:
    ./scripts/testnet/health-check.sh

  Onboard a new operator (issue them a preauth key first):
    ./scripts/testnet/join.sh --preauth-key <KEY> --control-url ${MESH_CONTROL_URL:-https://mesh.example}

  Tail logs:
    docker compose --env-file $ENV_FILE -f docker-compose.testnet.yml logs -f

  Grafana:    http://localhost:${GRAFANA_PORT:-3000}    (user: ${GRAFANA_ADMIN_USER:-admin})
  Prometheus: http://localhost:${PROMETHEUS_PORT:-9090}
  DERP:       http://localhost:${DERP_HTTP_PORT:-3340}

EOF
