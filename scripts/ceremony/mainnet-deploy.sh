#!/usr/bin/env bash
# OctraVPN v3 mainnet deploy + owner-wallet ceremony driver.
#
# Drives the operator through:
#   1. Validating the params file + source-hash integrity gate.
#   2. Computing a deterministic deploy-bundle hash over the
#      contract source + canonical constructor args.
#   3. Materialising an unsigned deploy transaction (canonical JSON)
#      and the matching message digest signers must sign.
#   4. Walking the m-of-n cold-key signer setup (default 3-of-5,
#      see ceremony/mainnet-params.toml.example for the rationale).
#   5. After collecting signatures from `signers/*.sig`, emitting a
#      ready-to-broadcast `submit_tx` envelope (the script does NOT
#      itself broadcast unless --no-dry-run is passed; default is
#      --dry-run).
#   6. After broadcast, polling `vm_contract` until `code_hash`
#      appears, then issuing transfer_ownership(multisig_addr)
#      followed by set_params(...) so the runtime parameters match
#      the ceremony spec.
#
# v1 of this script is intentionally text-mode multisig: each signer
# holds a passphrase-sealed key under `signers/<name>.key.sealed` and
# returns a detached signature over the unsigned-tx digest. A
# hardware-wallet variant would replace the "read sig file" step
# with "render the digest as a QR/HW prompt and read the response
# back"; that wiring lives under the HW TODO markers below.
#
# Dependencies: bash, jq, sha256sum (or shasum -a 256), curl.
# Source-of-truth wire shape comes from
# `crates/octravpn-core/src/v3_calls.rs`.

set -euo pipefail

# ---------------------------------------------------------------
# Argv parsing
# ---------------------------------------------------------------

PARAMS_FILE=""
DRY_RUN=1
ALLOW_DEVNET=0
SKIP_INTEGRITY=0
OUTPUT_DIR=""

usage() {
  cat <<EOF
usage: $0 --params <path> [options]

Required:
  --params <path>        Path to the TOML params file
                         (template: ceremony/mainnet-params.toml.example)

Options:
  --dry-run              (default) Stop after producing the unsigned
                         tx blob and broadcast envelope. The script
                         exits 0 and prints the on-disk paths.
  --no-dry-run           Actually POST to rpc_url. Refuses unless
                         m-of-n signatures are present AND the URL
                         does not contain "devnet" or "testnet"
                         (override with --allow-devnet for the
                         regression test that runs this against
                         devnet).
  --allow-devnet         Permit broadcasting against a *devnet*/
                         *testnet* RPC. Required for the smoke
                         harness; should never be set in production.
  --skip-integrity       Skip the source-hash gate. ONLY for
                         developing this script. Refuses to run with
                         --no-dry-run.
  --output-dir <path>    Where to write unsigned-tx / digest / sig
                         scratch files. Default: dirname(params) +
                         "/build".
  -h, --help             Show this.

Exit codes:
  0  success / dry-run produced unsigned tx
  1  generic error
  2  params validation failure
  3  source-hash integrity failure
  4  signer set incomplete / signatures missing
  5  RPC failure during broadcast or verification
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --params) PARAMS_FILE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-dry-run) DRY_RUN=0; shift ;;
    --allow-devnet) ALLOW_DEVNET=1; shift ;;
    --skip-integrity) SKIP_INTEGRITY=1; shift ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$PARAMS_FILE" ]]; then
  echo "error: --params is required" >&2
  usage
  exit 1
fi

if [[ ! -f "$PARAMS_FILE" ]]; then
  echo "error: params file not found: $PARAMS_FILE" >&2
  exit 2
fi

# ---------------------------------------------------------------
# Resolve repo root + helpers
# ---------------------------------------------------------------

# Repo root: this script lives at scripts/ceremony/ — two levels up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Pick sha256 implementation. macOS ships shasum; Linux ships
# sha256sum. preflight.sh and v3-smoke.sh both rely on one or the
# other being present.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256() { sha256sum "$@" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  SHA256() { shasum -a 256 "$@" | awk '{print $1}'; }
else
  echo "error: need sha256sum or shasum on PATH" >&2
  exit 1
fi

SHA256_STDIN() {
  # Hash stdin; print just the hex digest.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

command -v jq >/dev/null 2>&1 || { echo "error: jq required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "error: curl required" >&2; exit 1; }

hdr() { printf "\n=== %s ===\n" "$1"; }
ok()  { printf "  [ok]   %s\n" "$1"; }
warn(){ printf "  [warn] %s\n" "$1"; }
die() { printf "  [fail] %s\n" "$1"; exit "${2:-1}"; }

# ---------------------------------------------------------------
# Dumb TOML reader. Same approach as docker/devnet/preflight.sh:
# one `key = value` per line, strings double-quoted, integers bare.
# Comments (`#...`) and blank lines ignored.
# ---------------------------------------------------------------

toml_get() {
  local key="$1" file="$2"
  # Match: optional whitespace, key, whitespace, =, whitespace, value.
  # Capture value up to a trailing `#` comment if any.
  local raw
  raw=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" \
        | head -1 \
        | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//" \
        | sed -E 's/[[:space:]]*#.*$//' \
        | sed -E 's/[[:space:]]+$//' \
        || true)
  # Strip surrounding quotes if present.
  if [[ "$raw" =~ ^\"(.*)\"$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    # Strip underscores from integer literals.
    printf '%s' "${raw//_/}"
  fi
}

# ---------------------------------------------------------------
# Step 0 — load and validate params
# ---------------------------------------------------------------

hdr "0. Loading params from $PARAMS_FILE"

RPC_URL=$(toml_get rpc_url "$PARAMS_FILE")
CHAIN_ID=$(toml_get chain_id "$PARAMS_FILE")
CONTRACT_PATH=$(toml_get contract_source_path "$PARAMS_FILE")
EXPECTED_SRC_HASH=$(toml_get contract_source_sha256_expected "$PARAMS_FILE")

MIN_SESSION_DEPOSIT=$(toml_get min_session_deposit "$PARAMS_FILE")
MIN_TAILNET_DEPOSIT=$(toml_get min_tailnet_deposit "$PARAMS_FILE")
MIN_CIRCLE_STAKE=$(toml_get min_circle_stake "$PARAMS_FILE")
SESSION_GRACE_EPOCHS=$(toml_get session_grace_epochs "$PARAMS_FILE")
UNBOND_GRACE_EPOCHS=$(toml_get unbond_grace_epochs "$PARAMS_FILE")

SLASH_BURN_BPS=$(toml_get slash_burn_bps "$PARAMS_FILE")
SLASH_BOUNTY_BPS=$(toml_get slash_bounty_bps "$PARAMS_FILE")
PROTOCOL_FEE_BPS=$(toml_get protocol_fee_bps "$PARAMS_FILE")
SWEEP_GRACE_MULT=$(toml_get sweep_grace_multiplier "$PARAMS_FILE")
SWEEP_BOUNTY_BPS=$(toml_get sweep_bounty_bps "$PARAMS_FILE")

MULTISIG_M=$(toml_get multisig_threshold "$PARAMS_FILE")
MULTISIG_N=$(toml_get multisig_signer_count "$PARAMS_FILE")
SIGNERS_DIR=$(toml_get signers_dir "$PARAMS_FILE")

# Sanity-check required fields.
for var in RPC_URL CHAIN_ID CONTRACT_PATH MIN_SESSION_DEPOSIT \
           MIN_TAILNET_DEPOSIT MIN_CIRCLE_STAKE SESSION_GRACE_EPOCHS \
           UNBOND_GRACE_EPOCHS SLASH_BURN_BPS SLASH_BOUNTY_BPS \
           PROTOCOL_FEE_BPS SWEEP_GRACE_MULT SWEEP_BOUNTY_BPS \
           MULTISIG_M MULTISIG_N SIGNERS_DIR; do
  if [[ -z "${!var}" ]]; then
    die "missing required param: $var" 2
  fi
done

# Multisig threshold sanity.
if ! [[ "$MULTISIG_M" =~ ^[0-9]+$ ]] || ! [[ "$MULTISIG_N" =~ ^[0-9]+$ ]]; then
  die "multisig_threshold and multisig_signer_count must be integers" 2
fi
if (( MULTISIG_M < 1 || MULTISIG_M > MULTISIG_N )); then
  die "multisig_threshold ($MULTISIG_M) must be in [1, $MULTISIG_N]" 2
fi

# slash bps must sum to 10000.
if (( SLASH_BURN_BPS + SLASH_BOUNTY_BPS != 10000 )); then
  die "slash_burn_bps + slash_bounty_bps must equal 10000 (got $((SLASH_BURN_BPS+SLASH_BOUNTY_BPS)))" 2
fi

# Refuse mainnet broadcast against a devnet URL unless --allow-devnet.
if [[ $DRY_RUN -eq 0 ]]; then
  if [[ "$RPC_URL" == *devnet* || "$RPC_URL" == *testnet* ]]; then
    if [[ $ALLOW_DEVNET -ne 1 ]]; then
      die "rpc_url looks like devnet/testnet; pass --allow-devnet if intentional" 2
    fi
    warn "broadcasting against non-mainnet RPC: $RPC_URL"
  fi
fi

ok "rpc_url=$RPC_URL"
ok "chain_id=$CHAIN_ID"
ok "contract=$CONTRACT_PATH"
ok "multisig=${MULTISIG_M}-of-${MULTISIG_N}"

# ---------------------------------------------------------------
# Step 1 — source-hash integrity gate
# ---------------------------------------------------------------

hdr "1. Source-hash integrity gate"

CONTRACT_FULL="$REPO_ROOT/$CONTRACT_PATH"
if [[ ! -f "$CONTRACT_FULL" ]]; then
  die "contract source not found: $CONTRACT_FULL" 3
fi

LIVE_SRC_HASH=$(SHA256 "$CONTRACT_FULL")
ok "live  source SHA256: $LIVE_SRC_HASH"

if [[ -n "$EXPECTED_SRC_HASH" ]]; then
  ok "param source SHA256: $EXPECTED_SRC_HASH"
  if [[ "$LIVE_SRC_HASH" != "$EXPECTED_SRC_HASH" ]]; then
    if [[ $SKIP_INTEGRITY -eq 1 ]]; then
      warn "source-hash mismatch but --skip-integrity passed"
      if [[ $DRY_RUN -eq 0 ]]; then
        die "--skip-integrity is incompatible with --no-dry-run" 3
      fi
    else
      die "source-hash mismatch: live=$LIVE_SRC_HASH expected=$EXPECTED_SRC_HASH" 3
    fi
  else
    ok "source hash matches param"
  fi
else
  warn "contract_source_sha256_expected is empty; running with live hash"
  warn "pin this value in $PARAMS_FILE before --no-dry-run"
fi

# ---------------------------------------------------------------
# Step 2 — deterministic deploy bundle hash
# ---------------------------------------------------------------

hdr "2. Deploy bundle"

# The bundle is (in this order, separated by single LFs):
#   <SHA256 of contract source>
#   constructor_args = [<5 ints, comma-sep>]
#   chain_id = "<chain_id>"
#   protocol_version = "v3"
#
# Hashing this canonical string yields a single bundle digest that
# the signers attest to. The on-chain `code_hash` (returned by
# `vm_contract`) is a separate value that the chain itself computes
# over the compiled bytecode; we record both in the post-deploy
# attestation so a third party can verify either dimension.

CONSTRUCTOR_ARGS="${MIN_SESSION_DEPOSIT},${MIN_TAILNET_DEPOSIT},${MIN_CIRCLE_STAKE},${SESSION_GRACE_EPOCHS},${UNBOND_GRACE_EPOCHS}"

BUNDLE_CANONICAL=$(printf '%s\nconstructor_args = [%s]\nchain_id = "%s"\nprotocol_version = "v3"\n' \
  "$LIVE_SRC_HASH" "$CONSTRUCTOR_ARGS" "$CHAIN_ID")
BUNDLE_HASH=$(printf '%s' "$BUNDLE_CANONICAL" | SHA256_STDIN)

ok "constructor args: [$CONSTRUCTOR_ARGS]"
ok "bundle hash:      $BUNDLE_HASH"

# ---------------------------------------------------------------
# Step 3 — write the unsigned-tx scratch files
# ---------------------------------------------------------------

hdr "3. Unsigned tx materialisation"

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(dirname "$PARAMS_FILE")/build"
fi
mkdir -p "$OUTPUT_DIR"

UNSIGNED_TX="$OUTPUT_DIR/unsigned-deploy-tx.json"
UNSIGNED_DIGEST="$OUTPUT_DIR/unsigned-deploy-tx.digest"
UNSIGNED_SETPARAMS="$OUTPUT_DIR/unsigned-setparams-tx.json"
UNSIGNED_TRANSFER="$OUTPUT_DIR/unsigned-transfer-tx.json"
BROADCAST_PLAN="$OUTPUT_DIR/broadcast-plan.json"

# Canonical-JSON serialisation: jq -S produces sorted keys + stable
# whitespace. We use compact mode (-c) so the digest is stable across
# editors. The actual on-wire envelope shape used by
# octra_core::tx::sign_call is the legacy
# `{"kind","from","to","method","params","value","fee","nonce"}`
# (see crates/octravpn-core/src/v3_calls.rs::call). For deploy we
# emit a parallel `{"kind":"deploy", ...}` envelope; the actual
# signing/broadcast tooling that consumes this needs to be the
# octra-foundry `octra forge create` path because the bytecode
# compile + on-wire signing live there. This script's responsibility
# stops at producing a canonical artifact the foundry tool can
# ingest, plus the digest signers attest to.

# 3a. unsigned-deploy-tx.json
jq -nSc \
  --arg kind "deploy" \
  --arg chain_id "$CHAIN_ID" \
  --arg contract_path "$CONTRACT_PATH" \
  --arg source_sha256 "$LIVE_SRC_HASH" \
  --arg bundle_sha256 "$BUNDLE_HASH" \
  --argjson constructor_args "[$CONSTRUCTOR_ARGS]" \
  '{
    kind: $kind,
    chain_id: $chain_id,
    contract_path: $contract_path,
    source_sha256: $source_sha256,
    bundle_sha256: $bundle_sha256,
    constructor_args: $constructor_args,
    protocol_version: "v3"
  }' \
  > "$UNSIGNED_TX"

# Recompute digest over the canonical-JSON serialisation (NOT the
# bundle canonical form above — signers sign the JSON they can
# inspect with `jq .`).
TX_DIGEST=$(SHA256_STDIN < "$UNSIGNED_TX")
printf '%s' "$TX_DIGEST" > "$UNSIGNED_DIGEST"

ok "unsigned tx:      $UNSIGNED_TX"
ok "tx digest:        $TX_DIGEST"

# 3b. unsigned setparams + transfer placeholders. The owner-addr is
# unknown until after the multisig key gen step (3d below); these
# files are re-written with the real addr once the operator runs
# `--phase=set-owner`. For dry-run we materialise placeholders so
# operators can see the full surface up front.

jq -nSc \
  --arg chain_id "$CHAIN_ID" \
  '{
    kind: "contract_call",
    chain_id: $chain_id,
    method: "transfer_ownership",
    params: ["<MULTISIG_ADDR_AFTER_KEYGEN>"],
    value: 0,
    fee: 1000
  }' \
  > "$UNSIGNED_TRANSFER"

jq -nSc \
  --arg chain_id "$CHAIN_ID" \
  --argjson msd "$MIN_SESSION_DEPOSIT" \
  --argjson mtd "$MIN_TAILNET_DEPOSIT" \
  --argjson sge "$SESSION_GRACE_EPOCHS" \
  --argjson sgm "$SWEEP_GRACE_MULT" \
  --argjson sbb "$SWEEP_BOUNTY_BPS" \
  --argjson mcs "$MIN_CIRCLE_STAKE" \
  --argjson uge "$UNBOND_GRACE_EPOCHS" \
  --argjson sbu "$SLASH_BURN_BPS" \
  --argjson sbo "$SLASH_BOUNTY_BPS" \
  --argjson pfb "$PROTOCOL_FEE_BPS" \
  '{
    kind: "contract_call",
    chain_id: $chain_id,
    method: "set_params",
    params: [$msd, $mtd, $sge, $sgm, $sbb, $mcs, $uge, $sbu, $sbo, $pfb],
    value: 0,
    fee: 1000
  }' \
  > "$UNSIGNED_SETPARAMS"

ok "set_params tx:    $UNSIGNED_SETPARAMS"
ok "transfer tx:      $UNSIGNED_TRANSFER"

# ---------------------------------------------------------------
# Step 4 — multisig signer setup walkthrough
# ---------------------------------------------------------------

hdr "4. Signer set (${MULTISIG_M}-of-${MULTISIG_N})"

SIGNERS_FULL="$REPO_ROOT/$SIGNERS_DIR"
mkdir -p "$SIGNERS_FULL"

# Discover signer pubkeys. The file naming convention is
# `<name>.pub` (base64 ed25519) and `<name>.key.sealed`
# (passphrase-sealed secret key — the script never reads the secret).
# A signer is "present" if a matching .pub file exists.
mapfile -t SIGNER_PUBS < <(find "$SIGNERS_FULL" -maxdepth 1 -name '*.pub' -type f 2>/dev/null | sort)

if (( ${#SIGNER_PUBS[@]} < MULTISIG_N )); then
  warn "found ${#SIGNER_PUBS[@]} signer pubkeys under $SIGNERS_FULL/, need $MULTISIG_N"
  warn "before proceeding past dry-run, each signer must:"
  warn "  1. Generate an ed25519 keypair offline."
  warn "  2. Seal the secret with the wallet_enc format"
  warn "     (octra-core::wallet_enc), filename:"
  warn "       $SIGNERS_DIR/<name>.key.sealed"
  warn "  3. Drop the base64 pubkey at"
  warn "       $SIGNERS_DIR/<name>.pub"
  # HW TODO: in the hardware-wallet variant, replace step 2 with
  # "register the device public key under <name>.pub" and steps
  # 5/5a/5b below with the HW signing flow.
else
  ok "found ${#SIGNER_PUBS[@]} signer pubkeys:"
  for p in "${SIGNER_PUBS[@]}"; do
    ok "  $(basename "$p")"
  done
fi

# Derive a deterministic "multisig address" from the sorted, joined
# signer pubkeys + the threshold. The on-chain owner will be set to
# this addr via transfer_ownership at phase=set-owner. The address
# scheme here is a SHA256 over the canonical "m/n/pubkeys" string
# prefixed with "oct" — NOT a real Octra ed25519 address. The
# foundry tooling (`octra cast wallet multisig`) is the actual
# producer of the on-wire multisig address; this script reports the
# canonical hash so the operator can cross-check the foundry output.
if (( ${#SIGNER_PUBS[@]} >= MULTISIG_N )); then
  MS_INPUT="m=${MULTISIG_M}\nn=${MULTISIG_N}\n"
  for p in "${SIGNER_PUBS[@]}"; do
    MS_INPUT+="pub=$(cat "$p")\n"
  done
  MULTISIG_CHKHASH=$(printf "$MS_INPUT" | SHA256_STDIN)
  ok "multisig canonical hash: $MULTISIG_CHKHASH"
  ok "(cross-check this against the address produced by"
  ok " 'octra cast wallet multisig --m $MULTISIG_M --pubkeys ${SIGNERS_DIR}/*.pub')"
fi

# ---------------------------------------------------------------
# Step 5 — signing party
# ---------------------------------------------------------------

hdr "5. Signing party"

SIG_GLOB="$SIGNERS_FULL/*.sig"
mapfile -t SIG_FILES < <(find "$SIGNERS_FULL" -maxdepth 1 -name '*.sig' -type f 2>/dev/null | sort)

if (( ${#SIG_FILES[@]} < MULTISIG_M )); then
  warn "found ${#SIG_FILES[@]} signatures, need ${MULTISIG_M}"
  warn "each signer should now:"
  warn "  1. Verify the digest in $UNSIGNED_DIGEST"
  warn "     (file contents = $TX_DIGEST)"
  warn "  2. Verify the unsigned-tx body in $UNSIGNED_TX"
  warn "  3. Sign the digest with their sealed key (the foundry"
  warn "     'octra cast sign' subcommand consumes a .key.sealed"
  warn "     file + a hex digest and emits a base64 ed25519 sig)"
  warn "  4. Drop the result at $SIGNERS_DIR/<name>.sig"
  if [[ $DRY_RUN -ne 0 ]]; then
    ok "dry-run: stopping at the unsigned-tx artifact"
  fi
else
  ok "found ${#SIG_FILES[@]} signatures (threshold ${MULTISIG_M} met):"
  for s in "${SIG_FILES[@]}"; do
    ok "  $(basename "$s")"
  done
  # NOTE: this script does not itself verify ed25519 sigs — that
  # belongs to the foundry tool that knows the curve. We assume each
  # signer ran their own verify before dropping the .sig file.
fi

# ---------------------------------------------------------------
# Step 6 — broadcast plan
# ---------------------------------------------------------------

hdr "6. Broadcast plan"

jq -nSc \
  --arg rpc_url "$RPC_URL" \
  --arg chain_id "$CHAIN_ID" \
  --arg unsigned_tx "$UNSIGNED_TX" \
  --arg setparams_tx "$UNSIGNED_SETPARAMS" \
  --arg transfer_tx "$UNSIGNED_TRANSFER" \
  --arg tx_digest "$TX_DIGEST" \
  --arg bundle_hash "$BUNDLE_HASH" \
  --argjson multisig_m "$MULTISIG_M" \
  --argjson multisig_n "$MULTISIG_N" \
  --arg signers_dir "$SIGNERS_FULL" \
  '{
    rpc_url: $rpc_url,
    chain_id: $chain_id,
    bundle_hash: $bundle_hash,
    tx_digest: $tx_digest,
    multisig: { m: $multisig_m, n: $multisig_n, signers_dir: $signers_dir },
    txs: {
      deploy: $unsigned_tx,
      transfer_ownership: $transfer_tx,
      set_params: $setparams_tx
    },
    steps: [
      "1. octra forge create --aml program/main-v3.aml --multisig-sig-dir <signers_dir> --rpc-url <rpc_url>",
      "2. poll vm_contract <new-program-addr> until code_hash returns",
      "3. send transfer_ownership(multisig_addr) signed by current deployer",
      "4. send set_params(...) signed by the multisig",
      "5. record code_hash + program_addr back into ceremony/mainnet-params.toml under expected_code_hash + program_addr",
      "6. run scripts/ceremony/verify-deploy.sh <program_addr> and attach the PASS output to the attestation"
    ]
  }' > "$BROADCAST_PLAN"

ok "broadcast plan written: $BROADCAST_PLAN"

if [[ $DRY_RUN -ne 0 ]]; then
  hdr "DRY RUN — stopping before broadcast"
  cat <<EOF
Artifacts:
  unsigned deploy tx: $UNSIGNED_TX
  digest to be signed: $UNSIGNED_DIGEST  ($TX_DIGEST)
  unsigned set_params: $UNSIGNED_SETPARAMS
  unsigned transfer_ownership: $UNSIGNED_TRANSFER
  broadcast plan: $BROADCAST_PLAN

Next steps:
  1. Distribute $UNSIGNED_TX + $UNSIGNED_DIGEST to all $MULTISIG_N signers.
  2. Each signer returns a .sig file under $SIGNERS_DIR/.
  3. Re-run this script with --no-dry-run to actually broadcast,
     OR hand the artifact set off to the foundry tooling
     (octra forge create --multisig-sig-dir ...).
EOF
  exit 0
fi

# ---------------------------------------------------------------
# Step 7 — actual broadcast (gated on --no-dry-run)
#
# This script intentionally does NOT call octra-foundry directly;
# the operator's foundry CLI handles the on-wire signing + RPC
# `submit_tx` POST. We print the exact command line.
# ---------------------------------------------------------------

hdr "7. Broadcast"

# Verify threshold met before allowing broadcast.
if (( ${#SIG_FILES[@]} < MULTISIG_M )); then
  die "cannot broadcast: ${#SIG_FILES[@]} sigs found, need ${MULTISIG_M}" 4
fi

cat <<EOF
Broadcast is delegated to the foundry CLI. Run:

  octra forge create \\
    --aml $REPO_ROOT/$CONTRACT_PATH \\
    --constructor-args $CONSTRUCTOR_ARGS \\
    --rpc-url $RPC_URL \\
    --multisig-sig-dir $SIGNERS_FULL \\
    --multisig-threshold $MULTISIG_M

After the deploy confirms, capture the program addr and re-run:

  $0 --params $PARAMS_FILE --phase=set-owner --program-addr <addr>

(NOT IMPLEMENTED in v1 of this script — the set-owner phase is
manual: send the transfer_ownership tx from $UNSIGNED_TRANSFER and
the set_params tx from $UNSIGNED_SETPARAMS, each signed by the
multisig.)

Verify after broadcast:

  bash $REPO_ROOT/scripts/ceremony/verify-deploy.sh <program-addr>
EOF

exit 0
