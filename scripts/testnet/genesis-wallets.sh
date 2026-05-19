#!/usr/bin/env bash
# OctraVPN testnet — genesis-wallet ceremony.
#
# Generates the initial validator set + the 2-of-3 operator multisig
# that controls mesh-control. Writes sealed bundles (P1-6) into
# $GENESIS_DIR, one subdir per role.
#
# This is the TESTNET equivalent of scripts/ceremony/mainnet-deploy.sh.
# It is INTENTIONALLY separate so testnet bring-up cannot accidentally
# share key material with mainnet.
#
# Output layout (defaults shown):
#   ./deploy/testnet/state/genesis/
#       validator1/{wallet.key.sealed,wallet.pub,wg.key.sealed,wg.pub}
#       validator2/...
#       validator3/...
#       multisig/{signer1,signer2,signer3}/{key.sealed,pub}
#       multisig/threshold      (literal "2")
#       multisig/multisig.addr  (combined Octra address)
#       MANIFEST.txt            (everything generated, with sha256 of each pub)
#
# Usage:
#   scripts/testnet/genesis-wallets.sh [--out DIR] [--threshold N] [--signers N]
#
# Requires `octravpn` on PATH and OCTRAVPN_KEY_PASSPHRASE in the env
# (or it will be prompted for, once, and reused for every sealed
# bundle — testnet only; mainnet ceremony uses one passphrase per
# signer).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="./deploy/testnet/state/genesis"
THRESHOLD=2
SIGNERS=3
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)        OUT_DIR="$2"; shift 2 ;;
    --threshold)  THRESHOLD="$2"; shift 2 ;;
    --signers)    SIGNERS="$2"; shift 2 ;;
    --force)      FORCE=1; shift ;;
    -h|--help)
      sed -n '2,25p' "$0"
      exit 0
      ;;
    *) echo "unrecognised arg: $1" >&2; exit 2 ;;
  esac
done

if (( THRESHOLD < 1 || THRESHOLD > SIGNERS )); then
  echo "error: threshold ($THRESHOLD) must be 1..$SIGNERS" >&2
  exit 2
fi

# We tolerate `octravpn` not being installed during a dry/CI run by
# falling back to a clearly-marked stub that writes placeholder files.
# Real ceremonies MUST run with the real binary; the stub mode is so
# bootstrap.sh --dry-run can complete on a fresh checkout.
USE_STUB=0
if ! command -v octravpn >/dev/null; then
  echo "warning: octravpn binary not on PATH — using STUB key generator." >&2
  echo "         The output will be marked CEREMONY_STUB and is NOT valid for any chain." >&2
  USE_STUB=1
fi

# Single passphrase for the whole testnet ceremony. Mainnet ceremony
# uses per-signer passphrases; we don't bother on testnet.
if [[ -z "${OCTRAVPN_KEY_PASSPHRASE:-}" ]]; then
  read -r -s -p "Enter sealed-key passphrase (echo off): " OCTRAVPN_KEY_PASSPHRASE
  echo
  if [[ ${#OCTRAVPN_KEY_PASSPHRASE} -lt 12 ]]; then
    echo "error: passphrase must be ≥ 12 characters" >&2
    exit 2
  fi
  export OCTRAVPN_KEY_PASSPHRASE
fi

if [[ -d "$OUT_DIR" ]] && (( ! FORCE )); then
  echo "error: $OUT_DIR exists. Pass --force to overwrite, or rm -rf it manually." >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

gen_pair() {
  # gen_pair OUT_KEY_PATH OUT_PUB_PATH KIND
  # KIND ∈ {wallet, wg}
  local key="$1" pub="$2" kind="$3"
  if (( USE_STUB )); then
    {
      echo "CEREMONY_STUB"
      echo "kind=$kind"
      echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "sha256-of-this-line: $(date +%s%N | shasum | awk '{print $1}')"
    } > "$key"
    echo "stub-pub-$(basename "$(dirname "$key")")-$kind" > "$pub"
    return
  fi
  case "$kind" in
    wallet)
      octravpn keygen --seal --out "$key" --pub-out "$pub"
      ;;
    wg)
      octravpn wg-keygen --seal --out "$key" --pub-out "$pub"
      ;;
  esac
  chmod 0400 "$key"
  chmod 0444 "$pub"
}

MANIFEST="$OUT_DIR/MANIFEST.txt"
{
  echo "OctraVPN testnet genesis ceremony"
  echo "generated_at = $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "threshold    = $THRESHOLD"
  echo "signers      = $SIGNERS"
  (( USE_STUB )) && echo "MODE         = CEREMONY_STUB (not a real ceremony)"
  echo ""
} > "$MANIFEST"

# Validator set
for n in 1 2 3; do
  d="$OUT_DIR/validator$n"
  mkdir -p "$d"
  gen_pair "$d/wallet.key.sealed" "$d/wallet.pub" wallet
  gen_pair "$d/wg.key.sealed"     "$d/wg.pub"     wg
  echo "validator$n wallet pub sha256 = $(shasum -a 256 "$d/wallet.pub" | awk '{print $1}')" >> "$MANIFEST"
  echo "validator$n wg     pub sha256 = $(shasum -a 256 "$d/wg.pub"     | awk '{print $1}')" >> "$MANIFEST"
done

# Operator multisig signers
ms_root="$OUT_DIR/multisig"
mkdir -p "$ms_root"
for i in $(seq 1 "$SIGNERS"); do
  d="$ms_root/signer$i"
  mkdir -p "$d"
  gen_pair "$d/key.sealed" "$d/pub" wallet
  echo "multisig signer$i pub sha256 = $(shasum -a 256 "$d/pub" | awk '{print $1}')" >> "$MANIFEST"
done
echo "$THRESHOLD" > "$ms_root/threshold"

# Combined multisig address. Real implementation calls the binary;
# stub mode writes a clearly-fake string.
if (( USE_STUB )); then
  echo "octSTUB_multisig_$(date +%s)" > "$ms_root/multisig.addr"
else
  pubs=()
  for i in $(seq 1 "$SIGNERS"); do
    pubs+=("$ms_root/signer$i/pub")
  done
  octravpn multisig-addr --threshold "$THRESHOLD" "${pubs[@]}" \
    > "$ms_root/multisig.addr"
fi

echo "multisig address = $(cat "$ms_root/multisig.addr")" >> "$MANIFEST"

cat <<EOF

==> wrote sealed bundles to $OUT_DIR

  Validators:
    $OUT_DIR/validator1/wallet.key.sealed
    $OUT_DIR/validator2/wallet.key.sealed
    $OUT_DIR/validator3/wallet.key.sealed

  Operator multisig ($THRESHOLD-of-$SIGNERS):
    $OUT_DIR/multisig/signer{1..$SIGNERS}/key.sealed
    $OUT_DIR/multisig/multisig.addr   <- copy to OPERATOR_MULTISIG_ADDR in .env.testnet

  Manifest:
    $MANIFEST

Next:
  1. Fund every validator + the multisig address via the faucet:
       https://faucet.octra.network/
  2. Copy each validator's wallet address into deploy/testnet/.env.testnet
     (VALIDATOR{1,2,3}_ADDR) and the multisig into OPERATOR_MULTISIG_ADDR.
  3. Run: ./scripts/testnet/bootstrap.sh deploy/testnet/testnet-params.toml
EOF
