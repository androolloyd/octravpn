#!/usr/bin/env bash
# sealed-boot-matrix.sh — prove the P1-6 strict key-load path on a REAL node.
#
# Four boots of octravpn-node in docker, against the local sequence-12 node,
# each answering one question about how private keys load:
#
#   sealed-ok        sealed keys + correct passphrase + require_sealed_keys=true
#                    -> must BOOT (tunnel + control plane listening)
#   sealed-wrongpp   sealed keys + wrong passphrase
#                    -> must REFUSE ("wallet decryption failed")
#   plain-strict     plaintext keys + require_sealed_keys=true
#                    -> must REFUSE ("plaintext key on disk ... seal-keys")
#   plain-lax        plaintext keys + require_sealed_keys=false
#                    -> must BOOT (the legacy path still works)
#
# Why docker run -d and not `timeout docker run`: timeout only signals the
# docker CLIENT; the container keeps running and the "test" hangs forever.
# Why the local node: devnet can halt for hours (observed 2026-09-12 at epoch
# 1,500,060) and boot needs a live RPC only to warn, not to load keys.
#
# Requires: the local node up (octra-foundry/docker/octra-node, reachable from
# containers at http://host.internal:18080/rpc), a host-built octravpn-node
# (cargo build -p octravpn-node) to run seal-keys offline, and the linux
# daemon in the `octra-v4-relay-e2e_octravpn-bin` volume (built by
# v4-relay-e2e.sh). Exit 0 iff all four cases behave as specified.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
RPC_CONTAINER="${RPC_CONTAINER:-http://host.internal:18080/rpc}"
PROGRAM_ADDR="${PROGRAM_ADDR:-octEeiD9nQpoBmUQs7zj2sKuWAhtFQx1ue5oudsy9ULmpeg}"
BIN_VOLUME="${BIN_VOLUME:-octra-v4-relay-e2e_octravpn-bin}"
PASS="correct horse battery staple"
W="$(mktemp -d "${TMPDIR:-/tmp}/sealed-matrix.XXXXXX")"; trap 'rm -rf "$W"' EXIT
HOSTBIN=$(ls -t "$ROOT"/target/release/octravpn-node "$ROOT"/target/debug/octravpn-node 2>/dev/null | head -1)
[[ -n "$HOSTBIN" ]] || { echo "need a host-built octravpn-node for seal-keys"; exit 2; }
CAST=$(ls -t "$ROOT"/../octra-foundry/target/release/octra 2>/dev/null | head -1)

# fresh throwaway operator identity; strict mode is about the FILES, so an
# unfunded wallet is fine (boot only warns on chain reads).
"$ROOT"/target/*/octravpn keygen --out "$W/wallet.key" >/dev/null 2>&1 || "$HOSTBIN" --help >/dev/null
[[ -f "$W/wallet.key" ]] || python3 -c "import os,binascii;open('$W/wallet.key','w').write(binascii.hexlify(os.urandom(32)).decode())"
python3 -c "import os,binascii;open('$W/wg.key','w').write(binascii.hexlify(os.urandom(32)).decode())"
ADDR=$([[ -n "$CAST" ]] && "$CAST" cast wallet addr --key "$W/wallet.key" 2>/dev/null || echo octUNKNOWN)

toml() { # wallet wg strict
cat <<EOF
[chain]
rpc_url             = "$RPC_CONTAINER"
program_addr        = "$PROGRAM_ADDR"
validator_addr      = "$ADDR"
wallet_secret_path  = "$1"
require_sealed_keys = $3
[tunnel]
public_endpoint     = "127.0.0.1:51820"
listen              = "0.0.0.0:51820"
wg_secret_path      = "$2"
[pricing]
price_per_mb        = 100
region              = "sealed-matrix"
[control]
listen              = "0.0.0.0:51821"
audit_dir           = "/tmp/octravpn-audit"
EOF
}
# seal on the host (offline file op), keep plaintext for the lax/strict cases
sed "s#/etc/octravpn/#$W/#g" <(toml /etc/octravpn/wallet.key /etc/octravpn/wg.key false) > "$W/seal.toml"
printf '%s\n' "$PASS" > "$W/pp.txt"
"$HOSTBIN" --config "$W/seal.toml" seal-keys --passphrase-file "$W/pp.txt" >/dev/null || { echo "seal-keys failed"; exit 2; }
toml /etc/octravpn/wallet.key.sealed /etc/octravpn/wg.key.sealed true  > "$W/sealed.toml"
toml /etc/octravpn/wallet.key        /etc/octravpn/wg.key        true  > "$W/plain-strict.toml"
toml /etc/octravpn/wallet.key        /etc/octravpn/wg.key        false > "$W/plain-lax.toml"

fails=0
run_case() { # label toml passphrase expect(boot|refuse) pattern
  local name="sealmx-$1-$$"
  docker run -d --name "$name" -v "$BIN_VOLUME":/bin/octravpn:ro -v "$W":/etc/octravpn:ro \
    -e OCTRAVPN_KEY_PASSPHRASE="$3" -e RUST_LOG=info debian:bookworm-slim \
    /bin/octravpn/octravpn-node --config "/etc/octravpn/$2" run >/dev/null
  sleep 12
  local status; status=$(docker inspect -f '{{.State.Status}}' "$name")
  local log; log=$(docker logs "$name" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  docker rm -f "$name" >/dev/null 2>&1
  local booted=0; grep -q 'octravpn-node running' <<<"$log" && booted=1
  local verdict=FAIL
  case "$4" in
    boot)   [[ "$status" == running && $booted == 1 ]] && verdict=PASS ;;
    refuse) [[ "$status" == exited && $booted == 0 ]] && grep -qiE "$5" <<<"$log" && verdict=PASS ;;
  esac
  [[ $verdict == PASS ]] || fails=$((fails+1))
  printf '  %-15s %-5s status=%-8s booted=%s  %s\n' "$1" "$verdict" "$status" "$booted" \
    "$(grep -vE '^\s*$' <<<"$log" | tail -1 | cut -c1-110)"
}
echo "sealed-boot matrix — operator $ADDR, program $PROGRAM_ADDR"
run_case sealed-ok      sealed.toml       "$PASS"            boot   ''
run_case sealed-wrongpp sealed.toml       "wrong passphrase" refuse 'decryption failed|wrong passphrase'
run_case plain-strict   plain-strict.toml ""                 refuse 'plaintext key on disk'
run_case plain-lax      plain-lax.toml    ""                 boot   ''
echo "RESULT: $((4-fails))/4 as specified"; exit $(( fails>0 ))
