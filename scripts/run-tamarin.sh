#!/usr/bin/env bash
# A zero prover exit code is insufficient: every named lemma must be verified.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tamarin-prover >/dev/null || { echo 'tamarin-prover is required' >&2; exit 1; }
log_dir="${PROOF_LOG_DIR:-/tmp/octravpn-tamarin}"
mkdir -p "$log_dir"
for theory in octravpn relay_receipt_ack; do
  tamarin-prover --prove "proofs/tamarin/$theory.spthy" > "$log_dir/$theory.log" 2>&1
  python3 - "$log_dir/$theory.log" "$theory" <<'PY'
import pathlib,re,sys
expected={
 'octravpn': {'ClientAuthentication','NodeAuthentication','HonestReceiptReachable'},
 'relay_receipt_ack': {'AckRequiresDurableReceipt','SendAlwaysAfterPersistence','RecoveryCanDeliverAck'},
}
s=pathlib.Path(sys.argv[1]).read_text()
rows=re.findall(r'^\s+([A-Za-z0-9_]+) \((?:all-traces|exists-trace)\): ([^\n]+)$',s,re.M)
if {n for n,_ in rows} != expected[sys.argv[2]] or any(not v.startswith('verified (') for _,v in rows):
 print(s); sys.exit('Tamarin did not verify the exact required lemma set')
print(sys.argv[2]+': all required lemmas verified')
PY
done
