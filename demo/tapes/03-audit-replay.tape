# 03-audit-replay.tape
#
# Captures the operator-side audit surface: a structured replay of the
# HMAC-chained audit log + receipt journal, followed by a full
# cryptographic verify. Drives the real `octravpn-node audit replay`
# / `audit verify` subcommands inside a debian container against an
# in-container HMAC-chained fixture.
#
# Harness: demo/lib/audit-fixture-bringup.sh — spawns
# `octravpn-audit-fixture` (debian + bind-mounted octravpn-node) and
# writes a deterministic 8-record audit log + sibling key + empty
# receipt journal at /work/node/.
#
# Re-run with: vhs demo/tapes/03-audit-replay.tape

Output demo/recordings/03-audit-replay.gif
Output demo/recordings/03-audit-replay.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/audit-fixture-bringup.sh"
Enter
Sleep 15s
Type "# replay a day's worth of audit + receipt-journal entries"
Enter
Type "docker exec octravpn-audit-fixture octravpn-node audit replay --audit-path /work/node/audit.log --journal-path /work/node/receipts.bin"
Enter
Sleep 5s

Type "# same data, JSONL form (drop into jq, splunk, etc.)"
Enter
Type "docker exec octravpn-audit-fixture sh -c 'octravpn-node audit replay --audit-path /work/node/audit.log --journal-path /work/node/receipts.bin --json | head -10'"
Enter
Sleep 4s

Type "# strict cryptographic verify — HMAC chain + receipt monotonicity"
Enter
Type "docker exec octravpn-audit-fixture sh -c 'octravpn-node audit verify --audit-path /work/node/audit.log --journal-path /work/node/receipts.bin; echo exit=$?'"
Enter
Sleep 5s

Type "bash demo/lib/audit-fixture-teardown.sh"
Enter
Sleep 5s