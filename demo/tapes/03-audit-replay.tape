# 03-audit-replay.tape
#
# Captures the operator-side audit surface: a structured replay of the
# HMAC-chained audit log + receipt journal, followed by a full
# cryptographic verify.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - Pre-populated audit artifacts at:
#       demo/state/node/audit.log
#       demo/state/node/receipts.bin
#     For the canned demo, point at a checked-in fixture dir or the
#     state directory of a running devnet node. The exact paths are
#     overridable via the env vars `AUDIT_PATH` and `JOURNAL_PATH`,
#     but the .tape pins them so the recording is reproducible.
#
# Re-run with: vhs demo/tapes/03-audit-replay.tape

Output demo/recordings/03-audit-replay.gif
Output demo/recordings/03-audit-replay.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# replay a day's worth of audit + receipt-journal entries"
Enter
Type "octravpn-node audit replay --audit-path demo/state/node/audit.log --journal-path demo/state/node/receipts.bin"
Enter
Sleep 4s

Type "# same data, JSONL form (drop into jq, splunk, etc.)"
Enter
Type "octravpn-node audit replay --audit-path demo/state/node/audit.log --journal-path demo/state/node/receipts.bin --json | head -10"
Enter
Sleep 3s

Type "# strict cryptographic verify — HMAC chain + receipt monotonicity"
Enter
Type "octravpn-node audit verify --audit-path demo/state/node/audit.log --journal-path demo/state/node/receipts.bin"
Enter
Sleep 4s

Type "echo \"exit=$?\""
Enter
Sleep 1500ms
