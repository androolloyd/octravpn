# 21-audit-verify.tape
#
# Captures the operator's day-2 forensic surface: `audit verify`
# against a clean audit log (exact exit 0), then a valid-JSON
# record change (exact exit 1 plus line-one MAC mismatch). Every step
# runs inside the same container fixture tape 03 uses.
#
# Harness: demo/lib/audit-fixture-bringup.sh — octravpn-audit-fixture
# container with octravpn-node + a deterministic HMAC-chained
# audit.log + receipts.bin at /work/node/.
#
# Re-run with: vhs demo/tapes/21-audit-verify.tape

Output demo/recordings/21-audit-verify.gif
Output demo/recordings/21-audit-verify.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/audit-fixture-bringup.sh"
Enter
Sleep 15s
Type "# Clean control, then a valid-JSON modification with the original HMAC key"
Enter
Type "python3 demo/lib/negative-checks.py audit"
Enter
Sleep 12s

Type "# Required: clean exit 0; tampered exit 1 with MAC mismatch at line 1"
Enter
Sleep 4s

Type "# An operator wires the clean-verify into a cron healthcheck;"
Enter
Type "# any non-zero exit pages the on-call with the broken-line hint."
Enter
Sleep 3s

Type "bash demo/lib/audit-fixture-teardown.sh"
Enter
Sleep 5s