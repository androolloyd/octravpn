# 21-audit-verify.tape
#
# Captures the operator's day-2 forensic surface: `octravpn-node audit
# verify` against a clean audit log + receipt journal (exit 0,
# FileVerifyReport summary), then the same command against a
# tampered file (exit non-zero, first-broken-line pointer).
#
# The "tamper" we stage is a single-byte mutation in the middle of
# the audit log via `printf` + a fixed offset — small enough that the
# HMAC chain breaks at a deterministic line so the tape reads the
# same on every render.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - Pre-populated audit artifacts at:
#       demo/state/node/audit.log
#       demo/state/node/receipts.bin
#     Same fixture tape 03 uses. If the state-dir is empty, run a
#     short `octravpn-node run` against a devnet first, generate a
#     few sessions, then re-record.
#   - `cp`, `dd`, and a writable `/tmp`.
#
# Re-run with: vhs demo/tapes/21-audit-verify.tape

Output demo/recordings/21-audit-verify.gif
Output demo/recordings/21-audit-verify.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Step 1: clean verify against the operator's real audit log"
Enter
Type "octravpn-node audit verify --audit-path demo/state/node/audit.log --journal-path demo/state/node/receipts.bin"
Enter
Sleep 5s
Type "echo exit=$?"
Enter
Sleep 2s

Type "# Step 2: stage a tampered copy — flip one byte in the middle of the log"
Enter
Type "cp demo/state/node/audit.log /tmp/audit.tampered.log"
Enter
Type "FSIZE=$(wc -c < /tmp/audit.tampered.log) && OFFSET=$((FSIZE / 2))"
Enter
Type "printf 'X' | dd of=/tmp/audit.tampered.log bs=1 seek=$OFFSET count=1 conv=notrunc status=none"
Enter
Sleep 3s

Type "# Step 3: verify the tampered file — exits non-zero, names the broken line"
Enter
Type "octravpn-node audit verify --audit-path /tmp/audit.tampered.log --journal-path demo/state/node/receipts.bin || true"
Enter
Sleep 5s
Type "echo exit=$?"
Enter
Sleep 2s

Type "# An operator wires the clean-verify into a cron healthcheck;"
Enter
Type "# any non-zero exit pages the on-call with the broken-line hint."
Enter
Sleep 3s
