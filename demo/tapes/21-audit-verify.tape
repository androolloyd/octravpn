# 21-audit-verify.tape
#
# Captures the operator's day-2 forensic surface: `audit verify`
# against a clean audit log (exit 0), then the same command against
# a tampered file (exit non-zero, broken-line pointer). Every step
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
Type "# Step 1: clean verify against the synthesized audit log"
Enter
Type "docker exec octravpn-audit-fixture sh -c 'octravpn-node audit verify --audit-path /work/node/audit.log --journal-path /work/node/receipts.bin; echo exit=$?'"
Enter
Sleep 5s

Type "# Step 2: stage a tampered copy — flip one byte at FSIZE/2"
Enter
Type "docker exec octravpn-audit-fixture sh -c 'cp /work/node/audit.log /tmp/audit.tampered.log && FSIZE=$(wc -c < /tmp/audit.tampered.log) && OFFSET=$((FSIZE / 2)) && printf X | dd of=/tmp/audit.tampered.log bs=1 seek=$OFFSET count=1 conv=notrunc status=none && echo flipped byte at offset $OFFSET'"
Enter
Sleep 4s

Type "# Step 3: verify the tampered file — exits non-zero, names the broken line"
Enter
Type "docker exec octravpn-audit-fixture sh -c 'octravpn-node audit verify --audit-path /tmp/audit.tampered.log --journal-path /work/node/receipts.bin || true; echo exit=$?'"
Enter
Sleep 5s

Type "# An operator wires the clean-verify into a cron healthcheck;"
Enter
Type "# any non-zero exit pages the on-call with the broken-line hint."
Enter
Sleep 3s

Type "bash demo/lib/audit-fixture-teardown.sh"
Enter
Sleep 5s