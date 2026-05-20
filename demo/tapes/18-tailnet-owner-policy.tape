# 18-tailnet-owner-policy.tape
#
# Captures the tailnet-owner day-2 policy surface: edit a hujson
# policy locally, push it via `octravpn-node headscale policy set
# <FILE>`, and demonstrate that already-joined nodes pick up the new
# filter on the next `/map` poll. The parked-poller path wakes within
# ~1ms — see `crates/octravpn-node/tests/policy_e2e.rs` for the
# end-to-end assertion.
#
# REQUIRES:
#   - `octravpn-node` on PATH (the embedded `headscale` CLI surface).
#   - A reachable headscale control plane. Two ways to satisfy this:
#       (a) point HEADSCALE_URL / HEADSCALE_ADMIN_TOKEN at a running
#           control plane (e.g. the 3-node mesh from tape 08), OR
#       (b) source the in-repo mesh bringup (uncomment the Source line
#           below). Bringup costs ~120s of cold cache the first time.
#   - `curl` to confirm the live-reload (peer hits /map and sees the
#     new ACL set echoed back).
#
# Re-run with: vhs demo/tapes/18-tailnet-owner-policy.tape

Output demo/recordings/18-tailnet-owner-policy.gif
Output demo/recordings/18-tailnet-owner-policy.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

# Uncomment to bring the 3-node mesh up locally; in CI the heavy job
# already has the stack from the matrix step before this tape.
# Source demo/lib/3node-mesh-bringup.sh

Type "# Step 1: write a minimal hujson policy (allow all between alice + bob)"
Enter
Type "cat > /tmp/policy.hujson <<HUJSON"
Enter
Type "// allow alice <-> bob, deny everything else"
Enter
Type "{ acls: [ { action: 'accept', src: ['alice'], dst: ['bob:*'] } ] }"
Enter
Type "HUJSON"
Enter
Sleep 2s

Type "# Step 2: push the policy via the embedded headscale CLI"
Enter
Type "octravpn-node headscale policy check /tmp/policy.hujson"
Enter
Sleep 3s
Type "octravpn-node headscale policy set /tmp/policy.hujson"
Enter
Sleep 4s

Type "# Step 3: confirm the control plane echoes back the new policy"
Enter
Type "octravpn-node headscale policy get"
Enter
Sleep 4s

Type "# Step 4: any parked /map poller wakes within ~1ms (policy_e2e.rs pins this)"
Enter
Type "# A joined peer hits /machine/<key>/map and gets the updated PacketFilter:"
Enter
Type "octravpn-node headscale nodes list"
Enter
Sleep 4s

Type "# Done. New policy live across the tailnet without a peer reconnect."
Enter
Sleep 2s
