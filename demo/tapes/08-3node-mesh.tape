# 08-3node-mesh.tape
#
# Cold-start the 3-peer Tailscale mesh demo. Drives the canonical
# `tailscale up` flow (interop-test fixture, scaled to 3) against
# `octravpn-node mesh serve`. The payoff line is "READY" emitted by
# the bringup script when all three peers are visible to peer-1's
# `tailscale status`.
#
# Tapes 09 + 10 assume the stack from this tape is still up. Re-run
# this tape (or `3node-mesh-bringup.sh` directly) before either of
# them on a cold machine.
#
# REQUIRES:
#   - Docker Desktop (or equivalent) running.
#   - Sibling repos under ../octra-foundry and ../headscale-rs.
#   - openssl on the host (used to mint the derp-1 self-signed cert).
#   - First-run cold cache: 5-10 minutes of cargo build.
#
# Re-run with: vhs demo/tapes/08-3node-mesh.tape

Output demo/recordings/08-3node-mesh.gif
Output demo/recordings/08-3node-mesh.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# 3-peer Tailscale mesh on top of octravpn-node mesh serve"
Enter
Sleep 1s

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
# Cold-start budget: ~6 minutes (cargo build + compose up + 3x
# `tailscale up` + IP-plane convergence). Warm cache: <60s. vhs
# truncates the recording at the script's exit, so over-allocating
# the sleep is safe.
Sleep 420s

Type "# Show the roster from peer-1's vantage point"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock status"
Enter
Sleep 4s

Type "# Use the new mesh-status CLI against the local control plane"
Enter
Type "./target/release/octravpn-node mesh status --remote http://127.0.0.1:51821 --admin-token mesh-demo-token --json"
Enter
# Note: this hits /api/v1/machines on the admin surface; with the
# current Hub-free mesh serve the admin router isn't mounted, so the
# CLI surfaces a clear HTTP error. The flag exists for the post-Hub
# wire-up — recording the failure here documents the gap.
Sleep 5s

Type "# Teardown"
Enter
Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 10s
