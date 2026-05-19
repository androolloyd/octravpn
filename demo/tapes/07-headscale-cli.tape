# 07-headscale-cli.tape
#
# Captures the headscale-rs control-plane day-2 surface: create a user,
# list nodes, and mint a preauth key. The output mirrors the upstream
# headscale CLI (#216 brought the surface parity) so existing
# tailscale-ops runbooks transfer 1:1.
#
# REQUIRES:
#   - `headscale` on PATH from the headscale-rs sibling repo
#     (`cargo install --path . --bin headscale` from
#     ../headscale-rs/headscale-cli) OR a docker exec into the
#     `tsi-mesh-control` container after the interop stack is up.
#   - A headscale config file. If $HEADSCALE_CONFIG is unset we point
#     at the in-repo default at docker/devnet/tailscale-interop/
#     mesh-config/headscale.yaml (read-only for the recording).
#
# Re-run with: vhs demo/tapes/07-headscale-cli.tape

Output demo/recordings/07-headscale-cli.gif
Output demo/recordings/07-headscale-cli.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "export HEADSCALE_CONFIG=docker/devnet/tailscale-interop/mesh-config/headscale.yaml"
Enter
Sleep 500ms

Type "# create a user (the namespace that owns nodes + keys)"
Enter
Type "headscale users create alice"
Enter
Sleep 3s

Type "headscale users list"
Enter
Sleep 2s

Type "# mint a preauth key alice can paste into tailscale up"
Enter
Type "headscale preauthkeys create --user alice --reusable --expiration 24h"
Enter
Sleep 3s

Type "# enumerate joined nodes (machines)"
Enter
Type "headscale nodes list"
Enter
Sleep 3s
