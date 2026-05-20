# 22-headscale-cli-tour.tape
#
# Quick tour of the embedded `headscale` admin CLI surface — the
# single-binary win from simplify-5+ (one `octravpn-node`, no
# separate `headscale` install). Same flags, same exit codes, same
# stdout as the standalone binary in headscale-rs; the only
# difference is the `octravpn-node` prefix in the usage block.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - A reachable headscale control plane. `HEADSCALE_URL` /
#     `HEADSCALE_ADMIN_TOKEN` should be set, or `--server` /
#     `--token` passed explicitly. The 3-node mesh from tape 08
#     boots a control plane on http://127.0.0.1:51820 that works.
#
# Re-run with: vhs demo/tapes/22-headscale-cli-tour.tape

Output demo/recordings/22-headscale-cli-tour.gif
Output demo/recordings/22-headscale-cli-tour.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "export HEADSCALE_URL=http://127.0.0.1:51820"
Enter
Type "export HEADSCALE_ADMIN_TOKEN=mesh-demo-token"
Enter
Sleep 1s

Type "# 1. create a user (the namespace that owns nodes + keys)"
Enter
Type "octravpn-node headscale users create alice"
Enter
Sleep 3s

Type "octravpn-node headscale users list"
Enter
Sleep 3s

Type "# 2. enumerate joined nodes (machines)"
Enter
Type "octravpn-node headscale nodes list"
Enter
Sleep 3s

Type "# 3. mint a reusable preauth key for fleet rollouts"
Enter
Type "octravpn-node headscale preauthkeys create --user alice --reusable --expiration 24h"
Enter
Sleep 3s

Type "octravpn-node headscale preauthkeys list --user alice"
Enter
Sleep 3s

Type "# 4. inspect the active hujson policy"
Enter
Type "octravpn-node headscale policy get"
Enter
Sleep 3s

Type "# 5. tailnet-wide status — DERP regions, derp latency, peer count"
Enter
Type "octravpn-node headscale tailnet status"
Enter
Sleep 3s

Type "# All of that surface lives behind one binary now."
Enter
Sleep 2s
