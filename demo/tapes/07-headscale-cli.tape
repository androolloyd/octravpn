# 07-headscale-cli.tape
#
# Captures the headscale-rs control-plane day-2 surface as exposed
# by the `octravpn-node headscale` subcommand. Drives every call via
# `docker exec mesh-demo-control` so the recording is reproducible
# on any host with docker.
#
# Harness: demo/lib/3node-mesh-bringup.sh — boots the same
# mesh-control + 3-peer stack tapes 08/09/10 use. The headscale
# admin surface lives inside the mesh-control container at
# http://127.0.0.1:51820 (Bearer mesh-demo-token).
#
# Re-run with: vhs demo/tapes/07-headscale-cli.tape

Output demo/recordings/07-headscale-cli.gif
Output demo/recordings/07-headscale-cli.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s
Type "# create a user (the namespace that owns nodes + keys)"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale users create alice"
Enter
Sleep 4s

Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale users list"
Enter
Sleep 3s

Type "# mint a preauth key alice can paste into tailscale up"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale preauthkeys create --user alice --reusable --expires-in 24h"
Enter
Sleep 4s

Type "# enumerate joined nodes (machines)"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale nodes list"
Enter
Sleep 4s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s