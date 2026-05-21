# 22-headscale-cli-tour.tape
#
# Quick tour of the embedded `headscale` admin CLI surface as exposed
# by `octravpn-node headscale` — the single-binary win from
# simplify-5+ (one `octravpn-node`, no separate `headscale` install).
# Same flags, same exit codes, same stdout as the standalone binary
# in headscale-rs.
#
# Harness: demo/lib/3node-mesh-bringup.sh — mesh-demo-control hosts
# the headscale admin surface on 127.0.0.1:51820. Bearer token
# `mesh-demo-token` is baked into the compose env.
#
# Re-run with: vhs demo/tapes/22-headscale-cli-tour.tape

Output demo/recordings/22-headscale-cli-tour.gif
Output demo/recordings/22-headscale-cli-tour.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s
Type "# 1. create a user (the namespace that owns nodes + keys)"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale users create alice || true"
Enter
Sleep 3s
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale users list || true"
Enter
Sleep 3s

Type "# 2. enumerate joined nodes (machines) — peer-1/2/3 from the bringup"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale nodes list || true"
Enter
Sleep 4s

Type "# 3. mint a reusable preauth key for fleet rollouts"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale preauthkeys create --user alice --reusable --expiration 24h || true"
Enter
Sleep 4s
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale preauthkeys list --user alice || true"
Enter
Sleep 4s

Type "# 4. inspect the active hujson policy"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale policy get || true"
Enter
Sleep 4s

Type "# 5. tailnet-wide status — DERP regions, latency, peer count"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51820 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale tailnet status || true"
Enter
Sleep 4s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s