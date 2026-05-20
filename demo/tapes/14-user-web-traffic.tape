# 14-user-web-traffic.tape
#
# Captures two web-traffic shapes a tailnet user exercises:
#   1. Direct peer-to-peer HTTP: `curl peer-2:8080` over the WG mesh.
#   2. Internet egress via a paid exit node: `tailscale up
#      --exit-node peer-3` then `curl https://example.com`.
#
# Both shapes are narrated (CLI shape only) so the tape renders on a
# host without an actual tailnet handy. Tape 09 covers the live-
# traffic counterpart against the docker-compose 3-node mesh.
#
# REQUIRES:
#   - `tailscale` + `curl` on PATH.
#
# Re-run with: vhs demo/tapes/14-user-web-traffic.tape

Output demo/recordings/14-user-web-traffic.gif
Output demo/recordings/14-user-web-traffic.mp4

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# Shape A — peer-to-peer HTTP across the tailnet"
Enter
Type "# peer-2 is serving a small payload on :8080 (busybox httpd / nginx / etc)"
Enter
Sleep 1500ms
Type "# $ curl -sS http://peer-2:8080/payload"
Enter
Type "# hello-from-peer-2"
Enter
Sleep 2s
Type "# $ curl -sS -o /dev/null -w 'rtt=%{time_total}s code=%{http_code}\\n' http://peer-2:8080/payload"
Enter
Type "# rtt=0.012s code=200"
Enter
Sleep 2s

Type "# Shape B — exit-node routing through a paid validator (peer-3)"
Enter
Type "# peer-3 advertised an exit node via 'tailscale up --advertise-exit-node'"
Enter
Type "# the operator approved + priced it on chain; clients select it per-flow"
Enter
Sleep 2s
Type "# $ sudo tailscale up --exit-node peer-3"
Enter
Sleep 2s
Type "# $ curl -sS https://example.com | head -1"
Enter
Sleep 1s
Type "# <!doctype html>"
Enter
Sleep 2s
Type "# the request rode WG to peer-3, then NATted to the public internet"
Enter
Sleep 2s

Type "# Disable the exit node when you're done — traffic returns to direct paths"
Enter
Type "# $ sudo tailscale up --exit-node="
Enter
Sleep 2s
