# 14-user-web-traffic.tape
#
# Captures peer-to-peer HTTP traffic across the tailnet. busybox httpd
# on tsi-peer-2 serves /tmp/payload over :8080; tsi-peer-1 wgets it
# over the WireGuard data plane. Closes with a timing run via
# `wget --output-document=- -S` so the response code + RTT line up
# in the recording.
#
# The exit-node arm (curl to the public internet via peer-3) is
# narrated only — the docker network in compose has no real internet
# egress configured, so a live curl to example.com would either
# hairpin or fail depending on the runner's NAT. The arm is shown
# as a tour comment so the README's "shape" still appears.
#
# Harness: demo/lib/3node-mesh-bringup.sh — same as tapes 09 / 13.
#
# Re-run with: vhs demo/tapes/14-user-web-traffic.tape

Output demo/recordings/14-user-web-traffic.gif
Output demo/recordings/14-user-web-traffic.mp4

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s
Type "# Shape A — peer-to-peer HTTP across the tailnet"
Enter
Type "PEER2_IP=$(docker exec tsi-peer-2 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 | head -1)"
Enter
Type "echo peer-2 tailnet ip = $PEER2_IP"
Enter
Sleep 2s

Type "# Stand up busybox httpd on peer-2 with a known payload"
Enter
Type "docker exec tsi-peer-2 sh -c 'echo hello-from-peer-2 > /tmp/payload'"
Enter
Type "docker exec -d tsi-peer-2 sh -c 'busybox httpd -f -p 0.0.0.0:8080 -h /tmp'"
Enter
Sleep 2s

Type "# Real GET from peer-1 → peer-2:8080 over WireGuard"
Enter
Type `docker exec tsi-peer-1 sh -c "wget -qO- http://${PEER2_IP}:8080/payload"`
Enter
Sleep 4s

Type "# Same path, RTT + HTTP code via wget -S"
Enter
Type `docker exec tsi-peer-1 sh -c "time wget -qO /dev/null -S http://${PEER2_IP}:8080/payload 2>&1 | grep -E 'HTTP/|real'"`
Enter
Sleep 5s

Type "# Shape B (exit-node routing) is exercised in docker/devnet/tailscale-interop"
Enter
Type "# against a runner with real egress; the compose bridge here has none."
Enter
Sleep 3s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s