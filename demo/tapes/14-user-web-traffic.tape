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

Type "# Stand up a tiny HTTP responder on peer-2 (nc-based; the"
Enter
Type "# tailscale image's busybox lacks the httpd applet)."
Enter
Type "docker exec -d tsi-peer-2 sh -c 'while true; do printf \"HTTP/1.0 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nhello-from-peer-2\\n\" | nc -l -p 8080; done'"
Enter
Sleep 3s

Type "# Real GET from peer-1 → peer-2:8080 via tailscale nc"
Enter
Type "# (userspace-networking mode — wget can't see tailnet IPs directly)."
Enter
Type `docker exec tsi-peer-1 sh -c "(printf 'GET / HTTP/1.0\r\nHost: x\r\n\r\n'; sleep 1) | tailscale --socket=/var/run/tailscale/tailscaled.sock nc ${PEER2_IP} 8080 | tail -1"`
Enter
Sleep 4s

Type "# Status code via the same path"
Enter
Type `docker exec tsi-peer-1 sh -c "(printf 'HEAD / HTTP/1.0\r\nHost: x\r\n\r\n'; sleep 1) | tailscale --socket=/var/run/tailscale/tailscaled.sock nc ${PEER2_IP} 8080 | head -1"`
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