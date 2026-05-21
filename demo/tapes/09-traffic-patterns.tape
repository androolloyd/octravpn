# 09-traffic-patterns.tape
#
# Drive peer-to-peer traffic across the 3-node mesh. Demonstrates
# `tailscale ping` for control-plane reachability + an HTTP burst
# from peer-1 → peer-2 to exercise the WireGuard data plane.
#
# Standalone — calls `3node-mesh-bringup.sh` directly so it can be
# rendered on a fresh machine. Calls `3node-mesh-teardown.sh` on the
# way out for a clean handoff to tape 10.
#
# Note (analytics counters): in the current Hub-free `mesh serve`
# shape the daemon does not write an audit log; the analytics
# indexer in tape 10 will therefore report zero session_open /
# receipt_signed events even after this tape's traffic burst. The
# data plane itself flows fine (the burst is end-to-end real
# WireGuard) — only the accounting layer is stubbed out. Wiring an
# audit-log writer into `mesh serve` is tracked in the demo backlog;
# the endpoints in tape 10 still respond so the operator can validate
# the surface shape today.
#
# REQUIRES:
#   - Same as tape 08: Docker, sibling repos, openssl, ~6 min cold cache.
#
# Re-run with: vhs demo/tapes/09-traffic-patterns.tape

Output demo/recordings/09-traffic-patterns.gif
Output demo/recordings/09-traffic-patterns.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Bring the 3-peer mesh up (idempotent if already running)"
Enter
Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s

Type "# Discover peer-2's tailscale IP from peer-1's status table"
Enter
Type "PEER2_IP=$(docker exec tsi-peer-2 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 | head -1)"
Enter
Type "PEER3_IP=$(docker exec tsi-peer-3 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 | head -1)"
Enter
Type "echo peer-2=$PEER2_IP peer-3=$PEER3_IP"
Enter
Sleep 3s

Type "# Control-plane reach: peer-1 → peer-2, peer-1 → peer-3"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock ping --c 3 --timeout 10s $PEER2_IP"
Enter
Sleep 10s
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock ping --c 3 --timeout 10s $PEER3_IP"
Enter
Sleep 10s

Type "# Spin up a tiny HTTP target on peer-2 and pull bytes from peer-1"
Enter
# `tailscale/tailscale:latest` is alpine-based; busybox httpd is
# already present and serves the working dir over HTTP without a
# python dependency.
Type "docker exec -d tsi-peer-2 sh -c 'echo hello-from-peer-2 > /tmp/payload && busybox httpd -f -p 0.0.0.0:8080 -h /tmp &'"
Enter
Sleep 3s
Type `docker exec tsi-peer-1 sh -c "wget -q -O- http://$PEER2_IP:8080/payload"`
Enter
Sleep 4s

Type "# Policy CRUD against the admin surface. mesh serve now mounts"
Enter
Type "# /api/v1/policy via build_admin_router (see docs/operators/mesh-admin.md)."
Enter
Type "./target/release/octravpn-node mesh policy get --remote http://127.0.0.1:51821 --admin-token mesh-demo-token || true"
Enter
Sleep 5s

Type "# Teardown for tape 10"
Enter
Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 10s
