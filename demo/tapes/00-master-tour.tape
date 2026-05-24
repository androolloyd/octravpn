# 00-master-tour.tape
#
# Fast-cut concatenation of the canonical segments. Renders the
# operator side (deploy, set policy, rotate) and the user side
# (join, fetch) by driving REAL `docker exec` calls against the same
# harnesses the per-segment tapes use.
#
# Chain currently enforces sealed_read on all circles; the plaintext-
# fetch flow returns when chain enables `resource_mode = public_read`.
# See octra-foundry `cast circle put` (commit ef6d0ed) — the
# wire-compatible client side is already in place.
#
# Harness usage:
#   - devnet stack       — segment 1 (operator), 6 (circle update),
#                          both against the live devnet
#   - 3-node mesh        — segments 2 (policy), 3 (join), 4 (ping)
#   - audit fixture      — segment 5 (verify clean)
#
# Each `bash demo/lib/*-bringup.sh` is idempotent. Teardowns run
# between substrates so the recording's wall-clock budget stays
# under ~5 min.
#
# Re-run with: vhs demo/tapes/00-master-tour.tape

Output demo/recordings/00-master-tour.gif
Output demo/recordings/00-master-tour.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

# ── Segment 1: operator deploys against live devnet (~30s) ───────────
Type "# what's happening: an operator brings their demo-node up against live devnet"
Enter
Type "bash demo/lib/devnet-bringup.sh"
Enter
Sleep 60s
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T -e OCTRAVPN_KEY_PASSPHRASE=demo node1 octravpn-node --config /etc/octravpn/node.toml seal-keys || true"
Enter
Sleep 5s
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml health --remote http://127.0.0.1:51821 || true"
Enter
Sleep 5s
Type "bash demo/lib/devnet-teardown.sh"
Enter
Sleep 5s

# ── Segment 2: tailnet owner pushes policy (~30s) ────────────────────
Type "# what's happening: the tailnet owner pushes an ACL update"
Enter
Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s
Type "docker exec -i mesh-demo-control sh -c 'cat > /tmp/policy.hujson'"
Enter
Sleep 500ms
Type `{ "acls": [ { "action": "accept", "src": ["alice"], "dst": ["bob:*"] } ] }`
Enter
Ctrl+D
Sleep 1s
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51821 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale policy set --file /tmp/policy.hujson || true"
Enter
Sleep 4s

# ── Segment 3: user joins the tailnet — confirm via tailscale status ─
Type "# what's happening: stock-tailscale peer is up on the operator's tailnet"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock status"
Enter
Sleep 4s

# ── Segment 4: peer-to-peer reachability via tailscale ping ──────────
Type "# what's happening: a tailnet member runs a tailscale ping to peer-2"
Enter
Type "PEER2_IP=$(docker exec tsi-peer-2 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 | head -1)"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock ping --c 2 --timeout 8s $PEER2_IP"
Enter
Sleep 10s
Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s

# ── Segment 5: audit verify clean (~15s) ─────────────────────────────
Type "# what's happening: the operator runs the daily audit verify"
Enter
Type "bash demo/lib/audit-fixture-bringup.sh"
Enter
Sleep 15s
Type "docker exec octravpn-audit-fixture sh -c 'octravpn-node audit verify --audit-path /work/node/audit.log --journal-path /work/node/receipts.bin; echo exit=$?'"
Enter
Sleep 5s
Type "bash demo/lib/audit-fixture-teardown.sh"
Enter
Sleep 5s

# ── Segment 6: sealed-by-default circle fetch (~25s) ─────────────────
# All assets on devnet are sealed today; this segment shows the
# canonical "one passphrase unseals the whole asset set" flow.
Type "# what's happening: every chain-hosted asset is sealed by default; unseal with one passphrase"
Enter
Type "bash demo/lib/portal-container-bringup.sh"
Enter
Sleep 60s
Type `CIRCLE=$(docker exec octravpn-portal-demo printenv OCTRAVPN_DEMO_CIRCLE_ID) && echo $CIRCLE`
Enter
Sleep 2s
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch oct://$CIRCLE/policy.json || true"
Enter
Sleep 4s
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch oct://$CIRCLE/sealed.json || true"
Enter
Sleep 4s
Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s

Type "# end of tour — see demo/tapes/{01..22} for the full per-segment recordings"
Enter
Sleep 3s
