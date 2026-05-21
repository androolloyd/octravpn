# 04-mesh-preauth.tape
#
# Captures the mesh preauth-key minting surface end-to-end. There are
# three operator-facing shapes, each calling the same daemon-side
# `PreauthMinter`:
#
#   Shape A — `mesh mint-preauth` in **local mode** (default).
#             Generates a key in-process inside the CLI; no daemon
#             contact. Useful for shell scripting + the interop
#             test's "reachable surface" probe, but NOT honoured by
#             a real `tailscale up` join because the running daemon
#             doesn't know about the key.
#
#   Shape B — `mesh mint-preauth` in **daemon-bound mode**, via the
#             new `--remote` + `--admin-token` flags. The CLI POSTs
#             to `<remote>/admin/preauth` with `Authorization:
#             Bearer <token>`; the daemon's persistent `PreauthMinter`
#             materialises the key so it survives across process
#             boundaries and IS honoured by a real `tailscale up
#             --authkey "$KEY"`.
#
#   Shape C — raw `curl POST /admin/preauth`. Equivalent to Shape B
#             at the HTTP layer; useful for ops scripts that already
#             speak HTTP and don't want to bake in `octravpn-node` as
#             a build dep.
#
# Harness: demo/lib/3node-mesh-bringup.sh — boots mesh-control +
# derp-1 + 3 tailscale peers + analytics, with `[control].admin_token`
# set to `mesh-demo-token` so Shapes B and C have a real surface to
# hit. Tape exits via the matching teardown so the next tape starts
# clean.
#
# Re-run with: vhs demo/tapes/04-mesh-preauth.tape

Output demo/recordings/04-mesh-preauth.gif
Output demo/recordings/04-mesh-preauth.mp4

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s

Type "# Shape A — local mint (no daemon contact). Default behaviour."
Enter
Type "docker exec mesh-demo-control octravpn-node mesh mint-preauth --user alice"
Enter
Sleep 4s

Type "# Shape B — daemon-bound mint via the new --remote / --admin-token CLI flags."
Enter
Type "# The key minted here IS honoured by a real tailscale up --authkey join."
Enter
Type "docker exec mesh-demo-control octravpn-node mesh mint-preauth --user alice --remote http://127.0.0.1:51821 --admin-token mesh-demo-token"
Enter
Sleep 4s

Type "# Shape B variant — reusable key for a fleet rollout, 24h ttl."
Enter
Type "docker exec mesh-demo-control octravpn-node mesh mint-preauth --user fleet-ops --reusable --ttl-secs 86400 --remote http://127.0.0.1:51821 --admin-token mesh-demo-token"
Enter
Sleep 4s

Type "# Shape C — same surface over raw HTTP. Equivalent to Shape B at the wire layer."
Enter
Type "docker exec -i mesh-demo-control sh -c 'cat > /tmp/preauth.json'"
Enter
Sleep 500ms
Type `{"user":"bob","reusable":false}`
Enter
Ctrl+D
Sleep 1s
Type "docker exec mesh-demo-control cat /tmp/preauth.json"
Enter
Sleep 2s
Type `docker exec mesh-demo-control sh -c "apt-get update -qq >/dev/null 2>&1; apt-get install -y --no-install-recommends curl >/dev/null 2>&1 || true; curl -fsS -H 'Authorization: Bearer mesh-demo-token' -H 'Content-Type: application/json' --data @/tmp/preauth.json http://127.0.0.1:51821/admin/preauth"`
Enter
Sleep 8s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s
