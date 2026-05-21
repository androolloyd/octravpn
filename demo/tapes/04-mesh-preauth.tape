# 04-mesh-preauth.tape
#
# Captures the mesh preauth-key minting surface end-to-end:
#   1. CLI shape: `octravpn-node mesh mint-preauth` via `docker exec`
#      against the running mesh-control daemon.
#   2. HTTP shape: a real `curl POST /admin/preauth` with a JSON body
#      written through multiple Type lines (vhs heredoc pattern).
#
# Harness: demo/lib/3node-mesh-bringup.sh — boots mesh-control +
# derp-1 + 3 tailscale peers + analytics. Tape exits via the matching
# teardown so the next tape starts clean.
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

Type "# Shape A — single-use preauth key for alice (default ttl), via the CLI"
Enter
Type "docker exec mesh-demo-control octravpn-node mesh mint-preauth --remote http://127.0.0.1:51821 --admin-token mesh-demo-token --user alice"
Enter
Sleep 4s

Type "# Shape B — reusable key for a fleet rollout, ttl 24h"
Enter
Type "docker exec mesh-demo-control octravpn-node mesh mint-preauth --remote http://127.0.0.1:51821 --admin-token mesh-demo-token --user fleet-ops --reusable --ttl-secs 86400"
Enter
Sleep 4s

Type "# Shape C — same surface over HTTP. Write JSON body to a tempfile via heredoc."
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
