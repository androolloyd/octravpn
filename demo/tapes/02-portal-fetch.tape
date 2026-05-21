# 02-portal-fetch.tape
#
# Captures the `oct://` URL-handler flows: the portal HTTP server
# (containerized) and the CLI `fetch` (raw bytes + `--save` + `-i`
# interactive) all driven via `docker exec` against the same
# chain-backed asset resolver.
#
# Harness: demo/lib/portal-container-bringup.sh — boots mock-rpc +
# node1 (chain substrate) via docker-compose.yml, plus an
# `octravpn portal` container bound to 127.0.0.1:51823. /healthz is
# polled until 200 before the script returns.
#
# Re-run with: vhs demo/tapes/02-portal-fetch.tape

Output demo/recordings/02-portal-fetch.gif
Output demo/recordings/02-portal-fetch.mp4

Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/portal-container-bringup.sh"
Enter
Sleep 60s
Type "# /healthz is up — confirm before we drive the CLI"
Enter
Type "curl -s http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# raw bytes to stdout (against the mock chain via the portal container)"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch oct://octCircleDemo/policy.json"
Enter
Sleep 4s

Type "# same asset, save to disk + show Content-Type"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers -o /tmp/policy.json oct://octCircleDemo/policy.json"
Enter
Sleep 4s
Type "docker exec octravpn-portal-demo cat /tmp/policy.json"
Enter
Sleep 3s

Type "# interactive prompt path (sealed asset; surfaces 'sealed' error without TTY)"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch -i oct://octCircleDemo/sealed.json || true"
Enter
Sleep 5s

Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s