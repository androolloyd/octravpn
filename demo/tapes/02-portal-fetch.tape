# 02-portal-fetch.tape
#
# Captures the `oct://` URL-handler flows: the portal HTTP server, the
# CLI `fetch` (raw bytes + `--save` + `-i` interactive) all hitting the
# same chain-backed asset resolver.
#
# REQUIRES:
#   - A running `octravpn portal` on 127.0.0.1:51823. The `Source`
#     directive below boots it via demo/lib/start-portal.sh; that
#     helper is idempotent.
#   - A demo circle on the configured chain (devnet or mock-rpc) that
#     hosts `policy.json` as a plaintext asset. The demo state dir
#     (`demo/state/portal/config.toml`) should be pointed at a circle
#     with a known `oct://octCircleDemo/policy.json`.
#
# Re-run with: vhs demo/tapes/02-portal-fetch.tape

Output demo/recordings/02-portal-fetch.gif
Output demo/recordings/02-portal-fetch.mp4

Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set TypingSpeed 40ms

# Boot a portal in the background if one is not already up. The
# helper polls /healthz and only returns once the surface is ready.
Source demo/lib/start-portal.sh

Type "# /healthz is up — confirm before we drive the CLI"
Enter
Type "curl -s http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# raw bytes to stdout"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch oct://octCircleDemo/policy.json"
Enter
Sleep 3s

Type "# same asset, save to disk + show Content-Type"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch --headers -o /tmp/policy.json oct://octCircleDemo/policy.json"
Enter
Sleep 3s
Type "cat /tmp/policy.json"
Enter
Sleep 2s

Type "# interactive prompt path (sealed asset; will prompt on TTY)"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch -i oct://octCircleDemo/sealed.json"
Enter
Sleep 4s
