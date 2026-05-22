# 15-user-oct-url-public.tape
#
# Originally titled "public fetch flow". Re-authored for the
# sealed-only reality on Octra devnet today: the chain enforces
# `resource_mode = sealed_read` on every circle, so every chain-hosted
# asset is fetched through the sealed-decrypt path. This tape walks
# the interactive `octravpn open-url` flow that prompts for the
# passphrase before rendering, across the same MIME shapes a public
# tape would have shown (HTML, CSS, JSON, octet-stream).
#
# Forward-compat note: a true public (CONFIRM-page-bypassing) flow
# returns the day the chain enables `resource_mode = public_read`. See
# octra-foundry `cast circle put` (commit ef6d0ed) for the
# wire-compatible client side.
#
# Harness: demo/lib/portal-container-bringup.sh — devnet-backed portal
# + demo circle.
#
# Re-run with: vhs demo/tapes/15-user-oct-url-public.tape

Output demo/recordings/15-user-oct-url-public.gif
Output demo/recordings/15-user-oct-url-public.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/portal-container-bringup.sh"
Enter
Sleep 60s

Type "# 1. Health probe — portal pinned to the live devnet"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# resolve the demo circle id (one passphrase unseals the whole set)"
Enter
Type `CIRCLE=$(docker exec octravpn-portal-demo printenv OCTRAVPN_DEMO_CIRCLE_ID) && echo $CIRCLE`
Enter
Sleep 2s

Type "# 2. open-url on an HTML asset — portal renders CONFIRM, decrypts, then HTML inline"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml open-url oct://$CIRCLE/index.html || true"
Enter
Sleep 5s

Type "# 3. CSS sibling — sniffed as text/css after sealed-decrypt"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers oct://$CIRCLE/style.css || true"
Enter
Sleep 4s

Type "# 4. JSON metadata — application/json"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers oct://$CIRCLE/policy.json || true"
Enter
Sleep 4s

Type "# 5. Binary fallback — application/octet-stream after decrypt"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers -o /tmp/blob.bin oct://$CIRCLE/raw.bin || true"
Enter
Sleep 3s
Type "docker exec octravpn-portal-demo sh -c 'test -f /tmp/blob.bin && wc -c /tmp/blob.bin || echo no-blob'"
Enter
Sleep 2s

Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s
