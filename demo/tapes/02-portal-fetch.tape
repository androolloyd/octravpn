# 02-portal-fetch.tape
#
# Captures the `oct://` URL-handler flow against the **live Octra
# devnet**. Every chain-hosted asset is sealed by default
# (`resource_mode = sealed_read`) — there is no plaintext-fetch path on
# devnet today. This tape walks one passphrase unsealing the whole
# demo asset set:
#
#   /policy.json — sealed JSON (v3 ACL policy shape)
#   /index.html  — sealed HTML landing page
#   /style.css   — sealed CSS
#   /raw.bin     — sealed 256B blob
#   /sealed.json — sealed JSON (sensitive-looking)
#
# Forward-compat note: a plaintext-fetch flow returns the day chain
# enables `resource_mode = public_read`. See
# octra-foundry `cast circle put` (commit ef6d0ed) — the client-side
# wire format is already in place; only the chain policy needs to flip.
#
# Harness: demo/lib/portal-container-bringup.sh — ensures the demo
# circle (5 sealed assets, passphrase `demo`) exists on devnet, then
# spins up an `octravpn portal` container at 127.0.0.1:51823. The
# resolved circle id is exported as ${OCTRAVPN_DEMO_CIRCLE_ID} into
# the container env so the body of this tape doesn't hardcode an id.
#
# Re-run with: vhs demo/tapes/02-portal-fetch.tape

Output demo/recordings/02-portal-fetch.gif
Output demo/recordings/02-portal-fetch.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/portal-container-bringup.sh"
Enter
Sleep 60s

Type "# portal is up and pinned to the LIVE devnet — confirm health"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# resolve the demo circle id (sealed-by-default on devnet)"
Enter
Type `CIRCLE=$(docker exec octravpn-portal-demo printenv OCTRAVPN_DEMO_CIRCLE_ID) && echo $CIRCLE`
Enter
Sleep 2s

Type "# sealed fetch — passphrase via OCTRAVPN_SEALED_PASSPHRASE env"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch oct://$CIRCLE/policy.json"
Enter
Sleep 5s

Type "# same asset via headers + save-to-file (Content-Type comes through)"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers -o /tmp/policy.json oct://$CIRCLE/policy.json"
Enter
Sleep 4s
Type "docker exec octravpn-portal-demo cat /tmp/policy.json"
Enter
Sleep 3s

Type "# wrong passphrase => sealed envelope detects + refuses to render"
Enter
Type `docker exec -e OCTRAVPN_SEALED_PASSPHRASE=wrong octravpn-portal-demo sh -c 'octravpn --config /etc/octravpn/config.toml fetch oct://$CIRCLE/sealed.json || echo sealed-decrypt-failed-expected'`
Enter
Sleep 5s

Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s
