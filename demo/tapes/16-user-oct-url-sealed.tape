# 16-user-oct-url-sealed.tape
#
# Captures the sealed-asset oct:// flow against the same containerized
# portal as tape 15. The portal shows the CONFIRM card, prompts for
# the passphrase, decrypts in-process, then renders the plaintext.
# CLI surface only; the visual CONFIRM page is exercised in the
# OBS-captured browser half (see docs/demo.md §Segment 2).
#
# Harness: demo/lib/portal-container-bringup.sh.
#
# Re-run with: vhs demo/tapes/16-user-oct-url-sealed.tape

Output demo/recordings/16-user-oct-url-sealed.gif
Output demo/recordings/16-user-oct-url-sealed.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/portal-container-bringup.sh"
Enter
Sleep 60s
Type "# 1. portal is up; CONFIRM gate kicks in on first-touch sealed assets"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# 2. fetch a sealed JSON asset, passphrase via env (matches CI)"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase-correct-horse octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch -i oct://octCircleDemo/sealed.json || true"
Enter
Sleep 5s

Type "# 3. same asset via open-url — portal shows CONFIRM, prompts on TTY"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase-correct-horse octravpn-portal-demo octravpn --config /etc/octravpn/config.toml open-url oct://octCircleDemo/sealed.json || true"
Enter
Sleep 5s

Type "# 4. wrong passphrase — sealed envelope detects + refuses to render"
Enter
Type "docker exec -e OCTRAVPN_SEALED_PASSPHRASE=wrong octravpn-portal-demo sh -c 'octravpn --config /etc/octravpn/config.toml fetch oct://octCircleDemo/sealed.json || echo sealed: decrypt failed (expected)'"
Enter
Sleep 5s

Type "# 5. plaintext sibling unaffected — no CONFIRM, no passphrase needed"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch oct://octCircleDemo/policy.json || true"
Enter
Sleep 4s

Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s