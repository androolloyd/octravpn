# 16-user-oct-url-sealed.tape
#
# Captures the sealed-asset oct:// flow: the same portal as tape 15,
# but the asset path resolves to a circle entry that is encrypted
# under a per-circle passphrase. The portal shows the CONFIRM card,
# prompts for the passphrase, decrypts in-process, then renders the
# plaintext. CLI surface only; the visual CONFIRM page is exercised
# in the OBS-captured browser half (see docs/demo.md §Segment 2).
#
# The companion test that pins this flow end-to-end is
# `crates/octravpn-client/tests/portal_integration.rs::sealed_*`.
#
# REQUIRES:
#   - Same as tape 15: `octravpn` client on PATH; portal at
#     127.0.0.1:51823 (auto-spawned by the Source line below).
#   - A sealed asset at `oct://octCircleDemo/sealed.json` whose
#     plaintext is decryptable with `OCTRAVPN_SEALED_PASSPHRASE`.
#     The demo state directory must carry the matching keyset.
#
# Re-run with: vhs demo/tapes/16-user-oct-url-sealed.tape

Output demo/recordings/16-user-oct-url-sealed.gif
Output demo/recordings/16-user-oct-url-sealed.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

Source demo/lib/start-portal.sh

Type "# 1. portal is up; CONFIRM gate kicks in on first-touch sealed assets"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# 2. fetch a sealed JSON asset, passphrase via env (matches CI)"
Enter
Type "export OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase-correct-horse"
Enter
Sleep 1s
Type "octravpn --config demo/state/portal/config.toml fetch -i oct://octCircleDemo/sealed.json"
Enter
Sleep 4s

Type "# 3. same asset via open-url — portal shows CONFIRM, prompts on TTY"
Enter
Type "octravpn --config demo/state/portal/config.toml open-url oct://octCircleDemo/sealed.json"
Enter
Sleep 4s

Type "# 4. wrong passphrase — sealed envelope detects + refuses to render"
Enter
Type "OCTRAVPN_SEALED_PASSPHRASE=wrong octravpn --config demo/state/portal/config.toml fetch oct://octCircleDemo/sealed.json || echo 'sealed: decrypt failed (expected)'"
Enter
Sleep 4s

Type "# 5. plaintext sibling unaffected — no CONFIRM, no passphrase needed"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch oct://octCircleDemo/policy.json"
Enter
Sleep 3s
