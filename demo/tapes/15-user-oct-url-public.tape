# 15-user-oct-url-public.tape
#
# Captures the oct:// public-asset flow: `octravpn portal serve` on a
# loopback bind, then `octravpn open-url oct://<circle>/<path>` for a
# few representative MIME shapes. The portal is the in-process HTTP
# surface that a desktop browser renders (the `dist/` shim hands off
# to it). Public assets (no sealed envelope) bypass the CONFIRM page;
# tape 16 covers the sealed-asset companion.
#
# REQUIRES:
#   - `octravpn` (the client binary) on PATH or under
#     target/{release,debug}/. The `Source` directive boots a portal
#     in the background via the shared helper; it is idempotent and a
#     no-op when one is already up.
#   - A demo client config at demo/state/portal/config.toml pointed at
#     a circle that hosts `index.html`, `style.css`, `policy.json`
#     (or any analogous plaintext-asset triple).
#
# Re-run with: vhs demo/tapes/15-user-oct-url-public.tape

Output demo/recordings/15-user-oct-url-public.gif
Output demo/recordings/15-user-oct-url-public.mp4

Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set TypingSpeed 40ms

# Boot the in-process oct:// portal in the background (same helper
# tape 02 uses). Idempotent.
Source demo/lib/start-portal.sh

Type "# 1. Health probe — portal is on 127.0.0.1:51823"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# 2. open-url on an HTML asset — text/html is rendered inline"
Enter
Type "octravpn --config demo/state/portal/config.toml open-url oct://octCircleDemo/index.html"
Enter
Sleep 4s

Type "# 3. CSS sibling — sniffed as text/css, returned with content-type set"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch --headers oct://octCircleDemo/style.css"
Enter
Sleep 3s

Type "# 4. JSON metadata — application/json"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch --headers oct://octCircleDemo/policy.json"
Enter
Sleep 3s

Type "# 5. Binary fallback — application/octet-stream when the MIME sniff fails"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch --headers -o /tmp/blob.bin oct://octCircleDemo/raw.bin"
Enter
Sleep 3s
Type "file /tmp/blob.bin"
Enter
Sleep 2s
