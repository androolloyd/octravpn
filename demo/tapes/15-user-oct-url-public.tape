# 15-user-oct-url-public.tape
#
# Captures the oct:// public-asset flow against a containerized
# portal: a few representative MIME shapes for plaintext (un-sealed)
# assets. Plain envelopes bypass the CONFIRM page; sealed siblings
# are covered in tape 16.
#
# Harness: demo/lib/portal-container-bringup.sh — boots mock-rpc +
# node1 + a containerized `octravpn portal` listener at
# 127.0.0.1:51823. Every CLI call goes through `docker exec`.
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
Type "# 1. Health probe — portal is on 127.0.0.1:51823"
Enter
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s

Type "# 2. open-url on an HTML asset — text/html is rendered inline"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml open-url oct://octCircleDemo/index.html || true"
Enter
Sleep 4s

Type "# 3. CSS sibling — sniffed as text/css, returned with content-type set"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers oct://octCircleDemo/style.css || true"
Enter
Sleep 4s

Type "# 4. JSON metadata — application/json"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers oct://octCircleDemo/policy.json || true"
Enter
Sleep 4s

Type "# 5. Binary fallback — application/octet-stream when MIME sniff fails"
Enter
Type "docker exec octravpn-portal-demo octravpn --config /etc/octravpn/config.toml fetch --headers -o /tmp/blob.bin oct://octCircleDemo/raw.bin || true"
Enter
Sleep 3s
Type "docker exec octravpn-portal-demo sh -c 'test -f /tmp/blob.bin && wc -c /tmp/blob.bin || echo no-blob'"
Enter
Sleep 2s

Type "bash demo/lib/portal-container-teardown.sh"
Enter
Sleep 5s