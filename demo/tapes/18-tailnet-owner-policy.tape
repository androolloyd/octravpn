# 18-tailnet-owner-policy.tape
#
# Captures the tailnet-owner day-2 policy surface end-to-end:
# write a hujson policy to a tempfile inside mesh-demo-control via
# `docker exec -i sh -c 'cat > ...'`, then `octravpn-node headscale
# policy set` it, then read it back.
#
# Harness: demo/lib/3node-mesh-bringup.sh — same mesh + control
# plane every other "8/9/10" tape uses. The HEADSCALE_URL +
# HEADSCALE_ADMIN_TOKEN flow into the control container's admin
# surface at 127.0.0.1:51820.
#
# Re-run with: vhs demo/tapes/18-tailnet-owner-policy.tape

Output demo/recordings/18-tailnet-owner-policy.gif
Output demo/recordings/18-tailnet-owner-policy.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s

Type "# Step 1: write a minimal hujson policy (alice <-> bob accept-all)"
Enter
Type "docker exec -i mesh-demo-control sh -c 'cat > /tmp/policy.hujson'"
Enter
Sleep 500ms
Type `{ "acls": [ { "action": "accept", "src": ["alice"], "dst": ["bob:*"] } ] }`
Enter
Ctrl+D
Sleep 1s
Type "docker exec mesh-demo-control cat /tmp/policy.hujson"
Enter
Sleep 2s

Type "# Step 2: lint + push the policy via the embedded headscale CLI"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51821 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale policy check /tmp/policy.hujson || true"
Enter
Sleep 4s
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51821 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale policy set /tmp/policy.hujson || true"
Enter
Sleep 5s

Type "# Step 3: read the active policy back from the control plane"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51821 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale policy get || true"
Enter
Sleep 5s

Type "# Step 4: nodes list — parked /map pollers see the new packetfilter on next request"
Enter
Type "docker exec -e HEADSCALE_URL=http://127.0.0.1:51821 -e HEADSCALE_ADMIN_TOKEN=mesh-demo-token mesh-demo-control octravpn-node headscale nodes list || true"
Enter
Sleep 5s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s
