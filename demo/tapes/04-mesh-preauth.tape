# 04-mesh-preauth.tape
#
# Captures the mesh preauth-key minting surface: both the CLI (one-shot,
# emits key to stdout for shell capture) and the equivalent HTTP path
# that a running daemon's coordination plane exposes.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - For the HTTP probe the node must be running with `mesh serve`
#     bound to 127.0.0.1:51821. The tape demonstrates the CLI flow
#     unconditionally; the HTTP probe is left as a `curl` that the
#     viewer can read even when the daemon is not running.
#
# Re-run with: vhs demo/tapes/04-mesh-preauth.tape

Output demo/recordings/04-mesh-preauth.gif
Output demo/recordings/04-mesh-preauth.mp4

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# single-use key for alice (default ttl)"
Enter
Type "octravpn-node mesh mint-preauth --user alice"
Enter
Sleep 3s

Type "# reusable key for a fleet rollout"
Enter
Type "octravpn-node mesh mint-preauth --user fleet-ops --reusable --ttl-secs 86400"
Enter
Sleep 3s

Type "# same surface, over HTTP (Bearer-gated; daemon must be running):"
Enter
Type "#   POST /admin/preauth"
Enter
Type "#   Authorization: Bearer <token>"
Enter
Type "#   Content-Type: application/json"
Enter
Type "#   body: an admin-preauth-mint JSON document"
Enter
Type "# (curl example omitted; vhs cannot type literal JSON braces cleanly)"
Enter
Sleep 3s
