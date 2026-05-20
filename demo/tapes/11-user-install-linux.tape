# 11-user-install-linux.tape
#
# Captures the Linux end-user's join flow: install the stock
# `tailscale` package, `tailscale up --login-server` against the
# operator's `octravpn-node`-hosted control plane, then a peer
# reachability probe. Demonstrates the CLI surface only — the apt /
# tailscale invocations are narrated rather than executed so the tape
# renders on any host without root or a real tailnet handy.
#
# REQUIRES:
#   - `tailscale` on PATH (stock client, any 1.x).
#   - Nothing else: this is a narration of the steps an end user takes
#     against an already-running operator. The tape does not start a
#     daemon and does not require Docker.
#
# Re-run with: vhs demo/tapes/11-user-install-linux.tape

Output demo/recordings/11-user-install-linux.gif
Output demo/recordings/11-user-install-linux.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# Step 1: install the stock tailscale client (Debian/Ubuntu)"
Enter
Sleep 1s
Type "# $ curl -fsSL https://tailscale.com/install.sh | sh"
Enter
Type "# $ sudo apt-get install -y tailscale"
Enter
Sleep 2s

Type "tailscale version"
Enter
Sleep 2s

Type "# Step 2: join the operator's tailnet (login-server + preauth key)"
Enter
Type "# the operator gave you these out-of-band, or via 'octravpn-node headscale preauthkeys create'"
Enter
Type "# $ sudo tailscale up --login-server https://mesh.example.octra --authkey tskey-..."
Enter
Sleep 3s

Type "# Step 3: confirm the assigned IP + visible peers"
Enter
Type "tailscale status"
Enter
Sleep 3s

Type "# Step 4: control-plane reachability — ping a peer over the tailnet"
Enter
Type "# $ tailscale ping peer-2"
Enter
Sleep 2s
Type "# pong from peer-2 (100.64.0.2) via DERP region 1 in 14ms"
Enter
Sleep 2s
