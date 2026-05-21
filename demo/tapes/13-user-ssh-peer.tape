# 13-user-ssh-peer.tape
#
# Captures the tailnet user-to-user SSH path: MagicDNS resolves a peer
# hostname inside the tailnet, then `ssh peer-2` opens a session over
# the WireGuard data plane. The point is no port-forwards, no
# bastion, no public-IP exchange — the operator's control plane gives
# every peer a stable MagicDNS name + a routable tailnet IP, and
# OpenSSH does the rest.
#
# Harness: demo/lib/3node-mesh-bringup.sh — 3-peer tailscale mesh.
# Tape installs dropbear into tsi-peer-2 on the fly so peer-1's
# `ssh` invocation has something to connect to (the stock tailscale
# alpine image ships no SSH daemon).
#
# Re-run with: vhs demo/tapes/13-user-ssh-peer.tape

Output demo/recordings/13-user-ssh-peer.gif
Output demo/recordings/13-user-ssh-peer.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 120s
Type "# Confirm the peer roster from peer-1's view"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock status"
Enter
Sleep 4s

Type "# Resolve peer-2's tailnet IP — pure tailscale DNS, no public DNS hop"
Enter
Type "docker exec tsi-peer-1 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 tsi-peer-2"
Enter
Sleep 3s

Type "# Install dropbear + an authorized_keys pair so the SSH dial actually lands"
Enter
Type "docker exec tsi-peer-2 sh -c 'apk add --no-cache dropbear openssh-keygen >/dev/null && mkdir -p /etc/dropbear /root/.ssh && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1'"
Enter
Sleep 6s
Type `docker exec tsi-peer-1 sh -c 'apk add --no-cache openssh-client >/dev/null && ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -q'`
Enter
Sleep 6s
Type "docker exec tsi-peer-1 cat /root/.ssh/id_ed25519.pub | docker exec -i tsi-peer-2 sh -c 'cat > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys'"
Enter
Sleep 3s
Type "docker exec -d tsi-peer-2 dropbear -E -F -p 22 -r /etc/dropbear/dropbear_ed25519_host_key"
Enter
Sleep 2s

Type "# Resolve peer-2's tailnet IP into an env var, then SSH against it"
Enter
Type "PEER2_IP=$(docker exec tsi-peer-2 tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 | head -1)"
Enter
Type "echo peer-2 tailnet ip = $PEER2_IP"
Enter
Sleep 2s
Type `docker exec tsi-peer-1 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$PEER2_IP "uname -a; echo session_ok"`
Enter
Sleep 8s

Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 5s