# 13-user-ssh-peer.tape
#
# Captures the tailnet user-to-user SSH path: MagicDNS resolves a peer
# hostname inside the tailnet, then `ssh peer-2` opens a session over
# the WireGuard data plane. The point is that no port-forwards, no
# bastion, no public-IP exchange — the operator's control plane gives
# every peer a stable MagicDNS name + a routable tailnet IP, and
# OpenSSH does the rest.
#
# REQUIRES:
#   - `tailscale` + `ssh` on PATH.
#   - Nothing else: this is a CLI-shape demo, not a live tailnet.
#
# Re-run with: vhs demo/tapes/13-user-ssh-peer.tape

Output demo/recordings/13-user-ssh-peer.gif
Output demo/recordings/13-user-ssh-peer.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

Type "# Already up on the tailnet from tape 11 — confirm peer roster:"
Enter
Type "tailscale status"
Enter
Sleep 3s

Type "# MagicDNS resolution — peer-2 is a tailnet hostname, not a public DNS name"
Enter
Type "# $ tailscale ip -4 peer-2"
Enter
Sleep 1s
Type "# 100.64.0.2"
Enter
Sleep 1500ms
Type "# $ getent hosts peer-2"
Enter
Sleep 1s
Type "# 100.64.0.2  peer-2.demo-tailnet.ts.net  peer-2"
Enter
Sleep 2s

Type "# SSH straight through — OpenSSH sees a normal hostname"
Enter
Type "# $ ssh user@peer-2"
Enter
Sleep 1s
Type "# Welcome to peer-2 (Linux 6.5.0, octravpn tailnet member)"
Enter
Type "# Last login: from 100.64.0.1"
Enter
Type "# user@peer-2:~$ uname -a"
Enter
Sleep 1s
Type "# Linux peer-2 6.5.0 #1 SMP x86_64 GNU/Linux"
Enter
Type "# user@peer-2:~$ exit"
Enter
Sleep 2s

Type "# All traffic on this SSH session rode the WireGuard data plane,"
Enter
Type "# end-to-end, with the session billed against the operator's circle."
Enter
Sleep 2s
