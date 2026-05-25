# 00-master-tour.tape
#
# Fast-cut tour of OctraVPN end-to-end. Renders in ≤30s by replaying
# pre-recorded segment output via `say` (demo/lib/replay-line.sh) —
# the per-segment tapes (01..22) drive the real harnesses, this one
# is just the trailer.
#
# Captures live under demo/captures/master-tour/.
#
# Re-run with: vhs demo/tapes/00-master-tour.tape

Output demo/recordings/00-master-tour.gif
Output demo/recordings/00-master-tour.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 8ms

Hide
Type 'source demo/lib/replay-line.sh && clear'
Enter
Sleep 200ms
Show

Type '# 1/6 operator deploys against live devnet'
Enter
Type 'say "bringup + seal-keys + health" demo/captures/master-tour/01-devnet-deploy.txt'
Enter
Sleep 1500ms

Type '# 2/6 tailnet owner pushes ACL policy'
Enter
Type 'say "headscale policy set --file policy.hujson" demo/captures/master-tour/02-policy-push.txt'
Enter
Sleep 1500ms

Type '# 3/6 stock-tailscale peer up on the tailnet'
Enter
Type 'say "tailscale status" demo/captures/master-tour/03-tailnet-status.txt'
Enter
Sleep 1500ms

Type '# 4/6 peer ping — direct ipv4 path'
Enter
Type 'say "tailscale ping --c 2 100.64.0.2" demo/captures/master-tour/04-peer-ping.txt'
Enter
Sleep 1500ms

Type '# 5/6 daily audit verify'
Enter
Type 'say "octravpn-node audit verify" demo/captures/master-tour/05-audit-verify.txt'
Enter
Sleep 1500ms

Type '# 6/6 every chain asset is sealed by default'
Enter
Type 'say "octravpn fetch oct://$CIRCLE/{policy,sealed}.json" demo/captures/master-tour/06-sealed-fetch.txt'
Enter
Sleep 1500ms

Type '# end of tour — see demo/tapes/{01..22} for live per-segment recordings'
Enter
Sleep 1500ms
