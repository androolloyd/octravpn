# 06-tailscale-interop.tape
#
# The headline. Drives the docker-compose tailscale-interop harness:
# build octravpn-node for Linux, bring up mesh-control + derp-1 +
# tsi-peer-{a,b}, mint a preauth key (CLI + HTTP), join both peers with
# stock `tailscale up`, wait for IP-plane convergence, and run
# `tailscale ping`. Exit 0 (with the final "OK: tailscale interop
# succeeded" line) is the demo payoff.
#
# REQUIRES:
#   - Docker Desktop (or equivalent) running.
#   - The sibling repos at:
#       ../octra-foundry (for chain-side path deps)
#       ../headscale-rs  (for the tailscale-wire crate)
#   - openssl on the host (used to mint the derp-1 self-signed cert).
#   - Exit code 0 was confirmed in #245 (Wall 6 closed); pre-#245 the
#     script lands at exit 50 (TAILSCALE-PING FAILED) but every step
#     before that still records.
#
# Re-run with: vhs demo/tapes/06-tailscale-interop.tape

Output demo/recordings/06-tailscale-interop.gif
Output demo/recordings/06-tailscale-interop.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# stock-tailscale-against-our-control-plane interop drill"
Enter
Sleep 1s

Type "bash docker/devnet/tailscale-interop/run-interop.sh"
Enter
# Build phase + compose-up + peer-join + ping. First-run cold cache
# can hit 5-10 minutes; warm cache is sub-minute. We give it 6 min,
# vhs will truncate the recording at the script's exit.
Sleep 360s
