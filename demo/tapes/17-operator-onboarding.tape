# 17-operator-onboarding.tape
#
# Captures the operator's 90-second cold-start: seal the on-disk keys
# under the wallet passphrase, bond the minimum stake, register the
# endpoint, boot the daemon, then probe `octravpn-node health` to
# confirm the daemon is up + bonded + reachable from RPC.
#
# This is the headline of the operator deep-dive: from `octravpn-node
# init` output to a daemon visible on chain. Tape 01 already covers
# the keygen step; this tape picks up afterwards.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - A reachable RPC endpoint (devnet or mock-rpc) configured in
#     `demo/state/node/config.toml`. The bond / register subcommands
#     submit real transactions, so the chain must be live or the
#     calls will surface a clean RPC error rather than fake success.
#   - The operator wallet passphrase available as
#     `OCTRAVPN_KEY_PASSPHRASE` (so `seal-keys` does not prompt).
#
# Re-run with: vhs demo/tapes/17-operator-onboarding.tape

Output demo/recordings/17-operator-onboarding.gif
Output demo/recordings/17-operator-onboarding.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Step 1: seal on-disk keys (wallet + WG) under the operator passphrase"
Enter
Type "octravpn-node --config demo/state/node/config.toml seal-keys"
Enter
Sleep 4s

Type "# Step 2: bond the minimum stake (1000 OCT = 10^9 OU)"
Enter
Type "octravpn-node --config demo/state/node/config.toml bond --amount 1000000000"
Enter
Sleep 6s

Type "# Step 3: register the endpoint (idempotent — skips if already registered)"
Enter
Type "octravpn-node --config demo/state/node/config.toml register"
Enter
Sleep 6s

Type "# Step 4: launch the daemon in the background and let it settle"
Enter
Type "nohup octravpn-node --config demo/state/node/config.toml run >/tmp/octravpn-node.log 2>&1 &"
Enter
Sleep 1s
Type "OCTRAVPN_NODE_PID=$!"
Enter
Sleep 6s

Type "# Step 5: health probe — local file checks + chain state + remote /health"
Enter
Type "octravpn-node --config demo/state/node/config.toml health --remote http://127.0.0.1:51821"
Enter
Sleep 5s

Type "# Done. Daemon is up, bonded, registered, audit log writable."
Enter
Type "kill $OCTRAVPN_NODE_PID 2>/dev/null || true"
Enter
Sleep 3s
