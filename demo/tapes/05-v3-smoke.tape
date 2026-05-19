# 05-v3-smoke.tape
#
# Captures the chain-side v3 lifecycle end-to-end:
# deploy main-v3 -> register_circle -> create_tailnet -> open_session ->
# settle_claim -> settle_confirm -> local hash-chain replay ->
# claim_earnings -> overclaim rejection -> anchor rotation.
#
# REQUIRES:
#   - `bash` + `python3` + `curl` (all used inline by v3-smoke.sh).
#   - The Octra foundry binary at $OCTRA_BIN, or
#     ../octra-foundry/target/release/octra next to the repo root.
#   - A funded `deployer.key` at docker/devnet/state/deployer.key with
#     >200_000_000 OU on the configured RPC.
#   - $OCTRA_RPC_URL pointed at a devnet (mock-rpc or real devnet);
#     never run this against mainnet — the smoke is destructive.
#
# This tape simply drives the canonical smoke script and lets it
# narrate itself. The script's own `=== N. step ===` banners + ok/fail
# lines are the demo material.
#
# Re-run with: vhs demo/tapes/05-v3-smoke.tape

Output demo/recordings/05-v3-smoke.gif
Output demo/recordings/05-v3-smoke.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# v3 lifecycle smoke: deploy + register + session + settle + replay"
Enter
Sleep 1s

Type "bash docker/devnet/v3-smoke.sh"
Enter
# The smoke script blocks on `sleep 18` between txs to give the chain
# time to confirm; eight of those land in the recording window.
Sleep 180s
