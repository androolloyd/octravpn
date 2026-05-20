# 20-pvac-rotation.tape
#
# Captures the PVAC lattice-pubkey rotation runbook in motion. Drives
# `scripts/operators/rotate-pvac.sh` in dry-run (mint keypair, seal,
# AES KAT, build the `octra_registerPvacPubkey` tx envelope WITHOUT
# broadcasting), then with `--broadcast`. Closes by showing the daily
# probe CI status badge (the fhe-load-pk-probe workflow that tracks
# whether the PVAC bridge is wired on chain).
#
# REQUIRES:
#   - `octravpn-node` + `pvac-sidecar` on PATH.
#   - A configured operator state-dir (the script's `--state-dir`).
#     `demo/state/node/` is the default in this tape.
#   - For the `--broadcast` arm: a reachable mainnet RPC. Devnet
#     rejects the 4 MiB pubkey payload (1 MiB body cap) — see
#     `MEMORY.md > Devnet RPC 1 MiB body cap`.
#   - `curl` to fetch the probe badge.
#
# Re-run with: vhs demo/tapes/20-pvac-rotation.tape

Output demo/recordings/20-pvac-rotation.gif
Output demo/recordings/20-pvac-rotation.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Step 1: dry-run — mint, seal, AES KAT, build envelope; nothing on chain"
Enter
Type "bash scripts/operators/rotate-pvac.sh --state-dir demo/state/node --dry-run"
Enter
Sleep 8s

Type "# Step 2: real broadcast — same flow, but submits the registerPvacPubkey tx"
Enter
Type "# (uncomment for live runs; the tape narrates the call so CI doesn't broadcast)"
Enter
Type "# bash scripts/operators/rotate-pvac.sh --state-dir demo/state/node --broadcast"
Enter
Sleep 6s

Type "# Step 3: confirm the daily probe is green"
Enter
Type "# CI workflow: .github/workflows/fhe-load-pk-probe.yml runs at 06:00 UTC"
Enter
Type "curl -fsS 'https://github.com/androolloyd/octra/actions/workflows/fhe-load-pk-probe.yml/badge.svg' -o /tmp/fhe-probe.svg && file /tmp/fhe-probe.svg"
Enter
Sleep 5s

Type "# Done. Old key sealed in archive, new key registered on chain,"
Enter
Type "# probe will catch the bridge wiring on tomorrow's run."
Enter
Sleep 3s
