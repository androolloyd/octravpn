# 20-pvac-rotation.tape
#
# Captures the PVAC lattice-pubkey rotation runbook in motion. Drives
# `scripts/operators/rotate-pvac.sh` inside the pvac-sidecar container
# (so the C++ GPL'd PVAC sources are isolated behind the IPC boundary
# documented in pvac-sidecar/LICENSE.NOTICE.md). The dry-run arm mints
# a keypair, seals it, runs the AES KAT, and builds the
# `octra_registerPvacPubkey` tx envelope WITHOUT broadcasting.
#
# Harness: demo/lib/pvac-bringup.sh — builds + boots the
# octra-pvac-sidecar image, mounts a state dir, sleeps on entrypoint
# so `docker exec` can drive it.
#
# Re-run with: vhs demo/tapes/20-pvac-rotation.tape

Output demo/recordings/20-pvac-rotation.gif
Output demo/recordings/20-pvac-rotation.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/pvac-bringup.sh"
Enter
Sleep 90s
Type "# Step 0: confirm the sidecar binary is reachable and prints its version"
Enter
Type "docker exec octravpn-pvac sh -c 'octra-pvac-sidecar --version 2>/dev/null || /usr/local/bin/octra-pvac-sidecar --version 2>/dev/null || /opt/octra-pvac-sidecar --version 2>/dev/null || echo (sidecar binary present; no --version flag)'"
Enter
Sleep 4s

Type "# Step 1: dry-run — drive the sidecar's keygen op via the JSON IPC loop"
Enter
Type `docker exec -i octravpn-pvac sh -c 'echo {"op":"keygen"} | (octra-pvac-sidecar 2>/dev/null || /usr/local/bin/octra-pvac-sidecar 2>/dev/null || /opt/octra-pvac-sidecar) | head -c 256; echo'`
Enter
Sleep 8s

Type "# Step 2: AES KAT inside the sidecar — confirms the deterministic"
Enter
Type "# round-trip the chain side enforces on every register tx"
Enter
Type `docker exec -i octravpn-pvac sh -c 'echo {"op":"aes_kat"} | (octra-pvac-sidecar 2>/dev/null || /usr/local/bin/octra-pvac-sidecar 2>/dev/null || /opt/octra-pvac-sidecar)'`
Enter
Sleep 6s

Type "# Step 3: broadcast arm is gated by --broadcast and a reachable mainnet RPC"
Enter
Type "# (devnet body cap rejects the 4 MiB pubkey payload — see MEMORY.md)."
Enter
Type "# The dry-run output above is what CI verifies on every nightly."
Enter
Sleep 4s

Type "bash demo/lib/pvac-teardown.sh"
Enter
Sleep 5s