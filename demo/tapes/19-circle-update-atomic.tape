# 19-circle-update-atomic.tape
#
# Captures the atomic circle-asset update primitive (the
# `circle update` subcommand landed in commit a944c61). Walks the
# dry-run → commit pair for a sealed `/policy.json` rotation,
# demonstrates the on-chain anchor flip, then shows `list-orphans`
# returning a clean tree. If the anchor flip fails mid-update the
# command surfaces a `retry-anchor` recovery line; we narrate that
# arm at the end so the operator sees the contract end-to-end.
#
# REQUIRES:
#   - `octravpn-node` on PATH or under target/{release,debug}/.
#   - A reachable v3 chain (devnet or mock-rpc) configured in
#     `demo/state/node/config.toml` with a registered circle. The
#     fixture circle id used below (`octCircleDemo`) must already
#     have an on-chain anchor — i.e. you've run tape 17 (or the
#     equivalent register flow) at least once against this state dir.
#   - The sealed-asset passphrase exported as
#     `OCTRAVPN_SEALED_PASSPHRASE` so the CLI does not prompt.
#
# Re-run with: vhs demo/tapes/19-circle-update-atomic.tape

Output demo/recordings/19-circle-update-atomic.gif
Output demo/recordings/19-circle-update-atomic.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Prepare a new sealed-asset payload (policy.json) on disk"
Enter
Type "mkdir -p /tmp/circle-rotation && cat > /tmp/circle-rotation/policy.json <<JSON"
Enter
Type "{ region: 'eu-west', max_kbps: 100000, version: 7 }"
Enter
Type "JSON"
Enter
Sleep 2s

Type "# Step 1: dry-run — describe the txs WITHOUT broadcasting"
Enter
Type "octravpn-node --config demo/state/node/config.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --dry-run"
Enter
Sleep 5s

Type "# Step 2: real apply — blob puts, then the anchor flip (atomic)"
Enter
Type "octravpn-node --config demo/state/node/config.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --commit"
Enter
Sleep 7s

Type "# Step 3: confirm no orphaned blobs (old plaintext hashes no longer bound)"
Enter
Type "octravpn-node --config demo/state/node/config.toml circle list-orphans --circle octCircleDemo"
Enter
Sleep 5s

Type "# Failure mode: if the anchor flip had failed, the CLI prints"
Enter
Type "#   octravpn-node circle retry-anchor --circle octCircleDemo --anchor <hex>"
Enter
Type "# blobs are already on chain; the operator just re-submits the anchor tx."
Enter
Sleep 4s
