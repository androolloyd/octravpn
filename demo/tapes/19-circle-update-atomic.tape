# 19-circle-update-atomic.tape
#
# Captures the atomic circle-asset update primitive against the live
# Octra devnet (https://devnet.octrascan.io/rpc): dry-run -> commit
# pair for a sealed `/policy.json` rotation, then `list-orphans` to
# show the post-flip tree is clean. Drives every CLI call inside the
# demo-node1 container.
#
# Chain currently enforces sealed_read on all circles; the plaintext-
# fetch flow returns when chain enables `resource_mode = public_read`.
# See octra-foundry `cast circle put` (commit ef6d0ed) — the
# wire-compatible client side is already in place.
#
# Harness: demo/lib/devnet-bringup.sh — ensures the demo circle exists
# + brings up demo-node{1,2,3} pinned at devnet. Exports
# ${OCTRAVPN_DEMO_CIRCLE_ID} into the containers.
#
# Re-run with: vhs demo/tapes/19-circle-update-atomic.tape

Output demo/recordings/19-circle-update-atomic.gif
Output demo/recordings/19-circle-update-atomic.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/devnet-bringup.sh"
Enter
Sleep 60s

Type "# resolve the demo circle id from the running container env"
Enter
Type `CIRCLE=$(docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T node1 printenv OCTRAVPN_DEMO_CIRCLE_ID) && echo $CIRCLE`
Enter
Sleep 2s

Type "# Prepare a new sealed-asset payload inside the demo-node container"
Enter
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T node1 sh -c 'mkdir -p /tmp/circle-rotation'"
Enter
Sleep 1s
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -iT node1 sh -c 'cat > /tmp/circle-rotation/policy.json'"
Enter
Sleep 500ms
Type `{ "region": "eu-west", "max_kbps": 100000, "version": 7 }`
Enter
Ctrl+D
Sleep 1s
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T node1 cat /tmp/circle-rotation/policy.json"
Enter
Sleep 2s

Type "# Step 1: dry-run — describe the txs WITHOUT broadcasting"
Enter
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T -e OCTRAVPN_SEALED_PASSPHRASE=demo node1 octravpn-node --config /etc/octravpn/node.toml circle update --circle $CIRCLE --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --dry-run || true"
Enter
Sleep 6s

Type "# Step 2: real apply — blob puts, then the anchor flip (atomic)"
Enter
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T -e OCTRAVPN_SEALED_PASSPHRASE=demo node1 octravpn-node --config /etc/octravpn/node.toml circle update --circle $CIRCLE --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --commit || true"
Enter
Sleep 8s

Type "# Step 3: confirm no orphaned blobs (old plaintext hashes no longer bound)"
Enter
Type "docker compose -f docker-compose.yml -f docker-compose.demo.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml circle list-orphans --circle $CIRCLE || true"
Enter
Sleep 5s

Type "bash demo/lib/devnet-teardown.sh"
Enter
Sleep 5s
