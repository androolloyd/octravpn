# 19-circle-update-atomic.tape
#
# Captures the atomic circle-asset update primitive: dry-run -> commit
# pair for a sealed `/policy.json` rotation, then `list-orphans` to
# show the post-flip tree is clean. Drives every CLI call inside the
# node1 container against mock-rpc so the recording renders end-to-end
# without a live devnet round-trip.
#
# Harness: demo/lib/devnet-mock-bringup.sh — mock-rpc + 3-node stack
# from the root docker-compose.yml.
#
# Re-run with: vhs demo/tapes/19-circle-update-atomic.tape

Output demo/recordings/19-circle-update-atomic.gif
Output demo/recordings/19-circle-update-atomic.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/devnet-mock-bringup.sh"
Enter
Sleep 60s

Type "# Prepare a new sealed-asset payload inside the node container"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 sh -c 'mkdir -p /tmp/circle-rotation'"
Enter
Sleep 1s
Type "docker compose -f docker-compose.yml exec -iT node1 sh -c 'cat > /tmp/circle-rotation/policy.json'"
Enter
Sleep 500ms
Type `{ "region": "eu-west", "max_kbps": 100000, "version": 7 }`
Enter
Ctrl+D
Sleep 1s
Type "docker compose -f docker-compose.yml exec -T node1 cat /tmp/circle-rotation/policy.json"
Enter
Sleep 2s

Type "# Step 1: dry-run — describe the txs WITHOUT broadcasting"
Enter
Type "docker compose -f docker-compose.yml exec -T -e OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase node1 octravpn-node --config /etc/octravpn/node.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --dry-run || true"
Enter
Sleep 6s

Type "# Step 2: real apply — blob puts, then the anchor flip (atomic)"
Enter
Type "docker compose -f docker-compose.yml exec -T -e OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase node1 octravpn-node --config /etc/octravpn/node.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/circle-rotation/policy.json:default:4k --commit || true"
Enter
Sleep 8s

Type "# Step 3: confirm no orphaned blobs (old plaintext hashes no longer bound)"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml circle list-orphans --circle octCircleDemo || true"
Enter
Sleep 5s

Type "bash demo/lib/devnet-mock-teardown.sh"
Enter
Sleep 5s
