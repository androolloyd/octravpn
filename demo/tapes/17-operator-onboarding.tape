# 17-operator-onboarding.tape
#
# Captures the operator's cold-start: seal the on-disk keys under
# the wallet passphrase, bond the minimum stake, register the
# endpoint, boot the daemon, then probe `octravpn-node health`.
# Every step runs inside the node1 container against the mock-rpc
# chain so the recording is fully deterministic.
#
# Harness: demo/lib/devnet-mock-bringup.sh — boots mock-rpc + 3
# node containers from docker-compose.yml. Keys + node.toml are
# baked into docker/conf/node1 so seal-keys + bond + register all
# operate against real on-disk artefacts.
#
# Re-run with: vhs demo/tapes/17-operator-onboarding.tape

Output demo/recordings/17-operator-onboarding.gif
Output demo/recordings/17-operator-onboarding.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "bash demo/lib/devnet-mock-bringup.sh"
Enter
Sleep 60s
Type "# Step 1: seal on-disk keys (wallet + WG) under the operator passphrase"
Enter
Type "docker compose -f docker-compose.yml exec -T -e OCTRAVPN_KEY_PASSPHRASE=demo-passphrase node1 octravpn-node --config /etc/octravpn/node.toml seal-keys || true"
Enter
Sleep 5s

Type "# Step 2: bond the minimum stake (1000 OCT = 10^9 OU)"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml bond --amount 1000000000 || true"
Enter
Sleep 6s

Type "# Step 3: register the endpoint (idempotent — skips if already registered)"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml register || true"
Enter
Sleep 6s

Type "# Step 4: daemon is already running in node1 — confirm via 'ps' and the control port"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 sh -c 'ps -ef | grep octravpn-node | grep -v grep'"
Enter
Sleep 4s

Type "# Step 5: health probe — local file checks + chain state + remote /health"
Enter
Type "docker compose -f docker-compose.yml exec -T node1 octravpn-node --config /etc/octravpn/node.toml health --remote http://127.0.0.1:51821 || true"
Enter
Sleep 5s

Type "bash demo/lib/devnet-mock-teardown.sh"
Enter
Sleep 5s