# 01-init-keygen.tape
#
# Captures the cold-start operator flow: a fresh scratch dir in a
# throwaway container, an `octravpn init` that writes a config.toml +
# wallet key, then `octravpn keygen` for a bond wallet, and finally
# `octravpn identity` to print the derived address.
#
# Harness: demo/lib/keygen-fixture-bringup.sh — spins up a single
# `debian:bookworm-slim` container with the host-built `octravpn`
# binary bind-mounted at /usr/local/bin/octravpn. The recording's
# real terminal stays on the host; every `docker exec` call below
# drives the container.
#
# Re-run with: vhs demo/tapes/01-init-keygen.tape

Output demo/recordings/01-init-keygen.gif
Output demo/recordings/01-init-keygen.mp4

Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set TypingSpeed 40ms

# Bring up the fixture container (idempotent; ~1s warm, ~3s cold).
Type "bash demo/lib/keygen-fixture-bringup.sh"
Enter
Sleep 10s
Type "docker exec octravpn-keygen-fixture sh -c 'rm -rf /work/* && mkdir -p /work'"
Enter
Sleep 1s

Type "docker exec -w /work octravpn-keygen-fixture octravpn init --dir ."
Enter
Sleep 3s

Type "docker exec -w /work octravpn-keygen-fixture ls -la"
Enter
Sleep 2s

Type "docker exec -w /work octravpn-keygen-fixture octravpn keygen --out ./bond.key"
Enter
Sleep 3s

Type "docker exec -w /work octravpn-keygen-fixture ls -la"
Enter
Sleep 2s

Type "docker exec -w /work octravpn-keygen-fixture octravpn --config ./client.toml identity"
Enter
Sleep 3s

Type "bash demo/lib/keygen-fixture-teardown.sh"
Enter
Sleep 5s