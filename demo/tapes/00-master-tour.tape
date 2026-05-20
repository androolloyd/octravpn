# 00-master-tour.tape
#
# Fast-cut concatenation of the seven canonical segments. Render this
# tape to get one ~3-minute story arc that ties the operator side
# (deploy, set policy, rotate, verify) to the user side (join, ssh,
# fetch a sealed oct://). Each segment is a condensed version of the
# stand-alone tape — narration via `Type "# ..."` lines, real CLI
# only where the budget allows.
#
# Arc:
#   17 — operator deploys (seal-keys → bond → register → run → health)
#   18 — tailnet owner pushes a hujson policy; live-reload across peers
#   11 — Linux user installs tailscale + joins the operator's tailnet
#   13 — user SSHes into a peer via MagicDNS
#   16 — user fetches a sealed oct:// asset; CONFIRM + passphrase
#   19 — operator rotates a sealed circle asset atomically (dry-run + apply)
#   21 — operator runs `audit verify`; clean exit + tampered fail mode
#
# Budget: ~3 min total render. Each segment is ~25-30s.
#
# REQUIRES:
#   - Everything the individual tapes need:
#       * `octravpn` + `octravpn-node` on PATH (built in CI).
#       * A reachable headscale control plane for the policy + headscale
#         segments (the 3-node mesh from tape 08 is the canonical fixture).
#       * A reachable devnet/mock-rpc for the operator-onboarding +
#         circle-update segments.
#       * Pre-populated audit artifacts at demo/state/node/{audit.log,
#         receipts.bin}.
#       * `OCTRAVPN_KEY_PASSPHRASE` + `OCTRAVPN_SEALED_PASSPHRASE` in env.
#   - Render budget on a CI runner: roughly 4 minutes wall-clock.
#
# Re-run with: vhs demo/tapes/00-master-tour.tape

Output demo/recordings/00-master-tour.gif
Output demo/recordings/00-master-tour.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

# ── Segment 1: operator deploys (~25s) ───────────────────────────────
Type "# what's happening: an operator deploys their node from cold"
Enter
Sleep 1500ms
Type "octravpn-node --config demo/state/node/config.toml seal-keys"
Enter
Sleep 3s
Type "octravpn-node --config demo/state/node/config.toml bond --amount 1000000000"
Enter
Sleep 4s
Type "octravpn-node --config demo/state/node/config.toml register"
Enter
Sleep 4s
Type "nohup octravpn-node --config demo/state/node/config.toml run >/tmp/node.log 2>&1 &"
Enter
Sleep 4s
Type "octravpn-node --config demo/state/node/config.toml health --remote http://127.0.0.1:51821"
Enter
Sleep 4s

# ── Segment 2: tailnet owner pushes policy (~25s) ────────────────────
Type "# what's happening: the tailnet owner pushes an ACL update"
Enter
Sleep 1500ms
Type "cat > /tmp/policy.hujson <<HUJSON"
Enter
Type "{ acls: [ { action: 'accept', src: ['alice'], dst: ['bob:*'] } ] }"
Enter
Type "HUJSON"
Enter
Sleep 1500ms
Type "octravpn-node headscale policy set /tmp/policy.hujson"
Enter
Sleep 3s
Type "# parked /map pollers wake within ~1ms (policy_e2e.rs)"
Enter
Sleep 2s

# ── Segment 3: user joins the tailnet (~20s) ─────────────────────────
Type "# what's happening: a Linux user joins with a stock tailscale client"
Enter
Sleep 1500ms
Type "# $ curl -fsSL https://tailscale.com/install.sh | sh"
Enter
Sleep 1500ms
Type "# $ sudo tailscale up --login-server https://mesh.example.octra --authkey tskey-..."
Enter
Sleep 2s
Type "tailscale status"
Enter
Sleep 3s

# ── Segment 4: user SSHes a peer (~20s) ──────────────────────────────
Type "# what's happening: the user SSHes another tailnet member via MagicDNS"
Enter
Sleep 1500ms
Type "# $ tailscale ip -4 peer-2"
Enter
Type "# 100.64.0.2"
Enter
Type "# $ ssh user@peer-2"
Enter
Type "# Welcome to peer-2 (octravpn tailnet member)"
Enter
Type "# user@peer-2:~$ exit"
Enter
Sleep 3s

# ── Segment 5: sealed oct:// fetch (~25s) ────────────────────────────
Type "# what's happening: the user fetches a sealed oct:// asset"
Enter
Sleep 1500ms
Source demo/lib/start-portal.sh
Type "curl -fsS http://127.0.0.1:51823/healthz"
Enter
Sleep 2s
Type "export OCTRAVPN_SEALED_PASSPHRASE=demo-passphrase-correct-horse"
Enter
Type "octravpn --config demo/state/portal/config.toml fetch -i oct://octCircleDemo/sealed.json"
Enter
Sleep 4s

# ── Segment 6: atomic circle update (~25s) ───────────────────────────
Type "# what's happening: the operator rotates a sealed circle asset atomically"
Enter
Sleep 1500ms
Type "printf '%s\n' '{ region: eu-west, version: 8 }' > /tmp/new-policy.json"
Enter
Type "octravpn-node --config demo/state/node/config.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/new-policy.json:default:4k --dry-run"
Enter
Sleep 4s
Type "octravpn-node --config demo/state/node/config.toml circle update --circle octCircleDemo --blob /policy.json:/tmp/new-policy.json:default:4k --commit"
Enter
Sleep 5s

# ── Segment 7: audit verify (~25s) ───────────────────────────────────
Type "# what's happening: the operator runs the daily audit verify"
Enter
Sleep 1500ms
Type "octravpn-node audit verify --audit-path demo/state/node/audit.log --journal-path demo/state/node/receipts.bin"
Enter
Sleep 4s
Type "echo exit=$?"
Enter
Sleep 2s
Type "# Clean chain on a clean log; non-zero + a broken-line pointer on a tampered one."
Enter
Sleep 2s

Type "# end of tour — see demo/tapes/{11..22} for the full per-segment recordings"
Enter
Sleep 2s
