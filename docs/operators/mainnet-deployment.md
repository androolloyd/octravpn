# OctraVPN — mainnet deployment runbook

Operator-grade walkthrough from a clean Linux host to a paid v3 node
serving traffic and accruing OU on Octra mainnet. Every command is
copy-pasteable; every step is idempotent unless flagged otherwise. For
background see the top-level [`README.md`](../../README.md);
release-cutting lives in [`docs/release.md`](../release.md); the
"just-try-it" path lives in [`docs/install.md`](../install.md). This
runbook supersedes both for production.

**Who this is for.** ONE operator, ONE node on mainnet, bonded to ONE
circle, hosting ONE tailnet. Multi-machine HA, OIDC SSO, multi-tenant
operation are out of scope for v0.1 (`docs/production-readiness.md`).

**Assumed starting point.**
- Linux host with root, fixed public IP, a DNS name (or a bare IP)
  that peers can reach.
- An Octra wallet holding `MIN_CIRCLE_STAKE_DEFAULT` (1000 OCT) plus
  ~10 OCT gas headroom.
- A pre-deployed v3 operator circle whose `circle_id` you control
  (the node does NOT auto-`deploy_circle` in v3 — see §5).
- A password manager or KMS for the sealed-passphrase + wallet secret.

## 0. Before you start

### 0.1 Hardware

| Resource | Floor | Comfort |
|---|---|---|
| CPU | 2 vCPU x86_64 or arm64 | 4 vCPU |
| RAM | 1 GiB | 4 GiB |
| Disk | 10 GiB SSD (root + state + audit log) | 50 GiB SSD |
| Network | 100 Mbit/s symmetric, unmetered | 1 Gbit/s |

The audit log grows roughly 200 bytes per signed receipt. Plan for
log rotation if you expect >1 M receipts/day (see §9).

### 0.2 OS support

Per [`docs/release.md`](../release.md) §1: Ubuntu 22.04/24.04 LTS,
Debian 12 (`.deb`); Rocky / RHEL / Alma 9, Fedora 39+ (`.rpm`);
amd64 + arm64. Other distros work from source (§1.3) but lose the
shipped systemd integration.

### 0.3 Network

| Port | Direction | Protocol | Purpose |
|---|---|---|---|
| 443 | inbound | TCP | TLS-terminated control plane (`/key`, `/ts2021`, `/machine/...`) |
| 51820 | inbound | UDP | WireGuard data plane |
| 51821 | inbound | TCP | Plain-HTTP control + `/metrics` (loopback / private net only) |
| any | outbound | TCP/443 | Chain RPC + DERP relay reachability |

DNS: the SAN on your TLS cert must match what clients resolve your
control plane to.

### 0.4 Wallet preparation

The wallet must (1) hold ≥ 1000 OCT + gas, (2) match
`[chain].validator_addr` in `node.toml` (§3), and (3) be the deployer
of the circle whose id goes in `[chain].circle_id`. For key derivation
mechanics see [`docs/keys.md`](../keys.md). Hold the mnemonic + raw
secret in cold storage; the daemon only ever sees the sealed envelope
produced in §2.

## 1. Install the binary

### 1.1 From .deb (Ubuntu / Debian)

```sh
ARCH=$(dpkg --print-architecture)            # amd64 or arm64
VERSION=0.1.0
BASE=https://github.com/octra-labs/octravpn/releases/download/v${VERSION}

curl -fsSL ${BASE}/octravpn-node_${VERSION}-1_${ARCH}.deb     -o /tmp/octravpn-node.deb
curl -fsSL ${BASE}/octravpn-node_${VERSION}-1_${ARCH}.deb.sig -o /tmp/octravpn-node.deb.sig
curl -fsSL https://octra.org/keys/octravpn-release.asc | gpg --import
gpg --verify /tmp/octravpn-node.deb.sig /tmp/octravpn-node.deb

sudo dpkg -i /tmp/octravpn-node.deb
```

The postinst creates the `octravpn` system user, `/etc/octravpn`
(0750), `/var/lib/octravpn` (0700), `/var/log/octravpn` (0750), sets
`CAP_NET_ADMIN + CAP_NET_BIND_SERVICE` on the binary, and enables
(but does not start) the unit — see
[`deploy/debian/postinst`](../../deploy/debian/postinst).

### 1.2 From .rpm (RHEL / Rocky / Alma / Fedora)

```sh
VERSION=0.1.0
ARCH=$(rpm --eval '%{_arch}')                # x86_64 or aarch64
sudo dnf install -y \
  https://github.com/octra-labs/octravpn/releases/download/v${VERSION}/octravpn-node-${VERSION}-1.${ARCH}.rpm
```

Signature verification mirrors the .deb path. `dnf` refuses unsigned
packages if `gpgcheck=1` is set globally.

### 1.3 From source

```sh
git clone https://github.com/octra-labs/octravpn && cd octravpn
cargo build --release -p octravpn-node -p octravpn-client
sudo install -m 0755 target/release/octravpn-node /usr/local/bin/
sudo install -m 0755 target/release/octravpn      /usr/local/bin/
sudo setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/octravpn-node
```

Then lay out users + systemd units by hand mirroring
[`deploy/debian/postinst`](../../deploy/debian/postinst) and
[`deploy/systemd/`](../../deploy/systemd/).

## 2. Generate keys + lay out the state dir

Drop the keys in by hand — there is no `octravpn-node identity --new`
helper; the client binary provides `keygen`, and the wallet secret
comes from your cold-storage flow.

```sh
# WireGuard / receipt master (32 random bytes). Receipt-signing, noise,
# and WG keys all derive from this via HKDF.
sudo -u octravpn /usr/local/bin/octravpn keygen --out /etc/octravpn/wg.key
sudo chmod 0600 /etc/octravpn/wg.key

# Wallet secret (32-byte hex).
sudo install -m 0600 -o octravpn -g octravpn /dev/stdin \
  /etc/octravpn/wallet.hex <<< 'PASTE_WALLET_HEX_HERE'
```

Seal both under a passphrase the daemon resolves from
`OCTRAVPN_KEY_PASSPHRASE` at runtime (P1-6 in
`docs/production-readiness.md`):

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
  --config /etc/octravpn/node.toml seal-keys \
  --passphrase-stdin --remove-plaintext <<< 'YOUR_KEY_PASSPHRASE'
```

Produces `wallet.hex.sealed` + `wg.key.sealed`, unlinks the originals,
and is idempotent across reboots / Ansible runs. Per-OS passphrase
storage: [`docs/v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md).

## 3. Configure the node

`/etc/octravpn/node.toml` is the single source of truth loaded at boot
(schema lives in `crates/octravpn-node/src/config.rs`). Drop the
template below in, edit the marked fields, leave the rest at defaults.

```toml
[chain]
rpc_url            = "https://octra.network/rpc"               # MUST: mainnet
pinned_root_paths  = ["/etc/octravpn/octra-mainnet-roots.pem"] # defeats CA-MITM
program_addr       = "oct...MAINNET_OCTRAVPN_V3_PROGRAM..."    # MUST: v3 on mainnet
validator_addr     = "oct...YOUR_WALLET_ADDRESS..."            # MUST match sealed wallet
wallet_secret_path = "/etc/octravpn/wallet.hex.sealed"

protocol_version   = "v3"
chain_id           = 1869832813      # CHAIN_ID_MAINNET — devnet default would replay-leak

circle_id            = "oct...YOUR_OPERATOR_CIRCLE..."   # see §5
v3_initial_stake     = 1000000000                        # 1000 OCT
circle_v3_state_path = "/var/lib/octravpn/circle-v3.toml"

require_sealed_keys  = true                              # refuses to boot on plaintext

[tunnel]
public_endpoint   = "1.2.3.4:51820"  # MUST be reachable from peers
listen            = "0.0.0.0:51820"
wg_secret_path    = "/etc/octravpn/wg.key.sealed"

[pricing]
price_per_mb           = 100
price_per_mb_shared    = 100         # OU per MB of exit traffic
price_per_mb_internal  = 0           # intra-tailnet (usually free)
region                 = "eu-west"

[control]
listen                    = "0.0.0.0:51821"   # bind a private iface if possible
audit_dir                 = "/var/lib/octravpn/audit"
receipt_journal_path      = "/var/lib/octravpn/receipts.bin"
tailscale_wire_state_dir  = "/var/lib/octravpn/tailscale-wire"
tailscale_tailnet_id      = "your-tailnet-stable-string"
events_token              = "LONG_RANDOM_STRING"   # gates /events SSE
admin_token               = "LONG_RANDOM_STRING_2" # gates POST /admin/preauth

[attestation]
poll_interval_secs = 30
```

Drop the sealed-passphrase + key-passphrase into the systemd unit
environment (NOT the TOML — env wins and is rotatable):

```sh
sudo systemctl edit octravpn-node     # creates an override drop-in
# [Service]
# Environment=OCTRAVPN_SEALED_PASSPHRASE=<per-tailnet shared secret>
# Environment=OCTRAVPN_KEY_PASSPHRASE=<your key-passphrase from §2>
```

`OCTRAVPN_SEALED_PASSPHRASE` decrypts the tailnet sealed assets;
`OCTRAVPN_KEY_PASSPHRASE` unwraps the operator's own wallet + WG key.
Neither should land in plaintext on disk — load both from a secret
manager into the unit's environment.

## 4. Wallet ceremony (one-time)

Confirm the sealed wallet decrypts to the address you intended:

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
  --config /etc/octravpn/node.toml identity
# Prints: address, validator pubkey, WG pubkey, derived receipt pubkey.
```

If you minted a fresh wallet, fund it before §5 — minimum is
`v3_initial_stake + gas` ≈ 1010 OCT. A mismatch between the printed
address and `[chain].validator_addr` means the sealed wallet
decrypted into a different secret than you intended; re-seal before
proceeding.

## 5. Deploy + register your operator circle

`program/main-v3.aml` requires the operator to register a pre-existing
circle via `register_circle(circle, state_root, receipt_pubkey)`. The
daemon auto-calls this on first start, but the circle itself must
already exist on chain. The node does NOT bundle `deploy_circle` into
its boot flow (see the judgement-call comment in
[`crates/octravpn-node/src/v3_boot.rs`](../../crates/octravpn-node/src/v3_boot.rs)).

Deploy via the wallet CLI:

```sh
# From the sibling octra-foundry repo.
octra cast send <deployer_wallet> deploy_circle \
  --value 0 \
  --rpc-url https://octra.network/rpc
# Output: circle id = oct...
```

Paste the printed `circle_id` into `[chain].circle_id` in `node.toml`.

> **TODO (production-readiness P0 item #3, task #216).** A future
> `octravpn-node v3 deploy-circle` subcommand will fold this into the
> daemon CLI. Until it lands, the manual `octra cast` step above is
> the path.

Once the circle is on chain and the config is updated, starting the
daemon (§6) atomically calls `register_circle(circle, anchor,
receipt_pubkey_b64)` with `value = v3_initial_stake`. The anchor and
receipt pubkey are derived from your sealed keys — no extra arguments.
On-chain shape:
[`docs/v3-state-root-schema.md`](../v3-state-root-schema.md),
[`docs/v3-policy-schema.md`](../v3-policy-schema.md). Subsequent
restarts call `update_circle_state` iff the anchor changed.

## 6. Start the service

```sh
sudo systemctl daemon-reload                # picks up the env drop-in
sudo systemctl start  octravpn-node
sudo systemctl status octravpn-node
sudo journalctl -u octravpn-node -f
```

Expected first-startup log lines (order may vary):

```text
INFO  loaded sealed wallet from /etc/octravpn/wallet.hex.sealed
INFO  v3 register_circle submitted (atomic register+bond)
INFO  tunnel listening on 0.0.0.0:51820/udp
INFO  control listening on 0.0.0.0:51821
INFO  audit log opened at /var/lib/octravpn/audit
INFO  receipt journal opened at /var/lib/octravpn/receipts.bin
```

Health probes:

```sh
curl -s http://127.0.0.1:51821/health | jq .
# {"status":"ok","last_attestation_unix":...,"started_at_unix":...}

curl -sk https://127.0.0.1:443/key
# mkey:<64-char hex> — the persistent Noise long-term static pubkey.

curl -s http://127.0.0.1:51821/metrics | grep -E '^(octravpn_uptime|octravpn_active_sessions)'
```

A failure on any of these is your cue to read journalctl before
touching anything else.

## 7. Wire observability

The Prometheus + Grafana + Alertmanager pack lives in
[`deploy/observability/`](../../deploy/observability/) with the
per-alert "fired, now what" runbook in
[`docs/observability.md`](../observability.md). Minimum hookup:

1. Add this host to `targets.json` in your central Prometheus.
2. Drop [`deploy/observability/alerts.yml`](../../deploy/observability/alerts.yml)
   under your `rule_files:` glob.
3. Import `grafana/octravpn-overview.json` into Grafana.
4. Point Alertmanager at your pager.

`/metrics` is NOT auth-gated today
([`deploy/observability/README.md`](../../deploy/observability/README.md)
§"spec deviations"). Either terminate auth in a reverse proxy or bind
`[control].listen` to a private interface only.

## 8. First settlement — verify the loop works

From a separate machine (your laptop):

```sh
octravpn init --rpc-url https://octra.network/rpc \
              --program-addr <SAME_V3_PROGRAM>
# Edit config: protocol_version = "v3"; circle_id = <your operator>.
octravpn connect-v3 --circle-id <YOUR_OPERATOR_CIRCLE> --max-pay 1000
# Send traffic through the tunnel.
```

On the node, prove receipts + settlement work:

```sh
SINCE=$(date -d '10 minutes ago' +%s)

sudo -u octravpn /usr/local/bin/octravpn-node audit replay \
  --audit-path /var/lib/octravpn/audit \
  --journal-path /var/lib/octravpn/receipts.bin --since "$SINCE"
# Expect: session_announced, receipt_signed (one per chunk),
# session_settled, settle_claim tx hash.

sudo -u octravpn /usr/local/bin/octravpn-node audit verify \
  --audit-path /var/lib/octravpn/audit \
  --journal-path /var/lib/octravpn/receipts.bin
# Expect: exit 0; "verification PASSED".
```

A non-zero `audit verify` exit is your canary — stop the daemon, take
a forensic snapshot of `/var/lib/octravpn/`, and follow
[`docs/observability.md`](../observability.md) §OctravpnNodeDown.

## 9. Production hygiene

- **Backups.** `wallet.hex.sealed`, `wg.key.sealed`, and the receipt
  journal `receipts.bin` are non-reconstructible from chain state.
  Snapshot `/var/lib/octravpn/` + `/etc/octravpn/` nightly to offsite
  storage. The sealed-passphrase itself lives in your password
  manager / KMS — back that up separately.
- **Log rotation.** Audit log is one JSONL per UTC day under
  `[control].audit_dir`. Logrotate files older than ~90 days, and
  `octravpn-node audit verify` each rotated file before deleting.
- **Periodic attestation.** The package ships
  [`deploy/systemd/octravpn-attest.timer`](../../deploy/systemd/octravpn-attest.timer)
  firing every 2 min; enable with
  `sudo systemctl enable --now octravpn-attest.timer`.
  > **TODO (gap).** The `octravpn-node attest` one-shot verb the unit
  > invokes is not wired yet (`Cmd::Attest` is absent in
  > `crates/octravpn-node/src/main.rs`). The long-running daemon
  > handles attestation refresh via the `[attestation]` poll loop;
  > the timer is harmless but currently a no-op.
- **Firewall (ufw).**
  ```sh
  sudo ufw default deny incoming
  sudo ufw allow 22/tcp                                            # SSH
  sudo ufw allow 443/tcp                                           # control plane
  sudo ufw allow 51820/udp                                         # data plane
  sudo ufw allow from <PROMETHEUS_IP> to any port 51821 proto tcp
  sudo ufw enable
  ```
- **Unattended upgrades.** Debian: `apt install unattended-upgrades`
  + add `octra-labs` to the allowed origins. RHEL: `dnf install
  dnf-automatic` + enable `dnf-automatic.timer`. Pin to a major
  channel so v0.x → v1.x is always manual.
- **Sealed-passphrase rotation.** Per-tailnet shared secret rotates
  out-of-band by the tailnet owner; re-seal + restart workflow lives
  in [`docs/operator-guide.md`](../operator-guide.md) §12.3.

## 10. Common pitfalls

- **"Address already in use" on :443.** Disable nginx / apache / any
  other TLS terminator on that port, or move the control plane to a
  different host and reverse-proxy onto :443.
- **"circle not registered" at boot.** `[chain].circle_id` in
  `node.toml` does not match a circle on chain. Either you have not
  yet `deploy_circle`'d (§5) or you pasted the wrong id. Verify with
  `octra cast call get_circle_active <circle_id>` against your RPC.
- **"audit log out of sync."** Almost always means a partial write
  before a forced restart. Stop the daemon, rotate the affected
  `audit-YYYY-MM-DD.jsonl` aside, `audit verify` the prior day's
  file, then restart.
- **DERP not reachable.** Mainnet operators currently must point
  `[control].tailscale_wire_state_dir` at a host that can reach an
  upstream DERP. Embedded DERP is post-v0.1 (see
  `docs/headscale-gap-analysis.md` §5 and the open Wall 6
  worktree). Until then, either run your own DERP or accept the
  NAT-traversal-only ceiling.
- **`require_sealed_keys` refusing to boot.** Means a plaintext key
  was left next to a sealed one. Re-run `seal-keys --remove-plaintext`
  or manually `shred` the plaintext file.
- **Wrong `chain_id`.** Devnet receipts will not validate on mainnet
  and vice-versa. Set `chain_id = 1869832813` (CHAIN_ID_MAINNET); the
  default is devnet.

## 11. Upgrading

```sh
sudo apt upgrade octravpn-node        # Debian / Ubuntu
sudo dnf upgrade octravpn-node        # RHEL / Rocky / Alma
sudo systemctl restart octravpn-node
```

Tarball / source: replace `/usr/local/bin/octravpn-node`, re-run
`setcap`, restart. `/var/lib/octravpn/` is stable across upgrades
within a major version; check release notes before any v0.x → v1.x
jump. The receipt journal (P1-8/9) makes restarts safe — the next
signed receipt jumps strictly past the journal floor.

## 12. Decommissioning

There is no graceful-drain CLI today (TODO, task #216). The practical
equivalent is to firewall-drop :443 for new connections while leaving
:51820/udp open until in-flight sessions close (~`SESSION_GRACE` s).

```sh
NODE=/usr/local/bin/octravpn-node
C=<YOUR_CIRCLE_ID>

# Retire the circle (flips circle_active = 0; stake remains bonded).
sudo -u octravpn $NODE v3 retire          --circle "$C"
# Start unbond grace.
sudo -u octravpn $NODE v3 unbond          --circle "$C"
# Wait for circle_unbond_unlock_epoch (inspect via:
# octra cast call get_circle_unbond_unlock_epoch "$C"), then:
sudo -u octravpn $NODE v3 finalize-unbond --circle "$C"
# Optional — pull any unclaimed earnings.
sudo -u octravpn $NODE v3 claim-earnings  --circle "$C" --amount <OU>

# Stop the daemon + remove the package.
sudo systemctl disable --now octravpn-node octravpn-attest.timer
sudo apt purge octravpn-node      # or: sudo dnf remove octravpn-node
```

The deb `prerm` / `postrm` hooks tear down the systemd unit but
deliberately leave `/var/lib/octravpn` in place — `rm -rf` it
explicitly after confirming receipt journal + audit log are backed up
offline.
