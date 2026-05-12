# Your first OctraVPN validator-VPN node (10 minutes)

This tutorial walks a node operator from a clean Linux VPS to an
active, attested, on-chain validator-VPN node accepting client
sessions.

## What you'll need

- Linux x86_64 (Ubuntu 22.04+ or RHEL 9+ recommended).
- Public IPv4 address. (Behind NAT works only with port forwarding;
  see § Firewall.)
- Min `10000 OCT` bonded (configurable; defaults to the recommended
  starting point — see `docs/economics.md` § Reference bonds).
- A wallet you control.
- About 10 minutes.

## Step 1 — Install

```sh
curl -fsSL https://octravpn.org/install.sh | sudo sh -s -- --node
```

This:

- Installs `octravpn` (client) and `octravpn-node` (daemon) to
  `/usr/local/bin/`.
- Creates the `octravpn` system user + dirs:
  - `/etc/octravpn/` — config + keys (chmod 0750)
  - `/var/lib/octravpn/` — accumulator file
  - `/var/log/octravpn/` — logs
- Registers a `systemd` unit at
  `/etc/systemd/system/octravpn-node.service`.
- Calls `setcap cap_net_admin,cap_net_bind_service+ep` on the node
  binary so it can open TUN + bind 51820 without running as root.

## Step 2 — Provision config + keys

```sh
sudo octravpn-node init --config /etc/octravpn/node.toml \
                        --rpc-url https://octra.network/rpc \
                        --program-addr oct1xPLACEHOLDER...
sudo chown -R octravpn:octravpn /etc/octravpn
```

This writes:

- `/etc/octravpn/node.toml` — config (rpc_url, program_addr,
  region, price_per_mb, endpoint).
- `/etc/octravpn/wallet.key` — the **bond / signing** wallet
  (32-byte hex, chmod 0600).
- `/etc/octravpn/wg.key` — the **WG noise** master secret. HKDF
  derives the receipt-signing + X25519 noise subkeys from this.
- `/etc/octravpn/fhe.sk` / `fhe.pk` — reserved (for future
  FHE-based earnings; current accumulator is Pedersen).

Open `/etc/octravpn/node.toml` and edit:

```toml
[chain]
rpc_url       = "https://octra.network/rpc"
program_addr  = "oct1x...REAL_OCTRAVPN_PROGRAM..."
validator_addr = "oct1x...YOUR_VALIDATOR_ADDRESS..."   # printed by init
wallet_secret_path = "/etc/octravpn/wallet.key"
initial_bond  = 10000000000           # 10000 OCT in OU (6 decimals)

[tunnel]
listen              = "0.0.0.0:51820"
public_endpoint     = "your.public.fqdn:51820"   # MUST be reachable
wg_secret_path      = "/etc/octravpn/wg.key"

[pricing]
price_per_mb        = 100              # OU per MB; tune for your region
region              = "eu-west"

[control]
listen              = "0.0.0.0:51821"  # HTTP control plane

[attestation]
refresh_every_epochs = 5               # well below the chain's grace
```

## Step 3 — Bond + register

`octravpn-node register` is idempotent; running it submits a
`register_validator` tx if the validator isn't already registered.

```sh
sudo -u octravpn octravpn-node --config /etc/octravpn/node.toml register
```

The command:

- Submits an `octra_submit` tx for `register_validator`.
- Attaches `value = initial_bond` (OU).
- Verifies the bond commit was accepted.
- Prints the deployed validator address.

If the wallet has insufficient balance, you'll get
`insufficient balance` — fund the wallet first.

## Step 4 — Refresh attestation (one-shot smoke test)

```sh
sudo -u octravpn octravpn-node --config /etc/octravpn/node.toml attest
```

You should see `attestation refreshed`. The long-running daemon
does this automatically every `refresh_every_epochs`.

## Step 5 — Start the daemon

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now octravpn-node
sudo systemctl status octravpn-node
```

Logs:

```sh
sudo journalctl -u octravpn-node -f
```

Sample healthy startup:

```
INFO  octravpn-node running
INFO  control plane listening addr=0.0.0.0:51821
INFO  tunnel listening listen=0.0.0.0:51820
INFO  register_validator submitted
INFO  refresh_attestation submitted
```

## Step 6 — Confirm visibility

From another machine:

```sh
curl http://your.public.fqdn:51821/health
# expects: {"status": "ok", "uptime_s": <n>}

curl http://your.public.fqdn:51821/metrics
# expects: Prometheus-format counters
```

From the chain:

```sh
octra --rpc https://octra.network/rpc cast call oct1xPLACEHOLDER... \
      list_active_validators 0 50
# Your validator address should appear in the list.
```

## Step 7 — Firewall

Open these ports on your VPS host firewall and any upstream:

| Port | Protocol | Why |
| --- | --- | --- |
| 51820 | UDP | WireGuard data plane |
| 51821 | TCP | HTTP control plane (`/session`, `/health`, `/metrics`) |
| 443 | TCP outbound | Octra RPC |

### ufw (Ubuntu)

```sh
sudo ufw allow 51820/udp
sudo ufw allow 51821/tcp
```

### firewalld (RHEL / Fedora)

```sh
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --add-port=51821/tcp
sudo firewall-cmd --reload
```

### nftables (raw)

```
add rule inet filter input udp dport 51820 accept
add rule inet filter input tcp dport 51821 accept
```

## Step 8 — Monitor

Prometheus scrape:

```yaml
- job_name: octravpn-node
  static_configs:
    - targets: ['your.public.fqdn:51821']
```

Key counters:

- `octravpn_announces_total` — sessions clients have announced.
- `octravpn_receipts_signed_total` — receipts the node has signed.
- `octravpn_bytes_served_total` — cumulative bytes.
- `octravpn_active_sessions` — current open sessions.

## Step 9 — Claim earnings

Periodically (weekly is fine):

```sh
sudo -u octravpn octravpn-node --config /etc/octravpn/node.toml claim-earnings
```

This:

1. Reads the on-chain Pedersen earnings point for your validator.
2. Reads your local accumulator (running `(amount, blind_sum)`).
3. Submits `claim_earnings` with the opening.
4. Receives OCT via a private (stealth) transfer.
5. Resets your local accumulator.

## Step 10 — Backup

```sh
# Encrypt + offsite — see docs/keys.md.
sudo age -e -i ~/.config/age/key.txt \
    -o /secure/backup/wallet.key.age \
    /etc/octravpn/wallet.key
sudo age -e -i ~/.config/age/key.txt \
    -o /secure/backup/accumulator.age \
    /var/lib/octravpn/accumulator
```

Without `wallet.key` your bond is locked until unbond timer
expiry. Without the accumulator, you'll need to run `reconcile`
(see `docs/troubleshooting.md`) to rebuild it from chain events.

## Common pitfalls

- **`public_endpoint` not reachable**: clients can't connect.
  `octravpn-node doctor` checks NAT.
- **`refresh_every_epochs` too high**: jail risk if you fall
  behind the chain's `attest_grace_epochs`. Default 5 is safe.
- **`price_per_mb = 0`**: program rejects registration. Set a real
  value.
- **Disk full**: the accumulator + audit log grow over time.
  ~10 MB per million sessions; rotate logs.

## Next steps

- `docs/economics.md` — pricing strategy, slashing math.
- `docs/deploy.md` — full operator guide.
- `docs/troubleshooting.md` — when things go sideways.
