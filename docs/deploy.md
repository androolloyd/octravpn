# OctraVPN — Operator Deployment Guide

For validator operators running `octravpn-node` in production.

## 1. Sizing

| Resource | Minimum | Recommended |
| --- | --- | --- |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 1 GiB | 4 GiB |
| Disk | 10 GiB | 50 GiB SSD |
| Network | 100 Mbps symmetric | 1 Gbps symmetric |
| Public IPv4 | required | required + IPv6 |

Storage is mostly logs + the chain RPC cache + a small WAL of accepted
receipts and the validator earnings accumulator. The accumulator file
must be backed up; loss = loss of unclaimed earnings.

## 2. Firewall / NAT

Open these ports:

| Direction | Port | Use |
| --- | --- | --- |
| in/out | 51820/udp | WireGuard data plane (configurable) |
| in/out | 51821/tcp | HTTP control plane (`/session`, `/health`, `/metrics`) |
| out only | 443/tcp | Octra RPC (to your configured `rpc_url`) |

If you're behind NAT, port-forward 51820/udp and 51821/tcp to the host.
The validator's on-chain `endpoint` field must reach the host from the
public internet — clients discover and connect to it.

## 3. Permissions

| OS | What it needs | How install.sh provides it |
| --- | --- | --- |
| Linux | `CAP_NET_ADMIN` to open `/dev/net/tun`, `CAP_NET_BIND_SERVICE` to bind 51820 | `setcap cap_net_admin,cap_net_bind_service+ep …` |
| macOS | root (utun is root-only) | launchd service runs as root |
| Windows | LocalSystem (wintun driver) | SCM service runs as LocalSystem |

The systemd unit applies `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, and limits `CapabilityBoundingSet` to those two caps.

## 4. Provisioning

```sh
sudo octravpn-node init --config /etc/octravpn/node.toml \
                        --rpc-url https://octra.network/rpc \
                        --program-addr oct...REAL_OCTRAVPN_PROGRAM...
sudo chown -R octravpn:octravpn /etc/octravpn
sudo octravpn-node doctor
```

The init step writes:

```
/etc/octravpn/node.toml          # config
/etc/octravpn/wallet.key         # 32-byte hex (chmod 0600)
/etc/octravpn/wg.key             # WG master seed
/etc/octravpn/fhe.sk             # reserved
/etc/octravpn/fhe.pk             # reserved
/var/lib/octravpn/accumulator    # Pedersen earnings accumulator
```

## 5. Backup

The single load-bearing file is `wallet.key`. Without it you cannot
sign attestations and your bond is unrecoverable on the unbond timer.

Recommended:

```sh
# Encrypt with age, store offsite.
sudo age -e -i ~/.config/age/key.txt -o /backup/wallet.key.age /etc/octravpn/wallet.key
```

The accumulator file (`/var/lib/octravpn/accumulator`) holds the
running `(amount, blind_sum)` you'll need to open the on-chain
Pedersen earnings ledger. Backing this up too saves you from having to
re-scan chain events after a disk failure.

## 6. Monitoring

The node exposes:

- `GET http://<host>:51821/health` — returns 200 if attestation is
  fresh.
- `GET http://<host>:51821/metrics` — Prometheus-format counters
  (`octravpn_announces_total`, `octravpn_receipts_signed_total`,
  `octravpn_bytes_served_total`, `octravpn_active_sessions`,
  `octravpn_state_lookups_total`).

Sample Prometheus scrape config:

```yaml
- job_name: octravpn-node
  static_configs:
    - targets: ['node1.example:51821']
  metrics_path: /metrics
  scheme: http
```

Sample alert (Prometheus AlertManager):

```yaml
- alert: OctraVPNNodeStaleAttestation
  expr: time() - octravpn_attestation_last_unix > 600  # > 10 min
  for: 5m
  labels: { severity: critical }
  annotations:
    summary: "octravpn-node failed to refresh attestation"
```

## 7. Upgrades

```sh
# 1. Stop the daemon.
sudo systemctl stop octravpn-node

# 2. Reinstall with the new version.
curl -fsSL https://octravpn.org/install.sh | sudo sh -s -- --version=0.3.0 --node --no-service

# 3. Re-start.
sudo systemctl start octravpn-node

# 4. Confirm.
octravpn-node doctor
```

The chain side handles migrations through `rotate_keys` if the new
version changes the key schema — your bond stays bonded.

## 8. Slashing avoidance checklist

- ☐ Backup `wallet.key` + accumulator.
- ☐ `octravpn-node doctor` passes before enabling the service.
- ☐ Attestation refresh interval (`refresh_every_epochs`) ≤ half of
  the chain's `attest_grace_epochs`. Default 5 vs grace 50 leaves
  ample slack.
- ☐ Time sync (chronyd/ntpd) running — bad clocks reject attestations.
- ☐ NAT / firewall verified by `octravpn-node doctor`.
- ☐ Receipt-signing key is never the same as wallet key (HKDF takes
  care of this automatically).
- ☐ Monitor `/metrics` for `octravpn_attestation_failures_total` (TBD
  in upcoming release).

## 9. Migration / disaster recovery

If a host dies hard:

1. Restore `wallet.key` from offsite backup.
2. `octravpn-node init` against the *same* `validator_addr`. The
   on-chain `validators[addr]` record persists; your bond stays
   bonded.
3. Run `octravpn-node rotate-keys` if you suspect the old WG/receipt
   key was compromised. (Same wallet, fresh derived subkeys.)
4. Restore the accumulator file. Without it, run
   `octravpn-node reconcile` (TBD) which re-scans chain events to
   rebuild the (amount, blind_sum) pair.
5. `sudo systemctl restart octravpn-node`.
6. `octravpn-node doctor` to confirm.

## 10. Quick reference

```sh
# Identity
octravpn-node identity

# Start / stop / status
sudo systemctl {start,stop,status} octravpn-node
sudo journalctl -u octravpn-node -f

# Force a one-shot attestation
sudo octravpn-node --config /etc/octravpn/node.toml attest

# Claim accumulated earnings
sudo octravpn-node --config /etc/octravpn/node.toml claim-earnings

# Refresh keys (rotate WG + receipt keys; wallet key unchanged)
sudo octravpn-node --config /etc/octravpn/node.toml rotate-keys

# Update local earnings accumulator from a settle event
sudo octravpn-node --config /etc/octravpn/node.toml accumulator-add \
    --delta-amount 1000 --delta-blind-hex 9f6a...
```
