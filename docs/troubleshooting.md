# OctraVPN — Troubleshooting

## General diagnostic flow

1. `octravpn doctor` (client) or `octravpn-node doctor` (node).
2. Check the systemd / launchd / Windows event log.
3. Check `/metrics` and `/health` on the node.
4. Check the chain via `octra cast call <program> get_validator <addr>`.

## Client issues

### `octravpn init` says "wallet.key already exists"

Pass `--force` to overwrite (you'll lose the old key), or delete
the file manually after backing it up.

### `octravpn nodes` returns an empty list

- The Octra testnet may have no active validators (onboarding
  paused; see `docs/octra-research.md`).
- Your `rpc_url` may be wrong. `octra cast rpc node_status` should
  return the current epoch.
- Try the local docker-compose harness (`docker compose up
  mock-rpc node1 node2 node3`).

### `octravpn connect` fails with "not enough active validators"

You asked for N hops but only M < N validators are active. Lower
`--hops` or wait for more nodes.

### `octravpn connect` fails with "exit announce: status 502"

The exit node's HTTP control plane is down. Pick a different exit
via `--region` or trial.

### Settlement says "claim exceeds escrow"

The exit node signed a receipt for more bytes than your deposit
covered. Either:

- You under-deposited; in future open a bigger session.
- The node is buggy / malicious. After settle reverts, use
  `claim_no_show` (past grace) to recover the full deposit, then
  follow up with `slash_no_show_with_open` (see
  `docs/attack-cost.md` § 2).

### Tunnel is up but my traffic isn't going through it

OctraVPN today opens the on-chain session and announces; the
transparent system-traffic capture is on the roadmap
(`docs/gap-analysis.md` § Tier A). You need to apply the printed
WireGuard config to your OS WG client manually. To verify the
tunnel is correct:

```sh
sudo wg-quick up /tmp/octravpn-wg.conf
curl ifconfig.me   # should show the exit hop's IP
```

## Node issues

### `octravpn-node register` says "insufficient balance"

The wallet doesn't have enough OCT to cover `initial_bond + fee`.
Fund the wallet and retry. Registration is idempotent.

### Daemon crashes with "open TUN device" error

- **Linux**: `setcap cap_net_admin,cap_net_bind_service+ep
  /usr/local/bin/octravpn-node`. Re-run.
- **macOS**: must run as root (`sudo`) or via launchd.
- **Windows**: install the `wintun.dll` driver. Run the service as
  LocalSystem.

### `octravpn-node doctor` says "kernel TUN module not loaded"

Linux only:

```sh
sudo modprobe tun
```

Add to `/etc/modules-load.d/tun.conf` to persist across reboots.

### Daemon runs but `/health` says "warming up"

Health-endpoint is uptime-based at v1 (placeholder; see
`docs/gap-analysis.md` § A4). After 5s it switches to "ok".

### Attestation is jailed: `last_attest_epoch + grace < current_epoch`

The daemon was offline past `attest_grace_epochs`. Recover:

1. Confirm the daemon is now running.
2. `octravpn-node --config /etc/octravpn/node.toml attest`
3. The chain auto-unjails on next attestation if `bond ≥
   min_bond`. If your bond was slashed below that, call
   `octravpn-node add-bond` first.

### `claim_earnings` says "bad opening"

Your local accumulator file is out of sync with the on-chain
Pedersen ledger. Symptoms: you can see `enc_earnings[your_addr]`
on chain, but your `(amount, blind_sum)` doesn't open it.

Recovery options:

1. **Restore** the accumulator from your last backup if you have
   one.
2. **Reconcile** by replaying every `SessionSettled` event your
   address participated in:

```sh
sudo octravpn-node --config /etc/octravpn/node.toml reconcile \
    --from-epoch 1234
```

(Reconcile is part of the gap-closing sprint; see
`docs/gap-analysis.md` § A2.)

### "double-signed receipt" slash on your validator

This should not happen with the stock binary, which refuses to
sign a receipt with different `bytes_used` for the same `(session,
seq)`. If you see this:

1. Inspect the audit log:
   `/var/log/octravpn/audit.log` (when the audit-log feature is
   wired — see `docs/gap-analysis.md` § B3).
2. The two evidence receipts on chain — pull via
   `octra cast tx <hash>` for the slash event.
3. If you signed both legitimately (impossible with stock code),
   there's a real bug — open an issue with the audit log excerpt.
4. If your key was compromised, rotate immediately:
   `octravpn-node rotate-keys`.

### Metrics: `octravpn_active_sessions` keeps growing

Sessions are TTL-evicted from the control plane after 1 hour idle
(see `docs/security.md` § 3 — `CONTROL_SESSION_TTL`). If they
don't evict, the sweeper background task may have crashed —
check `journalctl -u octravpn-node | grep sweep`.

## Chain / RPC issues

### `node_status` returns 5xx

Octra's RPC endpoint is down or rate-limiting. Switch to a
fallback endpoint (validators have their own RPCs; see
`docs/octra-research.md`).

### `octra_submit` says "invalid signature"

Most common causes:

1. Wallet secret doesn't match the address you claim to be (your
   `validator_addr` or `wallet.addr` in the config). Regenerate
   with `octra cast wallet new` and re-derive.
2. Tx canonical form drift between this client and a remote
   chain. The repo's canonical form is verified against
   `octra-labs/webcli/lib/tx_builder.hpp`; if the chain has been
   updated, raise an issue.

### `register_validator` says "bad attest sig"

The attestation signature is over `sha256(self_addr || tag_bond
|| epoch)`. Mismatches usually mean:

- Wrong `program_addr` (the `self_addr` in the AML program is the
  program's address, not yours).
- Stale `epoch` (the chain rolled forward between your attest and
  your tx).

Re-run `register_validator`; it builds a fresh signature against
the current epoch.

## Install / package issues

### `install.sh` says "unsupported OS"

Currently only Linux + macOS. Windows uses `install.ps1`.
Other Unixes (FreeBSD, OpenBSD) need to build from source.

### `cargo build` fails on aarch64-unknown-linux-gnu

Cross-compile via `cross` or `cargo-zigbuild`. The release CI uses
`cross` — see `.github/workflows/release.yml`.

### `cargo wix` fails to find wintun

The Windows MSI doesn't bundle wintun.dll due to license
constraints. Install it separately from
https://www.wireguard.com/install/.

## Performance issues

### High CPU on the node

Likely the per-packet boringtun decap + onion peel. Check
`top`/`htop` to confirm it's the daemon. If it scales with traffic
that's expected; if it's idle CPU, file an issue with a perf trace.

### Latency variance > 50ms

Multi-hop adds latency proportional to the hops × geographic
spread. Drop to `--hops 1` for latency-sensitive use.
