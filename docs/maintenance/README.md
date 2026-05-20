# OctraVPN — Operator Maintenance

Operator-facing maintenance, upgrade, and rotation runbooks for a
production `octravpn-node`. This directory is the umbrella for the
five recurring tasks an operator has to do *after* a node is deployed:
version upgrades, key rotations, cert rotations, audit-log
verification, and disaster recovery.

End-user maintenance lives in [`docs/users/`](../users/) and is out
of scope here.

> Looking for the first-time install? Use
> [`docs/install.md`](../install.md) for the just-try-it path or
> [`docs/operators/mainnet-deployment.md`](../operators/mainnet-deployment.md)
> for the production walkthrough. This directory assumes you have a
> running node already.

## Upgrade vs rotate vs recover

| You want to … | You are doing | Start here |
|---|---|---|
| Move from `v0.1.x` to `v0.1.(x+1)` (same schema) | **Upgrade** | [upgrades-linux.md](upgrades-linux.md) / [upgrades-macos.md](upgrades-macos.md) / [upgrades-windows.md](upgrades-windows.md) |
| Move from a *retired* major (v1 → v2 → v3) | **Migrate** (new circle, new program addr — not an in-place upgrade) | [upgrades-linux.md §Major version migrations](upgrades-linux.md#major-version-migrations) |
| Replace a key/secret on a schedule or after suspected compromise | **Rotate** | [rotation-master.md](rotation-master.md) |
| The node won't boot / a key is lost / the journal is corrupt | **Recover** | [recovery.md](recovery.md) |
| Confirm the audit chain is clean | **Verify** | [audit-verify.md](audit-verify.md) |

If you're in an incident, jump straight to [`recovery.md`](recovery.md)
— it walks the daemon boot sequence phase by phase so you can locate
the broken step quickly.

## Per-OS path routing

Every command in this directory uses the OS-conventional layout for
the host OS. The same `node.toml` schema works on all three; only
the absolute paths differ:

| Surface | Linux | macOS | Windows |
|---|---|---|---|
| Config dir | `/etc/octravpn/` | `/usr/local/etc/octravpn/` (system) or `~/.octravpn/` (user) | `%ProgramData%\octravpn\` |
| State dir (audit log, receipt journal, sealed keys) | `/var/lib/octravpn/` | `/usr/local/var/octravpn/` | `%ProgramData%\octravpn\state\` |
| Log dir | `/var/log/octravpn/` | `/usr/local/var/log/` | `%ProgramData%\octravpn\logs\` |
| Service surface | `systemctl` (`octravpn-node.service`) | `launchctl` (`com.octravpn.node.plist`) | `Restart-Service octravpn-node` |
| Service unit file | [`deploy/systemd/octravpn-node.service`](../../deploy/systemd/octravpn-node.service) | [`deploy/launchd/com.octravpn.node.plist`](../../deploy/launchd/com.octravpn.node.plist) | (shipped in the MSI, see Windows doc) <!-- UNVERIFIED -->|
| Passphrase env file | `/etc/octravpn/keys.env` (mode 0600) | Keychain entry + LaunchDaemon env | system-wide env var or DPAPI <!-- UNVERIFIED --> |

If you bind-mount any of these into Docker (the supported test-harness
path; see memory note "Docker-only test harness"), make sure
`audit_dir`, `receipt_journal_path`, and the sealed-key dir all
survive container restart — they are the only files the daemon
*requires* to be durable. Everything else is reconstructable from
chain state.

## The five maintenance categories

### 1. Version upgrades

Replace the binary with a newer release. Same schema, same chain
program, same circle. Reversible by re-installing the previous
package.

- [Linux](upgrades-linux.md) — `.deb` / `.rpm` from
  [`docs/release.md`](../release.md), systemd flow.
- [macOS](upgrades-macos.md) — Homebrew (when shipped) or manual
  tarball swap, launchd flow.
- [Windows](upgrades-windows.md) — MSI or ZIP swap, Service
  Manager flow.

### 2. Sealed-key rotation

The on-disk wallet secret + WG static key. Lives in
`octra_core::wallet_enc` envelopes resolved at boot via
`OCTRAVPN_KEY_PASSPHRASE`. Existing runbook:
[`docs/v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md)
(decision tree + cadence in [rotation-master.md](rotation-master.md)).

### 3. TLS cert rotation

The `mesh serve` HTTPS listener cert (clients pin its SPKI via the
`oct://` URL). Existing runbook:
[`docs/operators/tls-rotation.md`](../operators/tls-rotation.md)
(decision tree + cadence in [rotation-master.md](rotation-master.md)).

### 4. PVAC pubkey rotation

The ~4 MB lattice PVAC public key registered on chain via
`octra_registerPvacPubkey`. Has a 24h dual-decrypt window. Existing
runbook: [`docs/operators/pvac-rotation.md`](../operators/pvac-rotation.md)
(decision tree + cadence in [rotation-master.md](rotation-master.md)).

### 5. Audit-log verification

The HMAC-chained JSONL audit log + the receipt-journal floor. The
daemon writes both; an operator must verify the chain (a) before any
upgrade and (b) on a daily cron. Runbook:
[`audit-verify.md`](audit-verify.md).

## Where to file maintenance bugs

If a runbook breaks (a CLI flag goes away, a default path shifts,
an exit code changes meaning), open an issue tagged `maintenance`
and the doc file name. The runbooks here are the contract the
operator relies on; we treat regressions as bugs, not docs drift.
