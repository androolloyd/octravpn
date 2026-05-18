# Validator (paid endpoint) hardening playbook

This document is for **Octra protocol validators** who additionally run
a paid OctraVPN endpoint. Everything below is in addition to the
baseline Octra validator setup; the items here protect the OctraVPN
data-plane and control-plane surface specifically.

The mental model: even though the OctraVPN program no longer bonds you
at the application layer, your **Octra protocol bond** is at risk if
your endpoint misbehaves in a way clients can prove on-chain
(equivocation, double-sign). Treat your endpoint like the rest of your
validator stack.

## 1. OS-level confinement

### 1.1 systemd unit

The release ships a systemd unit at
`deploy/systemd/octravpn-node.service`. Recommended overrides:

```ini
# /etc/systemd/system/octravpn-node.service.d/override.conf
[Service]
# Drop privileges as soon as the WG socket is bound.
User=octravpn
Group=octravpn
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Filesystem sandbox.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/octravpn /var/lib/octravpn
NoNewPrivileges=true

# Namespace + syscall hardening.
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectClock=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot @swap

# Resource caps so a runaway can't take the host down.
TasksMax=512
MemoryMax=2G
CPUQuota=200%
LimitNOFILE=65536
```

Validate with:

```sh
systemd-analyze security octravpn-node
# target: score ≤ 1.5 ("OK")
```

### 1.2 AppArmor profile (Debian/Ubuntu)

```apparmor
# /etc/apparmor.d/usr.local.bin.octravpn-node
#include <tunables/global>

profile octravpn-node /usr/local/bin/octravpn-node {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/local/bin/octravpn-node mr,
  /etc/octravpn/** r,
  /var/log/octravpn/** rw,
  /var/lib/octravpn/** rw,

  network inet  stream,
  network inet6 stream,
  network inet  dgram,
  network inet6 dgram,
  capability net_admin,
  capability net_bind_service,

  deny /proc/sys/kernel/** w,
  deny /sys/** w,
  deny @{HOME}/** r,
  deny /root/** r,
}
```

`apparmor_parser -r /etc/apparmor.d/usr.local.bin.octravpn-node`

### 1.3 SELinux (RHEL / Fedora)

A starter `.te` file ships in `deploy/selinux/octravpn-node.te`. Build
with `make -f /usr/share/selinux/devel/Makefile` and load via
`semodule -i octravpn-node.pp`.

## 2. Secrets at rest

| File                                | What                          | Recommended ACL |
| ----------------------------------- | ----------------------------- | --------------- |
| `/etc/octravpn/wallet.key`          | Wallet secret (32B raw / hex) | `0400 root:octravpn` |
| `/etc/octravpn/wallet.key.sealed`   | Passphrase-encrypted wallet (P1-6) | `0400 root:octravpn` |
| `/etc/octravpn/wallet.enc`          | (legacy v1.1 envelope)        | `0400 root:octravpn` |
| `/etc/octravpn/wg.key`              | WG master (HKDF parent)       | `0400 root:octravpn` |
| `/etc/octravpn/wg.key.sealed`       | Passphrase-encrypted WG master (P1-6) | `0400 root:octravpn` |
| `/var/lib/octravpn/circle.toml`     | v2 circle state cache         | `0400 root:octravpn` |
| `/var/lib/octravpn/receipts.bin`    | Persistent receipt-seq journal (P1-8/9) | `0600 octravpn:octravpn` |
| `/var/log/octravpn/audit/.audit.key`| HMAC chain key                | `0400 octravpn:octravpn` |

### 2.1 The `seal-keys` flow (P1-6)

In-daemon subcommand that wraps both the wallet secret and the WG
master under one passphrase via the `OCTRA-WALLET-V1` envelope
(ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256 200k). Supersedes v1.1
`wallet-encrypt`. Full walkthrough: `docs/v2-operator-key-hygiene.md`
§4 / `docs/v2-operator-flow.md` §"Sealing on-disk keys".

```sh
# 1. Seal both configured key files.
export OCTRAVPN_KEY_PASSPHRASE='...'
octravpn-node --config /etc/octravpn/node.toml seal-keys
# Produces wallet.key.sealed + wg.key.sealed atomically.

# 2. Point the TOML at the sealed files + enable strict mode:
[chain]
wallet_secret_path  = "/etc/octravpn/wallet.key.sealed"
require_sealed_keys = true
[tunnel]
wg_secret_path      = "/etc/octravpn/wg.key.sealed"

# 3. Once boot succeeds, shred the plaintext originals:
octravpn-node --config /etc/octravpn/node.toml seal-keys --remove-plaintext
```

Emergency rotation — `unseal-keys --tmpdir <PATH>` decrypts onto a
tmpfs / ramdisk (refused on non-memory-volatile mounts on Linux). Mount
tmpfs, unseal, re-seal under a fresh passphrase, swap, restart, umount.

### 2.2 Passphrase resolution

`seal-keys` / `unseal-keys` (`crates/octravpn-node/src/seal.rs`):
`--passphrase` > `--passphrase-file` > `--passphrase-stdin` >
`OCTRAVPN_KEY_PASSPHRASE` > TTY prompt (interactive only). The daemon
at boot reads sealed files using `OCTRAVPN_KEY_PASSPHRASE` (legacy
`OCTRAVPN_WALLET_PASSPHRASE` honoured for back-compat). For systemd:

```ini
# /etc/systemd/system/octravpn-node.service.d/passphrase.conf
[Service]
EnvironmentFile=/etc/octravpn/keys.env       # chmod 0600
```

Better: fetch the passphrase from `systemd-creds` / Vault / AWS
Secrets Manager at deploy time and write the EnvironmentFile to a
tmpfs mount the daemon unmounts after boot. Never ship a long-lived
plaintext passphrase in `/etc/`.

### 2.3 Strict mode (P1-6 closed)

`[chain].require_sealed_keys = true` refuses to boot if any
configured secret is plaintext-on-disk. Error
`CoreError::PlaintextKeyOnDisk` names the offending path and quotes
the `seal-keys` invocation. Devnet harnesses leave it off;
production v2 turns it on unconditionally.

## 3. Control-plane exposure

The control plane (default `0.0.0.0:51821`) carries:
- Session-announce: client publishes `(session_id, client_wg_pubkey)`
- Receipt-proposal: client fetches dual-sig receipt
- `/health`, `/metrics`, `/events` (SSE)

Recommended bind: `127.0.0.1:51821` with a TLS reverse proxy in front
(see `docs/operator-guide.md` §5a). Direct binding to a public IP is
acceptable but exposes the rate-limit middleware as the only DoS
defense; the proxy adds Layer-7 inspection + cert termination.

If you must bind to 0.0.0.0 (no proxy):

- Confirm rate limit is active: `curl -s http://localhost:51821/metrics | grep rate_limit` (counter present means middleware is wired).
- Set firewall to allow only the data-plane UDP (`51820/udp`) publicly
  and reverse-proxy `51821/tcp` from localhost.
- Use a per-IP ban-list (fail2ban) keyed on 429 responses.

## 4. Data-plane hardening

### 4.1 WireGuard

`boringtun` runs in-process so you can drop the linux-kernel WG module
entirely. If you keep the kernel module too, ensure only one binds
`51820/udp`.

### 4.2 Tunnel rate / connection caps

`crates/octravpn-node/src/onion.rs::OnionRouter` accepts unbounded
sessions today. Cap with environment overrides:

```sh
OCTRAVPN_MAX_SESSIONS=10000 \
OCTRAVPN_MAX_SESSION_TTL_S=3600 \
octravpn-node run ...
```

These match the existing `CONTROL_SESSIONS_CAP` / `CONTROL_SESSION_TTL`
constants and will reject session-announces past the cap with `429`.

### 4.3 Packet floor

For each session, the data plane enforces:
- `BoundedMap` TTL (idle session reaped after 1 h)
- Per-IP rate limit on the control plane (default 100 req/s sustained, 200 burst)
- Per-session monotonic `receipt_seq` (the program rejects stale settlement)

If you observe pathological traffic, the next escalation is `nftables`:

```sh
# Cap inbound UDP/51820 to 50k pps per source IP.
nft add rule inet filter octravpn meter src-rate { ip saddr limit rate over 50000/second } drop
```

## 5. Slashing-evidence response

If a client publishes evidence that **you** equivocated (signed two
contradictory receipts for the same `(session_id, seq)`), Octra
protocol slashing will hit your bond. To respond:

1. Receive evidence (PR/issue/email): JSON blob with both
   `(receipt_a, sig_a, receipt_b, sig_b)`.
2. Verify locally:
   ```sh
   octravpn slash-evidence verify <blob.json>
   ```
   The tool checks both signatures verify under your published
   `receipt_pubkey`. If yes → your endpoint key was compromised;
   rotate immediately via `octravpn-node rotate-keys`.
3. If your evidence verifies but the timestamps suggest a forgery
   (replayed signatures, mismatched session), publish a defense:
   ```sh
   octravpn slash-evidence dispute --blob <blob.json> --reason ...
   ```
4. If neither: file with the Octra dispute mechanism (out of scope here).

The `slash-evidence` subcommand is in `crates/octravpn-client/src/commands/slash.rs`.

## 6. Monitoring + alerting

Alert on every one of these (Prometheus rules):

```yaml
groups:
  - name: octravpn-validator
    rules:
      - alert: AttestationStale
        expr: time() - octravpn_last_attestation_unix > 300
        for: 1m
        labels: { severity: page }

      - alert: NotOctraValidator
        expr: octravpn_is_octra_validator == 0
        for: 1m
        labels: { severity: page }

      - alert: RateLimitSaturated
        expr: rate(octravpn_rate_limit_rejections_total[1m]) > 50
        for: 5m
        labels: { severity: warn }

      - alert: AuditChainBreak
        expr: octravpn_audit_chain_broken == 1
        labels: { severity: page }

      - alert: SessionsApproachingCap
        expr: octravpn_active_sessions / 10000 > 0.8
        for: 5m
        labels: { severity: warn }
```

Run the audit-chain verifier as a periodic check (every 5 min, cron):

```sh
octravpn-node verify-audit-log /var/log/octravpn/audit/audit-$(date -u +%F).jsonl
```

A non-zero exit means tamper detected; flip the
`octravpn_audit_chain_broken` gauge in your textfile collector.

## 7. Backups + key rotation

| Item                          | Cadence            | Method                         |
| ----------------------------- | ------------------ | ------------------------------ |
| `wallet.key` / `wallet.enc`   | One-time at setup  | Offline + paper                |
| `wg.key`                      | One-time at setup  | Offline + paper                |
| Earnings accumulator `*.acc`  | Daily              | rsync to two off-host stores   |
| Audit log + `.audit.key`      | Daily              | rsync to a write-once store    |
| `.audit.key`                  | At every key rot   | Encrypted at rest, separate store |

Rotate receipt-signing keys after any compromise or annually:

```sh
sudo systemctl stop octravpn-node
sudo octravpn-node rotate-keys --config /etc/octravpn/node.toml
sudo systemctl start octravpn-node
```

`rotate-keys` publishes new `(wg_pubkey, receipt_pubkey, view_pubkey)`
via the AML `rotate_keys` entrypoint; new sessions use the new keys
immediately, in-flight sessions still settle against the old keys
(snapshot at session open).

## 8. Incident-response runbook

| Symptom                                    | First action                                            |
| ------------------------------------------ | ------------------------------------------------------- |
| `/health` returns 503 attestation_stale    | Check Octra protocol-validator status; expect chain RPC reachable. |
| Sudden burst of session-announces from one IP | Confirm rate-limit middleware logs 429; consider tightening `OCTRAVPN_RATE_BURST`. |
| Earnings drift between local and chain     | `octravpn-node reconcile-earnings` (audits committed earnings vs. local accumulator). |
| Audit chain break alert                    | Pull the file + `.audit.key`, run `verify-audit-log`; if mismatch, treat host as compromised — rebuild + restore from earlier backup. |
| Validator jailed on Octra                  | Investigate protocol-level cause first; dVPN endpoint becomes inactive automatically because `is_octra_validator` returns false. |
| Stealth-claim fails AEAD                   | Most likely receiver lost their view_secret — useless beyond logging. Continue serving traffic; no rotation needed. |

## 9. Defense-in-depth summary

| Layer                           | Mechanism                                                                 |
| ------------------------------- | ------------------------------------------------------------------------- |
| **Economic**                    | Octra protocol bond + slashing (delegated, not duplicated)                |
| **Cryptographic**               | Dual-signed receipts, ECDH stealth, HMAC audit chain                       |
| **Network**                     | TLS reverse proxy, control-plane rate limit, optional nftables             |
| **Process**                     | systemd hardening, AppArmor/SELinux, non-root + read-only FS               |
| **Operational**                 | Per-key backups, regular rotation, Prometheus alerts on every failure mode |
| **Forensic**                    | Append-only HMAC-chained audit log + scheduled `verify-audit-log`          |

## 10. WG private-key passphrase wrapping

`wg.key` is the HKDF parent of the noise static key AND the receipt-
signing key — compromise = ability to forge receipts that feed
`slash_double_sign`. `seal-keys` §2.1 wraps it under the same envelope
as the wallet (both go through `read_secret_32_or_sealed` in
`octra-foundry/crates/octra-core/src/util.rs`).

Per-OS keyring alternatives in `docs/v2-operator-key-hygiene.md` §4:

- **`seal-keys` (default).** Pair with a kernel-keyring or Keychain-
  backed `EnvironmentFile` so the passphrase isn't long-lived on disk.
- **Linux kernel keyring.** `keyctl padd user OCTRAVPN_KEY_PASSPHRASE
  @u` + ExecStartPre helper. Cleared on reboot.
- **macOS Keychain.** `security find-generic-password -w` at
  ExecStartPre. Survives reboot; protected by login password.

Either way the on-disk artefact is useless without the passphrase; an
exfiltrator is reduced to offline PBKDF2-200k brute force — hence the
entropy floor (`docs/v2-threat-model.md` P1-4).

## 11. Audit cross-links

- `docs/v2-rust-leak-audit.md` — daemon leak surface; `/events` SSE
  auth (P0-1) is the highest-impact item closed.
- `docs/v2-threat-model.md` §1 row 8 + `v2-operator-key-hygiene.md`
  §4 — `seal-keys` (P1-6) closes plaintext-on-disk; strict mode is
  the production gate.
- P1-5 — `chain_id` + `program_addr` + `circle_id` folded into the
  receipt signing payload; v1.1 ↔ v2 ↔ devnet ↔ mainnet replay fails.
- P1-8 / P1-9 — persistent `receipt_journal.rs` floor closes the
  restart-replay double-sign window (§6).

Open items (notably P0-2 RPC cert pinning) tracked in
`docs/v2-threat-model.md`.
