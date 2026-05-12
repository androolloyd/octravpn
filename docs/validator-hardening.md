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
| `/etc/octravpn/wallet.enc`          | Passphrase-encrypted wallet   | `0400 root:octravpn` |
| `/etc/octravpn/wg.key`              | WG master (HKDF parent)       | `0400 root:octravpn` |
| `/var/log/octravpn/audit/.audit.key`| HMAC chain key                | `0400 octravpn:octravpn` |

For the wallet specifically, prefer the encrypted-envelope form:

```sh
OCTRAVPN_WALLET_PASSPHRASE=$(systemd-creds decrypt wallet.cred) \
  octravpn wallet-encrypt --in plain.hex --out wallet.enc
```

Then unlock at boot via `systemd-creds` or HashiCorp Vault — never
ship the passphrase via env file on disk.

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
