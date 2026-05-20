# OctraVPN — Audit-log verification runbook

The recurring "is my audit log clean?" check. Run **daily** via
cron, run **before and after** every upgrade or rotation, run on
demand whenever a node misbehaves. The audit log is the operator's
only post-mortem artifact; a verified-clean chain is what lets you
defend the node's behavior in a dispute.

## What the audit log is

The daemon writes two parallel persistent artifacts:

- **Audit log** — `crate::audit::AuditLog`. One JSONL file per
  UTC day at `<audit_dir>/audit-YYYY-MM-DD.jsonl`. Every line is
  HMAC-SHA256 chained to the previous line; the MAC covers
  `record_json` + the previous MAC, so a flipped byte anywhere
  breaks the chain at that line and every line after.
- **Receipt journal** — `octravpn_core::receipt_journal`. A
  binary file at `[control].receipt_journal_path` (default
  `./state/receipts.bin`). One `(session_id, last_signed_seq)`
  entry per session. Used as the floor that prevents
  forced-restart double-signing (P1-8/9).

The two artifacts are cross-checked: every signed-receipt seq in
the journal SHOULD have a corresponding `receipt_signed` row in the
audit log. A mismatch is a warning, not a fail — see §Cross-check
semantics.

## The recurring command

```sh
octravpn-node audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin
```

Exit-code contract:

| Exit | Meaning |
|---|---|
| 0 | All checks passed; audit log + journal are consistent. |
| 1 | Verification failure — one of the strict checks broke (chain MAC mismatch, journal CRC fail, journal seq=0 sentinel, etc.). |
| 2 | IO or parse error — usually a permissions issue or a truncated file. |
| 3 | Missing files — no audit log at `--audit-path` or no HMAC key at the conventional location. |

The HMAC key is auto-discovered next to the audit log: if
`--audit-path` is a directory, the tool looks for `.audit.key`
inside; if it's a single file, it looks for `<path>.key`. Pass
`--hmac-key <PATH>` to override.

## Schedule: daily cron + alert on non-zero

The shipped systemd unit does NOT include a verify timer (see
[`upgrades-linux.md §Per-systemd-target tweaks`](upgrades-linux.md#per-systemd-target-tweaks)
for the `octravpn-attest.timer` no-op caveat — verify is a separate
surface). Wire a cron job by hand:

```cron
# /etc/cron.d/octravpn-audit-verify
# Run daily at 03:17 UTC (off the top-of-hour storm).
17 3 * * * octravpn /usr/local/bin/octravpn-node audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin \
    >> /var/log/octravpn/audit-verify.log 2>&1 || \
    logger -t octravpn-audit-verify -p auth.crit "audit verify FAILED — exit $?"
```

The `logger -p auth.crit` trick lands the failure in syslog at
critical priority so any tail-syslog alerter (Promtail, Vector,
Splunk Universal Forwarder) sees it without a custom integration.

For systemd-only hosts, the equivalent timer:

```ini
# /etc/systemd/system/octravpn-audit-verify.service
[Service]
Type=oneshot
User=octravpn
ExecStart=/usr/local/bin/octravpn-node audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin

# /etc/systemd/system/octravpn-audit-verify.timer
[Timer]
OnCalendar=*-*-* 03:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

`systemctl enable --now octravpn-audit-verify.timer`. The unit
exits non-zero on a fail; the timer's `OnFailure=` hook (add as
needed) wires the alert.

> macOS launchd analog: a `LaunchDaemon` with `StartCalendarInterval`
> at `Hour=3` `Minute=17` and the same `ExecStart` shape.
> Windows analog: a Scheduled Task hitting `Restart-Service` …
> wait, that's the wrong analog — it's a Scheduled Task running
> the binary, alerting on `$LASTEXITCODE -ne 0`. <!-- UNVERIFIED -->

## The FileVerifyReport — cross-checking signed_seqs

The audit-log verifier (`crate::audit::AuditLog::verify_file`)
returns a `FileVerifyReport` carrying:

- `entries: u64` — number of audit-log lines walked.
- `first_error: Option<String>` — the first chain-break line, or
  `None` for a clean chain.
- `signed_seqs: BTreeMap<String, BTreeSet<u64>>` — per-session
  set of `(session_id, seq)` pairs harvested from
  `receipt_signed` rows.

The CLI consumes the `signed_seqs` map and cross-checks it against
the receipt journal's per-session floor. Three outcomes:

| Outcome | Semantics |
|---|---|
| `OK` | Every journal record's session_id has at least one matching audit row. |
| `Warn` | Journal-only sessions OR audit-only sessions exist. Reported in the detail string; does NOT flip `overall_pass`. |
| `Skipped` | Audit log was already broken, so cross-check is meaningless. |

The `Warn` outcome is expected when the audit log carries entries
for sessions that never reached the journal (e.g. an `announce`
with no subsequent `receipt_signed`) — that asymmetry is normal.
The cross-check is **symmetric**: orphan-journal AND orphan-audit
sessions are both reported, both as `Warn`.

> If your cross-check warns about *journal-only* sessions (the
> journal has a session id the audit log doesn't), that's a
> stronger signal. The receipt journal only gets a record when
> the daemon successfully signs a receipt; if a `receipt_signed`
> row never made it to the audit log for the same session, you
> have a write ordering bug. File an issue tagged `audit
> ordering-bug` and capture the journal + audit log.

## Recovering from a chain break

`audit verify` failed. The detail string names the file and line
number, e.g.:

```text
audit log:        FAIL     /var/lib/octravpn/audit/audit-2026-05-15.jsonl: line 1247: MAC mismatch
```

### Step 1 — Localize the break

```sh
# Capture the broken line + a few neighbours for forensic context.
sed -n '1245,1250p' /var/lib/octravpn/audit/audit-2026-05-15.jsonl
```

### Step 2 — Decide: tampering vs disk corruption

The MAC-mismatch line tells you the chain broke at that line.
The cause is one of two things:

- **Tampering**: somebody (a process, a human) modified the line.
  The `record_json` field doesn't match the MAC, which means
  somebody rewrote the JSON without recomputing the MAC (which
  would require the HMAC key, which lives in the audit dir as
  `.audit.key` mode 0600).
- **Disk corruption**: bit flip during a power loss, a filesystem
  bug, an over-committed COW backend. The line was written
  correctly; the bytes on disk don't match what was written.

Discriminators:

| Signal | Implies |
|---|---|
| `.audit.key` mode is 0600 root-owned, no anomalous reads in `auditd` | Disk corruption more likely |
| Line `record_json` field parses as JSON cleanly but the MAC doesn't match | Disk corruption (a bit flip in the MAC region) OR tampering with the MAC alone |
| Line `record_json` field is malformed JSON (truncated, garbled) | Disk corruption — the line was atomically written, so partial writes shouldn't happen, but torn reads on power loss can |
| `dmesg` shows a contemporaneous filesystem error around the audit file | Disk corruption confirmed |
| Last few lines of the file are all clean but line N is broken | Tampering more likely — disk corruption tends to cluster |

If you suspect tampering, **stop the daemon, do not continue
running**. File an internal incident; the operator wallet and
PVAC secret may be compromised too. Rotate everything per
[rotation-master.md §Coordinated rotations](rotation-master.md#coordinated-rotations)
and inform any dependent parties via your incident channel.

If you suspect disk corruption, the audit log is unrecoverable
for the day in question (the chain can't be re-MAC'd without the
HMAC key being used to retroactively rewrite history — by
design). Move on to step 3.

### Step 3 — Truncate the broken day, restart the chain

The audit log writer resets the chain at midnight UTC rotation, so
a broken day does NOT contaminate the next day's file. Today's
file is the only one affected:

```sh
sudo systemctl stop octravpn-node

# Archive the broken file rather than deleting — the operator may
# need it for forensic analysis later.
sudo mv /var/lib/octravpn/audit/audit-2026-05-15.jsonl \
    /var/lib/octravpn/audit/broken/audit-2026-05-15.jsonl.broken.$(date +%s)

# The receipt journal is independent; do NOT touch it.
sudo systemctl start octravpn-node
```

On boot, the daemon creates a fresh `audit-2026-05-15.jsonl` (if
the rotation hasn't kicked in) and starts a new HMAC chain.

> **The window between break and restart is unaudited.** Any
> receipts the daemon signed between the broken line and the
> restart are visible in the receipt journal but not in any audit
> log. If a dispute references this window, the operator has no
> defensible audit evidence — accept the dispute or run a manual
> reconstruction from the receipt journal's per-session
> `signed_seq`.

### Step 4 — Rebuild from the journal cross-check

The receipt journal's per-session floor is intact (it has its own
per-record CRC32; see §Corrupted receipt journal in
[recovery.md](recovery.md#corrupted-receipt-journal) for the
journal-side equivalent failure). You can use the journal to
*lower-bound* what the daemon signed during the audit gap:

```sh
octravpn-node audit replay \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin \
    --format json \
| jq -c 'select(.source == "journal")'
```

Every `journal_floor` row tells you the last seq the daemon signed
for that session. Compare against the surviving audit log: any
`receipt_signed` row with `seq < floor` means the receipt was
signed but not audited.

## Off-site replication

For real production deployments, ship the audit log + HMAC key
off-host so a compromise of the operator host doesn't also
compromise the audit evidence.

The docker-compose harness has the audit dir as a bind mount:

```yaml
# docker-compose.yml (excerpt)
services:
  octravpn-node:
    volumes:
      - ./audit-dir:/var/lib/octravpn/audit:rw
```

To extend to off-site:

```sh
# Cron job — copy to S3-compatible storage every 5 minutes.
*/5 * * * * octravpn rclone copy \
    /var/lib/octravpn/audit/ \
    s3:audit-archive-octravpn/$(hostname)/ \
    --include 'audit-*.jsonl' \
    --include '.audit.key' \
    --transfers 2 --checkers 4
```

Or push directly into a SIEM (Splunk, Datadog Logs, Loki):

```sh
# Vector / Promtail configuration excerpt:
sources:
  octravpn_audit:
    type: file
    include: [/var/lib/octravpn/audit/audit-*.jsonl]
    fingerprint:
      strategy: device_and_inode
```

Two correctness rules:

1. **Ship the HMAC key OFF-host alongside the JSONL**, OR keep
   the key on-host and accept that the off-host copy is
   verifiable only against the on-host key. The latter is the
   usual SIEM setup — the SIEM sees the chain as opaque JSON
   lines and trusts the daemon's prior verification.
2. **Append-only.** If your SIEM allows re-writes, gate the
   audit-log ingestion path with a "no-edit" ACL. An audit log
   that an attacker can rewrite is no audit log at all.

## Common audit-verify mistakes

1. **HMAC key not at the conventional path.** If the daemon
   was started with a custom audit dir, the key is at
   `<custom-dir>/.audit.key`. The verify CLI auto-discovers but
   only at the conventional location; non-default paths require
   `--hmac-key <PATH>`. Exit 3 with "HMAC key not found at …" is
   the symptom.
2. **Verifying an old day's file with the current key.** Each
   audit dir has one HMAC key for its lifetime; the key is not
   rotated when the daily file rotates at midnight. If you copied
   only the JSONL files off-host but not the key, verification
   fails on every line with MAC mismatch. Always copy
   `.audit.key` alongside.
3. **Running verify against a directory that contains broken-day
   archives.** The verifier walks every `audit-*.jsonl` file
   under the directory; a stray broken file from a prior
   incident causes the run to fail. Move broken files to a
   sibling `broken/` subdir, as in §Step 3 above.

## References

- [Audit log source — `crates/octravpn-node/src/audit/`](../../crates/octravpn-node/src/audit/).
- [Audit CLI — `crates/octravpn-node/src/audit_cli.rs`](../../crates/octravpn-node/src/audit_cli.rs).
- [Receipt journal — `crates/octravpn-core/src/receipt_journal/`](../../crates/octravpn-core/src/receipt_journal/) <!-- UNVERIFIED — exact path -->.
- [Rotation master](rotation-master.md) — every rotation must
  show up in the audit log; this runbook covers the verify
  side.
- [Recovery](recovery.md) — when the journal AND the audit log
  are both compromised.
- [Threat model — audit chain](../v2-threat-model.md) — for the
  invariants the chain is designed to defend.
