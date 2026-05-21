# Performance tuning (Perf-1: `Periodic(1s)` fsync default)

## TL;DR

As of Perf-1, a stock `octravpn-node` defaults the receipt-journal's
fsync policy to `Periodic(1s)` instead of `EveryWrite`. This lifts the
per-node signed-receipt ceiling from **~225 RPS** to **~500 000 RPS**
on the same hardware (a ~2 000× ceiling lift, audit-8 §3 throughput
table; `crates/octravpn-node/benches/settle_throughput.rs`).

The trade-off: up to **one second** of signed receipts is at risk on a
**hard kernel/host crash** (power-loss, kernel panic, OS hang). A
process-only crash (SIGKILL, panic, OOM) still preserves every record
— `File::write_all` in append mode pushes straight to the OS page
cache. The audit-log + `journal rebuild --from-audit` CLI backstops
the gap; see [Recovery story](#recovery-story) below.

---

## Why we flipped the default

The receipt-seq journal is a per-`(session_id, seq)` floor every
receipt-signing call MUST consult before signing (threat-model items
**P1-8** and **P1-9** in
[`docs/v2-threat-model.md`](../v2-threat-model.md): a forced restart
must never let an attacker collect two distinct receipts at the same
`(session_id, seq)`).

Under the pre-Perf-1 `EveryWrite` policy, every `bump` paid one
`sync_data` round-trip. On a typical NVMe host that's a ~4.26 ms
per-receipt floor → ~225 RPS/node — the ceiling
[audit-8](../audit/2026-05-20-load-perf-audit.md) §3 flagged as the
operative throughput limit:

| Policy            | Per-bump latency | Per-node ceiling |
| ----------------- | ---------------- | ---------------- |
| `EveryWrite`      | 4.26 ms          | ~225 RPS         |
| `Periodic(1s)`    | 1.92 µs          | ~500 000 RPS     |

(Numbers measured on the bench host; cross-reference the full table
at [audit-8 §3](../audit/2026-05-20-load-perf-audit.md#3-throughput-headlines).)

Under `Periodic(1s)`, the per-bump fsync is amortised across all
receipts that arrive within the 1-second window. Every append still
lands in the page cache immediately; only the user→kernel durability
barrier is deferred.

---

## When to revert: financial-invariant operators

Operators running **exit nodes with high-value sessions** — where even
a single second of replay-from-audit is unacceptable, or where the
host is on bare-metal with a known-unreliable PSU — should revert via
TOML:

```toml
[control]
# Pre-Perf-1 default. Durable instantly per receipt, ceilings at
# ~225 RPS/node. Pick this for financial-invariant exit nodes.
fsync_policy = "every_write"
```

To stay on the new default, either omit the field entirely **or** be
explicit:

```toml
[control]
# Perf-1 default. ~500 000 RPS/node ceiling; ≤1 s loss window on hard
# crash, recoverable from the audit log.
fsync_policy = "periodic"
```

The field is wired into
[`crates/octravpn-node/src/config.rs::ControlCfg::fsync_policy`]; the
runtime enum is
[`octravpn_core::receipt_journal::FsyncPolicy`].

---

## Recovery story

The journal is **not** the only durable record of `(session_id, seq)`
under Perf-1. Two layers backstop the 1-second loss window:

1. **OS page cache.** Every `bump` appends 44 bytes via
   `File::write_all` in `O_APPEND` mode. There is no user-space
   buffer; the bytes are in the kernel page cache the instant the
   `write(2)` syscall returns. A process-only crash (SIGKILL, panic,
   OOM kill, segfault) loses **nothing** — only an OS-level crash
   (kernel panic, power loss, host hang) can discard unfsync'd page
   cache. Confirmed by the journal proptests in
   `crates/octravpn-core/src/receipt_journal/proptests.rs`.

2. **Audit log.** The HMAC-chained audit log
   (`crates/octravpn-node/src/audit/`) records every
   `(session_id, seq)` the daemon committed **before** signing. Even
   if the journal file is torn at the tail by a power-loss inside the
   1s window, the audit log carries the floor verbatim.

When the daemon refuses to start with `JournalError::ChecksumMismatch`
or a regressed floor, the operator runs:

```bash
octravpn-node journal rebuild \
    --from-audit /var/lib/octravpn/audit \
    --output     /var/lib/octravpn/receipts.bin
```

This walks every `audit-YYYY-MM-DD.jsonl` file, HMAC-verifies the
chain, harvests the signed seqs per session, computes
`floor = max(seqs)`, and writes a fresh v1 journal. The rebuild
validates by reopening the journal and diffing the floor map against
the audit-derived set; any divergence surfaces as exit code 4 with the
per-session diff. See
[`crates/octravpn-node/src/cli/journal.rs`](../../crates/octravpn-node/src/cli/journal.rs)
+ audit-9 H-RTO for the safety contract (a tampered audit log fails
the HMAC chain check; the CLI refuses to emit a journal).

**Operator drill:** the disaster-recovery runbook at
[`docs/audit/2026-05-20-dr-drill-audit.md`](../audit/2026-05-20-dr-drill-audit.md)
walks this end-to-end. The whole pipeline runs in well under 2 minutes
at typical sizes (~10k-entry audit logs).

### Hard edge: audit-log loss inside the same window

The audit log fsyncs in batches (`audit/batched.rs`,
`DEFAULT_BATCH_INTERVAL_MS = 100`, batch size 64). On a hard crash a
sub-batch tail can be lost from the audit log too. The current
contract:

- If the **audit log** also lost the receipt → that receipt is
  unrecoverable, but the receipts-monotonic invariant still holds
  because no other party has a signed copy either (the chain only
  sees settled-epoch summaries, not individual receipts). The operator
  re-signs at the next seq when the session bumps again.
- If the **audit log** has the receipt but the **journal** doesn't →
  `journal rebuild --from-audit` recovers verbatim.
- If both have the receipt and a torn-tail rules out trust →
  `octravpn-node journal verify --from-audit` cross-checks both before
  re-emitting.

For operators who cannot tolerate even the audit-log-tail risk,
`fsync_policy = "every_write"` removes the journal side of the
window. The audit-log side is governed separately by
`audit::BatchedAuditConfig` (Perf-N for a future PR).

---

## Cross-references

- [audit-8 §3 throughput headlines](../audit/2026-05-20-load-perf-audit.md)
  — the throughput table this PR derives from.
- [`crates/octravpn-node/benches/settle_throughput.rs`] — repro the
  numbers on your host: `cargo bench -p octravpn-node --bench
  settle_throughput`.
- [`docs/v2-threat-model.md` §3 P1-8 / P1-9] — the receipts-monotonic
  invariant the journal exists to enforce.
- [`docs/audit/2026-05-20-dr-drill-audit.md`] — the audit-9 H-RTO
  drill that exercises `journal rebuild --from-audit`.
