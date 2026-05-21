# Audit-log operations (Perf-6)

The OctraVPN node writes an append-only, HMAC-chained audit log to
`<audit_dir>/audit-YYYY-MM-DD-NNN.jsonl`. Every line is committed to
by an HMAC-SHA256 chain rooted at `<audit_dir>/.audit.key`; an
attacker who can't read the key file cannot rewrite or delete history
undetectably.

This page covers the Perf-6 additions: **size-based rotation**, the
**chain-tip file**, and the **skip-to-tip boot replay**.

## TL;DR — defaults

```toml
[audit]
max_file_bytes = 268_435_456   # 256 MiB
max_file_count = 32            # ~8 GiB retention ceiling
boot_replay    = "skip_to_tip" # "full" to force the legacy walk
```

These are the values you get if you don't write an `[audit]` block.

## What changed in Perf-6

Pre-Perf-6 the node wrote one file per UTC day
(`audit-YYYY-MM-DD.jsonl`). On a node ingesting 100 receipts/s, a
30-day-old log was ~260 M lines = ~26 s of HMAC-chain re-walk at
boot (audit-8 §5.2). Three knobs close that gap:

1. **Size-based rotation.** When the active file would exceed
   `max_file_bytes`, the writer closes it and opens the next
   sequenced sibling
   (`audit-YYYY-MM-DD-001.jsonl` → `audit-YYYY-MM-DD-002.jsonl` → …).
   The HMAC chain carries forward: line 1 of file N+1's `prev_mac`
   equals the last MAC of file N.
2. **Ring-buffer eviction.** Once more than `max_file_count` audit
   files exist for any date, the oldest are deleted FIFO. Operators
   with strict retention requirements should ship rotated files
   off-box BEFORE the buffer evicts them; the node never blocks on
   retention.
3. **Chain-tip file.** `<audit_dir>/.audit-chain.tip` is a tiny JSON
   blob `{"file_id": "...", "seq": N, "mac": "<hex>"}` updated after
   every successful fsync. On boot the node reads it and **skips**
   re-verifying every line up to `seq` in `file_id`. The bench
   harness `cargo bench --bench audit_boot_replay` measures ~5000×
   speedup on a 100k-line file.

## On-disk layout post-upgrade

```
<audit_dir>/
├── .audit.key                  # 32 raw bytes, chmod 0600
├── .audit-chain.tip            # JSON: { file_id, seq, mac }
├── audit-2026-05-20.jsonl      # legacy (pre-upgrade) — read-only after upgrade
├── audit-2026-05-21-001.jsonl  # new (post-upgrade) — always carry -NNN suffix
├── audit-2026-05-21-002.jsonl
└── audit-2026-05-21-003.jsonl  # active write target
```

A pre-Perf-6 node's `audit-YYYY-MM-DD.jsonl` is still readable and
included in `octravpn-node audit verify` walks. The node never
appends to it again post-upgrade; the first write of the new day
goes into `audit-YYYY-MM-DD-001.jsonl`.

### Why hidden tip file?

`.audit-chain.tip` starts with `.` so legacy ops scripts that glob
`<audit_dir>/audit-*` to enumerate audit files (and the upstream
test suite that does the same) don't accidentally sweep it up.

## Operator knobs

### `max_file_bytes` (default 256 MiB)

Rotation trigger. Smaller values produce more files (more `open(2)`
churn but smaller files for off-box shipping); larger values
amortise fewer rotations but make any full-replay fallback slower.
**The skip-to-tip fast path is O(1) in line count per file**, so the
file size only matters when (a) the tip file is missing OR
(b) `boot_replay = "full"`.

### `max_file_count` (default 32)

Hard ring-buffer cap. At 256 MiB × 32 files = 8 GiB on disk. At 100
receipts/s a 30-day window holds ~8.9 M lines × ~300 B/line ≈ 2.7
GiB, so 32 × 256 MiB is roughly a 90-day retention horizon.
Operators with strict regulatory retention requirements should
either bump `max_file_count` higher OR (preferred) configure an
out-of-band log shipper that copies rotated files off the node
**before** they age out.

### `boot_replay` (default `skip_to_tip`)

- `"skip_to_tip"` — honours `.audit-chain.tip`. Falls back to full
  replay if the tip is missing, corrupt, or commits to a file that
  has been ring-buffer-evicted.
- `"full"` — forces a complete HMAC walk on every cold start.
  Available for paranoid operators or for diagnosing tamper
  reports. Note: on a 30-day node this is ~26 s of CPU at boot.

The legacy `octravpn-node audit verify` CLI walks the directory
under `"full"` semantics regardless of this knob — it's the
forensic recovery tool.

## Operator runbooks

### "My node's `.audit-chain.tip` got corrupted."

Symptom: at boot, `audit boot replay (skip-to-tip)` logs `chain
broke` or the verify path returns an error. Action: delete the tip
file and restart.

```bash
rm <audit_dir>/.audit-chain.tip
systemctl restart octravpn-node
```

The node will boot under full replay (slow on a 30-day node), then
re-establish a fresh tip after the first fsync.

### "I want to keep audit history beyond the ring."

Configure a log shipper (logrotate, fluentd, rsync cron) that
copies `audit-YYYY-MM-DD-*.jsonl` files off the node into long-term
storage BEFORE `max_file_count` evicts them. The
`octravpn-node audit verify --full <archive_dir>` CLI works against
any directory containing the same `(.audit.key, audit-*.jsonl)`
file set.

### "I want to force a chain-tip refresh without restarting."

Not currently supported via the control plane — the tip is updated
after every fsync, so triggering any audit-emitting endpoint (e.g.
`POST /admin/preauth`) advances it. A SIGHUP-driven refresh is on
the post-Perf-6 follow-up list.

### "I see `audit-2026-05-21.jsonl` (no suffix) — is that a problem?"

No — that's the pre-Perf-6 legacy form. The node keeps reading it
during boot replay and skip-to-tip recovery, but never appends to
it post-upgrade. New writes go to `-001`, `-002`, etc. You can
safely archive or delete the legacy file once you've copied its
contents off-box.

## Trade-off summary

| Knob              | Smaller value                | Larger value                       |
| ----------------- | ---------------------------- | ---------------------------------- |
| `max_file_bytes`  | More files; more `open(2)`s. | Fewer rotations; slow full-replay. |
| `max_file_count`  | Less disk; tighter retention. | More disk; longer history.        |
| `boot_replay`     | `"skip_to_tip"` is sub-s.    | `"full"` re-walks every line.      |

## Format contract (unchanged from pre-Perf-6)

Each JSONL line is a JSON object with three string fields:

```
{"record_json": "...escaped canonical AuditRecord...",
 "prev_mac":    "<64 hex>",
 "mac":         "<64 hex>"}
```

- `prev_mac` is the previous line's `mac`, or 64 zeros for the FIRST
  line of a date (the chain root). On mid-day size-rotation the
  first line of file N+1 reuses the LAST mac of file N as its
  `prev_mac` — the chain stays linear across rotation boundaries
  within a day. UTC-midnight rolls always reset the chain to zeros.
- `mac = HMAC_SHA256(key, prev_mac_bytes || record_json_bytes)`.
- `record_json` is the canonical `AuditRecord` carried verbatim —
  no serializer round-trip drift.

The on-disk format is contract; downstream tooling (`audit verify`,
the analytics indexer's `audit_reader.rs`, archive verifiers) all
parse this exact shape.
