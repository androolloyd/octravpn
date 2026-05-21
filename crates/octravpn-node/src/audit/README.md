# `audit/` — append-only audit log

This module ships the operator's evidence trail: every state-changing
control-plane request writes a tamper-evident JSON Lines record to a
rotating per-day file under `<dir>/audit-YYYY-MM-DD.jsonl`. Lines are
chained with an HMAC-SHA256 MAC so an attacker who can't read the key
file (`<dir>/.audit.key`, chmod 0600) cannot rewrite or delete history
undetectably.

## Submodules

| File           | Owns                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------- |
| `mod.rs`       | `pub(crate) struct AuditLog` + re-exports + `inline_fallback_total()` accessor                      |
| `inner.rs`     | `struct Inner` (owned state) + `struct AuditCounters` (lock-free atomics)                           |
| `log.rs`       | `AuditRecord`, `ChainedLine` envelope, sync `open` / `write`, shared `write_inner_direct`           |
| `batched.rs`   | async flusher, `FlusherCmd`, `open_batched(_with_cap)`, `write_async`, `flush_and_close`, knobs     |
| `chain.rs`     | `chain_step` (the HMAC step), `load_or_create_key`, date math                                       |
| `verify.rs`    | `FileVerifyReport`, `FileVerifyError`, offline `verify_file`                                        |
| `tap.rs`       | `with_analytics_tap`, `tap_publish` (best-effort `mpsc` side-channel)                               |
| `test_util.rs` | shared `#[cfg(test)]` helpers for the per-submodule test blocks                                     |

## Threading model

`AuditLog` is a cloneable handle (`#[derive(Clone)]`) over four
non-owning references:

  1. `Arc<parking_lot::Mutex<Inner>>` — the file handle + MAC chain
     state. Owned jointly by every `AuditLog` clone *and* by the
     batched-fsync flusher task.
  2. `Arc<AuditCounters>` — process-lifetime atomics. The `/metrics`
     scrape path reads `inline_fallback_total` lock-free, so it never
     blocks on the (potentially disk-stalled) `Inner` mutex.
  3. `Option<mpsc::Sender<FlusherCmd>>` — `Some` iff this log was
     opened via `open_batched`. **Bounded** at
     [`batched::DEFAULT_BATCH_QUEUE_CAP`] (8192 entries, ~2 MB
     worst-case buffered RAM). When the last sender drops, the
     flusher's `rx.recv()` returns `None`, triggers a final fsync,
     and the task exits.
  4. `Option<mpsc::UnboundedSender<AnalyticsEvent>>` — the best-effort
     tap into the in-process analytics indexer. Send failures are
     ignored; observability MUST NOT block forensics.

The **`Inner` mutex is shared between three writers**:

  - **Sync path** (`AuditLog::write` in `log.rs`): acquires the mutex,
    runs `write_inner_direct(..., fsync=true)`, drops the mutex. Lock
    hold-time = one append + one `fsync_data`.
  - **Flusher task** (`batched::flusher_loop` in `batched.rs`):
    acquires the mutex on every `FlusherCmd::Write` to run
    `write_inner_direct(..., fsync=false)`, then drops it. The fsync
    boundary (`fsync_now`) is a *second* lock acquisition — the
    flusher never holds the mutex across the fsync syscall plus the
    next channel `recv`.
  - **Inline fallback** (`write_async` in `batched.rs`, queue-full
    branch): on `spawn_blocking`, acquires the mutex, runs
    `write_inner_direct(..., fsync=true)`, drops it. The flusher
    never calls back into `write_async`, so the shared mutex is safe
    — the two paths contend but neither waits on the other's
    progress.

All three paths drop the mutex **before** touching any channel. The
flusher's `tokio::select!` never holds the mutex across an `await`.
The inline fallback runs on a `spawn_blocking` thread, not a runtime
worker, so the parking-lot lock is acquired off the executor.

> **Lock-order rule.** Acquire `Inner` → do one sync I/O burst →
> drop `Inner` before any `.await` or any `mpsc::send`. Never hold
> `Inner` across a task yield point.

Violating this rule deadlocks the runtime because `parking_lot::Mutex`
is not async-aware and blocks the executor thread until release.

## Durability ladder

  - **Per-line fsync** (sync path, `open`): zero in-flight loss.
    Throughput-bounded by disk fsync latency (~ms per write on SSD).
  - **Batched fsync** (`open_batched`, fast path): ≤ `batch_interval_ms`
    of in-flight records lost on hard kill. Defaults
    `DEFAULT_BATCH_SIZE = 64`, `DEFAULT_BATCH_INTERVAL_MS = 100`.
  - **Inline fallback** (`open_batched`, queue full): when the bounded
    flusher channel saturates (disk stall, IO error spam),
    `write_async` falls back to a synchronous inline write under the
    same `Inner` mutex the flusher uses — the entry is written +
    fsynced before `write_async` returns. **No record is lost; no
    record is duplicated.** Each fallback increments
    `audit_inline_fallback_total`, surfaced on `/metrics` as
    `octravpn_audit_inline_fallback_total`. Non-zero growth is the
    operator-facing disk-stall signal.

### Backpressure contract (audit-2 C-6 / OOM-3 fix)

Under flood + disk stall the audit log is durable under all successful
returns from `write_async`. Performance degrades to per-line fsync —
never silent drop, never OOM. The bounded queue caps worst-case
buffered RAM at `DEFAULT_BATCH_QUEUE_CAP × ~256 B/entry ≈ 2 MB`;
previously the unbounded queue allowed 125 MB/s of growth on stall.

The audit log is observability — the **receipt journal**
(`octravpn-core::receipt_journal`) is the authoritative state for
forced-restart double-sign protection (P1-8/9).

## On-disk format (DO NOT CHANGE)

Each line is a JSON object with three fields:

```
{"record_json": "...escaped canonical AuditRecord...", "prev_mac": "<hex>", "mac": "<hex>"}
```

  - `prev_mac` is the previous line's `mac` (hex-encoded), or 64 zeros
    on the first line of each daily file.
  - `mac = HMAC_SHA256(key, prev_mac_bytes || record_json_bytes)`.
  - `record_json` is the canonical `AuditRecord` serialised once and
    carried verbatim — round-tripping through `serde_json` is
    explicitly avoided in the verifier so the MAC input bytes are
    exactly what was hashed.

`FileVerifyReport` (in `verify.rs`) is the only sanctioned re-walker.
`audit_cli::verify_audit_files` consumes it. New code MUST NOT
re-implement the chain walk.
