# `receipt_journal`

Persistent per-session receipt-sequence floor for octravpn-node.

Fixes threat-model items **P1-8** and **P1-9** (`docs/v2-threat-model.md`):
a forced restart of the operator daemon must never let an attacker
collect two distinct receipts at the same `(session_id, seq)` under the
operator's receipt-signing pubkey. Two such receipts feed
`slash_double_sign` (`program/main-v2.aml:382-418`) and burn the bond
of an honest operator.

The journal is the durable floor every receipt-signing call MUST
consult. See the parent module docstring (`mod.rs`) for the bump
protocol.

---

## Module layout

| File              | Role                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `mod.rs`          | `pub struct ReceiptJournal` + the public API surface                 |
| `inner.rs`        | The mutex-guarded `Inner` state (in-mem map, handle, file size, …)   |
| `codec.rs`        | v1 record encoder/decoder, CRC32, `MAGIC_V1`, `RECORD_SIZE`          |
| `migration.rs`    | v0 → v1 in-place migration; `ensure_v1_header`; snapshot rewrite     |
| `compact.rs`      | Sync `compact_locked` + async snapshot/swap worker; tempfile path    |
| `fsync_policy.rs` | `FsyncPolicy` + `DEFAULT_COMPACTION_WATERMARK`                       |
| `errors.rs`       | `JournalError` + `JournalResult`                                     |
| `proptests.rs`    | Four proptest properties (monotonicity, isolation, torn tails)       |

---

## v1 on-disk format

```text
Offset   Size   Field
------   ----   -------------------------------------------------------
0x00     8      magic       = b"OCRJ2\0\0\0"
0x08     ...    record × N  (44 bytes each, in append order)
```

Each record is exactly **44 bytes**:

| Offset (in record) | Size | Field        | Encoding                       |
| ------------------ | ---- | ------------ | ------------------------------ |
| `0`                | 32   | `session_id` | raw bytes from `SessionId`     |
| `32`               | 8    | `seq`        | `u64` big-endian               |
| `40`               | 4    | `crc32`      | `u32` big-endian, IEEE poly    |

`crc32 = crc32_ieee(record[0..40])`.

The file is **append-only** in the steady state. Records for the same
`session_id` may appear multiple times — replay takes the max seq per
id and discards earlier entries. Compaction rewrites the file as
exactly one record per live session (in `BTreeMap` iteration order)
followed by any post-snapshot delta records.

### Constants (declared in `codec.rs`)

| Name                          | Value             | Visibility   |
| ----------------------------- | ----------------- | ------------ |
| `MAGIC_V1`                    | `b"OCRJ2\0\0\0"`  | `pub(crate)` |
| `RECORD_SIZE`                 | `44`              | `pub(crate)` |
| `COMPACTING_SUFFIX`           | `".compacting"`   | `pub(crate)` |
| `DEFAULT_COMPACTION_WATERMARK`| `10 * 1024 * 1024`| `pub`        |

`COMPACTING_SUFFIX` lives in `compact.rs` because it only concerns
the compaction tempfile path — but it's the third format-anchored
constant the threat model cares about, so it's pinned here for
ease of audit.

---

## Backward compatibility: v0 → v1 migration

The legacy v0 format:

```text
0x00   8      magic = b"OCRJ1\0\0\0"
0x08   4      n: u32 BE (entry count)
0x0C   40·N   entry[i] = [session_id: 32][seq: u64 BE]
```

was a `BTreeMap` snapshot rewritten on every bump (O(N) bytes + a
synchronous fsync per receipt). On `open()`:

1. Read the file; if it starts with `OCRJ1`, decode it via
   `migration::decode_v0`.
2. Atomically rewrite the path as a v1 snapshot via
   `migration::write_v1_snapshot` (tempfile + rename + dir fsync).
3. Open the freshly-rewritten v1 file in append mode.

Migration is a one-shot cost paid on the first boot after the upgrade;
subsequent opens see `OCRJ2` and take the fast path.

---

## Atomicity contract

Every operation MUST leave the on-disk file in a recoverable state.
"Recoverable" = `open()` returns the same `BTreeMap` (or a strict
superset) that the operator has signed against. We enumerate each
operation and the crash points that matter.

### `bump`

1. **Append the encoded record.** The record is 44 bytes. If the
   process crashes mid-write, the file ends in a short tail
   (`< RECORD_SIZE` bytes past the last complete record). `replay_v1`
   silently drops short tails; the floor advances only for complete
   records, which is exactly the contract `bump` documents to its
   caller ("we have NOT committed to this seq until `bump` returns").
2. **(Optionally) fsync.** Under `FsyncPolicy::EveryWrite`, the record
   is durable when `bump` returns. Under `Periodic`, durability is
   bounded by the configured interval; an OS crash inside that window
   may drop the tail, but the same drop-the-tail logic handles it.
3. **Update in-mem map.** The in-mem write happens after the disk
   write. A crash here is invariant-preserving: the on-disk floor is
   already at `new_seq`, so the next `open()` sees the new floor and
   no signer ever observed an in-mem floor higher than what's on disk.

### Synchronous `compact()`

The lock is held across the whole rewrite:

1. **Drop the current append handle.** No new appends can land while
   the lock is held.
2. **`write_v1_snapshot(path, by_session)`** — `tempfile::NamedTempFile`
   in the same directory, write `MAGIC_V1` + one record per entry,
   `sync_all`, `persist` (which `rename`s atomically), then `sync_all`
   the parent directory.
3. **Reopen the append handle** on the freshly-renamed file.

Crash points:

- **Mid step 2 (before rename):** the tempfile is left on disk under
  a random suffix (`tempfile` crate's default). The live journal
  inode is untouched. `tempfile` won't unlink on drop after `persist`,
  but pre-`persist` we rely on `NamedTempFile`'s drop guard. In the
  worst case the orphan tempfile is harmless garbage in the journal
  directory.
- **Between rename and reopen:** the new file is durably the journal;
  on next `open()` the in-mem state is rebuilt from it.

### Async `compact_async()` — single-tempfile snapshot/swap protocol

Three phases. The slow phase (2) runs *off* the journal lock. The
**single durability barrier** is the atomic `rename` in phase 3b: the
tempfile is fully durable (snapshot + deltas + fsync) **before** the
rename, so the rename commits an already-complete journal in one
observable step. See B-1 in
`docs/audit/2026-05-20-correctness-leaks-audit.md` for the historical
bug this fixes (previously the delta-replay happened *after* the
rename, so a crash in that window would discard durable bumps and
regress the seq floor on reboot — slashable under `slash_double_sign`).

| Phase  | Lock held? | What happens                                                                                                                                                        |
| ------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1      | yes        | Clone `by_session` to a snapshot, set `compaction_inflight = true`. Drop the lock.                                                                                  |
| 2      | **no**     | On a `spawn_blocking` task: write the snapshot to `<journal>.compacting`, `sync_all`. Concurrent `bump`s keep appending to the live journal file.                   |
| **3a** | yes        | Open `<journal>.compacting` in append mode. For each `(id, seq)` in the live `by_session` that is strictly greater than the snapshot's value (or absent from the snapshot), append one fresh delta record. `sync_data` the tempfile. Drop the tempfile handle. |
| **3b** | yes        | Drop the live append handle. `rename(<journal>.compacting → <journal>)`. fsync the parent dir. Reopen the append handle on the freshly-swapped file. Clear `compaction_inflight`. |

The lock is held continuously from the start of phase 3a through the
end of phase 3b. No bump can land between the delta computation and
the rename; therefore the post-rename file holds every bump the
in-memory map ever reflected at the moment phase 3a started.

#### Phase-by-phase crash contract

**Crash during phase 1.** The lock was held; only an in-mem flag was
flipped. The next `open()` recovers via the standard v1 replay. The
flag is reset because it's not persisted across process restart.

**Crash during phase 2 (before phase 3 starts).** The tempfile
`<journal>.compacting` is on disk with some (possibly partial)
content. The live journal file at `journal_path` is *untouched* — it
still holds every record that was appended up to the moment of the
crash. Recovery: `open()` unconditionally unlinks
`<journal>.compacting` before replaying the journal. The tempfile
contents are by construction a strict subset of (or stale relative to)
the live journal — they cannot contain any record that isn't already
in the live journal (the snapshot was taken under the lock, before
any concurrent bump could append). Removing the orphan is therefore
invariant-preserving.

**Crash during phase 3a (deltas being written into the tempfile, lock
held, before the rename).** The tempfile is in some state — possibly
with a fully-written deltas suffix, possibly torn mid-record, possibly
unsynced. The live journal file at `journal_path` is **still the
authoritative pre-compaction file**, byte-for-byte unchanged. Recovery:
`open()` unlinks the tempfile orphan; the pre-compaction journal
replays as if no compaction was attempted. **No bump is lost** because
every bump that landed before this crash is in the pre-compaction file
(or was never durable to begin with under the active `FsyncPolicy`).

**Crash during phase 3a, AFTER deltas were written + fsync'd, BEFORE
the rename.** Same as above: the tempfile is complete and durable, but
not yet at the canonical path. `open()` removes the orphan and replays
the pre-compaction file. The deltas in the tempfile are discarded —
this is safe because every delta represents a bump whose authoritative
durable record is also in the pre-compaction file (`bump` appends to
the live file under the lock before updating `by_session`).

**Crash during phase 3b, AFTER the rename, before the dir fsync /
reopen.** The atomic rename has committed the post-compaction journal
(snapshot + deltas, all fsync'd by phase 3a) at the canonical path.
The dir fsync that follows the rename promotes the rename itself to
durable; on a power-loss before that dir fsync the rename may revert
to the pre-compaction file (POSIX-permitted). Either way the on-disk
state is a complete, valid v1 journal:
- **rename durable** → post-compaction journal (snapshot + deltas);
- **rename not yet durable** → pre-compaction journal (unchanged).

Both cases preserve every bump up to the start of phase 3a.

**Crash during phase 3b, after dir fsync.** The file is the post-
compaction journal. Normal replay path.

#### Atomicity summary (one paragraph)

After B-1: the journal at the authoritative path is **either** the
full pre-compaction file **or** the post-compaction file (snapshot
plus every delta from phase 2, all durable before the rename). There
is no intermediate state visible to a process restart. Recovery: on
`open()`, the orphan `<journal>.compacting` is unconditionally
unlinked; whichever file is at the canonical path is replayed
verbatim. The in-memory floor map that `bump` maintains is always a
superset of the on-disk floor (we append + fsync before updating the
map), so a crash never regresses the floor below the highest seq the
operator ack'd as signed.

#### Concurrent `compact_async` calls

The `compaction_inflight` flag is the lock: a second `compact_async`
called while a first is in flight returns a resolved no-op handle.
The in-flight worker already covers the current state, and its
swap-phase delta replay picks up any further bumps that land before
phase 3 completes. Stacking a second compaction would add I/O for no
invariant gain.

#### `open()` orphan scrub

```rust
let compacting_path = compacting_tempfile_path(&path);
if compacting_path.exists() {
    let _ = fs::remove_file(&compacting_path);
}
```

Unconditional — the orphan is always either (a) garbage from a
crashed-mid-phase-2 worker, or (b) a sibling file an operator hand-
placed (which is an operator error, not ours to preserve). The
unlink failure case is tolerated: the next `compact_async` will
overwrite the tempfile in place.

---

## Fsync policy

`FsyncPolicy::EveryWrite` (default) — `sync_data` after every append.
Durable; one fsync round-trip per receipt.

`FsyncPolicy::Periodic(Duration)` — `sync_data` only when the
configured interval has elapsed since the last fsync. The OS write
buffer still receives every append immediately (an `append`-mode
`File::write_all` doesn't buffer in user space), so a process crash
without an OS crash still preserves every record. Throughput-mode for
operators who accept a bounded loss window across an OS crash. The
loss bound is `Duration` of receipts.

---

## Compaction watermark

`DEFAULT_COMPACTION_WATERMARK = 10 MB`. Auto-compaction fires when
`bump` lands a record that crosses this size threshold and no
compaction is already in flight. 10 MB ≈ 240k v1 records — well
above any realistic tailnet's live session count, so compaction is
rare in production. Tests use `set_compaction_watermark` to drop the
threshold to a handful of records and exercise the path quickly.
