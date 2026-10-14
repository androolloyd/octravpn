# Octra execution extensions

Extensions consume immutable committed epochs from a host-owned durable history.
Callbacks run in trusted Rust code, in order, and checkpoint only after success.
A crash can replay a callback; sinks must be idempotent. Wake notifications may
coalesce because committed history, rather than notification count, determines
what is delivered. A callback failure or panic is reported and halts that worker.

`SqliteCheckpoints` stores namespaced progress with WAL, FULL synchronization and
compare-and-swap updates. Full u64 sequences survive close/reopen. The node host
must persist the epoch history with chain commits or reconstruct it reliably;
checkpoints alone are not an event journal.

`SqliteEpochSource` now supplies that history for a future Rust host whose
canonical chain state also lives in SQLite. The host passes its chain-state
transaction to `append`, commits once, and then calls `notify_commit`. Rolling
back the host transaction also rolls back the extension outbox. The adapter
rejects skipped or divergent epochs and retains full-width sequence numbers.
It cannot safely be attached to a separate database without a recovery scan.

`NativeEpochSource` supplies that recovery path for the native Irmin host.
`scripts/node-port/native-history-export.ml` acquires the native store lock,
opens Irmin and chaindata read-only, verifies published HEAD through native
startup recovery, and checks retained epoch bindings and transaction identity.
It refuses pending forward recovery, auxiliary receipt rollback and missing
epoch tags. A crash after HEAD publication but before the commit-journal suffix
is recoverable. Exports retain arbitrary OCaml byte strings through base64.

The Rust importer independently checks identity digests, ordered transaction
IDs, epoch-index commitments, folded state roots and predecessor links. A
bounded page updates its outbox and native cursor in one SQLite transaction.
After an uncertain outcome, export again after `native_head()`; old pages are
rejected. Call `notify_commit()` only after import succeeds. An ExEx restart
discovers existing backlog without needing another notification.

This is a trusted **local native host** adapter, not a finality verifier for
peer-supplied history. Receipts remain host auxiliary data. Exact transactions
use the native hash's canonical representation, including null optionals;
legacy signed exports redact fields outside their identity. The exporter needs
an offline directory or invocation under the native host's existing exclusive
ownership. Its startup verification scans retained history before bounded
page export, so this is a recovery path rather than a per-epoch polling design.

Regenerate the real-store integration fixture with:

```sh
python3 scripts/node-port/native-history-fixtures.py \
  --upstream /path/to/lite_node --builder-image YOUR_NATIVE_BUILDER \
  --out out/native-history-fresh.json
```

The fixture uses synthetic transactions in real Irmin/chaindata stores. It
checks HEAD publication, native recovery, locking, auxiliary rollback, pruning
and raw transaction bytes; it does not execute consensus or authenticate peers.

Tests cover replay, ordering, duplicate delivery, gaps, root mismatches, crashes,
slow consumers, persistence, concurrent checkpoint writers, transactional
rollback and reopen. The live consensus commit hook and VPN session projection
remain integration work; this does not establish complete Rust node parity.
