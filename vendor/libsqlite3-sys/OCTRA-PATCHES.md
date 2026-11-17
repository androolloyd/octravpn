# Local storage safety backport

This is the crates.io `libsqlite3-sys` 0.30.1 archive, SHA256
`2e99fb7a497b1e3339bc746195567ed8d3e24945ecd636e3619d20b9de9e9149`.
Rust APIs, feature flags, bindings and bundled SQLite version are unchanged.

The SQLite and SQLCipher amalgamations carry the upstream WAL-reset guard:
a checkpoint revalidates the live WAL salts after obtaining reader lock 0,
before copying frames or publishing `nBackfill`. This backports Fossil commits
`053bd3930f827156fd67ea4546a36227cffbb6f8bada3b5d1a7cf5f1867ac624`
and `decb69015457b4f70cf574aeef87d40f9de60b94965f4a915e8d0cd7559ef2ae`.
The upstream test-only fault hook is kept in the regression harness, not this
production backport. The package still reports its original SQLite version;
qualification must bind these exact source hashes rather than infer the patch
from that version string.

Sources:
- https://sqlite.org/wal.html#walreset
- https://github.com/sqlite/sqlite/commit/fe57e14b49f9189b56da8233ab3415ce5ff6b1ff
- https://github.com/sqlite/sqlite/commit/bb80d688acfdd33706f6f7a773fbf8960aeb112b

This affects local database durability only. It does not change consensus,
Irmin hashing, schema, transaction execution or application protocol rules.

## WAL page-size read (CVE-2026-119375, RUSTSEC-2026-0459)

Both amalgamations also carry upstream SQLite commit
`e5bf119821f25be1d7f10ef0a2edbe175289166e` (Fossil
`f9b4ee369557c36c606666bd7e6d8dc4685d87531993d3ce4e7a718aa814a5ac`), applied
verbatim to `sqlite3WalReadFrame`: when the WAL page size is smaller than the
database page size, the rest of the output buffer is zeroed instead of being
left as it was. Without it, a database opened beside a crafted `-wal` returns
recycled page-cache memory through ordinary queries.

The node opens SQLite files it did not write when an operator adopts a
retained-state directory, so this input is reachable. The crate still reports
version 0.30.1 and SQLite 3.46.0, which is why the advisory is listed as
reviewed in `.cargo/audit.toml` and `deny.toml` rather than cleared by a
version bump; upstream's fixed crate (0.39) needs a newer `sqlx`.

`crates/octra-node-runtime/tests/sqlite_wal_page_size.rs` builds that file
pair and fails against the unpatched source (3,006 leaked bytes when this was
written). Re-vendoring must keep it green.

Sources:
- https://github.com/sqlite/sqlite/commit/e5bf119821f25be1d7f10ef0a2edbe175289166e
- https://rustsec.org/advisories/RUSTSEC-2026-0459
