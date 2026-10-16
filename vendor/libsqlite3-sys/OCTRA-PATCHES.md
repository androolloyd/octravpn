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
