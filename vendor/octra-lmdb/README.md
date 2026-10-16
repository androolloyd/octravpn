# Octra LMDB ownership adapter

This source adapter pins `heed = 0.22.1` and provides scoped access to the native
compute history's four named LMDB maps. It is local adapter code, not a copied
or independently qualified LMDB implementation.

The directory must belong to the effective user and have no group or other
permissions. Opening takes an exclusive directory `flock`, checks existing LMDB
file ownership and refuses symlinks. The environment uses transactions without
TLS, default durable LMDB flags, and an explicit map-size policy based on its
actual page size. Values leave transactions as owned bytes. Writes commit only
after their callback succeeds; errors or unwinding drop and abort the transaction.

Only environment open and its initial resize use unsafe code. The environment
is private during both operations, no transaction exists during resize, and its
directory guard outlives the environment. No public API exposes environment
clones, raw file handles, flags, runtime resizing or mapped byte references.
These obligations follow the primary [heed open documentation](https://docs.rs/heed/0.22.1/heed/struct.EnvOpenOptions.html#method.open)
and [resize documentation](https://docs.rs/heed/0.22.1/heed/struct.Env.html#method.resize).

The crate is kept outside workspace `unsafe_code = deny` so this narrow native
storage boundary can be reviewed separately. Runtime and protocol code remain
under the workspace rule. Dependency resolution/lock expansion, native LMDB
version comparison, source review, builds, differential tests and crash/reopen
qualification remain pending the final validation phase. This adapter has not
been built, tested, opened against a live store or deployed.
