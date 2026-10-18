# Native integration observer adoption — 2026-10-18

Normal release `fbe1684ef09ac04ce8a5620eab8e03ebbed2b35d` was installed on the retained public devnet observer after all 35 local candidate gates passed. The adopted native reference remains `7f9be4489870645cfcc95439638cde40f5da9f50`; consensus rules are unchanged. The binary hash is `a4d46e4679efc1c9294d1f8e67d7c0b5378eb5d2f82bce801b9ae7f203a55e8e`, with normal features and no test helpers.

The old observer exited cleanly with code zero. One supervised replacement launched at 03:08:46 UTC, retaining epoch **1,711,611**, sequence **13,851**, the identity, configuration, environment and shared relay. No state reset or funds expenditure occurred. RPC was first observed open at 03:24:12 UTC; the 28 preceding unavailable samples remain recorded. This bounds startup observation, rather than identifying the exact opening instant.

Two read-only audits preserved the immutable retained prefix and verified forward canonical, outbox, checkpoint and archive consistency. The final audit reached epoch **1,711,677**, sequence **13,917**: **66 new epochs and 491 transaction events**, with matching ExEx. The first audit's new archive records remain identical in the second. These storage checks are separate from the running node's finality verification.

The last guarded status sample at 03:27:46 UTC reported epoch **1,711,685**, exact process/environment identity, no exit, zero connected peers and `serving:false` while publishing a canonical epoch. Operator RPC returned 200; public `/status` returned 503. The observer is advancing through catch-up; this record does not qualify sustained serving or public P2P retention.

Near the last head comparison, local epoch 1,711,678 lagged official RPC/secondary **current-epoch hints by 160–161 epochs**, compared with 188 in the preceding sample. The primary endpoint was stale at 1,706,811. Requests are not atomic; HTTP head hints are not finality authority, and this does not establish tip synchronization.

Paid service remains unconfigured. Public paid onboarding, portal funding, public DNS/TLS, sustained availability, every native profile, mixed Circle/private-proof workloads and Mainnet remain unqualified. At the saved GitHub snapshot, Headscale parity and privileged WireGuard smoke had passed; CI, Proof and Coverage were still running.

[Machine-readable record](native-integration-public-adoption.json) binds the exact retained evidence. [Local qualification](../2026-10-17/native-integration.md) and [mixed validators](../2026-10-17/mixed-validators.md) retain their separate scopes.
