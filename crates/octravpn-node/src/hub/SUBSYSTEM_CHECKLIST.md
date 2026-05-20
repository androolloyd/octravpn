# Adding a new subsystem to the `hub/` module

Every "wire this in at boot" feature historically grew a single 200-line
closure in `spawn_control_plane`. The result was the highest-churn
file in the tree (24 commits / 30d) and a magnet for merge conflicts.

If you're about to add a new subsystem — an analytics indexer, a new
metrics surface, another tailscale-like wire interop, a sealed-key
variant, anything that needs to run alongside the daemon — touch the
**five steps** below in order. If you find yourself wanting to add a
*sixth* step, that's a sign the layout needs another submodule rather
than another callsite.

## Five canonical touch points

### 1. Config struct — `src/config.rs`

Add a `[<subsystem>]` block to `NodeConfig` with sensible defaults
and `serde(default)` annotations so existing operator TOMLs keep
parsing. Default to `enabled = false` for anything that touches an
external service (sidecar binary, network socket) — opt-in beats
silent-spawn for ops.

```rust
#[derive(serde::Deserialize, Clone, Default)]
pub struct MySubsystemCfg {
    #[serde(default)]
    pub enabled: bool,
    // ... per-subsystem fields ...
}
```

### 2. Hub field — `src/hub/mod.rs`

If the subsystem needs to be reachable from anywhere else in the
daemon (e.g. the receipt-signing path needs the PVAC client), add a
field on `Hub`. If it lives entirely inside one background task,
**do not add a field** — pass the config in at `spawn_*` time and
let the value live in the spawned task. This is what cuts the
god-object growth.

```rust
pub(crate) struct Hub {
    // ... existing fields ...
    /// New subsystem handle. `None` when `cfg.my_subsystem.enabled = false`.
    pub my_subsystem: Option<Arc<MySubsystemClient>>,
}
```

### 3. Spawn fn — `src/hub/spawn.rs` (or its own submodule)

If the subsystem has its own long-lived task, give it a `spawn_<name>`
fn on `impl Hub`. If wiring is non-trivial (>30 LOC), put it in its
own free helper at the bottom of `spawn.rs` (or, better, a new
`src/hub/<name>.rs`) and have `spawn_control_plane` call into the
helper as `let foo = build_foo(self.cfg.clone())?;`. Do not append
to the `spawn_control_plane` closure body.

```rust
impl Hub {
    pub(crate) fn spawn_my_subsystem(self: Arc<Self>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { /* ... */ })
    }
}
```

Wire the spawn into `main::run` alongside `spawn_tunnel` and
`spawn_control_plane`.

### 4. Route mount — `src/control.rs`

If the subsystem exposes an HTTP surface, add the route to the axum
router built in `control::serve`. Gate the mount behind the same
config flag as the field in step 2 so an operator with the subsystem
disabled does not get a half-mounted endpoint. Return `404` /
hide rather than `503` for hidden-by-config — matches the existing
`/events` pattern.

### 5. Audit emit — `src/audit.rs` + emit sites

If the subsystem performs operations that ops + auditors care about
(stake change, key rotation, policy rewrite, settlement), emit an
`AuditEvent` from the action path. Keep the event payload small and
self-describing. Reuse an existing event type if the semantics
match; only add a new variant when none of the existing ones fit.

## Module growth rules

- Submodule LOC target: 100–400. Approaching 400 because one
  subsystem is naturally chunky? Fine — keep going.
- Approaching 400 because you've added a *second* concern to a file?
  Carve out a new `src/hub/<concern>.rs`.
- Cross-submodule reaches are `super::` or `crate::hub::sub::*`,
  never absolute paths.
- New helpers used by exactly one caller don't need a public name —
  keep them `pub(super)` and let the boundary do its job.

## When in doubt

Re-read `src/hub/mod.rs`'s top-of-file docs and the per-file headers.
They tell you *where the seams are* — if the new subsystem doesn't
fit any of them, that's a signal to add a new submodule, not stretch
an existing one.
