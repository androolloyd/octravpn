//! Persistence hook (currently a no-op placeholder).
//!
//! ## Status: not yet wired
//!
//! The interop test (and every current call site) tears the container
//! down on every run, so [`super::preauth::PreauthMinter`] holds its
//! `mints` / `redemptions` state in [`octravpn_core::bounded::BoundedMap`]s
//! and forgets everything on process exit. That's intentional for the
//! interop blocker.
//!
//! When #235 (the `preauth_persistent` integration) lands, the
//! `PersistentPreauthAdmin` call-out lives in this module: the minter
//! delegates `mint` / `redeem` / `sweep_expired` through a small
//! `PreauthStore` trait so a sled / rocksdb / postgres backend can plug
//! in without touching the bounded-LRU semantics from #236.
//!
//! For now, this file is intentionally empty of runtime code — it
//! exists to pin the directory layout from
//! `docs/refactor-plan-2026-05-20.md` candidate #6 and to give the
//! eventual #235 author a single, obvious place to land the
//! integration without redoing the modularization.
//!
//! Public re-exports out of [`super`] stay identical whether or not
//! this module ships code; consumers depend only on
//! `octravpn_mesh::PreauthMinter` and friends.
