//! DERP transport plumbing.
//!
//! Today this module exposes a single submodule, [`front`], which
//! implements the **domain-fronting** dialer used as a censor-resistant
//! fallback for the operator's DERP relay pool.
//!
//! See `docs/operators/derp-fronting.md` for the full threat model.
//! The short version: a state censor that already concedes the TLS
//! channel (because it can't break BoringTun + obfs4) can still cut us
//! off by IP-blocklisting every `derp-*` address in the operator's
//! pool. Fronting routes DERP-bound HTTPS through a CDN-hosted Worker
//! whose IP is shared with the rest of the CDN, raising the political
//! cost of a block to "block half the modern web".

pub mod front;
