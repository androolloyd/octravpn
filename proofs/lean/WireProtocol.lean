import WireProtocol.Controlbase
import WireProtocol.BeNonce
import WireProtocol.HmacToken
import WireProtocol.PortalCache
import WireProtocol.V3Canonical
import WireProtocol.V3Members
import WireProtocol.V3Policy
import WireProtocol.HFHE

/-!
# OctraVPN — wire-protocol primitive proofs.

Sibling to `OctraVPN_Rust/` (the 54-theorem Rust security-primitive
module from PR #181). This module covers the wire-protocol primitives
that landed during the Tailscale interop work (Walls 1-5, PRs #212/#213
and the portal HMAC token plumbing in #218):

  * `WireProtocol.Controlbase` — 3-byte / 5-byte header round-trip +
    length invariants for
    `headscale-rs/headscale-api/src/tailscale_wire/controlbase.rs`.
  * `WireProtocol.BeNonce`     — big-endian counter → nonce composition
    + monotonicity for
    `headscale-rs/headscale-api/src/tailscale_wire/be_transport.rs`.
  * `WireProtocol.HmacToken`   — per-circle approval token equality +
    determinism for `crates/octravpn-client/src/portal/routes.rs::
    PortalState::{token_for, token_valid}`.
  * `WireProtocol.PortalCache` — approve + unseal cache lifecycle
    invariants for the same portal module.
  * `WireProtocol.V3Canonical`, `WireProtocol.V3Members`,
    `WireProtocol.V3Policy` — the v3 canonical-JSON encoder + the
    `(members, policy)` anchors.
  * `WireProtocol.HFHE` — the hypergraph-FHE / PVAC scheme that
    backs the receipt shadow-blob fields. Closes the longest-
    standing PROOF GAP shared with the AML modules.

See `WireProtocol/Theorems.md` for the full plain-English index +
Rust-signature mapping.

## Build

`lake build WireProtocol` from `proofs/lean/` reaches zero `sorry`,
zero `admit` (same standard as the Rust-primitive module).
-/
