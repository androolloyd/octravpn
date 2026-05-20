import WireProtocol.Controlbase
import WireProtocol.BeNonce
import WireProtocol.HmacToken
import WireProtocol.PortalCache
import WireProtocol.V3Canonical
import WireProtocol.V3Members
import WireProtocol.V3Policy
import WireProtocol.HFHE
import WireProtocol.Shielding
import WireProtocol.Wire
import WireProtocol.RpcEnvelope

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
  * `WireProtocol.Shielding` — the four obfuscation / probe-resist
    layers: AmneziaWG, obfs4 NTOR+AEAD transport, PSK-knock,
    domain-fronted DERP. 20 theorems covering round-trip,
    junk-drop, H-byte identity preservation, counter-replay
    rejection, padding non-determinism, mac1 probe-resistance,
    knock-window math, byte-stable 404, SNI/Host split, replay-
    window rejection.
  * `WireProtocol.Wire` — the Tailscale wire round-trip (Walls 1-7):
    streamed `MapResponse` chunked framing, delta peer updates
    (PeersChanged / PeersRemoved / PeersChangedPatch), Wall-7
    `MachineRecord.disco_key` + `endpoints` propagation.
  * `WireProtocol.RpcEnvelope` — the chain JSON-RPC envelope's
    canonical bytes + sign/verify path.  Mirrors
    `crates/octravpn-core/src/rpc.rs` + `tx.rs::canonical_bytes`.
    Provides the method/chain-id/nonce binding theorems used by
    `OctraVPN_Rust.EndToEnd` to argue cross-chain / cross-method
    replay is impossible at the tx layer.

See `WireProtocol/Theorems.md` for the full plain-English index +
Rust-signature mapping.

## Build

`lake build WireProtocol` from `proofs/lean/` reaches zero `sorry`,
zero `admit` (same standard as the Rust-primitive module).
-/
