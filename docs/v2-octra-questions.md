# Questions for Octra dev team — OctraVPN v2 on Circles

> Compiled from `docs/v2-circles-design.md` §9. Send this verbatim (or close to it) to the dev team via the Discord development channel or `dev@octra.org`. Answers gate the v2 implementation work in tasks #141–#143.

We're building **OctraVPN**, a decentralized Tailscale-compatible mesh on Octra. v1 ships against current main-net primitives (AML + HFHE ledger + stealth payments). For v2 you mentioned that Circles let us hide operators while still offering clear-internet egress — *"you can build a VPN on this."* We took that as a hint and designed a v2 architecture where each operator is a Circle, the proxy contract is the public face on main-net, and the access contract gates membership / class / pricing.

Before we author any Circle-shaped code we need to ground six things. Numbered for easy reply.

## 1. Circle SDK + DSL — current state of the art

The litepaper (§2.3, §4.2) says Circles run logic in Rust, C++, OCaml, or WASM. None of the public `octra-labs` repos ship a Circle example yet (`program-examples` has token / multisig / vault / escrow / amm / private_ml — no Circle).

- Is there an internal SDK we should request access to?
- Which target (Rust? OCaml? WASM?) is the recommended path for new dApps?
- Is the Circle bytecode (OCTB) the same format as smart-contract bytecode, or distinct?

## 2. Proxy contract grammar

§4.4.2 describes the proxy contract as deployed with "a pre-allocated resource address for the backend" and as the bridge between Circle and main-net via "interaction actors."

- Is the proxy authored in AML (with special pragmas), or its own DSL?
- How is the *allowlist of predefined callers* declared? (We need an interface that says "only these tailnet members can enumerate / call methods on this proxy.")
- Can the proxy receive callbacks from main-net AML programs (e.g. "main-net says: this session was confirmed; release X OU to the operator wallet"), and how is that callback declared/dispatched?

## 3. Access contract syntax

§4.2 says "access is defined during Circle deployment through an access contract, which includes the necessary functions for interface exchange."

- Same question as 2: AML-with-pragmas or separate DSL?
- Is the function table declared inline or in a separate manifest? Are there hooks for tag-based routing (we want: "members tagged `internal-only` route to the `internal` class; members tagged `user` route to `shared`")?

## 4. HFHE on the proxy side

We currently use `fhe_add`, `fhe_sub`, `fhe_add_const`, `fhe_scale`, `fhe_verify_zero` inside `program/main.aml` (the v1 AML). For v2, the natural place to compute `total_paid = bytes_used * price_per_mb` is in the Circle (so byte counts stay encrypted), but the resulting amount has to escape to main-net for OU transfer.

- Are the HFHE primitives available inside the Circle's logic, or only at the proxy boundary?
- What's the supported path for **decrypting a Circle-internal ciphertext into a main-net cleartext value** at settle time? Is `fhe_verify_zero` (which we already use for plaintext earnings claim) the right pattern, or is there a richer transcipher primitive?

## 5. Bond escrow at proxy deployment

We want operators to lock a slashable OU bond when they deploy a proxy contract, so that AML-detected misbehavior (equivocating `settle_claim` submissions, refusing to honor `internal` traffic when `charge_internal_traffic == 0`) can slash on-chain.

- Does proxy deployment support attaching a bond, escrowed by main-net? If yes, what's the slash interface — does main-net call a method like `proxy.slash_bond(amount, reason)`?
- If not yet, is there a recommended pattern? (We could hold the bond in our v2 AML program keyed by proxy address — workable but it splits the bond's authority across two contracts.)

## 6. Operator discovery

The point of hidden operators is that an outside observer can't enumerate them. But the tailnet owner has to discover available operators *somehow* in order to add them to the authorized-proxy set.

- Is there an Octra-blessed pattern for opt-in discovery? (E.g., an "operator directory" Circle that proxies opt into; the directory's access contract is public-read, the operator's actual proxy stays opaque?)
- Or are we expected to roll our own out-of-band channel (e.g., signed advertisements on a separate p2p layer)?

---

## Why we care

v1 ships today on main-net AML with public operator addresses. We can keep extending v1 incrementally, but the privacy and ACL story is much cleaner if v2 sits on Circles. We don't want to ship a v1.5 with shared-exit / internal-subnet ACL just to throw it away in v2 — so we'd love to know:

7. **Timeline.** Is there a target release for the public Circle SDK / proxy DSL? Same quarter as mainnet beta? Or further out?

We're happy to share our v2 design doc (in our repo at `docs/v2-circles-design.md`) for sanity-check. If there's a private SDK to test against, we'd love access — the team building this is at `andrew@golast.xyz`.

Thanks!
