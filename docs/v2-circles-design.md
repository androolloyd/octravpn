# OctraVPN v2 — Circle-native design

> **Status: live on devnet as of 2026-05-17.** The slim registry (`program/main-v2.aml`) and operator-circle (`program/operator-circle.aml`) programs are committed; the registry is deployed at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`. One operator circle (`octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA`) is registered + bonded + has a sealed `/policy.json` asset uploaded + a v2 session opened against it. The v2 adversarial drill (`docker/devnet/e2e-adversarial-v2.sh`) lands 45 / 45.
>
> §9 (open questions) below is preserved historically; the **§0 Status snapshot** added at the top of this doc supersedes it.

## 0. Status snapshot (2026-05-17)

What's shipped on chain:
- `octra cast circle predict|deploy|info|asset|asset-key|key|put-encrypted|encrypt-only|get-encrypted` in `octra-foundry` (commit `ba094dd`+). Wire format mirrors the reference webcli (`octra-labs/webcli` `f9c73e1`).
- `octra-core::circle` primitive: deterministic `circle_id_of_deploy(deployer, nonce, payload)` (sha256 + base58, `oct` prefix, 47-char), `resource_key`, sealed-envelope encrypt/decrypt (AES-GCM + PBKDF2-SHA256-120k, "OCRS1" magic, padding classes 4k/16k/32k/128k).
- `program/main-v2.aml` — slim registry. Operators are circles (not wallet addresses). Slashing carries v1.1's `slash_double_sign` (40/40 adversarial-proof) verbatim, re-keyed on circle_id. `register_circle` is `payable` and atomic (catches the chicken-and-egg `bond_endpoint requires owner` issue the live e2e surfaced — see commit `6c3ce5a`).
- `program/operator-circle.aml` — in-circle program (design + compile target). Holds encrypted policy resource_keys, member ACL, per-session metering counters, accepts member-acceptance signatures, demonstrates the new AML `payable` / `nonreentrant` modifiers shipped in `octra-labs/program-examples`.
- `docker/devnet/e2e-adversarial-v2.sh` — 45-case drill, all hold (commit `beae338`).

Tx hashes of the canonical v2 e2e:
- `forge create main-v2` constructor `(100, 10, 1_000_000_000, 100, 1000)` → `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`
- `register_circle` (atomic register + 1 OCT bond) → tx `54d84c02d5a61bfade3122c1abd918f142cd54ace95b2c251aaf11cf49dbc74b`
- `create_tailnet` → tx `e33463e3f253c6ecd09be1dcdf09397152d852a76645c876cc88cf239f7c879e`
- `authorize_circle` → tx `e4de76f3ae235efde0fd45a912bd7ec14977526d1128d3e3708f8cff1e0fb41c`
- `open_session` (class=0 shared, max_pay=200, price auto-stamped from registry) → tx `434ad40cf475dd4f509550daee36362655375d43c40d064b3e8c65aeae8ff7ae`
- `circle_asset_put_encrypted` (sealed `/policy.json`, 4k-padded AES-GCM) → tx `5811465946323b04de530924825b87ad6c95953dce55b9bbb2416cf2aa1bc494`

What we learned in implementation that this doc didn't predict:
1. **Circles are addressable like wallets** — `circle_id` is structurally `oct…` (47-char) and shows up in `to_` of normal txs. No separate proxy-contract grammar is needed; the v2 program treats `circle: address` like any other addressable thing.
2. **CREATE2-style deterministic id** — `(deployer_wallet, nonce, deploy_payload)` ⇒ a unique circle_id, computable BEFORE submitting the deploy tx. Lets us predeclare `to_=circle_id` and lets the registry assert ownership-at-registration without trusting the deployer to disclose the id correctly.
3. **Sealed-read assets are plain AES-GCM** — no HFHE involvement at this layer. The path-private fetch (`circle_asset_ciphertext_by_resource_key`) is the privacy lever for hidden exits — chain observers can't tell which asset path a client fetched.
4. **AML `bytes` type is char-length-counted UTF-8** — passing 32 raw bytes requires a 32-character string. Hex (64 chars) and base64 (44 chars) both fail the `len == 32` check. Documented in `~/.claude/projects/-Users-androolloyd-Development-octra/memory/octra_aml_wire_format.md`.
5. **AML `ed25519_ok` wants base64** for both `pk` and `sig`. Tx canonical bytes are bare canonical-JSON over the envelope (no domain prefix). Same memory file.
6. **Governance bypasses pause** — `withdraw_program_treasury`, `set_params`, `transfer_ownership`, `set_paused` are owner-only AND intentionally NOT pause-gated. A compromised owner can `set_paused(0)` first anyway, so gating governance on pause adds no defense and breaks emergency-response (refunds, migrations). v1.1 had a brief detour adding the gate; reverted in commit `d7aaa65`.

What's still pending (active subagents, 2026-05-17):
- Lean + TLA port to v2 entrypoint shape.
- octravpn-node + client wiring against v2.
- PVAC integration for real HFHE ciphertexts (unblocks settle/claim).
- Rust formal verification + leak audit on shared crypto + node infra.

This document is now an architecture map; the canonical source for what's deployed is `program/main-v2.aml` and `docker/devnet/wallets.toml`. The §1–§9 sections below retain the pre-public-circles design reasoning for posterity.

---

> Original status note (pre-public-circles release; preserved for context): v1 (the program currently in `program/main.aml`) continues to be the shippable MVP on main-net. This document sketches a v2 architecture that uses Octra's native **Circle** primitive as the substrate for operator identity, ACL, and encrypted metering. The Octra dev team flagged this direction as the right way to "build a VPN on Octra where the exits are hidden, like in Tor, with clear-internet access."

## 1. Why v2 — what v1 doesn't give us

v1 (see `architecture.md`) is everything we need to ship the MVP today. Trade-offs we accepted:

| Concern | v1 reality | What we'd prefer |
|---|---|---|
| Operator identity | Public `octV…` address, IP and WG key on-chain | Operator unlinkable from outside the tailnet |
| ACL | Per-tailnet `members: map[address]bool` and `exit: address` only — every member can use every configured exit at the same price | Per-class routing (shared exit vs internal subnet), per-class price, tag-based gating |
| Pricing flexibility | One `price_per_mb` per endpoint | Per-class price, per-tailnet "is intra-tailnet free?" toggle |
| Metering | bytes_used is plaintext in `settle_claim` / `settle_confirm` | Encrypted in the operator's compute environment, only the settlement amount escapes |
| Resistance to operator enumeration | Anyone can list all operators (it's a public map) | Operators visible only to authorized callers |

None of these block the MVP. They all matter if OctraVPN wants to compete on privacy with Tor / Loki / Nym / Mysterium / Sentinel.

## 2. Circles primer

This section restates the litepaper for engineers reading this doc cold. Authoritative source: [Octra Network Litepaper, 2024](https://octra.org/litepaper.pdf), §2.3, §2.9, §4.2, §4.4.2; index at https://docs.octra.org/.

A **Circle** is an Isolated Execution Environment "rigidly connected to the main network." Up to 32 MB on-chain app state per Circle (clusters compose multiple). Logic in Rust / C++ / OCaml / WASM. State and computation can be partial- or fully-encrypted under HFHE.

Two contract types matter for our purposes:

- **Access contract** — declared at Circle deployment. Defines the Circle's interface and who is authorized to call what.
- **Proxy contract (§4.4.2)** — the bridge between the Circle and main-net via "interaction actors." Direct quote: *"can be completely isolated from all participants except those predefined in the proxy contract configuration. Developers can create autonomous private applications for their needs that virtually no external observer will ever discover unless they define the scope in advance."*

**Transciphering** (§2.9) lets data move between the Circle's key and the main-net key without ever decrypting.

Three properties of Circles directly map onto VPN concerns:
1. **Opacity** → hidden exits (proxy contract is enumerable only by predefined callers).
2. **Programmable access** → ACL (which member tag can call which Circle method).
3. **Encrypted state + HFHE compute** → metering and earnings stay encrypted inside the Circle.

## 3. v2 architecture at a glance

```
                ┌─────────────────────────────────────────────────────┐
                │              Octra main-net (public)                │
                │                                                     │
                │   AML program OctraVPN-v2                           │
                │   ─ tailnets, escrow, deposits, dispute, slash      │
                │   ─ NO operator registry, NO endpoint table         │
                │   ─ knows operators only as proxy-contract addrs    │
                └────────────┬──────────────────┬─────────────────────┘
                             │                  │
                             │ proxy contracts  │
                ┌────────────▼──────┐   ┌───────▼──────────┐
                │   Operator A      │   │   Operator B     │
                │  Circle (hidden)  │   │  Circle (hidden) │
                │ ─ WG keys         │   │ ─ WG keys        │
                │ ─ access contract │   │ ─ access contract│
                │ ─ HFHE byte ctrs  │   │ ─ HFHE byte ctrs │
                │ ─ exit policy:    │   │ ─ exit policy:   │
                │   shared / inner  │   │   shared / inner │
                └───────────────────┘   └──────────────────┘
                             ▲                  ▲
                             │ WireGuard (carrier; no Octra knowledge)
                             │
                ┌────────────┴──────────────────┴──────────────┐
                │      Client (stock Tailscale-compatible)     │
                │  ─ headscale-rs coordinates the tailnet      │
                │  ─ openSession → Circle proxy, not address   │
                └──────────────────────────────────────────────┘
```

The split: **main-net handles money, the Circle handles identity + policy + metering**.

## 4. What lives where

### 4.1 Main-net AML (the thin v2 program)

`program/main-v2.aml` shrinks dramatically vs v1. It keeps:

- `tailnets : map[u64]TailnetRecord` — owner, ACL pubkeys, member set, treasury, governance.
- `sessions : map[u64]SessionRecord` — `opener`, `circle_proxy: address`, `deposit`, `status`, `operator_claim`, `client_confirm`. The session no longer holds an `exit: address` — it holds the proxy address of the Circle that runs the exit.
- The two-tx `settle_claim` + `settle_confirm` pattern unchanged. The proxy contract submits `settle_claim` on behalf of the Circle.
- Equivocation slash (proxy-level), dispute recording.
- Tailnet treasury + protocol fee + the encrypted earnings ledger (this could also live in the Circle — see §4.4).

It drops:

- `endpoints` map (no public operator registry).
- `endpoint_stake`, `endpoint_bond` (the Circle escrows its own bond at deployment; the proxy contract holds the slashable bond).
- `register_endpoint`, `bond_endpoint`, `unbond_endpoint`, `update_endpoint` (lifecycle now happens inside the Circle).
- `configure_tailnet_exit` (replaced by a tailnet → set-of-authorized-proxies map; ACL is owner-managed).

### 4.2 The Circle (per operator)

Each operator deploys their own Circle. The Circle holds:

- **Identity**: WireGuard keypair, IPs to expose, region tag. Encrypted; never leaves the Circle.
- **Access contract**: a function table that decides who can call what. Methods like `open_session(client_addr, kind: ExitKind, max_pay)` are gated by:
  - is `client_addr` in the authorized member set?
  - what's the `client_addr`'s tag set, and does it overlap with the policy for this `kind`?
- **Exit-class policy**: `shared_exit: bool`, `intra_only: bool`, `price_per_mb_shared: u64`, `price_per_mb_intra: u64`. The Circle decides at runtime which tariff applies based on which class the client requested.
- **HFHE byte counters**: incremented inside the Circle as packets flow. Plaintext bytes never escape.
- **Earnings ciphertext**: under the operator's own pubkey, claimable on main-net.

### 4.3 The proxy contract (per operator)

The proxy contract is the public face of the Circle on main-net. It exposes only the methods main-net needs to know about:

```
proxy interface OctraVPNExit {
  // called by the Circle internals
  fn settle_claim(session_id: u64, bytes_used_ct: bytes) -> bool
  fn settle_confirm_ack(session_id: u64) -> bool  // forwarded from client
  fn report_dispute(session_id: u64, reason: bytes) -> bool

  // called by main-net AML
  fn slash_bond(amount: u64, reason: bytes) -> bool
  fn release_settled(session_id: u64, amount_to_operator: u64) -> bool
}
```

Critical property from §4.4.2: the proxy contract is enumerable only by addresses listed in its configuration. So a non-member of the tailnet **cannot even discover** which operator(s) serve that tailnet by reading on-chain state. To the broader chain, an operator looks like an opaque proxy address whose function table is gated on the caller.

### 4.4 Encrypted metering — what stays encrypted, what doesn't

The Circle counts bytes internally as HFHE ciphertexts. At settle time, the Circle (via its proxy) emits a `settle_claim(session_id, bytes_used_ct)`. Main-net AML now needs to compute `total_paid = bytes_used * price_per_mb` over a ciphertext. Two paths:

- **Path A — settle in clear**: the Circle decrypts `bytes_used` at settle time and the proxy submits a cleartext claim. Loses metering privacy but simplest. v1 already does this. **MVP for v2**.
- **Path B — settle encrypted**: `total_paid` is computed under HFHE; the client confirms by decrypting and signing the cleartext amount; main-net AML stores both ciphertext and amount. Strongest privacy; needs `fhe_scale` on `price_per_mb` and a transcipher to release main-net OU. **Future**.

Both paths use exactly the same main-net schema; the difference is who decrypts what.

## 5. ACL — shared exit vs internal subnet

The user's earlier ACL ask collapses cleanly into the Circle's access contract.

Two exit classes:

| Class | Egress | Default price | When used |
|---|---|---|---|
| `shared` | Public internet | Metered (operator-set) | A member needs the operator's clean-IP exit |
| `internal` | Tailnet-internal only (member→member) | Configurable; commonly 0 OU/MB | Member-to-member services hosted by the operator |

ACL rules live in the Circle's access contract:

```
acl {
  // tags propagate from tailnet member records
  rule allow members(tag = "user") → shared_exit
  rule allow members(tag = "user", tag = "internal-only") → internal
  rule deny  members(tag = "guest") → shared_exit
  rule allow members(tag = "guest") → internal-bookkeeping
}
```

Tailnet-level toggle `charge_internal_traffic: bool` lives in the main-net tailnet record. When false, the operator's Circle is contractually obliged (enforced at settle time by the proxy) to compute `total_paid = 0` for all `internal` class bytes; the chain side rejects any non-zero claim where the session's class is internal and the toggle is off.

## 6. Client SDK — what changes

Today a client opens a session against a public `octV…` address. In v2 the client opens against a **proxy address**, which it learns from the tailnet's authorized-proxy set (only visible to members):

```rust
// v1
session.open(tailnet_id, exit_addr: Address, max_pay).await?;

// v2
session.open(tailnet_id, proxy_addr: ProxyAddress, class: ExitClass, max_pay).await?;
```

`ProxyAddress` is structurally a main-net address but semantically opaque — the SDK doesn't display it to the user; the operator's identity stays inside the Circle.

The WireGuard wire format and headscale-rs coordination layer are **unchanged**. The Circle is upstream of the data plane; once a session opens, packets flow over WireGuard exactly as in v1.

## 7. Hidden-exits semantics

Two distinct properties, both delivered by Circles:

1. **Operator opacity (Tor-like).** Non-authorized callers cannot enumerate or inspect the proxy contract. They see traffic to *some* proxy address but cannot tell whether the proxy is an OctraVPN exit, a different dApp's Circle, or a passive smart contract. The litepaper is explicit on this (§4.4.2).
2. **Egress unlinkability.** The clear-internet exit IP belongs to the operator. From a destination service's perspective, traffic appears to come from the operator's clean IP — the client's identity is hidden by the WG layer, the operator's blockchain identity is hidden by the Circle.

What this **does not** give us:

- Multi-hop circuit anonymity (Tor's three-hop routing). v2's data plane is still single-hop unless we add onion routing in the headscale-rs / `octravpn-core::onion` layer (which already exists in code; v1 doesn't expose it at the AML level).
- Resistance to a malicious operator. The operator runs the Circle and sees the cleartext WG packets. Same trust model as any other VPN.

## 8. Migration path

We do not migrate v1 → v2 in-place. v1 is its own deployment on main-net. v2 deploys later as a separate program once Octra publishes the Circle DSL and reference proxy-contract grammar.

- v1 operators register as public addresses; v2 operators register their proxy addresses with the tailnet.
- A tailnet can be either v1 or v2; mixed-mode is out of scope.
- Headscale-rs (`~/Development/headscale-rs`) is the coordination layer for both. The integration shim in OctraVPN consumes `MeteringSnapshot` events from headscale-rs and dispatches them to either the v1 AML or the v2 Circle proxy.

## 9. Open questions / upstream dependencies

The following must be answered by Octra before v2 can be implemented.

Resolved on the public AML side as of the **2026-05-14** Octra dev-team announcement (reference deployment `octBDvZSiTqdEBAyFSp79CHeoLMR9MzHugX9YkHtuQ57MRB`):

- `ed25519_ok(pk, msg, sig) -> bool` — confirmed. Unblocks the cryptographic equivocation slash on the public AML side (see `program/main.aml::slash_double_sign`, `docs/security.md §3.2`).
- `digest_sha256`, `digest_keccak256` — confirmed.
- `current_tx_hash` — confirmed.
- Native `bool` type — confirmed (already used in v1 entrypoint returns).

These resolve the public-AML slice of the original §9 (in particular, the cryptographic-slash piece of dependency 4). The questions below are what remains for the Circle / proxy / access-contract layer:

1. **Circle DSL + SDK.** What language and tooling do we use to author the Circle's internal logic? The litepaper says Rust / C++ / OCaml / WASM; we need the SDK and the compiler path. As of 2026-05-14, `octra-labs/program-examples` ships no Circle examples.
2. **Proxy contract grammar.** Is the proxy contract authored in AML with special pragmas, or in its own DSL? How do we declare the "predefined callers" allowlist?
3. **Access contract grammar.** Same: AML-with-pragmas, or separate? What's the function-table syntax? Are there hooks for tag-based routing?
4. **Circle-internal HFHE primitive availability.** The public AML side of HFHE is now confirmed (we already use `fhe_add`, `fhe_sub`, `fhe_add_const`, `fhe_scale`, `fhe_verify_zero` in `program/main.aml`, and the AML side of cryptographic primitives is locked in by the 2026-05-14 announcement). What we still need: are the HFHE primitives also available inside the Circle's logic, or only at the proxy boundary? What's the supported path for **decrypting a Circle-internal ciphertext into a main-net cleartext value** at settle time?
5. **Bond escrow at proxy deployment.** Litepaper says the Circle's proxy is "deployed with a pre-allocated resource address." Can we attach a slashable OU bond to the proxy address at deployment? What's the slash interface? (We could otherwise hold the bond in our v2 AML program keyed by proxy address — workable but it splits authority across two contracts.)
6. **Operator discovery.** If only authorized callers can enumerate a proxy, how does a tailnet owner discover available operators to add to their authorized-proxy set in the first place? Some out-of-band channel? An opt-in public directory Circle?

Until these are answered we cannot write `main-v2.aml` against Octra's actual primitives. The work blocked on upstream:

- Authoring the Circle (no DSL).
- Authoring the proxy/access contracts (no grammar).
- HFHE byte counters inside the Circle (uses the existing `octra-labs/HFHE` library, but the in-Circle integration is undocumented).

Work that is **not** blocked and can proceed now:

- Sketch the v2 AML program (`program/main-v2.aml`) using the same AML grammar v1 uses, treating "proxy contract address" as just an address. We won't be able to compile-check it against Circle semantics, but the chain-side surface is concrete enough to write and review.
- Design the tailnet ACL data structures and the tag system.
- Update the client SDK to take a `ProxyAddress` instead of an operator `Address`.
- Update `headscale-rs` integration to wire `MeteringSnapshot` events at a "Circle proxy" abstraction (a Rust trait `OperatorBackend { fn settle_claim(...) }` with two impls: `MainnetOperator` for v1 and `CircleOperator` for v2).

## 10. Decision: what we do now

Ship v1. Use this document as the v2 design contract. When the user revisits the priority of v2 vs continued v1 polish, this doc is the starting point.

Open items captured as tasks:

- Write `program/main-v2.aml` skeleton against the v2 schema (no compile gate yet).
- Add the `OperatorBackend` trait abstraction in the client SDK so v1 and v2 can coexist behind one interface.
- Reach out to Octra dev team with §9's six open questions.
