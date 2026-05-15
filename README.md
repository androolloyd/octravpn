# OctraVPN

A decentralized VPN — Tailscale-style mesh with on-chain coordination —
that runs on Octra. Operators stake OU to run exit/relay endpoints,
tailnet owners group members under shared treasuries, sessions escrow
their cost in OU, traffic flows over WireGuard, and settlement is
**two-tx** (operator claims bytes_used → client confirms → AML
settles or records a public dispute). Misbehavior is slashed
in-AML.

> **Status: v1 production-ready.** AML compiles on mainnet, the Rust
> workspace ships **218 passing tests** + property tests + bounded-
> model harnesses + an in-process e2e harness. Formal specs in
> TLA+ (10,173 distinct states, 12 invariants), Tamarin (advisory),
> Lean 4 (clean `lake build`, 27 surviving + 10 new lemmas, zero
> `sorry`), and Kani (advisory) cover the structural and
> cryptographic protocol properties. HFHE primitives are wired
> against Octra's confirmed AML helpers (`fhe_load_pk`, `fhe_deser`,
> `fhe_ser`, `fhe_add`, `fhe_sub`, `fhe_add_const`, `fhe_scale`,
> `fhe_verify_zero`).

A **v2 Circle-native design** is captured in
[`docs/v2-circles-design.md`](docs/v2-circles-design.md) and tracks
the path to hidden operators + per-class ACL + encrypted metering
once Octra publishes the Circle SDK. See
[`docs/v2-octra-questions.md`](docs/v2-octra-questions.md) for the
six open questions for the Octra dev team.

---

## Architecture

```
                ┌──────────────────────────────────────────────┐
                │             Octra chain (program)            │
                │       /program/main.aml (compile-gated)      │
                │                                              │
                │  • operator stake registry (bond/unbond/slash) │
                │  • tailnet records (owner, treasury, members)│
                │  • sessions + two-tx settle (claim+confirm)  │
                │  • HFHE encrypted earnings ledger            │
                │  • hash-precommit join tokens                │
                │  • equivocation slash in-AML                 │
                └─────────────▲──────────────▲─────────────────┘
                              │              │
       JSON-RPC contract_call │              │  octra_submit
                              │              │
       ┌──────────────────────┴───┐    ┌─────┴──────────────────────┐
       │  octravpn (client CLI)    │    │  octravpn-node (operator  │
       │  /crates/octravpn-client  │    │  daemon)                  │
       │                           │    │  /crates/octravpn-node    │
       │  • discover endpoints     │    │                           │
       │  • tailnet open_session   │    │  • boringtun WG endpoint  │
       │  • boringtun client tunnel│◄──►│  • bandwidth metering     │
       │  • settle_confirm         │    │  • settle_claim           │
       │                           │    │  • claim_earnings (HFHE)  │
       └───────────────────────────┘    └───────────────────────────┘

                       Off-chain control + WireGuard data
```

Headscale-rs (separate sibling repo) is the future coordination
layer for Tailscale-protocol compatibility. See
[`https://github.com/androolloyd/headscale-rs`](https://github.com/androolloyd/headscale-rs).

Shared types and the JSON-RPC client live in `/crates/octravpn-core`,
which re-exports `address`/`sig`/`coverage` from the standalone
`octra-core` crate in the sibling foundry repo (see below).

## What's shielded, by layer

| Surface             | Shielded?      | Mechanism                                          |
| ------------------- | -------------- | -------------------------------------------------- |
| Tunnel contents     | yes            | WireGuard Noise IK                                 |
| Onion peeling       | yes (data plane) | per-hop ChaCha20-Poly1305 layer; AML is single-hop in v1 |
| Session→client link | yes            | ephemeral session pubkey, never wallet pubkey      |
| Earnings            | yes            | HFHE ciphertexts; homomorphic accumulation on chain |
| Payment recipients  | yes            | stealth outputs via Octra's X25519 ECDH scheme     |
| WG handshake fingerprint | partial   | pluggable transport scaffolded; obfs4 wrapping is a v2 milestone |
| Operator identity   | **no in v1**   | public `octV…` addresses; **hidden via Circles in v2** |
| Exit egress IP      | **no (inherent)** | the exit must actually send the request to the public internet |

The exit-IP limit is fundamental to *any* VPN. Mitigations: TLS-only
browsing, layering Tor over OctraVPN, and (v2) Circle-native operator
opacity so that even the *identity* of the exit operator is hidden
from non-authorized callers.

## Operators

Operators stake OU to register an endpoint. Registration requires:

1. `bond_endpoint` value-bearing tx with `amount ≥ MIN_ENDPOINT_STAKE`
   (default 1000 OCT).
2. `register_endpoint(endpoint, wg_pubkey, hfhe_pubkey, initial_enc_zero, region, price_per_mb)`.

There is no `register_validator` attestation step in v1 — operator
identity is the wallet address that posts the bond. The AML cannot
yet call `verify_ed25519` at compile time, so cryptographic
attestation is deferred until Octra exposes that primitive (or
until v2 Circles, which sidestep it entirely).

Liveness: an operator can `unbond_endpoint` to start the grace
period; after `UNBOND_GRACE` epochs the stake unlocks via
`finalize_unbond`. The endpoint becomes inactive immediately on
unbond.

Slashing conditions (all in-AML, no signature verification needed):

| Condition                  | Evidence                                                      | Slash               |
| -------------------------- | ------------------------------------------------------------- | ------------------- |
| Settle-claim equivocation  | same operator submits two `settle_claim` for the same session with different `bytes_used` | 90% burn + refund deposit |
| Governance slash           | owner calls `gov_slash_operator(addr, evidence)` after off-chain proof | 90% burn / 10% bounty |
| Unbond + sweep             | operator goes offline → tailnet owner / sweeper finalizes via `sweep_expired_session` | 1% bounty to sweeper |

Slashed funds split per program params: bounty to claimant +
treasury burn share. Sums must equal 10000 bps.

## Repository layout

```
octra/                              # this repo
├── program/                        # AppliedML on-chain program
│   ├── main.aml                    # v1 OctraVPN program (production)
│   └── main-v2.aml                 # v2 Circle-native skeleton (design)
│
├── crates/
│   ├── octravpn-core/              # shared types + Octra JSON-RPC + crypto
│   │                               #   (address/sig/coverage re-exported
│   │                               #    from octra-core in the foundry repo)
│   ├── octravpn-node/              # operator daemon (boringtun + chain glue)
│   ├── octravpn-client/            # CLI: discover, connect, settle, reclaim
│   ├── octravpn-tun/               # TUN device wrapper (Linux/macOS/Windows)
│   ├── octravpn-mesh/              # mesh coordination scaffolding
│   └── octravpn-admin-ui/          # operator admin web UI
│
│  (The `octra` dApp dev CLI — forge / cast / anvil / chisel — and the
│   octraforge / octra-mock-rpc / octra-core libraries live in the
│   sibling `octra-foundry` repo.)
│
├── tests/e2e/                      # full-flow integration tests vs mock RPC
│
├── proofs/
│   ├── tla/                        # TLA+ — 12 invariants, 10173 states, depth 18
│   ├── tamarin/                    # Dolev-Yao crypto-protocol model (advisory)
│   ├── lean/                       # Lean 4 entrypoint + lemma proofs (clean build)
│   └── kani/                       # bounded model checks for Rust crypto/parsing
│
├── docker/                         # Dockerfiles + compose harness + e2e.sh
├── docker-compose.yml              # mock-rpc + 3 nodes + client
├── .github/workflows/ci.yml        # CI: fmt, clippy, test, TLA, Lean, Kani, e2e
└── docs/                           # see Documentation table below
```

### Sibling repos (path-deps)

This workspace path-deps onto two sibling repos that must be checked
out side-by-side at the same directory level as `octra/`:

| Repo | Role |
| --- | --- |
| [octra-foundry](https://github.com/androolloyd/octra-foundry) | Foundry-style testing toolkit: `octraforge` (Forge equivalent), `octra-mock-rpc` (Anvil equivalent), `octra-core` (thin types crate) |
| [headscale-rs](https://github.com/androolloyd/headscale-rs) | Rust impl of Tailscale-style mesh coordination — slated as the v2 coordination layer |

```sh
mkdir octravpn-workspace && cd $_
git clone https://github.com/androolloyd/octravpn.git octra
git clone https://github.com/androolloyd/octra-foundry.git
git clone https://github.com/androolloyd/headscale-rs.git    # optional
cd octra && cargo build --workspace
```

## Quickstart — local

```sh
# Build everything (needs both repos cloned side-by-side; see above)
cargo build --workspace --release

# Run unit + integration + e2e tests (uses in-process mock RPC)
cargo test --workspace
```

Expected output: **218 tests pass**.

## Quickstart — Docker

```sh
# Build the full image set (Docker context is the parent dir so
# the foundry sibling is reachable)
docker compose build

# Boot mock RPC + 3 operator nodes
docker compose up -d mock-rpc node1 node2 node3

# Smoke: list active endpoints
./docker/e2e.sh

# Full tailnet happy-path
./docker/e2e-tailnet.sh
```

## Deploying the on-chain program

Full flow lives in [`docs/architecture.md`](docs/architecture.md).
Short version:

1. Open the Octra client's dev tools.
2. **Import folder** the `program/` directory.
3. Click **Compile** with the language set to `AppliedML (.aml)`.
4. Inspect ABI / Assembly / Storage tabs.
5. Enter constructor params (JSON array, positional):
   `[100, 10]` — `(min_session_deposit, min_tailnet_deposit)`.
6. **Preview address** if you want the deployed address up front,
   then **Deploy**.
7. After deployment, use **Verify contract source** to bind the
   deployed bytecode back to the `program/` source tree.

The compile-gate CI job re-runs `octra_compileAml` against the
live mainnet RPC on every PR.

## Formal verification

| Layer               | Tool      | Scope                                           |
| ------------------- | --------- | ----------------------------------------------- |
| State machine       | TLA+      | conservation, no double-settle, slash safety, two-tx confirm invariant, equivocation refund, token single-redeem (10173 states / depth 18 / <1s) |
| Crypto protocol     | Tamarin   | receipt unforgeability, double-sign slashable, no link before settle |
| Program semantics   | Lean 4    | bond/slash/register/tailnet/claim/two-tx settle/hash-token lemmas — zero `sorry` |
| Rust implementation | Kani      | receipt round-trip, monotonic check, payload determinism |
| Rust runtime        | proptest  | the same lemmas at unbounded sizes              |

Run them via:

```sh
# TLA+
cd proofs/tla
java -cp tla2tools.jar tlc2.TLC -workers auto -deadlock OctraVPN -config OctraVPN.cfg

# Tamarin (advisory)
cd proofs/tamarin
tamarin-prover --prove octravpn.spthy

# Lean
cd proofs/lean
lake build

# Kani (advisory)
cd proofs/kani
cargo kani

# Property + integration tests
cargo test --workspace
```

CI runs all of these on every PR.

## What's stubbed vs working

| Component                           | Status                                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| AML program (`program/main.aml`)    | complete, mainnet compile-gated                            |
| Rust workspace (build, types, RPC)  | complete, 218 tests pass                                   |
| Receipts (sign, verify, monotonic)  | complete + property-tested + Kani-checked                  |
| Pedersen commitments (route hiding) | complete (hash-based; HFHE-native swap is single-file)     |
| Onion routing (1–3 hops)            | data plane complete; AML is single-hop in v1               |
| boringtun WireGuard tunnel          | complete on Linux/macOS                                    |
| HFHE primitives                     | wired against Octra's confirmed AML helpers — see `octra-research.md` |
| Stealth payout                      | derivation + Octra-aligned X25519 ECDH integration complete |
| Two-tx settle                       | complete (operator `settle_claim` + client `settle_confirm`) |
| Equivocation slashing               | complete (in-AML, no `verify_ed25519` needed)              |
| Hash-precommit join tokens          | complete                                                   |
| Mock RPC                            | covers every method OctraVPN exercises                     |
| Docker compose                      | builds + boots end-to-end                                  |
| GitHub Actions CI                   | runs all tests + formal checks                             |
| v2 Circle-native operators          | design doc + AML skeleton + SDK trait; blocked on upstream  |

## Threat model

- **Adversary**: Dolev-Yao network attacker; can compromise individual
  operator keys or session keys.
- **Trust assumption**: Octra validator set is honest-majority (chain
  consensus guarantees apply).
- **What's *not* defended**: a fully malicious exit hop logs the
  destinations of egress traffic — this is fundamental to any VPN. The
  `MIN_ENDPOINT_STAKE` bond + slashing makes this expensive but not
  impossible. Multi-hop with diversity reduces correlation;
  Tor-over-OctraVPN eliminates it for users who need that. v2 Circles
  additionally hide the operator's identity.

## Documentation

| File | What's in it |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Long-form system design, current v1 two-tx flow |
| [`docs/v2-circles-design.md`](docs/v2-circles-design.md) | v2 Circle-native architecture (hidden ops + ACL + encrypted metering) |
| [`docs/v2-octra-questions.md`](docs/v2-octra-questions.md) | Six open questions for the Octra dev team |
| [`docs/aml-grammar.md`](docs/aml-grammar.md) | AppliedML grammar reference |
| [`docs/aml-gap-analysis.md`](docs/aml-gap-analysis.md) | Audit + migration rationale for v1 against confirmed Octra primitives |
| [`docs/security.md`](docs/security.md) | Threat model, primitives, per-component guarantees, formal-verification correspondence |
| [`docs/validator-hardening.md`](docs/validator-hardening.md) | Operator (validator-of-VPN) hardening guide |
| [`docs/economics.md`](docs/economics.md) | OU-only design, money flows, operator P&L |
| [`docs/attack-cost.md`](docs/attack-cost.md) | Concrete attack-cost analysis |
| [`docs/governance.md`](docs/governance.md) | Roles, parameters, decentralization roadmap, treasury policy |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversary capability table |
| [`docs/keys.md`](docs/keys.md) | Per-role key inventory and rotation |
| [`docs/octra-research.md`](docs/octra-research.md) | Public-info dossier on the Octra chain (validator economics, RPC, AML helpers, …) |
| [`docs/operator-guide.md`](docs/operator-guide.md) | Operator deployment guide: sizing, ports, perms, backup, monitoring |
| [`docs/production-checklist.md`](docs/production-checklist.md) | Pre-deploy checklist |
| [`docs/install.md`](docs/install.md) | Per-OS install: one-shot script, native package, or from source |

## License

MIT OR Apache-2.0
