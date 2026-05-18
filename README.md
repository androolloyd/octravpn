# OctraVPN

A decentralized VPN — Tailscale-style mesh with on-chain coordination —
that runs on Octra. Operators stake OU to run exit/relay endpoints,
tailnet owners group members under shared treasuries, sessions escrow
their cost in OU, traffic flows over WireGuard, and settlement is
**two-tx** (operator claims bytes_used → client confirms → AML
settles or records a public dispute). Misbehavior is slashed in-AML.

> **Status (2026-05-17).** Two AML deployments are live on devnet and
> run in parallel, gated by the node/client `protocol_version` config:
>
> - **v1.1** — `program/main.aml`, deployed at
>   `oct2YehVLezCi2RCcSkURc3nyyYtzxmspwGHHALm6pjkUvJ`. Public-registry
>   operators, two-tx settle, cryptographic `slash_double_sign`. The
>   v1.1 49-case adversarial drill landed clean. Production-ready.
> - **v2** — `program/main-v2.aml`, deployed at
>   `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`. Slim registry
>   + per-operator **Octra Circle** holding sealed `/policy.json`,
>   per-class ACL, and metering counters. 45/45 adversarial drill,
>   end-to-end on devnet through `open_session`. HFHE settlement is
>   the last gate — see "What's blocked" below.
>
> Across both programs: **95 Lean 4 theorems** (clean `lake build`,
> zero `sorry`), **TLA+** v1.1 + v2 modules (~4 M distinct states,
> 17 invariants, 0 violations), 30 Rust proptest harnesses, Kani
> bounded checks, and a GPL-isolated PVAC sidecar (`pvac-sidecar/`)
> producing chain-compatible HFHE blobs.

[Detailed v2 release notes](docs/v2-release-notes.md) ·
[Circle-native design](docs/v2-circles-design.md) ·
[v2 threat model](docs/v2-threat-model.md) ·
[v2 operator flow](docs/v2-operator-flow.md) ·
[v2 client flow](docs/v2-client-flow.md) ·
[v1.1 release notes](docs/v1.1-release-notes.md)

---

## Architecture

### v1.1 — public registry (still shippable)

```
                ┌──────────────────────────────────────────────┐
                │             Octra chain (program)            │
                │       /program/main.aml (v1.1, deployed)     │
                │                                              │
                │  • operator stake registry (bond/unbond/slash) │
                │  • tailnet records (owner, treasury, members)│
                │  • sessions + two-tx settle (claim+confirm)  │
                │  • HFHE encrypted earnings ledger            │
                │  • slash_double_sign (cryptographic)         │
                └─────────────▲──────────────▲─────────────────┘
                              │              │
       JSON-RPC contract_call │              │  octra_submit
                              │              │
       ┌──────────────────────┴───┐    ┌─────┴──────────────────────┐
       │  octravpn (client CLI)    │    │  octravpn-node (operator  │
       │  /crates/octravpn-client  │    │  daemon)                  │
       │                           │    │  /crates/octravpn-node    │
       │  • discover endpoints     │    │  • boringtun WG endpoint  │
       │  • open_session           │◄──►│  • bandwidth metering     │
       │  • settle_confirm         │    │  • settle_claim           │
       └───────────────────────────┘    └───────────────────────────┘

                       Off-chain control + WireGuard data
```

### v2 — circle-keyed, slim registry

```
                ┌──────────────────────────────────────────────┐
                │   Octra chain — slim registry (v2)           │
                │   /program/main-v2.aml (deployed)            │
                │                                              │
                │  • CircleRecord (owner, receipt_pk, prices)  │
                │  • tailnets + authorized_circles[tid][cid]   │
                │  • atomic register_circle (payable + bond)   │
                │  • two-tx settle keyed on circle_id          │
                │  • slash_double_sign / gov_slash on circle   │
                │  • HFHE ledger via fhe_load_pk(circle.owner) │
                └─────────▲────────────▲───────────▲───────────┘
                          │            │           │
       deploy_circle      │            │           │ open_session(tid, circle, class, max_pay)
       register_circle    │            │           │ settle_*
        + asset_put       │            │           │
                ┌─────────┴──┐  ┌──────┴──┐  ┌─────┴───────────────┐
                │ Operator   │  │ Operator│  │  Client (octravpn)  │
                │ Circle A   │  │ Circle B│  │  /crates/octravpn-  │
                │            │  │         │  │      client         │
                │ /policy.json│ │ ...     │  │                     │
                │ (sealed)   │  │         │  │  discover v2 <tid>  │
                │ ACL +      │  │         │  │  connect-v2 …       │
                │ metering   │  │         │  │  settle_confirm     │
                └────────────┘  └─────────┘  └─────────────────────┘
                       ▲                              │
                       │  octravpn-node               │
                       │  /crates/octravpn-node       │
                       │  • predict circle_id         │
                       │  • deploy_circle             │
                       │  • circle_asset_put_encrypted (sealed)│
                       │  • atomic register_circle    │
                       │  • boringtun WG endpoint     │
                       │  • PVAC sidecar IPC          │
                       └──────────────────────────────┘
```

The data plane is **unchanged**: WireGuard via boringtun, the same
JSON receipt protocol, and the same two-tx on-chain settle pattern.
What changed is **who the operator is on chain** (a circle, not a
wallet) and **how the client learns about it** (sealed asset fetched
by `resource_key`, not a public `EndpointRecord`).

## What's shielded, by layer

| Surface             | Shielded?      | Mechanism                                          |
| ------------------- | -------------- | -------------------------------------------------- |
| Tunnel contents     | yes            | WireGuard Noise IK                                 |
| Onion peeling       | yes (data plane) | per-hop ChaCha20-Poly1305 layer; AML is single-hop |
| Session→client link | yes            | ephemeral session pubkey, never wallet pubkey      |
| Earnings            | yes            | HFHE ciphertexts; homomorphic accumulation on chain |
| Payment recipients  | yes            | stealth outputs via Octra's X25519 ECDH scheme     |
| WG handshake fingerprint | partial   | pluggable transport scaffolded; obfs4 wrapping pending |
| Operator identity   | **v1.1: no.** Public `octV…` address. **v2: hidden via per-operator Circle** — sealed `/policy.json` carries the endpoint + WG pubkey; the chain only sees `circle_id` plus `from=deployer_wallet`, see `docs/v2-operator-key-hygiene.md` for the fresh-wallet rule | per-operator Circle + sealed AES-GCM asset + path-private `circle_asset_ciphertext_by_resource_key` fetch |
| Exit egress IP      | **no (inherent)** | the exit must actually send the request to the public internet |

The exit-IP limit is fundamental to *any* VPN. Mitigations: TLS-only
browsing, layering Tor over OctraVPN, and (v2) Circle-native operator
opacity so even the operator's wallet address is decoupled from a
public registry entry.

## Operators

### v1.1

Stake OU + register publicly:

1. `bond_endpoint` value-bearing tx with `amount ≥ MIN_ENDPOINT_STAKE`
   (default 1000 OCT).
2. `register_endpoint(endpoint, wg_pubkey, hfhe_pubkey, initial_enc_zero, region, price_per_mb, receipt_pubkey)`.

### v2

Deploy your own Circle, upload sealed policy, register atomically.
The node automates this — see [`docs/v2-operator-flow.md`](docs/v2-operator-flow.md):

1. **Predict** `circle_id` deterministically from
   `(deployer_wallet, nonce, deploy_payload)` (octra-core::circle).
2. `deploy_circle` if the predicted id is not on chain yet.
3. `circle_asset_put_encrypted` with the sealed `/policy.json` —
   AES-GCM-256 + PBKDF2-SHA256-120k + `"OCRS1"` magic + padding class
   (4k / 16k / 32k / 128k). The plaintext carries the WG endpoint,
   pubkey, region, and tariffs; only tailnet members holding the
   shared passphrase can read it.
4. `register_circle(circle, receipt_pubkey_b64, region, price_shared, price_internal)`
   carrying `value = MIN_CIRCLE_STAKE` — `register_circle` is
   **payable + atomic** in v2 (the chicken-and-egg of "bond requires
   owner / owner requires bond" surfaced in the live e2e and is
   fixed at `program/main-v2.aml:455`).

PVAC pubkey registration is a separate per-wallet step (run once,
not per-circle) because Octra's PVAC registry is wallet-keyed:
`octra cast register-pvac` (in the `octra-foundry` sibling) signs
`"register_pvac|<addr>|<sha256_hex(pk)>"` and submits
`octra_registerPvacPubkey`. v2 `fhe_load_pk(circles[c].owner)`
then resolves to the wallet-registered key.

Slashing (identical 90% burn / 10% bounty in both versions):

| Condition                  | Evidence                                                      |
| -------------------------- | ------------------------------------------------------------- |
| In-AML equivocation        | same operator submits two `settle_claim` for the same session with different `bytes_used` |
| Cryptographic equivocation | two distinct ed25519-signed receipt payloads under the operator's `receipt_pubkey` — see `slash_double_sign` |
| Governance slash           | owner calls `gov_slash_operator(addr/circle, evidence)`       |
| Unbond + sweep             | operator goes offline → 1% bounty to sweeper                  |

## Repository layout

```
octra/                              # this repo
├── program/                        # AppliedML on-chain programs
│   ├── main.aml                    # v1.1 (deployed, oct2Yeh…)
│   ├── main-v2.aml                 # v2 slim registry (deployed, oct3fxj…)
│   └── operator-circle.aml         # in-circle program (per-operator)
│
├── crates/
│   ├── octravpn-core/              # shared types + JSON-RPC + crypto +
│   │                               #   receipt journal (P1-8/9) + sealed
│   │                               #   key envelope (P1-6)
│   ├── octravpn-node/              # operator daemon (v1.1 + v2 register
│   │                               #   flows, seal-keys/unseal-keys cmds)
│   ├── octravpn-client/            # CLI: includes `discover v2 <tid>`
│   │                               #   and `connect-v2`
│   ├── octra-circle-sim/           # Rust simulator for an OctraVPN Circle
│   ├── octravpn-tun/               # TUN device wrapper
│   ├── octravpn-mesh/              # mesh coordination scaffolding
│   └── octravpn-admin-ui/          # operator admin web UI
│
├── pvac-sidecar/                   # GPL-isolated HFHE blob producer
│                                   #   (JSON-over-stdio; not linked into
│                                   #   the Rust workspace's MIT/Apache crates)
│
├── proofs/
│   ├── lean/                       # OctraVPN (v1.1) + OctraVPN_V2 modules
│   ├── tla/                        # OctraVPN.tla + OctraVPN_V2.tla
│   ├── tamarin/                    # Dolev-Yao crypto-protocol model (advisory)
│   └── kani/                       # bounded model checks
│
├── tests/e2e/                      # full-flow integration tests vs mock RPC
├── docker/                         # Dockerfiles, compose harness, e2e scripts
│   └── devnet/                     # e2e-adversarial-v2.sh (45 cases)
├── docker-compose.yml
└── docs/                           # see Documentation table below
```

### Sibling repos (path-deps)

| Repo | Role |
| --- | --- |
| [octra-foundry](https://github.com/androolloyd/octra-foundry) | `octraforge` (Forge), `octra-mock-rpc` (Anvil), `octra-core` (types + Circle primitive: `circle_id_of_deploy`, sealed-envelope codec, `resource_key`), `octra-cli` (`cast circle …`, `cast register-pvac`) |
| [headscale-rs](https://github.com/androolloyd/headscale-rs) | Rust Tailscale-style mesh coordination — v2 coordination layer |

```sh
mkdir octravpn-workspace && cd $_
git clone https://github.com/androolloyd/octravpn.git octra
git clone https://github.com/androolloyd/octra-foundry.git
git clone https://github.com/androolloyd/headscale-rs.git    # optional
cd octra && cargo build --workspace
```

## Quickstart — local

```sh
# Build everything (needs both sibling repos cloned side-by-side)
cargo build --workspace --release

# Run unit + integration + e2e tests (uses in-process mock RPC)
cargo test --workspace
```

## Quickstart — Docker

```sh
# Build the full image set (Docker context is the parent dir so
# the foundry sibling is reachable)
docker compose build

# Boot mock RPC + 3 operator nodes
docker compose up -d mock-rpc node1 node2 node3

# Smoke: list active endpoints (v1.1)
./docker/e2e.sh

# Full tailnet happy-path (v1.1)
./docker/e2e-tailnet.sh

# v2 adversarial drill (45/45 holds)
./docker/devnet/e2e-adversarial-v2.sh
```

## Deploying the on-chain programs

Full flow lives in [`docs/architecture.md`](docs/architecture.md). The
v1.1 program is in `program/main.aml`, the v2 slim registry is in
`program/main-v2.aml`, and each operator's in-circle program is in
`program/operator-circle.aml`.

For v2 deploys via `octraforge`:

```sh
# Slim registry (one per chain)
octra forge create program/main-v2.aml \
  --constructor-args '[100, 10, 1000000000, 100, 1000]'
# Per-operator circle is automated by `octravpn-node v2 register`
```

The compile-gate CI job re-runs `octra_compileAml` against the
live mainnet RPC on every PR.

## Formal verification

| Layer               | Tool      | Scope                                           |
| ------------------- | --------- | ----------------------------------------------- |
| State machine v1.1  | TLA+      | `OctraVPN.tla` — 12 invariants, 223,118 distinct states, depth 26 |
| State machine v2    | TLA+      | `OctraVPN_V2.tla` — circle-keyed, atomic register-bond, per-class price-stamp, 3,805,681 distinct states, depth 31 |
| Program semantics   | Lean 4    | v1.1 + v2 modules in `proofs/lean/OctraVPN[_V2]/` — 95 theorems / 0 `sorry` |
| Crypto protocol     | Tamarin   | receipt unforgeability, double-sign slashable, no link before settle (advisory) |
| Rust implementation | Kani      | receipt round-trip, monotonic check, payload determinism |
| Rust runtime        | proptest  | 30 harnesses across `octravpn-core` + `octravpn-mesh` — canonicalization, monotonic seq, security, receipt context binding, sweep determinism |

Run them via:

```sh
cd proofs/tla && java -cp tla2tools.jar tlc2.TLC -workers auto -deadlock OctraVPN -config OctraVPN.cfg
cd proofs/tla && java -cp tla2tools.jar tlc2.TLC -workers auto -deadlock OctraVPN_V2 -config OctraVPN_V2.cfg
cd proofs/lean && lake build
cd proofs/kani && cargo kani
cargo test --workspace
```

## What's blocked

- **End-to-end HFHE settle / claim_earnings on devnet**: the devnet
  RPC nginx body cap rejects POST > 1 MiB, and the PVAC pubkey
  registration tx is ~4 MB. Until the cap is raised (filed
  upstream), `octra cast register-pvac` fails on devnet with a 413.
  Mainnet accepts it; the PVAC sidecar has cleared the AES KAT
  gate and produces chain-compatible blobs.

## Threat model

- **Adversary**: Dolev-Yao network attacker; can compromise individual
  operator keys or session keys.
- **Trust assumption**: Octra validator set is honest-majority.
- **What's *not* defended**: a fully malicious exit hop logs the
  destinations of egress traffic — fundamental to any VPN. v2 hides
  the operator's *identity* (sealed policy + path-private fetch) but
  not the exit IP. Operator-side key hygiene matters because
  `deploy_circle` is a normal tx with `from=deployer → to_=circle_id`
  permanently recorded — see [`docs/v2-operator-key-hygiene.md`](docs/v2-operator-key-hygiene.md).

Full cryptographic threat model in [`docs/v2-threat-model.md`](docs/v2-threat-model.md)
(18-item fix queue; **P0-1 / P0-2 / P0-3 / P1-5 / P1-6 / P1-8 / P1-9 / P1-10
all FIXED in source as of `d6b3930`**).

## Documentation

| File | What's in it |
| --- | --- |
| [`docs/v2-release-notes.md`](docs/v2-release-notes.md) | v2 substrate — what shipped, commit-by-commit |
| [`docs/v1.1-release-notes.md`](docs/v1.1-release-notes.md) | v1.1 cryptographic `slash_double_sign` notes |
| [`docs/architecture.md`](docs/architecture.md) | Long-form system design (v1.1 + v2) |
| [`docs/v2-circles-design.md`](docs/v2-circles-design.md) | v2 Circle-native architecture (status snapshot in §0) |
| [`docs/v2-threat-model.md`](docs/v2-threat-model.md) | Cryptographic threat model + 18-item fix queue |
| [`docs/v2-operator-flow.md`](docs/v2-operator-flow.md) | Operator runbook for v2 (deploy + register) |
| [`docs/v2-client-flow.md`](docs/v2-client-flow.md) | Client runbook for v2 (discover + connect-v2) |
| [`docs/v2-operator-key-hygiene.md`](docs/v2-operator-key-hygiene.md) | Fresh-wallet rule + sealed-key mode |
| [`pvac-sidecar/README.md`](pvac-sidecar/README.md) | GPL-isolated HFHE blob producer |
| [`docs/aml-grammar.md`](docs/aml-grammar.md) | AppliedML grammar reference |
| [`docs/security.md`](docs/security.md) | v1.1 threat model + formal-verification correspondence |
| [`docs/economics.md`](docs/economics.md) | OU-only design, money flows, operator P&L |
| [`docs/governance.md`](docs/governance.md) | Roles, parameters, decentralization roadmap |
| [`docs/operator-guide.md`](docs/operator-guide.md) | Operator deployment guide |
| [`docs/install.md`](docs/install.md) | Per-OS install |
| [`docs/octra-research.md`](docs/octra-research.md) | Public-info dossier on the Octra chain |

## License

MIT OR Apache-2.0 for the Rust workspace + AML programs.
GPL-2+ (with OpenSSL exemption) for `pvac-sidecar/` — isolated as a
separate process; no GPL symbols cross into the Rust crates.
