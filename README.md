# OctraVPN

A decentralized VPN that runs on Octra. Validators are the VPN nodes,
sessions route through 1–3 hops with onion encryption, payments are
shielded end-to-end via Octra's stealth and FHE primitives, and
misbehavior is slashed by the on-chain program.

> **Status: v1 reference implementation.** The Applied program is
> complete; the Rust workspace builds and ships 17 passing tests +
> property tests + bounded-model harnesses + an in-process e2e harness;
> formal specs in TLA+, Tamarin, and Lean 4 cover the structural and
> cryptographic protocol properties. Concrete HFHE primitives are
> wired through a pluggable `octravpn-fhe-helper` so the system runs
> end-to-end against a stub today and against Octra's HFHE SDK as
> soon as it ships.

---

## Architecture

```
                ┌────────────────────────────────────────────┐
                │          Octra chain (program)             │
                │  /program/main.aml + interfaces/IOctraVPN  │
                │                                            │
                │  • validator registry (gated on validator  │
                │    attestation + bond)                     │
                │  • multi-hop session escrow                │
                │  • FHE encrypted earnings ledger           │
                │  • stealth payouts via private transfer    │
                │  • slashing: double-sign, no-show, offline │
                └─────────────▲──────────────▲───────────────┘
                              │              │
       JSON-RPC contract_call │              │  octra_submit / privateTransfer
                              │              │
       ┌──────────────────────┴───┐    ┌─────┴──────────────────────┐
       │  octravpn (client CLI)    │    │  octravpn-node (validator │
       │  /crates/octravpn-client  │    │  daemon)                  │
       │                           │    │  /crates/octravpn-node    │
       │  • discover validators    │    │                           │
       │  • commit to route (1..3) │    │  • boringtun WG endpoint  │
       │  • open session, escrow   │    │  • onion forwarding       │
       │  • boringtun client tunnel│◄──►│  • bandwidth metering     │
       │  • settle / reclaim       │    │  • receipt store + sign   │
       │                           │    │  • claim earnings stealth │
       └───────────────────────────┘    └───────────────────────────┘

                       Off-chain control + tunnel data
```

Shared types and the JSON-RPC client live in
`/crates/octravpn-core`.

## What's shielded, by layer

| Surface             | Shielded?      | Mechanism                                          |
| ------------------- | -------------- | -------------------------------------------------- |
| Tunnel contents     | yes            | WireGuard Noise IK                                 |
| Onion peeling       | yes            | per-hop ChaCha20-Poly1305 layer                    |
| Session→client link | yes            | ephemeral session pubkey, never wallet pubkey      |
| Session→node link   | yes (during)   | Pedersen commitments to node addresses             |
| Payment amounts     | yes            | FHE ciphertexts; homomorphic accumulation on chain |
| Payment recipients  | yes            | stealth outputs via `octra_privateTransfer`        |
| WG handshake fingerprint | partial   | pluggable transport scaffolded; obfs4 wrapping is a v2 milestone |
| Exit egress IP      | **no (inherent)** | the exit hop must actually send the request to the public internet |

The exit-IP limit is fundamental to *any* VPN. Mitigations: TLS-only
browsing, multi-hop routing (so the entry hop can't correlate destination),
or layering Tor over the VPN.

## Validators-only

Only Octra validators can register as VPN nodes. Registration requires:

1. A bond ≥ `min_bond` attached to `register_validator` (`value`).
2. An ed25519 attestation signature over `(self_addr || tag_bond || epoch)`
   verified against the caller's account key.
3. `caller == origin` (no proxy registrations).

Liveness is enforced via `refresh_attestation` — a validator must call it
at most every `attest_grace_epochs`. Missed attestations let anyone call
`slash_offline` for a small bounty + jail.

Slashing conditions:

| Condition          | Evidence                                              | Slash         |
| ------------------ | ----------------------------------------------------- | ------------- |
| Double-signed receipt | two distinct receipts signed by same node for same `(session, seq)` | full bond, jail |
| Offline            | `last_attest_epoch + grace < current_epoch`            | 1% of bond, jail |
| No-show on session | client reveals entry hop after `claim_no_show`         | up to 10% of bond |

Slashed funds split per `params.slash_*_bps`: bounty to claimant + burn +
treasury. Sums must equal 10000 bps.

## Repository layout

```
octra/
├── program/                       # AppliedML on-chain program
│   ├── main.aml                   # OctraVPN program (state, entrypoints)
│   └── interfaces/IOctraVPN.aml   # public ABI surface
│
├── crates/
│   ├── octravpn-core/             # shared types, Octra JSON-RPC, crypto, FHE wire fmt
│   ├── octravpn-node/             # validator-side daemon (boringtun + chain glue)
│   └── octravpn-client/           # CLI: discover, connect, settle, reclaim
│
├── fhe-helper/                    # pluggable HFHE bridge (stub today)
│
├── tests/
│   ├── mocks/                     # in-process Octra JSON-RPC mock for tests
│   └── e2e/                       # control-plane integration tests vs the mock
│
├── proofs/
│   ├── tla/                       # TLA+ state-machine spec + invariants
│   ├── tamarin/                   # Dolev-Yao crypto-protocol model
│   ├── lean/                      # Lean 4 entrypoint + lemma proofs
│   └── kani/                      # bounded model checks for Rust crypto/parsing
│
├── docker/                        # Dockerfiles + compose harness + e2e.sh
├── docker-compose.yml             # mock-rpc + 3 nodes + client
├── .github/workflows/ci.yml       # CI: fmt, clippy, test, TLA, Tamarin, Lean, Kani, e2e
└── README.md
```

## Quickstart — local

```sh
# Build everything
cargo build --workspace --release

# Run unit + integration + e2e tests (uses in-process mock RPC)
cargo test --workspace
```

Expected output: 17 tests pass.

## Quickstart — Docker

```sh
# Build the full image set
docker compose build

# Boot mock RPC + 3 validator-VPN nodes
docker compose up -d mock-rpc node1 node2 node3

# Run the smoke test (one-shot: lists active validators)
./docker/e2e.sh
```

## Deploying the on-chain program

Follow `docs/architecture.md` for the production flow. Short version:

1. Open the Octra client's dev tools.
2. **Import folder** the `program/` directory (keeps `main.aml` plus
   `interfaces/IOctraVPN.aml` in the same project).
3. Click **Compile** with the language set to `AppliedML (.aml)`.
4. Inspect ABI / Assembly / Storage tabs.
5. Enter constructor params (JSON array, positional):
   `[1000, 10, 5, 100, 10]` — `(min_bond, min_session_deposit, attest_grace_epochs, session_grace_epochs, unbond_epochs)`.
6. Click **Preview address** if you want to know the deployed address up
   front; then **Deploy**.
7. After deployment, use **Verify contract source** to bind the deployed
   bytecode back to the `program/` source tree.

## Formal verification

| Layer               | Tool      | Scope                                           |
| ------------------- | --------- | ----------------------------------------------- |
| State machine       | TLA+      | conservation, no double-settle, slash safety, monotonic seq, settle-or-refund liveness |
| Crypto protocol     | Tamarin   | receipt unforgeability, double-sign slashable, no link before settle |
| Program semantics   | Lean 4    | register, addBond, completeUnbond, settle, slashDoubleSign lemmas |
| Rust implementation | Kani      | receipt round-trip, monotonic check, payload determinism |
| Rust runtime        | proptest  | the same lemmas at unbounded sizes              |

Run them via:

```sh
# TLA+
cd proofs/tla
java -cp tla2tools.jar tlc2.TLC -workers auto -deadlock OctraVPN -config OctraVPN.cfg

# Tamarin
cd proofs/tamarin
tamarin-prover --prove octravpn.spthy

# Lean
cd proofs/lean
lake build

# Kani
cd proofs/kani
cargo kani

# Property + integration tests
cargo test --workspace
```

CI runs all of these on every PR.

## What's stubbed vs working

| Component                           | Status                                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| AML program (`program/`)            | complete                                                   |
| Rust workspace (build, types, RPC)  | complete                                                   |
| Receipts (sign, verify, monotonic)  | complete + property-tested + Kani-checked                  |
| Pedersen commitments (route hiding) | complete (hash-based; HFHE-native swap is single-file)     |
| Onion routing (1–3 hops)            | data structures + policy complete; tunnel forwarding is partial |
| boringtun WireGuard tunnel          | server bind + packet RX scaffolded; full TUN egress is OS-specific |
| FHE primitives                      | pluggable `octravpn-fhe-helper`; stub today, real HFHE SDK swap-in single file |
| Stealth payout                      | derivation + RPC integration complete                      |
| Slashing entrypoints                | complete                                                   |
| Mock RPC                            | covers every method OctraVPN exercises                     |
| Docker compose                      | builds + boots end-to-end                                  |
| GitHub Actions CI                   | runs all tests + formal checks                             |

## Threat model

- **Adversary**: Dolev-Yao network attacker; can compromise individual
  validator keys or session keys.
- **Trust assumption**: Octra validator set is honest-majority (chain
  consensus guarantees apply).
- **What's *not* defended**: a fully malicious exit hop logs the
  destinations of egress traffic — this is fundamental to any VPN. The
  `min_bond` + slashing makes this expensive but not impossible. Multi-
  hop with diversity reduces correlation; Tor-over-OctraVPN eliminates
  it for users who need that.

## License

MIT OR Apache-2.0
