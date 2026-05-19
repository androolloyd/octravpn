# Threat Model — v3 Executive Summary

Two-page executive summary of the OctraVPN v3 threat model. Pulled
from the audit-log + receipt + ACL invariants captured in
`security-properties.md` and from the v2 base in
`docs/v2-threat-model.md` (the v2 doc is the long-form prior art —
v3 inherits its layer index and adversary classes, and changes only
the chain-resident surface). If a v3-specific long-form lives at
`docs/security/threat-model-v3.md` at audit time, that document
supersedes this summary; the file you are reading is the version
that ships with the audit-prep snapshot.

---

## Adversary classes

We model six observer / attacker roles, in increasing capability:

1. **N-Pass** — Passive on-path network observer (ISP, transit).
2. **N-MITM** — Active on-path attacker (rogue CA, captive portal,
   evil-twin Wi-Fi). Can drop, reorder, inject.
3. **OctraRPC** — The TLS terminator at `devnet.octrascan.io`
   (mainnet equivalent). Sees every JSON-RPC body.
4. **Op** — Malicious exit-node operator. Runs the daemon; controls
   one bonded circle's keys.
5. **Mem** — Authorized tailnet member (gets the policy passphrase).
6. **Own** — Tailnet owner (issued the passphrase; can rotate ACL).
7. **Q** — Cryptographically-relevant quantum adversary (future).

---

## What v3 protects, and against whom

### 1. Bytes counted, payments enforced

> Claim: A session that delivers N bytes settles for ≥ N bytes,
> and any operator that signs two different `bytes_used` for the
> same `(session_id, seq)` loses their bond.

- Defended by: dual-signed receipts (P1, P2), receipt journal (P3),
  monotonic `seq` (P4), `slash_double_sign` AML entrypoint (P5),
  validator-bond boot gate (P6).
- Holds against: Op (cannot equivocate undetected), N-MITM (cannot
  forge a receipt), OctraRPC (cannot tamper a signed receipt
  in-flight without invalidating it).
- Does NOT hold against: a chain that fails to deliver
  `slash_double_sign` atomically (we treat this as a precondition,
  not a defended property — see "out of scope" in README §4).

### 2. Operator history is tamper-evident

> Claim: Any modification, deletion, or reordering of an operator's
> `audit-YYYY-MM-DD.jsonl` log is detected by `audit verify`.

- Defended by: HMAC chain (P7).
- Holds against: Op (post-incident self-tampering is detected),
  forensic reviewer (deterministic chain walk).
- Does NOT hold against: Op tampering with the live log + the
  `.audit.key` on the same host before any external collection.
  Operators are expected to ship the log + key to off-host storage
  (see `docs/operators/mainnet-deployment.md` §10).

### 3. Member set + ACL are anchored

> Claim: The tailnet owner cannot quietly rewrite history. Every
> `members.json` and `acl.json` change advances an on-chain anchor;
> a verifier with the off-chain JSON and the chain anchor agrees on
> who-is-a-member-when.

- Defended by: canonical-JSON encoder (P13), `members.json` schema
  (`crates/octravpn-core/src/v3_members.rs`), ACL parser with
  default-deny + `deny_unknown_fields` (P10), on-chain
  `update_members_root` / `update_acl` (which the AML guards as
  owner-only — P18).
- Holds against: Own attempting silent history rewrites,
  Mem replaying a stale members.json (chain anchor mismatches).
- Does NOT hold against: a verifier that doesn't actually compare
  the canonical-bytes sha256 against the chain anchor. The CLI
  verbs (`octravpn verify-members`, etc.) do this; clients calling
  raw chain RPCs are expected to follow the same pattern.

### 4. Preauth keys are single-use

> Claim: A preauth key minted with `reusable = false` cannot be
> redeemed twice. Every redemption is audit-logged.

- Defended by: `PreauthMinter::redeem` removal-on-redeem (P11),
  redemption audit record with bounded TTL.
- Holds against: a stolen preauth key being used twice (second
  attempt returns `RedeemError::Unknown`).
- Does NOT hold against: an attacker who intercepts the key before
  the legitimate user redeems it AND races them to the redeem
  endpoint — the attacker wins. Mitigation: the preauth bearer
  channel between operator and client must be confidential
  end-to-end (operator UI ships it over TLS; ops scripts that
  echo to stdout in CI logs are an anti-pattern called out in
  `docs/operators/mainnet-deployment.md`).

### 5. Control-plane DoS is bounded

> Claim: A flood from a single IP cannot stall the control plane
> for legitimate clients; bounded per-peer state limits memory
> growth.

- Defended by: token-bucket rate limiter (P8), `BoundedMap` per-peer
  state (P9).
- Holds against: N-MITM or random-IP-spoofer attempting resource
  exhaustion.
- Does NOT hold against: a distributed flood from thousands of
  source IPs (rate limit is per-IP). Mitigation: deploy the control
  plane behind a CDN/edge that does L4 anti-DDoS — documented in
  the mainnet deployment runbook.

### 6. Confidentiality on the wire

> Claim: WG data plane is end-to-end ChaCha20-Poly1305 between
> client and exit; intermediate onion hops see only their per-hop
> ciphertext.

- Defended by: boringtun (data plane), per-hop X25519+HKDF AEAD
  (P21, P22), session-counter nonce monotonicity (P4, P15).
- Holds against: N-Pass / N-MITM seeing application payloads,
  intermediate operators reading the inner stream.
- Does NOT hold against: the EXIT operator. The exit decrypts the
  egress payload — that is the operator's contract. The
  `v2-threat-model.md §1A` and §1B residual leaks (WG static
  pubkey + on-chain `from→to_` binding) remain valid in v3 because
  the registration tx shape is unchanged.

### 7. Cross-deploy replay safety

> Claim: A receipt signed against program A on chain C in circle X
> is invalid against any other (A', C', X').

- Defended by: v1.2 domain binders in the receipt payload (P2).
- Holds against: cross-deploy / cross-chain / cross-circle replay
  (e.g. testnet→mainnet replay, multi-region operator with two
  parallel v3 deploys).

---

## What v3 does NOT protect

These are explicit residual risks. Each is documented in detail in
`security-properties.md` "Properties intentionally NOT claimed"
and is reiterated here so the auditor's exec sees them up front:

- **Quantum-classical break of Curve25519 / ChaCha20.** No PQ
  overlay. Captured WG handshakes + JSON-RPC TLS bodies become
  decryptable to a CRQC. We do not claim PQ resistance.
- **`from→to_` chain-public binding.** The operator's deploy wallet
  is permanently linked to the circle. Mitigation: operator key
  hygiene (`docs/v2-operator-key-hygiene.md`).
- **Traffic analysis of WG UDP envelopes.** 5-tuples, packet
  sizes, and timings remain on the wire. Padding classes
  (P22) blunt size correlation but do not erase it.
- **JSON-RPC TLS terminator (devnet.octrascan.io).** With the
  default trust-system-roots configuration, this party sees every
  RPC body in cleartext. Pinned-root mode
  (`Rpc::new_with_pinned_roots`, `octravpn-core/src/rpc.rs:93`) is
  available but not default.
- **Earnings amounts on chain.** While the HFHE/PVAC bridge is
  unwired on devnet (memory `octra_aml_fhe_load_pk_blocked.md`),
  the earnings hash-chain commits are tamper-evident but NOT
  hiding. Per-epoch earnings amounts are publicly observable.
  Privacy parity with the v2 target requires the HFHE bridge to
  ship.

---

## Layer index (compressed)

Full version: `docs/v2-threat-model.md` §0. The v3-relevant
deltas:

| # | Layer | v2 surface | v3 surface |
|---|---|---|---|
| 1 | WG data plane | unchanged | unchanged |
| 2 | JSON-RPC | rustls 0.23 | unchanged |
| 3 | Sealed `/policy.json` | inline AES-GCM in chain map | sha256 anchor on chain + circle sealed asset |
| 4 | Tx envelope | unchanged | adds v1.2 domain binders to receipts |
| 5 | Earnings ledger | Pedersen (Ristretto) + HFHE-target | sha256 hash-chain commit (HFHE deferred) |
| 6 | Member ACL | chain-resident member rows | sha256 anchor on chain + off-chain `members.json` |
| 7 | Tailnet plane | HTTP control + Ed25519-signed gossip | unchanged + preauth bridge to TS-wire |
| 8 | On-disk keys | plain-hex by default | optional sealed mode (P12) via `seal-keys` |

---

## Recommended audit focus, in priority order

1. **Receipt / journal / slash path** — the load-bearing
   crypto-economic contract. Properties P1–P5.
2. **Audit-log HMAC chain** — operator integrity surface; the
   only post-incident forensic anchor. Property P7.
3. **v3 anchor schemas + canonical-JSON encoder** — silent
   anchor mismatch = silent invariant break. Properties P13, P18.
4. **AML program entrypoints** — `slash_double_sign`,
   `gov_slash_operator`, `register_circle_atomic`,
   `update_members_root`, `update_acl`. Property P18; drill
   `e2e-adversarial-v3.sh`.
5. **Preauth bridge + Tailscale-wire integration** — Property P11
   plus the cross-repo boundary into `headscale-api`. Tests:
   `crates/octravpn-node/tests/tailscale_wire_integration.rs`.
6. **Sealed key custody** — `seal-keys` envelope, passphrase
   handling. Property P12.
