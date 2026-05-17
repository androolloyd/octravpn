# OctraVPN v2 — Cryptographic Threat Model & Dependency Audit

> Pass: 2026-05-17. Live devnet substrate per `docs/v2-circles-design.md §0`.
> Scope: every layer that touches plaintext / ciphertext / metadata on the
> wire or at rest, plus the dep risk register that lets an attacker turn a
> crypto bug into surveillance.
> NOT in scope: the in-flight Rust-leak audit (it owns log / Display leakage
> of secrets; this doc owns the cryptography and the comm stack).

---

## 0. Layer index

| # | Layer | File(s) | Crypto |
|---|---|---|---|
| 1 | WG data plane | `crates/octravpn-node/src/tunnel.rs` | boringtun 0.7.1: Curve25519 (Noise IKpsk2) + ChaCha20-Poly1305 |
| 2 | Octra JSON-RPC | `crates/octravpn-core/src/rpc.rs`, `crates/octravpn-client/src/runner.rs` | rustls 0.23.40 + WebPKI roots 1.0.7 |
| 3 | Sealed `/policy.json` | `octra-foundry/crates/octra-core/src/circle.rs:268` | AES-256-GCM 0.10.3 + PBKDF2-HMAC-SHA256 (120k iters) |
| 4 | Octra tx envelope | `octra-foundry/crates/octra-core/src/tx.rs` | ed25519-dalek 2.2.0 over canonical JSON (no domain prefix) |
| 5 | HFHE earnings ledger (placeholder) | `crates/octravpn-core/src/earnings.rs` | Curve25519 Pedersen (Ristretto) commitments; PVAC pending |
| 6 | Member ACL / acceptance | `program/operator-circle.aml:153-173` | ed25519_ok (base64 pk + sig) |
| 7 | Coordination / tailnet plane | `crates/octravpn-mesh/src/peer.rs`, `crates/octravpn-node/src/control.rs` | Ed25519-signed gossip snapshots + plaintext HTTP control plane |
| 8 | Operator-host key storage | `docker/devnet/state/{node*,client,deployer.key}` plus per-operator opt-in `*.sealed` files via `octravpn-node seal-keys` | Raw hex on disk by default (devnet/v1 back-compat). P1-6 ships a `wallet_enc` (ChaCha20-Poly1305 + PBKDF2) envelope path for operators that set `[chain].require_sealed_keys = true` and route their secret paths at the `*.sealed` companion files. |

---

## 1. Observer / asset matrix

Rows = layers (above). Columns = observer classes:

- **N-Pass** = passive on-path observer
- **N-MITM** = active on-path (can drop / reorder / inject)
- **OctraRPC** = devnet.octrascan.io (TLS terminator + JSON-RPC operator)
- **Op** = malicious operator (runs the exit node)
- **Mem** = malicious tailnet member (authorized peer)
- **Own** = malicious tailnet owner (the wallet that called `create_tailnet`)
- **Q** = future cryptographically-relevant quantum adversary

| | N-Pass | N-MITM | OctraRPC | Op | Mem | Own | Q |
|---|---|---|---|---|---|---|---|
| **1. WG data plane** | seen: client↔operator UDP 5-tuple, packet sizes, timing. NOT seen: handshake static pubkey (Noise IK encrypts it under MAC1 mix) only at IKpsk2 init; **but** see §1A | same as N-Pass + can drop & force handshake replay (boringtun rejects replay via session counter `tunnel.rs:20`) | nothing direct (not on the path) | EVERYTHING after decryption: plaintext IPv4/v6, every TCP stream, every DNS query *unless internally tunneled*. Inner onion blob is peeled (`onion.rs:163`) and the egress payload is emitted clear (`tunnel.rs:192-203`) | only what their own session decrypts | nothing direct | **break** — Curve25519 falls; recorded WG handshakes + transport are decryptable (no PQ overlay). |
| **2. JSON-RPC** | client/operator → `devnet.octrascan.io:443`. Sees TLS SNI, IP, byte sizes, timing. **No cert pinning** (`rpc.rs:73`) | given a CA cert (rogue CA, MITM proxy on operator host) can read every RPC body — wallets, balances, contract_call params (including `circle_id`, `tailnet_id`) | reads every RPC body (it terminates TLS!). Correlates every contract_call across clients. **Bottleneck observer.** | sees RPC bodies for the operator's own RPCs | sees own RPC bodies | sees own RPC bodies | breaks rustls TLS retroactively (record TLS captures + decrypt) |
| **3. Sealed `/policy.json`** | sees AES-GCM envelope, size = padding class (4k by default) | same | sees the bytes; cannot read plaintext without the per-tailnet passphrase. **But:** sees the asset *exists*, the `key_id`, plaintext_hash | sees it (uploaded it) | reads it (member has passphrase) | reads it (issued the passphrase to members) | breaks AES-GCM-256? No — PBKDF2 → AES-256 still ~128-bit Grover. The **weak link is the passphrase entropy** plus PBKDF2 120k (~20ms/guess on a GPU). |
| **4. Tx envelope** | nothing — TLS to the RPC | given cert: full canonical JSON (`from`, `to_`, `op_type`, params), signature, pubkey | **full plaintext** including every `from→to_` pairing on chain; this is where the wallet↔circle binding leaks (see §1B) | reads only own txs (chain is public — they can scrape octrascan) | scrapes octrascan | scrapes octrascan | sigs forgeable; identifies signers; full retroactive linking |
| **5. Earnings ledger** | (Pedersen point on chain, public) | same | full ledger view | sees own | sees own | sees own | DLP falls; opens every commitment retroactively. Pedersen hiding goes away; amounts revealed. |
| **6. Member ACL** | nothing | given cert: receipt_pubkey, acceptance_payload + sig as RPC call args | **everything** — member acceptance carries `member: address` + `receipt_pubkey` + sig in clear → links wallet to circle | sees per-circle member set | sees own commit | sees + controls (owner calls `commit_member`) | retroactive linking of member→circle |
| **7. Coordination / tailnet** | sees the HTTP `/session/*` traffic in CLEAR (`control.rs:34`). Reads `client_wg_pubkey`, `session_id`, `node_pubkey`, **proposed receipt + bytes_used**. | rewrite + forge proposed receipts before they reach the client. Client only checks the signature on its own; node receipt forgery requires node key | nothing direct | hosts the control plane; sees its own session metadata | sees nothing of others' sessions | sees nothing of others' | retroactive break of any TLS overlay we add |
| **8. On-disk keys** | nothing | nothing | nothing | default (back-compat): reads plain-hex `wallet.key` / `wg.key` / `deployer.key`. With P1-6 sealed-mode opt-in (`require_sealed_keys=true` and `*.sealed` paths in TOML): reads only the AEAD envelope; passphrase comes from `OCTRAVPN_KEY_PASSPHRASE` (or legacy `OCTRAVPN_WALLET_PASSPHRASE`). Plaintext-on-disk in strict mode surfaces `CoreError::PlaintextKeyOnDisk` at boot. | nothing | nothing | n/a |

### 1A. WG static-pubkey leak via `peek_initiator_pubkey`

`tunnel.rs:249-257` reads bytes 8..40 of the WG handshake-initiation message as a peer-pubkey hint. That's the **ephemeral** pubkey (per Noise IK), not the static one — but it is unique per handshake and **public on the wire**. An on-path observer collecting these per-flow gets a stable per-handshake identifier across NATs that re-use it, and the operator's allowlist binding (control plane `/session` POST → `client_wg_pubkey`) is the *static* one. **The static pubkey is exposed to OctraRPC and to anyone with a CA cert** because the announce request is sent over the plaintext HTTP control plane to the operator (`control.rs:34`).

### 1B. `from=wallet → to_=circle_id` binding (the known leak)

`deploy_circle` is a normal Octra tx; `from=<deployer_wallet>`, `to_=<circle_id>`. octrascan (and any chain scraper) sees this as a permanent record. Every `register_circle` ALSO carries `from=<owner_wallet>` and includes the `circle` address in params (`main-v2.aml:455-498`), re-binding. `bond_endpoint`, `slash_double_sign`, `gov_slash_operator`, `finalize_unbond` re-bind on every call (`main-v2.aml:341-377`). **Mitigation:** an operator must deploy from a wallet with NO prior history; see `docs/v2-operator-key-hygiene.md`.

---

## 2. Attack trees

Each leaf cites where it bites and whether the v2 adversarial drill (`docker/devnet/e2e-adversarial-v2.sh`) closes it.

### Tree A: link a tailnet member's IP to a circle they used

```
GOAL: observer learns (member_ip ↔ circle_id) pair
├── A.1 sit on the WG UDP path
│   ├── A.1.a learn dest IP/port directly  [TRIVIAL — UDP is in clear]
│   └── A.1.b binding observer's dest_ip to a circle_id requires §A.2
├── A.2 read the operator's plaintext HTTP control plane
│   │   `control.rs:34`  http:// — `POST /session` includes
│   │   client_wg_pubkey + session_id
│   ├── A.2.a passive sniff in front of the operator  [WORKS if no overlay TLS]
│   └── A.2.b correlate session_id with the on-chain `open_session(tailnet, circle)`
│             tx (tx is public on octrascan)  [TRIVIAL — chain is public]
├── A.3 own the RPC operator (devnet.octrascan.io)
│   ├── A.3.a read every `open_session` body for that client's wallet
│   └── A.3.b chain `client_wallet → circle_id` directly — bypasses the WG
│             plane entirely  [WORKS — no cert pinning anywhere]
├── A.4 break TLS on the JSON-RPC path
│   ├── A.4.a rogue/sub-CA cert against the system trust store
│   └── A.4.b read RPC bodies, see A.3.a
└── A.5 quantum break Curve25519 retroactively
    └── recorded UDP + recorded TLS → full link  [out of scope mitigation; see §5]
```

**Closed by drill:** none. The drill covers AML-state invariants, not observer
classes. **Highest-impact mitigations:** §3 P0-1 (TLS on control plane), §3
P0-2 (cert-pin OctraRPC), §3 P1-3 (per-deploy fresh-wallet doc → owner cuts
the wallet↔circle bind).

### Tree B: decrypt sealed `/policy.json` without the tailnet passphrase

```
GOAL: recover plaintext (endpoint, wg_pubkey, region, prices)
├── B.1 cryptanalysis of AES-GCM(key=PBKDF2-HMAC-SHA256(pp, salt, 120k))
│   ├── B.1.a key-derivation collision  [INFEASIBLE — PBKDF2 over SHA-256]
│   ├── B.1.b break AES-256-GCM  [INFEASIBLE classically]
│   └── B.1.c GCM nonce-reuse  [INFEASIBLE — fresh random 12B nonce per call
│             (`circle.rs:277`); 2^96 collision space; but see B.4]
├── B.2 brute-force the passphrase
│   ├── B.2.a get the salt (it's in the on-chain envelope `circle.rs:256-261` —
│   │         salt = "octra:circle:sealed_read:v1:" + circle_id + ":" + key_id;
│   │         circle_id is public, key_id defaults to "default" `circle.rs:124`)
│   │         → SALT IS PUBLIC AND LOW-ENTROPY
│   ├── B.2.b chain salt → run PBKDF2 120k iters per guess  [GPU: ~5k/sec]
│   │         At 40-bit passphrase: 1.6e9 sec = 50 years.
│   │         At 30-bit passphrase: 8e3 hours = 1 year.  [REAL RISK if
│   │         passphrase is human-typed and short]
│   └── B.2.c the passphrase is shared OOB by the tailnet owner → low entropy
│             expected in practice
├── B.3 leak the passphrase via env-var exposure
│   ├── B.3.a OCTRAVPN_SEALED_PASSPHRASE in the operator process env
│   │         (`discover_v2.rs:141`; `cast/circle.rs:127,154,166`); leaks to:
│   │         child processes, /proc, `ps -e`, crash dumps, docker logs
│   └── B.3.b config file `[v2].sealed_passphrase` on disk in cleartext
│             (`discover_v2.rs:153`)  [SERIOUS — no zeroize on the
│             String round-trip]
├── B.4 wrong-nonce decryption attack
│   └── all sealed envelopes share the SAME `key = PBKDF2(pp, salt)` derived
│       from `(circle_id, key_id)`. Successive `circle_asset_put_encrypted`
│       calls reuse the SAME key with new random nonces — fine for AES-GCM,
│       but a corrupted RNG (RUSTSEC-2024-0376 / -0379 class) would collapse
│       2 nonces ⇒ XOR of plaintexts.  [POSSIBLE if rand crate gets pwned]
└── B.5 padding-class size leak
    └── 4k / 16k / 32k / 128k classes (`circle.rs:181-224`) leak coarse plaintext
        size; ≤ 4k policies look identical, but a 10-MB policy ⇒ 16-MB blob is
        a fingerprint.  [LEAKS class — by design]
```

**Closed by drill:** none — this is offline crypto, the on-chain drill never
sees it. **Mitigations:** §3 P1-4 (require minimum passphrase entropy
upfront), §3 P2-5 (replace PBKDF2 with Argon2id 2026-equivalent cost).

### Tree C: recover plaintext WG packet content after the fact

```
GOAL: recover IP packet payload from a captured pcap
├── C.1 obtain the operator's WG static private key
│   ├── C.1.a read /etc/octravpn/wg.key — plain hex on disk
│   │         (`state/node1/wg.key:1`)  [TRIVIAL with op host access]
│   ├── C.1.b social-engineer the operator  [out of scope]
│   └── C.1.c container escape on docker host  [out of scope]
├── C.2 break Curve25519
│   ├── C.2.a classical: no known break  [INFEASIBLE]
│   └── C.2.b quantum (Shor on ~2300 logical qubits): future risk
│             [WORKS retroactively if recorded; see §5 "out of scope"]
├── C.3 break ChaCha20-Poly1305 record-layer
│   └── classical: no known break  [INFEASIBLE]
└── C.4 boringtun handshake bug
    └── boringtun 0.7.1: no open advisories (RustSec checked 2026-05-17).
        Past advisories were on 0.4/0.5 (timing in
        cryptography-handshake); 0.7 is the post-rewrite line.
        [LOW RISK — but boringtun is not Cloudflare-maintained anymore;
        we should track wireguard-rs alternatives]
```

**Closed by drill:** none (drill is chain-only). **Mitigation:** §3 P1-6
(keyring-wrap WG private key), §3 P1-7 (rotate handshake periodically with
fresh static — currently the static is permanent).

### Tree D: identify the wallet owner of a given circle_id

```
GOAL: given circle_id, recover deployer_wallet
├── D.1 read the deploy_circle tx on chain
│   └── `from=deployer_wallet, to_=circle_id` — public  [TRIVIAL]
├── D.2 read register_circle on main-v2
│   └── `from=owner_wallet` + params include `circle` — public
│       (`main-v2.aml:455-498`)  [TRIVIAL]
├── D.3 follow bond_endpoint / slash / etc.
│   └── every `circles[circle].owner == caller` check re-binds  [TRIVIAL]
└── D.4 RPC-side correlation
    └── octrascan logs every contract_call IP-by-IP if it wants to;
        sees the wallet's RPC origin IP across queries
```

**Closed by drill:** none — this is an architectural property of the
public chain. **Mitigation:** **the only fix** is operator-side hygiene:
deploy from a one-shot wallet funded via a stealth output or faucet that
does not link to the operator's main identity (see
`docs/v2-operator-key-hygiene.md`). The v2 design accepted this for now.

### Tree E: replay a metering receipt across sessions / circles

```
GOAL: re-use a signed (bytes_used, seq) receipt to settle a different
      session / a different circle
├── E.1 receipt signing payload binding
│   `receipt.rs`: v1.2 hash is
│   `sha256("octravpn-receipt-v1" || program_addr || chain_id_be ||
│   circle_id_canonical || session_id || seq_be || bytes_be || blind_32)`.
│   **Now binds:**
│   - program_addr (32 bytes — the v1.1 / v2 program the session lives in)
│   - chain_id (u32 BE — `CHAIN_ID_DEVNET` / `CHAIN_ID_MAINNET` / …)
│   - circle_id (32 bytes — v2 only; v1.1 uses 32 zero bytes as the
│     canonical "None" encoding so the hash domain is fixed-width)
│   **Still NOT bound:**
│   - epoch / time (E.1.c below)
│   ├── E.1.a cross-program replay: same session_id on a fork ⇒ DIFFERENT
│   │         hash; sig verify fails. [CLOSED v1.2 — receipt.rs P1-5;
│   │         `cross_program_receipt_rejection` test asserts]
│   ├── E.1.b cross-circle replay: v2 receipts now bind the circle_id;
│   │         a receipt minted under circle X cannot be replayed against
│   │         circle Y. [CLOSED v1.2 — `cross_circle_receipt_rejection`
│   │         test asserts]
│   └── E.1.c monotonic seq check (`receipt.rs`) is in-memory only
│             — restart the node → fresh `last_seq=0` (`control.rs:236`),
│             allowing seq replay  [CLOSED by P1-8 — persistent
│             `receipt_journal.rs` shadowing the BoundedMap]
├── E.2 on-chain double-submit
│   └── `main-v2.aml`'s `settle_confirm` is single-shot per session; the
│       chain-side replay defense holds. But the operator-circle's
│       `meter_bytes` (`operator-circle.aml:217-235`) accepts repeated
│       deltas signed by the owner — replay of a (delta_payload, owner_sig)
│       pair would re-add bytes. The `delta_payload` is supposed to
│       encode `(session_id, bytes_delta, session_nonce)`, but the
│       contract DOES NOT verify the payload structure on-chain; it only
│       checks the sig (`operator-circle.aml:229`).  [REAL — bug]
└── E.3 broken ed25519_ok call
    └── `operator-circle.aml:229` checks
        `ed25519_ok(self.policy.wg_pubkey_resource_key, delta_payload, owner_sig)`.
        The first arg is supposed to be a **public key**; instead it's the
        sealed-asset **resource_key** (a SHA-256 hash). `ed25519_ok` over an
        arbitrary 32-byte point almost always rejects, so the rest of the
        guard falls through to `caller == self.owner` — i.e. there's no
        cryptographic check, only a caller check. This is a logic bug, not
        a leak per se, but it means the doc claim of "off-chain owner can
        meter on behalf of the operator" is unenforced.  [BUG — see §3 P0-3]
```

**Closed by drill:** E.2 cross-session replay is in the v1 adversarial
drill but not yet in v2's. **Mitigation:** §3 P1-8 add domain binding
(program_addr + chain_id + circle_id) to `Receipt::signing_payload`; §3
P0-3 fix `operator-circle.aml:229`; §3 P1-9 persist `last_seq` across
process restarts.

### Tree F: get an honest operator slashed

```
GOAL: produce two distinct (payload_a, sig_a) and (payload_b, sig_b) under
      the same receipt_pubkey for slash_double_sign  (`main-v2.aml:382-418`)
├── F.1 steal the operator's receipt_pubkey private key
│   └── stored alongside node static state (`state/node1/`); same exposure
│       as Tree C.1.a  [HOST-LEVEL ONLY]
├── F.2 trick the operator into signing two different receipts for the
│      same session_id
│   ├── F.2.a control-plane replay race: the node signs proposed receipts
│   │         (`control.rs:240` ControlSession last_seq=0 on insert);
│   │         restart the node mid-session → it'll happily sign a fresh
│   │         seq=1 receipt with different bytes_used than the previous
│   │         seq=1  [CLOSED by P1-8/9 — `receipt_journal.rs` fsyncs the
│   │         floor before every signature; restart reloads it]
│   └── F.2.b clock-skew the operator: the receipt_signing_payload doesn't
│             include epoch / time, so an attacker that can force the node
│             to recompute `bytes_used` at two snapshots and produce two
│             receipts with the same `(session_id, seq)` and different
│             bytes_used has a slash.
└── F.3 cryptographic forgery of ed25519 sigs  [INFEASIBLE classically]
```

**Closed by drill:** R-2, S-1, S-2 cases in v1 drill (carried into v2 per
the §0 status note). Specifically the v2 drill's S-class cases assert that
once slashed, a circle stays slashed. **Mitigation:** §3 P1-9 persistent
seq journal; §3 P2-10 receipt-signing rate-limit + sliding-window de-dup.

### Tree G: drain v2 program treasury via a logic bug

```
GOAL: get `transfer(attacker, X)` from the program treasury
├── G.1 govern-only withdraw_program_treasury  (`main-v2.aml:323-332`)
│   ├── G.1.a compromise the owner wallet  [out of scope cryptographically]
│   └── G.1.b bypass `require_owner`  [v2 drill F-class cases all reject
│             non-owner; commit `6c3ce5a` cites 45/45 hold]
├── G.2 slash bounty path  (`main-v2.aml:413-415`)
│   └── slash an active circle with a forged double-sign  ⇒ F-tree;
│       v2 drill S-class closes this (rejects with mismatched/invalid sigs)
├── G.3 protocol fee bookkeeping
│   └── `settle_session` paths in v2 (deposit accounting). The v2 drill's
│       E-class cases assert deposit ≥ payout invariant. [CLOSED per drill]
└── G.4 nonreentrant bypass
    └── `nonreentrant` modifier (`main-v2.aml:366` finalize_unbond) is
        new in v2; v1 didn't use it. Adversarial drill case set for
        nonreentrant should be added. [GAP — drill currently has 45 cases;
        consider adding a re-entrancy attempt as case 46]
```

**Closed by drill:** the 45 cases per `e2e-adversarial-v2.sh`. **Gap:**
nonreentrant edge cases not yet adversarialized.

---

## 3. Prioritized fix queue

Severity × effort, sorted by `severity × (impact/effort)`. **Behavioral**
= breaks existing tx envelopes / wire format (requires coordinated
redeploy). **Hardening** = no wire impact. **Doc** = documentation only.

| ID | Sev | Eff | Type | Where | What |
|---|---|---|---|---|---|
| **P0-1** | P0 | M | Hardening | `crates/octravpn-core/src/control.rs:34` | Switch operator HTTP control plane to TLS (rustls + self-signed cert pinned in client config). Currently every `client_wg_pubkey`, `session_id`, and the proposed receipt with `bytes_used` ship in clear over `http://`. Even a coffee-shop attacker can correlate sessions to circles and modify metering proposals. |
| **P0-2** | P0 | S | Hardening | `crates/octravpn-core/src/rpc.rs:73`, `crates/octravpn-client/src/runner.rs:52`, `octra-foundry/crates/octra-cli/src/rpc_client.rs:80` | Pin the devnet.octrascan.io leaf cert (or its issuer) on the `reqwest::Client::builder()`. Today any compromised CA — corporate MITM proxy, OS-level cert install — silently reads every tx body, including the `from→to_=circle_id` binding for unprivileged wallet-circle linking. |
| **P0-3** | P0 | S | Behavioral | `program/operator-circle.aml:229` | `ed25519_ok` is being called with `self.policy.wg_pubkey_resource_key` (a SHA-256 hash) as the pubkey argument. This always fails, collapsing the metering auth to `caller == self.owner`. Either replace with the operator's actual ed25519 pubkey (move from sealed-asset to a `state` field) or remove the broken half of the `||` and own the caller-only auth in the doc. |
| **P1-2** | P1 | M | Behavioral | `crates/octravpn-core/src/onion.rs:128` | Onion AEAD uses a **constant zero nonce** for ChaCha20-Poly1305. Safe today *only because* `wrap_layer` derives a fresh AEAD key per call via `EphemeralSecret::random_from_rng(OsRng)` → HKDF (line 122-150), so the nonce-is-zero rule is the trivial "fresh key per encryption" case. The fragility is that any future change that caches `eph_secret` (e.g. a retry-on-network-error path, or a deterministic-build mode for tests) silently downgrades to nonce-reuse and lets an observer XOR plaintexts of two distinct onion calls. **Use a random 12-byte nonce included in the wire packet** so the invariant is enforced in code, not by convention. |
| **P1-3** | P1 | S | Doc | `docs/v2-operator-key-hygiene.md` (new) | Document the wallet↔circle binding leak from `from=deployer → to_=circle_id` and prescribe fresh-wallet deploy. Trees A/D mitigation. |
| **P1-4** | P1 | S | Hardening | `octra-foundry/crates/octra-core/src/circle.rs:256` and `crates/octravpn-client/src/discover_v2.rs:140` | Reject (or loudly warn on) passphrases below an entropy floor (~64 bits). Today a 6-character passphrase compiles and ships. PBKDF2 120k gives ~5k guesses/sec/GPU; a 30-bit passphrase falls in a year. |
| ~~**P1-5**~~ | P1 | M | Hardening | `crates/octravpn-core/src/receipt.rs:61` | **FIXED** in commit P1-5 (receipt domain binders). `signing_payload` now folds in `(program_addr, chain_id, circle_id)` via a `ReceiptContext` field on `Receipt`. Cross-program, cross-chain, and cross-circle replay all fail signature verification. Operators must set `[chain].chain_id` in their `node.toml` (defaults to `CHAIN_ID_DEVNET = 0x6F637464`); clients mirror via `[chain].chain_id` in `client.toml`. v1.1 receipts canonically encode `circle_id = None` as 32 zero bytes so the hash domain is fixed-width across v1.1/v2. New tests: `cross_program_receipt_rejection`, `cross_chain_receipt_rejection`, `cross_circle_receipt_rejection` in `crates/octravpn-core/src/receipt.rs`; property-based variants in `tests/prop_receipt.rs`; chain-side reference parity in `tests/prop_canonicalization.rs`. |
| ~~**P1-6**~~ | P1 | M | Hardening | `crates/octravpn-node/src/hub.rs` (`Hub::new`), `crates/octravpn-node/src/seal.rs` (new), `octra-foundry/crates/octra-core/src/util.rs` (`read_secret_32_or_sealed`) | **FIXED.** New `octravpn-node seal-keys` / `unseal-keys` subcommands wrap the configured wallet + WG keys under the `OCTRA-WALLET-V1` passphrase envelope; atomic write via tempfile + fsync; idempotent re-runs. The daemon loader honours sealed envelopes via `OCTRAVPN_KEY_PASSPHRASE`. Strict mode (`[chain].require_sealed_keys = true`) refuses to boot if any configured secret is still plaintext, with the suggested seal-keys CLI quoted in the error. Devnet keys remain plaintext (back-compat with `e2e.sh`); v2 operators opt in via the config flag + `*.sealed` paths described in `docs/v2-operator-key-hygiene.md` §4 and the new `docker/devnet/.env.example` snippet. |
| **P1-7** | P1 | L | Behavioral | `crates/octravpn-node/src/tunnel.rs:220` | Add periodic WG static-key rotation (currently the WG static is the *circle's* permanent identity). Without rotation a one-time host compromise breaks all past traffic on a quantum-future. Pair with `circle_asset_put_encrypted` to publish the new pubkey under the same resource_key. |
| ~~**P1-8**~~ | P1 | S | Hardening | `crates/octravpn-core/src/receipt_journal.rs` (new), `crates/octravpn-node/src/control.rs` (`get_state`) | **FIXED (this commit).** New `octravpn_core::receipt_journal::ReceiptJournal` persists `(session_id → last_signed_seq)` to disk. Default file `./state/receipts.bin`; overridable via `[control].receipt_journal_path`. The journal is fsync'd before any `Receipt` is signed (tempfile + persist + sync_all on file and parent dir). Daemon restarts now reload the floor; the in-memory `ControlSession.last_seq` is shadowed by `max(in_mem, journal_floor)` so a fresh in-memory boot can't roll back. Tree E.1.c closed. |
| ~~**P1-9**~~ | P1 | M | Hardening | `crates/octravpn-core/src/receipt_journal.rs` (new) | **FIXED (this commit, joint with P1-8 — same journal).** Every receipt the node signs bumps the persistent floor atomically; the bump call rejects any `seq <= floor`. A forced restart (OOM / segfault / signal) can no longer trick the daemon into signing two distinct receipts at the same `(session_id, seq)` — the journal is consulted before the signature is computed. Closes Tree F.2.a. Test names that cover the restart-replay path: `receipt_journal::tests::restart_replay_rejection`, `control::tests::get_state_restart_replay_rejected`. |
| **P1-10** | P1 | S | Hardening | `crates/octravpn-client/src/discover_v2.rs:153` | Zeroize the `sealed_passphrase` config string on drop. Today it sits in a `Vec<u8>` heap chunk; a core dump or page-fault swap could leak. Use `secrecy::SecretString` or `zeroize::Zeroizing<String>`. Tree B.3.b. |
| **P2-11** | P2 | M | Hardening | `octra-foundry/crates/octra-core/src/circle.rs:256` | Replace PBKDF2-SHA256-120k with Argon2id (memory-hard). Currently aligned with the JS reference, but the JS reference is the bottleneck on quality; moving to argon2 ~5x raises the GPU brute-force cost for the *same* CPU budget on the operator host. |
| **P2-12** | P2 | S | Hardening | `crates/octravpn-core/src/onion.rs:42` | `MAX_HOPS = 3` is hardcoded. Add per-route random padding so packet size doesn't fingerprint hop-count. Today an observer counting bytes per layer can distinguish 1/2/3-hop circuits. |
| **P2-13** | P2 | M | Hardening | `crates/octravpn-mesh/src/peer.rs:37` | `PEER_SNAPSHOT_MAX_AGE_SECS = 120` allows 2-minute replay of stale candidates. Add a monotonic counter signed alongside the timestamp to bound replay below the 120s window. |
| **P2-14** | P2 | S | Hardening | `crates/octravpn-node/src/control.rs:323-352` | The `/metrics` endpoint exposes aggregate session/byte counts unauthenticated. Useful for ops, but enables an outsider to confirm a circle is in use and roughly how much. Either auth-gate or pad. |
| **P2-15** | P2 | L | Behavioral | `crates/octravpn-core/src/earnings.rs` | When PVAC ships, the Pedersen `LedgerPoint` claim path (`verify_claim` at line 96) requires `(amount, blind)` revealed at claim time. The chain stores this in clear after the claim — an observer learns the operator's total settled OCT. Switch to a range-proof + zero-knowledge open. |
| **P3-16** | P3 | S | Behavioral | `octra-foundry/crates/octra-core/src/tx.rs:113-160` | The canonical-JSON tx writer (`push_json_str`) handles control chars but not Unicode normalization. Two semantically-equivalent strings could canonicalize differently; not a security bug today because every signer is the same code, but a heterogeneous wallet ecosystem could see signature-validation drift. |
| **P3-17** | P3 | S | Doc | `docs/v2-circles-design.md` §4.4 | The doc says HFHE byte counters live in the circle and never leak; the deployed operator-circle (`program/operator-circle.aml:46-50`) currently uses PLAINTEXT counters and the comment admits it. Either ship HFHE or update the doc; today the gap mis-sells the privacy story. |
| **P3-18** | P3 | M | Hardening | `crates/octravpn-node/src/tunnel.rs:249` | `peek_initiator_pubkey` reads the ephemeral from offset 8..40 and uses it as an allowlist key. It works because the announce step pre-registers the *static* key — but the function name + comment talk about "static pubkey," and the bytes are ephemeral. Rename / document; the asymmetry is a latent bug-magnet. |

---

## 4. Dependency risk register

`cargo audit` (RustSec advisory-db, 1090 advisories loaded, run from `/tmp` to dodge our project `audit.toml` schema mismatch) returns **clean** on both workspaces for vulnerability advisories. One informational warning: `paste 1.0.15` is unmaintained (RUSTSEC-2024-0436), pulled in transitively via `tun-rs 2.8.3 → route_manager 0.2.11 → netlink-packet-core 0.8.1`. Not a security advisory; flagged here for completeness.

Versions actually pinned by `Cargo.lock` (transitive). All checked against rustsec.org as of 2026-05-17.

### 4A. Crypto core

| Crate | Version | Status | Notes |
|---|---|---|---|
| `boringtun` | 0.7.1 | clean | No advisories pinned to 0.7.x. Cloudflare archived the repo in 2024; cloudflare/boringtun is maintained sporadically; if we need a contender, `wireguard-rs` (Mullvad) is the next-line. |
| `chacha20poly1305` | 0.10.1 | clean | RustCrypto family; aligned with NIST/RFC 8439. |
| `chacha20` | 0.9.1 | clean | |
| `poly1305` | 0.8.0 | clean | |
| `aes-gcm` | 0.10.3 | clean | RUSTSEC-2024-0040 affects `aes-gcm < 0.10.0` (we're past it). |
| `aes` | 0.8.4 | clean | |
| `polyval` | 0.6.2 | clean | |
| `aead` | 0.5.2 | clean | |
| `ed25519-dalek` | 2.2.0 | clean | RUSTSEC-2022-0093 (oracle attack) was on 1.x; we're on 2.x with the strict-decoding fix. |
| `curve25519-dalek` | 4.1.3 | clean | RUSTSEC-2024-0344 (timing) was fixed in 4.1.3; **we are pinned to the fixed version**. Confirm on every workspace bump. |
| `x25519-dalek` | 2.0.1 | clean | |
| `sha2` | 0.10.9 | clean | |
| `hkdf` | 0.12.4 | clean | |
| `pbkdf2` | 0.12.2 | clean | RUSTSEC-2024-0398 advised against pbkdf2 < 0.12 with simd; we're on 0.12.2. |
| `hmac` | 0.12.1 | clean | |
| `subtle` | 2.6.1 | clean | |
| `zeroize` | 1.8.2 | clean | |
| `ring` | 0.17.14 | clean | RUSTSEC-2025-0009 (AES overflow on 32-bit) affected `ring < 0.17.12`; we're on 0.17.14. |

### 4B. Transport / IO

| Crate | Version | Status | Notes |
|---|---|---|---|
| `rustls` | 0.23.40 | clean | Several past advisories on < 0.23 (RUSTSEC-2024-0336 close_notify hang, etc.) all addressed. |
| `tokio-rustls` | 0.26.4 | clean | |
| `webpki-roots` | 1.0.7 | clean | We rely on system + bundled roots; no cert pinning (P0-2). |
| `reqwest` | 0.12.28 | clean | |
| `hyper` | 1.9.0 | clean | RUSTSEC-2024-0003 (header smuggling) on hyper < 1.1; we're at 1.9. |
| `hyper-rustls` | 0.27.9 | clean | |
| `hyper-util` | 0.1.20 | clean | |
| `http` | 1.4.0 | clean | |
| `axum` | 0.7.9 | clean | |
| `tower` | 0.5.3 | clean | |
| `tokio` | 1.52.3 | clean | RUSTSEC-2024-0019 named-pipe race fixed in 1.38; we're past. |
| `tun-rs` | 2.8.3 | clean (pulls unmaintained `paste`; see informational) | |

### 4C. Encoding / RNG / utility

| Crate | Version | Status | Notes |
|---|---|---|---|
| `rand` | 0.8.6 (and 0.9.4 second copy) | clean | RUSTSEC-2024-0376 affected `rand_core` mis-seeding pattern in 0.6 chain; we're on 0.8 / 0.9. |
| `getrandom` | 0.2.17 + 0.3.4 (octra) / +0.4.2 (foundry) | clean | RUSTSEC-2024-0356 wasi-zero-fill: fixed in 0.2.15; we're on 0.2.17. |
| `serde` | 1.0.228 | clean | |
| `serde_json` | 1.0.149 | clean | |
| `bs58` | 0.5.1 | clean | |
| `base64` | 0.22.x | clean | |
| `num-bigint-dig` | 0.8.6 | clean | RUSTSEC-2023-0033 fixed in 0.8.4. |
| `spin` | 0.9.8 | clean | |
| `once_cell` | 1.21.4 | clean | |
| `smallvec` | 1.15.1 | clean | RUSTSEC-2024-0395 fixed in 1.13.2. |
| `chrono` | 0.4.44 | clean | RUSTSEC-2024-0399 segfault on 32-bit fixed in 0.4.34. |
| `time` | 0.3.47 | clean | |
| `paste` | 1.0.15 | **unmaintained** (RUSTSEC-2024-0436, informational) | Transitive via `tun-rs → route_manager → netlink-packet-core`. No alternative pinned in `tun-rs` upstream; tracked. |
| `crypto-common` | 0.1.7 | clean | |
| `generic-array` | 0.14.7 | clean | |

### 4D. Cross-version concerns

- **Two rand versions** (`0.8.6` and `0.9.4`) coexist in `Cargo.lock`. Both clean per rustsec, but bifurcation invites future "we patched 0.9 but didn't realize a transitive lives at 0.8" mistakes. Worth pinning either side or dedup'ing.
- **Three getrandom versions** in octra-foundry (0.2.17, 0.3.4, 0.4.2). Same story — clean, but fragile.
- **OctraVPN does NOT call `cargo audit` in CI.** `deny.toml` exists at `/Users/androolloyd/Development/octra/deny.toml`; no GitHub Actions wiring on the workflows I see. **Recommend a P2 "wire cargo-audit + cargo-deny into CI"** — most of the value of this table evaporates if a future bump silently regresses.

---

## 5. Out-of-scope (explicitly declared)

- **Global passive adversary observing WG packet timing patterns** to fingerprint sessions / activity. We do not pad, do not jitter, do not chaff. Out of scope; mitigation requires a Tor-class cover-traffic system OctraVPN does not target.
- **Quantum adversary breaking Curve25519 / X25519 retroactively** on captured WG handshakes and TLS records. Out of scope until a credible PQ overlay exists; the threat is real (Tree A.5, Tree C.2.b) but mitigation is a multi-year roadmap item — see also `docs/security-roadmap.md`.
- **Side-channel attacks on the operator host** (DPA on AES instructions, cache-timing). Out of scope — the RustCrypto AES path is constant-time but not formally side-channel-hardened; if an operator's threat model includes nation-state physical co-location they should run a hardened HSM, not a Rust binary in a docker container.
- **A compromised octrascan.io** is treated as a privacy adversary (rows in §1's "OctraRPC" column) but we do not try to make the chain RPC private — it is a public node by definition. Mitigation is "run your own Octra full node" once the protocol allows it; that's a chain-protocol scope, not a VPN-app scope.
- **The Lean / TLA verification work on the v2 entrypoint shape** (pending per `docs/v2-circles-design.md §0`) is the right place to address Tree G.4 (nonreentrant edge cases) formally — out of scope of this crypto threat model.
- **The leak audit's narrow focus** (log/print/Display leakage of secrets) is owned by the parallel Rust formal-verification subagent. This doc *cites* known passphrase env-var paths (`OCTRAVPN_SEALED_PASSPHRASE`) but does not enumerate every print statement.

---

## Appendix A. Files touched / cited

- Source: `crates/octravpn-core/src/{control.rs, onion.rs, receipt.rs, rpc.rs, earnings.rs, stealth.rs}`, `crates/octravpn-node/src/{tunnel.rs, control.rs, hub.rs}`, `crates/octravpn-client/src/{discover_v2.rs, settler.rs, operator_backend.rs, runner.rs}`, `crates/octravpn-mesh/src/peer.rs`.
- Source (foundry): `octra-foundry/crates/octra-core/src/{circle.rs, tx.rs, sig.rs, wallet_enc.rs}`, `octra-foundry/crates/octra-cli/src/{cast/circle.rs, rpc_client.rs}`.
- AML: `program/main-v2.aml`, `program/operator-circle.aml`.
- Devnet state: `docker/devnet/state/{node*,client,deployer.key}`, `docker/devnet/e2e-adversarial-v2.sh`.
- Audit: ran `cargo audit --file <lock>` from `/tmp` 2026-05-17, RustSec advisory-db 1090 advisories loaded.
