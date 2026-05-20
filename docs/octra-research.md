# Octra deep research dossier

Compiled 2026-05-10 against live mainnet (`https://octra.network/rpc`, `v3.0.0-irmin`, epoch 818,850).

---

## 1. Validator economics & epoch model

**Minimum stake, slashing, and rotation rules are NOT publicly documented.** The only validator-docs page (https://docs.octra.org/validator-docs/running-a-node) says onboarding is paused ahead of full decentralization.

From the litepaper (https://octra.org/litepaper.pdf §3, §3.6):

- **Node tiers**: bootstrap, standard validator, light node.
- **Consensus**: custom **ABFT** + **Proof-of-Useful-Work** rewards. Score `f(ω) = α·THS + β·NPT + γ·SVB + δ·SP + ε·CPS` (tx history, participation time, verified blocks, **stake share**, compute) — stake is one of 30+ inputs, not pure PoS.
- **Epochs**: docs say "minutes on testnet, target seconds on mainnet". **Live: ~10.0 s/epoch** across `epoch_summaries(818841..818850)`.
- **Sharding scope**: 24 nodes per epoch, pool of 120 (§3.2). Unlimited validators; only the sharded subset rotates.
- **Slashing**: not specified at protocol layer. PoUW implies reward attenuation, not stake-burn (https://docs.octra.org/oct-docs/octranomics).
- **Reward pool**: 37% of max supply (370M OCT).

**Live state**: all 10 most recent epochs finalized by `oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb` — the Octra Labs 10% ecosystem-fund operational wallet. Single-validator bootstrap mode.

---

## 2. Address codec

Refs: `wallet-gen/src/server.ts:270-287`, `webcli/wallet.hpp:204`.

```
address = "oct" + LeftPad('1', Base58(SHA256(ed25519_pubkey)), 44)
```

- Single **SHA-256** of the 32-byte Ed25519 public key.
- **Base58** Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
- **No checksum.** Total length always **47** (`"oct"` + 44 b58 chars).
- **Canonical 32-byte form** = the SHA-256 digest itself. Recover by base58-decoding the substring after `"oct"`. **Hashing the display string is wrong.**

**HD derivation**: BIP-39 → PBKDF2-HMAC-SHA512 (2048) → HMAC-SHA512 keyed `"Octra seed"` (custom, not `"ed25519 seed"`) → path `m/345'/coin'/network'/contract'/account'/token'/subnet'/index`. Network types: 0 MainCoin, 1 SubCoin, 2 Contract, 3 Subnet, 4 Account.

---

## 3. Transaction signing (canonical form)

Authoritative: `webcli/lib/tx_builder.hpp:78-92` — confirmed identical in Rust (`ocs01-test/src/main.rs:67-75`) and Python (`octra_pre_client/cli.py:494`).

```cpp
canonical = "{\"from\":\"<from>\",\"to_\":\"<to>\",\"amount\":\"<amt>\","
            "\"nonce\":<int>,\"ou\":\"<ou>\",\"timestamp\":<float>,"
            "\"op_type\":\"<op_or_standard>\""
            "[,\"encrypted_data\":\"<...>\"][,\"message\":\"<...>\"]}"
signature = base64(ed25519_detached_sign(canonical_utf8, sk))
tx_hash   = hex(sha256(canonical_utf8))   // 64 chars lowercase
```

Things OctraVPN likely gets wrong:

1. **Recipient field is `"to_"` (trailing underscore)**, not `"to"`.
2. **Signed bytes are the JSON string itself**, UTF-8. No tagged-binary, no domain separator, no length-prefix.
3. **Field order is insertion order, not alphabetical**: `from, to_, amount, nonce, ou, timestamp, op_type, [encrypted_data], [message]`. In Python: `json.dumps(ordered_dict, separators=(",",":"))`.
4. **Types**: `amount` and `ou` are JSON strings (integer micro-units); `nonce` unquoted int; `timestamp` unquoted **float** (Python `time.time()`, e.g. `1778440240.269806`).
5. `signature` and `public_key` are base64 of 64 and 32 bytes — added **after** signing, never part of signed blob.
6. **Default `op_type` is `"standard"`** when field is empty. Known values: `standard, encrypt, decrypt, stealth, claim, deploy, call` (`webcli/main.cpp:1054`).
7. Submission RPC: `octra_submit(tx_json)` JSON-RPC 2.0, or legacy `POST /send-tx`.
8. **Auxiliary signed messages** use literal-string domain separators (NOT bytes): encrypted-balance auth `"octra_encryptedBalance|" + addr`; PVAC register `"register_pvac|" + addr + "|" + sha256_hex(pk_blob)`; view-pubkey register `"register_pubkey:" + addr` (`tx_builder.hpp:130-158`, `main.cpp:229`).

---

## 4. HFHE / cryptographic primitives

HFHE is **custom**, NOT CKKS or BFV. Sources: docs (https://docs.octra.org/tech-docs/hfhe), litepaper §2.4–2.9, PoC (https://github.com/octra-labs/pvac_hfhe_cpp).

- **HFHE** = Hypergraph FHE. Binary-parity LWE on a dense random k-uniform hypergraph, arithmetic over the **Mersenne prime field F_p with p = 2^127 − 1** (per pvac_hfhe_cpp README; explicitly a PoC, **NOT production parameters**).
- Logical gates: AND/OR/XOR/NOT/NAND/NOR/XNOR via hyperedge intersection/union/complement.
- Hash everywhere in key sharding: **BLAKE3**.
- **Per-epoch keys**: SK, DK, BK, PK — all four deterministically split into 24 shards across 24 nodes per epoch, regenerated from fresh randomness each epoch. **No threshold quorum is ever assembled** (litepaper §2.4); majority-malicious nodes still can't reconstruct keys.
- **Pedersen**: `pvac_pedersen_commit(amount, blinding_32) -> 32 bytes` (`pvac_bridge.hpp:132`). **Curve not publicly stated** — likely Curve25519/Ristretto (tweetnacl heavy), unconfirmed.
- **Range proofs**: `pvac_make_range_proof` / `pvac_make_aggregated_range_proof`. Wire `"rp_v1|"` + base64. Aggregated form suggests Bulletproofs; **scheme name not stated**.
- **ZK zero proofs**: `pvac_make_zero_proof`. Wire `"zkzp_v2|"`.
- **Ciphertext wire**: `"hfhe_v1|" + base64`.
- **Client AES wrapper for encrypted balance**: AES-256-GCM keyed `SHA256("octra_encrypted_balance_v2" + privkey)`, v1 legacy fallback (`octra_pre_client/cli.py:122-181`).

---

## 5. Stealth scheme

From `webcli/lib/stealth.hpp`. **Not Sapling, not Monero** — a lightweight ECDH-tag scheme on Curve25519, closer to Sapling's view-key scan than Monero one-time addresses.

1. **View keypair**: derived from Ed25519 wallet via `ed25519_sk_to_curve25519`. View secret = `clamp(SHA512(ed25519_seed)[0:32])`. **No separate view key in wallet file.**
2. **Sender** (`main.cpp:1302-1486`):
   - Fresh ephemeral X25519 keypair `(eph_sk, eph_pk)`.
   - `shared = SHA256(X25519(eph_sk, recipient_view_pub))`.
   - `stealth_tag = SHA256(shared || "OCTRA_STEALTH_TAG_V1")[0:16]` (hex on wire).
   - `claim_secret = SHA256(shared || "OCTRA_CLAIM_SECRET_V1")`.
   - `claim_pub = SHA256(claim_secret || recipient_addr || "OCTRA_CLAIM_BIND_V1")`.
   - `enc_amount = AES-256-GCM_{shared}(amount_le_u64 || blinding_32)`, 12-byte nonce, 16-byte tag → 68 bytes, base64.
   - Bundled with HFHE delta cipher, Pedersen amount commitment, range proofs (delta + balance), zero-proof into tx `encrypted_data` JSON. `op_type="stealth"`, `to_="stealth"`, `amount="0"`, default `ou="5000"`.
3. **Recipient**: scan `octra_stealthOutputs(from_epoch)`, recompute `shared` from `(view_sk, output.eph_pub)`, match `stealth_tag`, decrypt `enc_amount`.

Domain separators are literal ASCII strings. Use exactly: `"OCTRA_STEALTH_TAG_V1"`, `"OCTRA_CLAIM_SECRET_V1"`, `"OCTRA_CLAIM_BIND_V1"`.

---

## 6. AML host calls reference

**No published host-calls reference page.** Only first-party source: `octra-labs/contract-examples/example_1.aml`.

Confirmed FHE host functions called from AML: `fhe_load_pk(addr)`, `fhe_deser(b64)`, `fhe_ser(ct)`, `fhe_add(pk,a,b)`, `fhe_sub(pk,a,b)`, `fhe_add_const(pk,ct,k)`, `fhe_scale(pk,ct,k)`, `fhe_verify_zero(pk,ct,proof)`.

Confirmed runtime helpers: `require/assert/revert`, `transfer(addr,amount)`, builtins `caller / origin / value / epoch / self_addr`, `checkpoint() / commit() / rollback()`, `concat`, `to_string`, `parse_ints`, `mget`, `emit Event(...)`.

**NOT present** in public docs or example: `verify_ed25519`, `verify_ed25519_acct`, `pedersen_commit`/`pedersen_verify`, `emit_private_transfer`, any stealth host call. The webcli's Pedersen/range/zero-proof functions are **client-side** library calls (`pvac_bridge.hpp`), NOT confirmed AML host calls. Treat OctraVPN's placeholder names as unverified.

---

## 7. Validator-set discovery from a program

From live RPC + https://docs.octra.org/developer-docs/rpc-scheme:

- `epoch_get(epoch_id)` returns one field `finalized_by` — a **single address**. Live: every recent epoch finalized by exactly one validator. Behaviour today is **single-validator-per-epoch (Algorand-round-leader-style)**, not a multi-validator committee.
- `node_status` returns `{epoch, validator, ...}` — single address.
- Litepaper §3.6 describes a multi-validator quorum ("chiefs"), but this isn't visible in the RPC schema.
- **No documented `epoch_validators(epoch_id) -> [addr]`.** AML's `epoch` builtin gives the integer id; no host call returns the active set.

"Is X a validator this epoch?" is not first-class today — must ask the team.

---

## 8. Network parameters (live, 2026-05-10)

- Network version: `v3.0.0-irmin` (`node_status`).
- Decimals: **6** (1 OCT = 1,000,000 OU).
- Max supply: 1,000,000,000 OCT. Live total/circulating: 612,127,774.609505 OCT (live supply endpoints + `node_stats`).
- Accounts: 1,455,335 total (1,383,108 active). Total tx: 172,035,516.
- **Fees** (`octra_recommendedFee([])`): min 1 OU, base/recommended **1000 OU = 0.001 OCT**, fast 2000 OU = 0.002 OCT. Stealth default 5000 OU = 0.005 OCT (`webcli/main.cpp:1467`). Epoch capacity 10,000,000,000 OU.
- Epoch length: **~10 s** empirically (from `epoch_summaries`).
- Throughput claim: ~800 TPS on 24 nodes (64 GB / 8 vCPU / 10 TB) — litepaper §2.8.
- Price / mcap (octrascan.io): $0.073 / ~$44.5M.

**Genesis split** (octranomics): 18.5% investors, 15% Octra Labs, 10% ecosystem, 10% Uniswap CCA, 4.87% Echo/Juicebox, 4.63% faucet, 37% validator rewards. Genesis total 630M / circulating 580M.

**Ethereum-side**: wOCT `0x4647e1fE715c9e23959022C2416C71867F5a6E80`, Bridge `0xE7eD69b852fd2a1406080B26A37e8E04e7dA4caE`, LightClient `0xC01cA57dc7f7C4B6f1B6b87B85D79e5ddf0dF55d` (contract-addresses doc).

---

## 9. GitHub & code references

Official org **`https://github.com/octra-labs`** (16 public repos). Most useful:

- `wallet-gen` (TS) — address codec + HD derivation.
- `octra_pre_client` (Python) — tx signing, encrypt/decrypt, private transfers.
- `webcli` (C++17) — `canonical_json`, stealth, Pedersen/range-proof bindings.
- `ocs01-test` (Rust) — Rust signing reference (`sign_tx`).
- `contract-examples` (AML) — only public AML host-call usage.
- `pvac_hfhe_cpp` (C++17 hdr-only) — HFHE math PoC, **not production parameters**.
- `HFHE` — "Experimental version of the FHE library on hypergraphs."
- `light-node` (OCaml) — **empty skeleton**, every source file is 0 bytes as of 2026-05-10.
- `node_configuration`, `zig-libp2p`, `octra_ref_client`, `Zarith`, `blake3-ocaml`, `irmin`, `primitives` — operator scripts / forks / deps.

**No open-source node implementation exists.** light-node is empty; pvac_hfhe_cpp explicitly disclaims production parity. The server is closed-source — integrators must trust the JSON-RPC contract.

Channels: https://x.com/octra, https://discord.com/invite/octra, https://t.me/octra, https://t.me/octra_chat_en, dev@octra.org. Explorer https://octrascan.io.

---

## 9.1 Circles primitive — 2026-05-15 public release

Octra shipped Circles publicly on **2026-05-15** via `octra-labs/webcli`
commit `f9c73e1` (`static/circles.html` + supporting wallet code). The
`octra-labs/program-examples` repo simultaneously demonstrated the
`payable` / `nonreentrant` AML modifiers used in real circle code. Our
v2 integration landed on devnet by 2026-05-17 (`docker/devnet/e2e-
adversarial-v2.sh` 45 / 45).

### Wire format

A circle deploys via the standard tx envelope with `op_type="deploy_circle"`,
`to_=<predicted circle_id>`, and a JSON `message` payload containing
nine fields: `runtime, privacy_class, browser_mode, resource_mode,
limits, code_b64, policy_hash, members_root, export_policy`. See
`docs/aml-grammar.md §10.1` for the full schema.

### Deterministic id derivation (CREATE2-style)

```
seed       = digest_sha256("octra:circle_deploy_id:v1" || deployer_addr_bytes || u64be(nonce) || payload_hash_hex_bytes)
circle_id  = "oct" + base58(seed)[:44]
```

The id is computable BEFORE submitting the deploy tx, enabling main-net
programs to assert ownership at registration without trusting deployer-
disclosed metadata. Reference impl: `octra-foundry/crates/octra-core/src/circle.rs`.

### Sealed-asset envelope crypto

For path-private resources (`/policy.json`, `/manifest.json`, etc.):

- AES-GCM-256 over plaintext payload.
- Key = PBKDF2-SHA256(password, salt, **120 000 iters**, 32 bytes).
- Magic header `"OCRS1"` (5 bytes); version byte; 12-byte nonce;
  16-byte tag.
- Padding to one of four buckets: 4 KiB / 16 KiB / 32 KiB / 128 KiB
  (so size doesn't leak content type).
- On-chain `resource_key = digest_sha256(circle_id || path)`; path
  never escapes the client.

Fetched via `circle_asset_ciphertext_by_resource_key(circle_id,
resource_key)` (read-only) and published via
`circle_asset_put_encrypted` (`op_type="circle_asset_put_encrypted"`).

### AES KAT gate

Devnet chain-side runtime enforces an AES Known-Answer-Test on first
sealed-asset access; programs hang for ~1s on first call per worker
while the KAT runs. PVAC sidecar code that previously bypassed this
caused intermittent failures; observed in `pvac-sidecar` development
(commit `9e16868`).

### Tx hashes — canonical v2 e2e (devnet)

Captured 2026-05-17 against `https://devnet.octrascan.io/rpc`:

| Step                                             | tx hash                                                            |
| ------------------------------------------------ | ------------------------------------------------------------------ |
| `forge create main-v2` → registry deployed        | (deploy tx; registry at `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`) |
| `register_circle` (atomic register + 1 OCT bond) | `54d84c02d5a61bfade3122c1abd918f142cd54ace95b2c251aaf11cf49dbc74b`   |
| `create_tailnet`                                  | `e33463e3f253c6ecd09be1dcdf09397152d852a76645c876cc88cf239f7c879e`   |
| `authorize_circle`                                | `e4de76f3ae235efde0fd45a912bd7ec14977526d1128d3e3708f8cff1e0fb41c`   |
| `open_session` (class=0 shared, max_pay=200)      | `434ad40cf475dd4f509550daee36362655375d43c40d064b3e8c65aeae8ff7ae`   |
| `circle_asset_put_encrypted` (4k-padded sealed `/policy.json`) | `5811465946323b04de530924825b87ad6c95953dce55b9bbb2416cf2aa1bc494` |

Reference operator circle: `octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA`.

### Mainnet vs devnet behaviour

| Surface                              | Mainnet                                            | Devnet (`devnet.octrascan.io`)                       |
| ------------------------------------ | -------------------------------------------------- | ----------------------------------------------------- |
| `deploy_circle` op-type accepted     | Yes                                                | Yes                                                   |
| `circle_asset_put_encrypted` accepted | Yes                                               | Yes                                                   |
| `octra_registerPvacPubkey` body cap   | ≥8 MB (accepts a 4 MB base64 PVAC pk)              | ≥8 MB ✓ (raised 2026-05-18; was ~1 MiB pre-fix)        |
| AES KAT on first sealed-asset access  | Yes (one-time per worker)                          | Yes                                                   |
| `ed25519_ok` accepts base64           | Yes                                                | Yes                                                   |

The devnet body cap was raised 2026-05-18 and `octra_registerPvacPubkey`
now confirms ~4 MB PVAC pubkey blobs on devnet. The remaining HFHE
blocker is chain-side: AML `fhe_load_pk` reverts for our contracts
even after a successful pubkey registration — verified against both
our own `FheProbe` and an unmodified deploy of
`octra-labs/program-examples/private_ml`. See
`memory/octra_aml_fhe_load_pk_blocked.md` and
`docs/octra-dev-questions.md §1`. Filed with the Octra dev team.

### HFHE inside circles

The chain-side HFHE ops (`fhe_load_pk`, `fhe_deser`, `fhe_add`,
`fhe_add_const`, `fhe_verify_zero`, etc.) work inside any AML
program, including those deployed to circles. **Critical**:
`fhe_load_pk(addr)` requires `addr` to have a per-wallet PVAC
pubkey registered via the off-chain RPC `octra_registerPvacPubkey`.
Circles have no keypair (they're addresses derived from a deploy
seed), so contracts must route HFHE lookups through `circle.owner`
(the wallet that submitted the deploy tx) rather than `self_addr`.
Saved memory: `octra_hfhe_pubkey_per_wallet.md`.

---

## 10. Gaps — must ask the team

1. Validator min stake (OCT) — none published; onboarding paused.
2. Slashing conditions/penalties — not documented at protocol layer.
3. Mainnet target epoch length — committed value unstated; ~10 s empirically.
4. AML host call to query active validator set — `epoch_get` only exposes one `finalized_by`.
5. Pedersen commitment **curve** — 32-byte output, curve unstated. Critical if we re-implement verification.
6. Range-proof scheme — likely Bulletproofs, unconfirmed.
7. Full AML host-call reference — only FHE primitives shown in the public example. `verify_ed25519`, `pedersen_verify`, `emit_private_transfer` are **not confirmed**.
8. Production HFHE parameters — pvac_hfhe_cpp is a 2024 PoC; production security level / ring dim / plaintext modulus unstated.
9. DK reset cadence and "indirect pointer" semantics — deferred to "subsequent articles."
10. ~~Extensibility of `op_type` beyond `standard, encrypt, decrypt, stealth, claim, deploy, call`.~~ **Partially resolved 2026-05-15**: `deploy_circle`, `circle_asset_put_encrypted` (and read-only `circle_asset_ciphertext_by_resource_key`) are now public. Extensibility for app-specific op-types still open.
11. Multi-validator quorum at decentralization — single-validator today; will it stay Algorand-style or become a `chiefs` set (litepaper §3.6)? Changes how programs prove witness counts.
12. Octra SDK and full paper — promised in litepaper §7, not published. 2026-Q1 EVM-compat upgrade slipped.
13. **NEW**: devnet RPC `client_max_body_size` is ~1 MiB at the nginx edge, blocking `octra_registerPvacPubkey` (~4 MB body). Mainnet accepts. Ask: raise devnet to ≥8 MB. See `docs/v2-octra-questions.md §7`.

---

### Sources

- **Docs** (all under https://docs.octra.org/): root, `validator-docs/running-a-node`, `oct-docs/{octranomics,role-of-oct,contract-addresses}`, `user-docs/{sending-transactions,encrypting-the-balance,stealth-transactions}`, `developer-docs/{rpc-scheme,programs,introduction-to-applied}`, `tech-docs/hfhe`, `tech-docs/hfhe/hfhe-key-sharding`.
- **Litepaper**: https://octra.org/litepaper.pdf (16 pp).
- **Code** (all under https://github.com/octra-labs/): `wallet-gen`, `octra_pre_client`, `webcli`, `ocs01-test`, `contract-examples`, `pvac_hfhe_cpp`, `light-node`.
- **Live RPC**: `POST https://octra.network/rpc` — `node_status / node_stats / node_version / epoch_current / epoch_get / epoch_summaries / octra_recommendedFee`.
- **Live supply**: `https://octra.network/{circulating,total,max}-supply`.
- **Explorer**: https://octrascan.io.
