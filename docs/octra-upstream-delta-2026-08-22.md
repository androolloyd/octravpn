# Octra upstream delta — 2026-08-17 → 2026-08-22

> What `octra-labs/lite_node` shipped in the three commits after our
> sequence-2 pin, and what it changes for OctraVPN / octra-foundry.
>
> Compared `dd342e754c91df55a41b515c510369d637af2385` (the foundry
> local-node image and the previous canary baseline) against HEAD
> `f3b6d580537294123153ef5cd1ef8fc08208501a`. Live marker:
> `https://releases.octra.network/v1/devnet/latest.json`.

---

## 0. One paragraph

Sequence 4 is a **required** validator/sync release. It does **not**
change the client money path. Signing preimage, error-code table, and
JSON-RPC method names are unchanged (212 dispatchable names, 136
primaries — re-scraped). `runtime_profile_hash` and
`consensus_rules_id` (`finalized_rejection_commitment`) are unchanged.
The load-bearing client-visible deltas are: staging RPCs now sample
instead of dumping the whole queue; `contract_verify` no longer
persists source/abi on verify; circle object-member scans gain an
effort cost at epoch **1,380,000**. Foundry's local Single-mode pin
stays at `dd342e7` until a release moves the RPC surface or the
runtime profile.

---

## 1. What shipped

| Commit | Date | What it is |
|---|---|---|
| `12c3163` | 2026-08-21 | capped consensus reads and signed range catchup |
| `5c3d86b` | 2026-08-21 | devnet peer set and snapshot source |
| `f3b6d58` | 2026-08-22 | signed snapshot reads in upgrade tooling |

Live marker (verified 2026-08-22):

| Field | Sequence 2 (ours) | Sequence 4 (now) |
|---|---|---|
| `public_commit` | `dd342e754c91df55a41b515c510369d637af2385` | `f3b6d580537294123153ef5cd1ef8fc08208501a` |
| `source_commit` | `75d9ed1d73a0e3731f7d7a4262d29b672ad3c24e` | `f8d868f92962ab5639d9a2be3fe206458c5ad019` |
| `consensus_rules_id` | `finalized_rejection_commitment` | same |
| `consensus_profile` | 16 | same |
| `runtime_profile_hash` | `14bac4b2…cee6` | same |
| `network_sha256` | `26e5ca5a…7a78` | `020de9dc…c26b` |
| `expires_at` | 2026-08-19 (expired) | 2026-08-25 |

Release.py still signs the same 14-field compact JSON array. Verification
switched from `openssl pkeyutl` to PyNaCl; our canary still verifies
with openssl against the same ed25519 key.

---

## 2. Client compatibility

### Unchanged (money path, signing, RPC names)

- `lib/core/transaction.ml` signing preimage and hash JSON — **not in
  the diff**. `to_`, float timestamps, base64 ed25519, no `chain_id`.
- Error-code table (`lib/core/rpc.ml`) — **not in the diff**.
- RPC dispatch composition: still 212 names / 136 primaries. Re-scraped
  at HEAD with `tools/rpc-scrape`; no add/remove/rename.
- `octra_submit` / `octra_transaction` / `octra_balance` /
  `contract_receipt` / `octra_contractStorage` / `octra_validatorSetProof`
  response keys — no shape change.
- Tx payload size limits moved into `lib/core/tx_payload.ml` with the
  same numbers (50 MB encrypted_data, 10 MB program message, …). Admission
  now runs at decode time; the limits themselves did not move.

### Changed, not on our path

| Surface | Change | Our use |
|---|---|---|
| `staging_view` / `staging_stats` / `staging_estimateOu` | Sampled (64/256 rows), extra `total`/`truncated`/`sample_size` keys; messages > 4 KiB become `null` + `message_truncated` | VPN does not call these |
| `contract_verify` | No longer writes source/abi/certificate into the store on verify | foundry `forge verify` persistence, not VPN runtime |
| `octra_epochTags` | Same JSON keys, computed from stats instead of listing every tag | unused |
| Bootstrap peers / `OCTRA_STATE_SYNC_SOURCES` | Peer set expanded; state-sync now a single primary URL + one extra exporter | ops only; local Single-mode compose does not join the public set |

### Gated, watch epoch 1,380,000

`object_cost` (`rule_graph.ml:114-118`, `contract_vm.ml` `OBJECT_MEMBER_*`)
activates on devnet at epoch **1,380,000** (anchor 1,353,962). Member
scans then charge `len(storage)*5` effort. Our AML does not emit
`OBJECT_MEMBER_*` opcodes. Native circle-object experiments
(`docker/devnet/experiments/`) would feel it after activation.

Ledger freeze/thaw (`ledger.ml`) is a consensus-internal clone helper.
No client-visible account shape change.

---

## 3. What we did

- **VPN:** accepted the sequence-4 marker into
  [`docs/audit/octra-release-baseline.json`](audit/octra-release-baseline.json).
  Canary will go green on `source_commit` + `consensus_rules_id` match.
  Validator oracle already speaks `octra_validatorSetProof`; no RPC
  rewrite required by this drop.
- **foundry:** local image pin stays `dd342e7`. ChainBackend mock/node
  backends land; mock `octra_submit` stages; scraped method table is
  committed; fiction methods (`octra_isValidator`, `octra_fhe*`) now
  return `-32601`.

## 4. Still open from 2026-08-17

Unchanged by this drop: native relay rail is still attestation-only;
`fhe_verify_*` is still view-only; sealed-asset write observability is
still unproven; `anvil --fork` is still a mock seed, not a state-sync
import. Real fork remains "boot a second node on imported state and
point `OCTRA_FORK_RPC` at it".
