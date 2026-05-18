# OctraVPN v3 — Circle-Resident Architecture

Status: deployed on devnet 2026-05-18 at
`oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`. Sibling to
`docs/v2-circles-design.md`. End-to-end lifecycle verified
(register_circle → create_tailnet → open_session → settle_claim →
settle_confirm → claim_earnings); hash-chain replay matches on-chain
head byte-for-byte. Smoke script: `docker/devnet/v3-smoke.sh`.

### Encoding note: sha256 anchors are 64-char hex strings

The AML runtime does not decode `bytes` params at the RPC boundary —
`len(bytes_arg)` returns the JSON-string character count. AML's own
`sha256()` builtin emits a 64-char hex string. So every "32-byte
sha256 anchor" below is stored as a 64-char hex digest
(`len() == 64`), not a raw 32-byte buffer. The chain doesn't
crypto-verify the value; integrity comes from off-chain verifiers
fetching the canonical source (state-root.json, members.json) and
comparing `sha256_hex(source) == anchor`. The earnings hash chain is
likewise initialized at `register_circle` to `sha256(state_root)`
(see `circle_earnings_chain` init) so replayers don't depend on the
AML default-value quirk that makes unset `bytes` read back as `"0"`.

## 1. Why v3 exists

v2 designed for a world where AML had full HFHE math, where circles
ran code, and where map values could hold MB-class blobs. As of
2026-05-18 none of those are true on devnet. v3 is the design that
fits the chain we actually have, while staying forward-compatible
with the chain Octra has said is coming.

### 1.1 Three empirical constraints we engineer around

1. **`map[address]string` truncates silently at ~4096 bytes.**
   Verified 2026-05-18; a 56 KB PVAC ciphertext stored via
   `register_circle` came back at exactly 4096 bytes. Memory:
   `octra_aml_string_cap_4kb.md`. We cannot store policy bundles,
   ciphertexts, ACLs, or any blob inline.

2. **AML `fhe_*` host calls revert on devnet.** Verified by deploying
   Octra's own `program-examples/private_ml` verbatim and observing
   `execution reverted` at `private_predict`'s first `fhe_load_pk`.
   The chain accepts deploy + routes the call; the AML-to-HFHE bridge
   is unwired. Memory: `octra_aml_fhe_load_pk_blocked.md`.

3. **Circles store `code_b64` but don't execute it.** `deploy_circle`
   computes a real `code_hash`, but `contract_call` against the circle
   returns `"bytecode not found"`. Memory:
   `octra_circles_not_executable.md`. Bonds + slash cannot move into
   a circle yet.

### 1.2 Three primitives we lean on

- **Circles as addressable wallets + 32 MiB sealed-asset namespaces**
  (`circle_asset_put_encrypted` / `circle_asset_ciphertext_by_resource_key`).
- **Tx bodies up to multi-MB.** Storage is capped at 4 KiB per map
  value; payload size is not.
- **`sha256()` + string `concat` at chain runtime.** Verified
  2026-05-18: `sha256("hello" + "world")` matches local. This makes
  audit-grade tamper-evident commitments cheap.

### 1.3 v3's thesis

The chain's only job is to enforce what can only be enforced on chain:

- OU custody (bonds, session escrow, tailnet treasury, fee treasury).
- Ed25519 verification of equivocating signatures (slash).
- Time-locked unbond (no-withdraw-before-grace).
- Permanent slash flag (cannot re-register).
- A 32-byte sha256 anchor per role pointing at the role's circle.

Everything else lives in role-specific Octra circles as sealed assets.
Main-v3 stores no structs (only flat maps of int / address / 32-byte
bytes / short string), so a redeploy doesn't lose user-meaningful
data — the canonical copies were always in operators' circles. The
chain only needs each operator to re-anchor.

## 2. What main-v3 keeps vs what circles hold

| Chain enforces (main-v3.aml) | Circle holds (sealed assets) |
| --- | --- |
| `circle_bond` / `_unbonding` / `_unbond_unlock_epoch` | Operator policy (`/policy.json`) |
| `circle_slashed` (permanent ban) | Encrypted endpoint URL + WG pubkey |
| `circle_owner` (auth) | Per-session receipts (`/receipts/{epoch}.json`) |
| `circle_receipt_pk` (44-char base64 ed25519) | Attestation bundle (`/attestation.json`) |
| `circle_state_root` (32B sha256 anchor) | Encrypted earnings state (`/enc-state.bin`) |
| `circle_state_version` (monotonic) | Canonical `/state-root.json` (the file the anchor commits to) |
| `session_*` (escrow + status + adjudication) | Tailnet `/tailnet-{id}/config.json` |
| `tailnet_treasury` (OU custody) | Tailnet `/tailnet-{id}/members.json` |
| `tailnet_members_root` (32B sha256 anchor) | Tailnet `/tailnet-{id}/acl-root` |
| `tailnet_owner` (auth) | Tailnet per-member sealed keys |
| `circle_earnings_total` (plaintext counter) | Slash evidence (`/slashed/{circle_id}/evidence/{tx}.json`) |
| `circle_earnings_claimed` | Governance log (`/governance/params.json`) |
| `circle_earnings_chain` (32B sha256 head) |  |
| `treasury` + `burned` + governance params |  |

Net effect: chain-side storage per circle drops from a `CircleRecord`
struct (8 fields including `region: string` and two price fields) +
HFHE pubkey + zero-ciphertext + earnings ciphertext (≈ 4 KB capped
truncated values) to **2 short scalars + a 32-byte hash + an int +
an int** per circle (≈ 60 bytes deterministic).

## 3. Per-role circle schemas

### 3.1 Operator circle

```
oct://<circle_id>/policy.json              # encrypted endpoint URL, WG pubkey, region, price tiers
oct://<circle_id>/state-root.json          # canonical: { version, policy_hash, acl_root, attestation_hash, member_count, timestamp }
oct://<circle_id>/receipts/{epoch}.json    # per-session signed receipt: { sid, bytes, net, class, price, blinding, sig_op, sig_client }
oct://<circle_id>/enc-state.bin            # operator-only encrypted running state (post-HFHE this holds the ciphertext)
oct://<circle_id>/attestation.json         # remote-attestation bundle for the box hosting the exit
```

`circle_state_root[circle] == sha256(state-root.json)`. Verifiers
fetch `state-root.json` (plaintext canonical JSON, or sealed and
gated by attestation), hash, compare.

### 3.2 Tailnet-owner circle

```
oct://<circle_id>/tailnet-{id}/config.json       # display name, region pinning, charge_internal flag
oct://<circle_id>/tailnet-{id}/members.json      # sorted [{ wallet, pubkey, joined_epoch }]
oct://<circle_id>/tailnet-{id}/acl-root          # 32B Merkle root over members.json
oct://<circle_id>/tailnet-{id}/sealed-keys/{member}.bin   # per-member sealed key envelope
```

`tailnet_members_root[tid] == sha256(members.json)`. Member-join
proofs are off-chain Merkle proofs against the root.

### 3.3 Governance circle

```
oct://<gov_circle>/slashed/{circle_id}/record.json           # final slash record
oct://<gov_circle>/slashed/{circle_id}/evidence/{tx}.json    # signed equivocation pair, original tx hashes
oct://<gov_circle>/governance/params.json                    # canonical params history (audit log)
oct://<gov_circle>/governance/owner-rotations.json           # transfer_ownership log
```

The chain emits `OperatorSlashed(...)` and `ProgramTreasuryWithdrawn(...)`;
an off-chain bot owned by the governance multisig listens, reads the
slashed circle's policy + the slash tx, and seals a record into the
governance circle. The chain never reads from the governance circle.

## 4. Redeploy flow — the load-bearing claim

### 4.1 What's lost on redeploy

Main-v3 redeploys at a new address. All map storage on the old
address is left behind. Concretely:

- **OU in escrow stays on the old contract.** Bonds, tailnet
  treasuries, open session deposits, and the program treasury are
  all OU held by the old contract address. They do NOT move.
- **All `circle_*`, `tailnet_*`, `session_*` maps reset to empty.**

### 4.2 What's preserved

The authoritative copy of every operator's policy, every tailnet's
member set, every per-session receipt was always in a circle. The
circle's `circle_id` is deployer-derived (CREATE2-style) and stable
across main-v3 redeploys — Octra's `circle_id` derivation does not
depend on the main contract. So:

1. Every operator's `circle_id` is unchanged.
2. Every operator's sealed assets are unchanged.
3. Every operator's `state-root.json` is unchanged.
4. Every tailnet's `members.json` is unchanged.

### 4.3 The re-anchor walk-through

The post-redeploy migration is mechanical and operator-local. No
governance coordinator is needed.

1. **Owner (governance) deploys main-v3 at new address `R'`.** New
   constructor params are passed (typically copied from the old
   contract via `get_params`); paused = 0; treasury = 0.
2. **Operators run `register_circle(circle, state_root, receipt_pk)`
   on `R'` and re-bond.** They post fresh OU as the initial stake;
   their `state_root` is the same sha256 they previously committed
   (because the underlying state-root.json hasn't changed).
3. **Tailnet owners run `create_tailnet(members_root)` on `R'`** and
   re-deposit OU. The chain assigns a NEW `tailnet_id` (the old id
   was main-contract-local; receipts that reference the old id stay
   valid as historical records under the old contract but new opens
   target the new id).
4. **Clients update their wallet's "active contract" pointer** from
   `R` to `R'`. Clients can keep claiming refunds / sweeping expired
   sessions against `R` for as long as `R` stays unpaused. Owner
   may eventually call `set_paused(1)` on `R` after a grace window.
5. **Slash bonds left on `R` are not migrable.** Operators who had
   live bonds on `R` either let them sit (continuing to back any
   open sessions against `R`'s judgements) or unbond + finalize +
   re-bond on `R'`.

### 4.4 Timing windows + risks

- **Window 1 (anchor race):** between (deploy `R'`) and (operator
  re-anchors), a malicious client could open a session against the
  operator's circle on `R'` and `R` simultaneously. Mitigation: the
  off-chain receipt is sealed in the operator's circle with a chain-
  contract-address tag; the operator refuses to co-sign settlement
  receipts that name the wrong main contract. Sessions opened on the
  not-yet-anchored `R'` simply have no operator to claim → swept
  back to the tailnet after grace.
- **Window 2 (members.json drift):** the tailnet owner re-anchors
  with a stale members.json (forgets a recent add). Mitigation: the
  members.json `version` field bumps monotonically and is part of
  the file; off-chain validators reject `update_members_root` calls
  whose version is older than the last known version. (Chain doesn't
  enforce monotonic versions — the owner could go backward — but
  the audit log will surface it.)
- **Window 3 (slash escape):** an operator equivocates on `R`,
  refuses to re-anchor on `R'`. Their bond on `R` is slashable as
  before (anyone can submit `slash_double_sign` against `R`); their
  identity on `R'` is gated by re-anchor, which they cannot do once
  the equivocation is on chain (the signatures bind to the operator's
  `receipt_pk`, which is in their state-root.json hash). They can
  rotate the on-chain receipt pubkey, but the off-chain
  attestation-history bot will flag the rotation.

### 4.5 Acceptance criterion

If main-v3 redeploys, EVERY operator + tailnet owner can re-anchor
their state with a single tx each, no off-chain coordinator. That's
the load-bearing claim of v3.

## 5. The settle/claim mechanism while HFHE is blocked

### 5.1 Why not just plaintext-on-chain?

Plaintext earnings on chain mean any chain observer sees how much
each operator earned per session. That defeats one of v2's
hidden-exit goals. v3 splits the storage:

- **`circle_earnings_total`** is the plaintext running total. The
  chain HAS to know this to gate `claim_earnings` safely. But it
  bumps once per settle, not per packet — chain observers learn
  totals, not per-session granularity.
- **`circle_earnings_chain`** is a sha256 hash-chain over per-session
  blindings. Chain observers see the head; they cannot derive
  per-session amounts from it. Off-chain auditors (who hold the
  signed receipts) reconstruct the chain and detect tampering.

This is strictly weaker than HFHE-encrypted totals but strictly
stronger than plaintext-per-settle.

### 5.2 The HFHE swap path

When Octra ships `fhe_*` against new deploys, the migration is
additive: `settle_confirm` gains an HFHE branch that runs in parallel
with the hash-chain branch. `claim_earnings` gains an optional
`fhe_zero_proof` arg; if provided, the chain verifies the ciphertext
balance matches the plaintext total. We DO NOT remove the plaintext
total — it stays as the authoritative gate. Storage shape: identical.

## 6. The circle-execution swap path

When Octra ships `contract_call` against circle code, bonds can move
into a `BondEscrow` circle. Main-v3 shrinks further:

- `circle_bond` / `_unbonding` / `_slashed` / `apply_slash` move into
  the `BondEscrow` circle (which has its own AML; sketch in
  `program/operator-circle-v3.aml`).
- Main shrinks to: tailnet treasury, session escrow, fee treasury,
  governance. The slash invariant moves into the `BondEscrow`
  circle and is enforced there.
- `circle_state_root` / `_version` stay on main as a global registry
  (circles can't see each other's state without main as a routing
  hub), unless Octra ships inter-circle reads — in which case main
  becomes just an OU-routing contract for sessions.

## 7. What the chain still enforces vs what circles hold (summary)

**Enforced by chain (no off-chain trust required):**
- OU never leaves the contract without the right signature.
- Bonds can't be withdrawn before grace.
- Slashed circles cannot re-register or re-bond.
- Session deposits cap operator earnings.
- Equivocating signatures slash bonds.

**Trust-shifted to circles (off-chain auditors verify):**
- What policy a circle is serving.
- Who is in a tailnet's ACL.
- What price tariff a session ran at.
- What attestation a host box presents.
- The provenance of slash evidence.

For each trust shift the chain holds a 32-byte commitment, so
tampering is detectable even though it's not prevented at chain
runtime.

## 8. Out of scope

- **HFHE settle on chain right now.** Blocked by
  `octra_aml_fhe_load_pk_blocked.md`. We design the storage shape
  to add it later additively.
- **Circle code execution right now.** Blocked by
  `octra_circles_not_executable.md`. Bonds stay on main-v3.
- **Inter-circle reads.** Circles cannot fetch each other's sealed
  assets at chain runtime. All cross-circle reads are mediated by
  off-chain clients today.
- **Migrating bonds across main-v3 redeploys.** Bonds stay on the
  old contract. We accept this trade — moving them would require a
  trusted bridge contract, which is more centralization than v3 is
  willing to introduce.
- **Rust-side changes.** `octravpn-node` and `octravpn-client`
  changes follow once v3 deploys. This doc lists only the AML +
  circle-resident state shape.

## 9. Open questions for the Octra dev team

1. When will `fhe_*` AML host calls run against new deploys?
   `program-examples/private_ml` reverts the same way ours does.
2. When will `contract_call` dispatch against circle `code_b64`?
   The field is accepted + persisted + a `code_hash` is computed.
3. Is there a `bytes` or `blob` storage class with a higher cap than
   the 4 KiB observed on `map[address]string`?
4. Is `circle_id` derivation truly main-contract-independent? If a
   future change tied `circle_id` to the registering contract, the
   redeploy flow in §4 breaks.
5. Will the chain emit anything observable when sealed assets are
   modified, or are they only readable by RPC?

## 10. Acceptance checklist for v3

- [x] `program/main-v3.aml` compiles via `octra_compileAml`. (Verified
  2026-05-18 against `https://devnet.octrascan.io/rpc`.)
- [x] No inline blobs > 4 KB in any map value.
- [x] No `fhe_*` host calls in any entrypoint.
- [x] Pause halts user flows; governance bypasses pause.
- [x] Slash burns 90% / pays 10% bounty (configurable).
- [x] Two-tx settle (operator claim + opener confirm).
- [x] `register_circle` is payable; initial bond is atomic.
- [x] Redeploy = operator re-anchor with one tx each.
- [x] Devnet deploy: 2026-05-18 at
  `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`. End-to-end
  lifecycle confirmed; hash-chain replay matches byte-for-byte.
- [ ] 40-case adversarial drill on v3 (next spike — patterned after
  `docker/devnet/e2e-adversarial-v2.sh`).
