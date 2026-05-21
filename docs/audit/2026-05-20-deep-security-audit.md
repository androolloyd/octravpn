# Deep Security Audit — OctraVPN v3 + headscale-rs + octra-foundry
**Date:** 2026-05-20
**Scope:** crypto primitives, wire protocol, chain integration
**Audited HEAD:** `worktree-agent-a229e34852a17ea1d` (parent: `d6b3930`)
**Methodology:** manual code-level review against the Lean spec
(`proofs/lean/`), the threat model (`docs/security/threat-model-v3.md`),
and the 2026-05-20 audit-prep package (`docs/audit/`).

> **Scope note.** The Lean proofs (255 theorems) and proptests
> (30+ properties) treat primitives as opaque/axiomatized. This audit
> focuses on places where the Rust impl could diverge from those axioms
> — i.e. shape mismatches between what is proved and what is shipped.

> **BLOCK MAINNET tag (see §CRITICAL):** there is **one** item I would
> hold mainnet on if I had veto power: **C-1 — `settle_confirm`
> dispute is a permanent stuck-funds state**. The deposit is locked,
> no resolution path exists on chain, and no Lean theorem covers the
> dispute-resolution branch.

## Findings by severity

### CRITICAL (block mainnet) — count: 1
- **C-1**  `settle_confirm` dispute is a non-resolvable stuck-funds state (chain)

### HIGH (fix before mainnet) — count: 5
- **H-1**  `oct://` SPKI fingerprint pinning claimed in threat-model is **not implemented** in code (wire)
- **H-2**  obfs4 frame counter uses `wrapping_add` — silent nonce reuse after 2^64 frames (crypto)
- **H-3**  No explicit per-route `RequestBodyLimit`/`DefaultBodyLimit` on the axum control router (wire)
- **H-4**  Plaintext-key boot path remains accepted when `require_sealed_keys = false` (crypto/ops)
- **H-5**  Equivocation detector for double-sign is unwired; chain slash is post-hoc only (chain)

### MEDIUM (fix in 30d) — count: 7
- **M-1**  DERP CDN cert SAN-only pin (no SPKI) — re-issued cert from same CN bypasses (wire)
- **M-2**  Single-RPC submission — no multi-validator failover for slash submission (chain)
- **M-3**  Onion layer uses fixed zero nonce — safe today, fragile if key reuse ever introduced (crypto)
- **M-4**  obfs4 handshake has **no replay cache** — wasted server work on replay (wire)
- **M-5**  Receipt journal compaction races could lose seq-floor if `rename` partially fails on non-POSIX FS (chain)
- **M-6**  HFHE shadow blob is unverified on chain (HFHE-2) — privacy only, no integrity (chain)
- **M-7**  obfs4 `node_id` doubles as HMAC key — 20-byte secret with no rotation primitive (crypto)

### LOW (housekeeping) — count: 6
- **L-1**  `rand::random::<u64>()` jitter in RPC retry — CSPRNG-backed but not auditable at a glance (crypto)
- **L-2**  `unseal_one` writes plaintext hex to disk via tempfile rename — heap copy may persist (crypto)
- **L-3**  Knock `now_unix()` defaults to 0 on `duration_since` error → trivially valid knock at unix epoch boundary (wire)
- **L-4**  amnezia recv: `buf.copy_within(off..n, 0)` does not zero the tail bytes; cipher-irrelevant but a fingerprint surface (wire)
- **L-5**  Knock middleware path-prefix check returns same 404 — but **does not** rate-limit knock failures separately from valid 404s (wire)
- **L-6**  v3 settle blinding required `len(settle_blinding) > 0` only — accepts a 1-byte blind, defeating hash-chain entropy (chain)

---

## CRITICAL — count: 1

### C-1 — `settle_confirm` dispute is a permanent stuck-funds state — **BLOCK MAINNET**

- **File:** `program/main-v3.aml:549-601`, `crates/octravpn-client/src/settler.rs:88-95`
- **Category:** chain
- **Description:**  When opener and operator disagree on `bytes_used`,
  `settle_confirm` writes `client_confirm_set = 1`, emits
  `SettleDispute`, and returns `false`. Session state remains
  `SESSION_OPEN`. No on-chain code path:
    1. transitions the session out of `OPEN`,
    2. releases the deposit,
    3. burns operator bond,
    4. or arbitrates the discrepancy.
  `claim_no_show` (line 603) requires `operator_claim_set == 0`, so
  it cannot rescue a disputed session.
- **Impact:**  Either party (with operator equivocation OR with a
  malicious opener picking `bytes_used != operator's claim`) can
  permanently lock the session's deposit on chain. An attacker who
  controls a corner of the wallet relationship can grief the
  counterparty for the cost of one `settle_confirm` tx — and the
  tailnet treasury, the operator's earnings, AND the protocol fee are
  all stranded. This is a value-loss bug that survives indefinitely
  on chain.
- **Proposed fix:**  Add `settle_resolve(session_id, evidence)`
  callable by either party: (a) two signed receipts from operator
  at distinct `bytes_used` for the same `(session_id, seq)` →
  route to `slash_double_sign` + refund opener; (b) else after
  `dispute_grace_epochs`, settle to `min(operator_claim,
  client_confirm)`.
- **Test:**  AML integration test that opens a session, settle_claims
  at `b1`, settle_confirms at `b2 != b1`, then asserts the deposit is
  releasable via the new resolver. Property: ∀ disputed sessions,
  ∃ epoch after which the deposit is no longer locked.
- **Lean coverage:** None today. `proofs/lean/WireProtocol/` covers
  receipt context binding and canonical encoding but does NOT touch
  `SettleDispute` state machine.

---

## HIGH — count: 5

### H-1 — `oct://` SPKI fingerprint pinning claimed in threat-model is **not implemented**

- **File:** `crates/octravpn-client/src/portal/chain.rs:608-625`,
  `crates/octravpn-core/src/rpc.rs:93-117`,
  `docs/security/threat-model-v3.md:92` (5.f claim)
- **Category:** wire
- **Description:**  The threat model row 5.f says: *"The URL carries
  an SPKI fingerprint the client pins."* Reality:
  `RpcClient::new_with_pinned_roots` does CA-bundle pinning (rustls
  trust roots) — there is no SPKI extraction, no SHA-256 of the
  cert's SubjectPublicKeyInfo, and `grep -rn 'spki|SPKI|fingerprint'
  crates/ --include='*.rs'` returns zero non-comment hits. Any cert
  issued under a pinned root passes.
- **Impact:**  Any cert minted under a pinned CA (compromised LE
  account, coerced corporate CA, DigiNotar-style breach) silently
  MITMs the chain RPC and `oct://` flow — exactly the failure mode
  the threat-model claims mitigated.
- **Proposed fix:**  Implement a custom `rustls::client::ServerCertVerifier`
  that (a) calls the default WebPKI verifier first, then (b)
  computes SHA-256 of the leaf cert's SPKI (DER-encoded) and
  constant-time-compares to the SPKI fingerprint extracted from the
  `oct://` URL. Add a `pinned_spki_sha256: Option<[u8; 32]>` field
  to `RpcClient` and require it on the portal path.
- **Test:**  Property test: any cert chain whose leaf SPKI hash
  differs from the pinned value is rejected, regardless of root.
- **Lean coverage:** No formal proof — fuzz-only coverage. Property
  `pinned_spki_rejects_mismatch` would be the home for a `cargo
  fuzz` target.
- **Fixed in commit `7d016618155c`** — new module
  `crates/octravpn-core/src/spki_verifier.rs` ships a
  `rustls::client::danger::ServerCertVerifier` that extracts the
  leaf cert's `SubjectPublicKeyInfo` via a hand-rolled DER walk
  (`extract_spki_der`), computes `sha256(SPKI)`, and constant-time
  compares to a pin set parsed out of an
  `oct://...?spki=<base64>[,<base64>...]` URL by
  `SpkiPinVerifier::parse_pins_from_oct_url`. On match it defers to
  a `WebPkiServerVerifier` for chain + hostname validation; on
  mismatch it returns
  `rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)`
  before the inner verifier runs. Empty pin set fails closed.
  Multiple pins are supported for rotation grace. Wired into
  `crates/octravpn-client/src/portal/chain/fetch.rs::build_rpc_for_oct_url`
  and called from `commands::open_url`; legacy oct:// URLs without
  the `spki=` query continue to use CA-bundle pinning, preserving
  the wire format. Six tests in `spki_verifier::tests` pin: match
  → accept-and-delegate; mismatch → reject with
  `ApplicationVerificationFailure`; multi-pin rotation grace; empty
  pin set rejects; non-cert input rejects without panic;
  oct-URL pin parsing happy + sad paths.

### H-2 — obfs4 frame counter uses `wrapping_add` — nonce reuse after 2^64 frames

- **File:** `crates/octravpn-obfs4/src/frame.rs:153, 224`
- **Category:** crypto (IND-CPA / AEAD nonce uniqueness)
- **Description:**  `FrameSealer::seal_into` advances the 64-bit
  counter with `self.counter.wrapping_add(1)`. The 12-byte ChaCha20
  nonce is `4-byte direction prefix || u64 BE counter`. After 2^64
  seals on a single session key, the counter wraps to 0 and the same
  (key, nonce) pair encrypts a new plaintext — a catastrophic
  ChaCha20-Poly1305 nonce reuse leaking the keystream XOR of the
  colliding plaintexts AND making Poly1305 forgeable across both
  messages.
- **Impact:**  Practically unreachable at 64-bit counter
  (~585 millennia at 1 Mfps). Real risk: a future change to a
  32-bit counter (tighter wire format) silently introduces the
  bug; lint-against-wrapping has no compile-time enforcement.
- **Proposed fix:**  Replace `wrapping_add(1)` with
  `checked_add(1).ok_or(FrameError::CounterExhausted)?` and trigger
  a rekey when the counter exceeds e.g. 2^60 (huge safety margin).
  The handshake already runs cheap; a periodic forced rekey is
  defense-in-depth at near-zero cost.
- **Test:**  Unit test that forces `counter = u64::MAX`, calls
  `seal_into`, and asserts `Err(FrameError::CounterExhausted)`.
- **Lean coverage:**  `proofs/lean/WireProtocol/BeNonce.lean:100-182`
  proves nonce uniqueness *up to* counter monotonicity. The proof
  axiom does **not** cover wrap-around. Add a Lean axiom
  `counter_never_wraps` and pin it to the Rust impl.

> **Fixed in commit `21df30e` on branch `worktree-agent-a557416bd6d3fba66`.**
> Both `FrameSealer::seal_into` and `FrameOpener::open_from` now pre-
> compute `next_counter = self.counter.checked_add(1).ok_or(
> FrameError::CounterExhausted)?` BEFORE the AEAD seal/open call —
> a sealer at `u64::MAX` rejects the next frame outright without
> appending bytes to the output buffer (verified by
> `sealer_at_counter_max_refuses_next_frame`). The new
> `FrameError::CounterExhausted` variant is also added to the
> `transport.rs` `server_handle` match (folded in with `BadTag`/
> `BadInnerLen` to trigger session teardown — a session whose
> nonce budget is spent must re-handshake to obtain a fresh key +
> zeroed counter). Boundary pinned by
> `sealer_one_below_max_still_seals` (last legitimate frame is at
> `u64::MAX - 1`, so the per-key budget is 2^64 - 1 frames). The
> module header (`frame.rs:42-62`) documents the budget in plain
> English so a future shrink to `u32` surfaces in code review.

### H-3 — No explicit body-size limit on axum control router

- **File:** `crates/octravpn-node/src/control.rs:487-548`
- **Category:** wire (DoS surface)
- **Description:**  `router_axum` mounts `/session`, `/admin/preauth`,
  `/events`, `/metrics` and the tailscale-wire surface. No
  `tower_http::limit::RequestBodyLimitLayer` or
  `axum::extract::DefaultBodyLimit` is applied. axum's `Json`
  extractor has a 2 MB default, but the tailscale-wire `/ts2021`
  upgrade path bypasses axum entirely (`raw_tls.rs:319`) and reads
  the body via the raw TLS socket with no size cap.
- **Impact:**  An attacker can stream gigabytes to `/ts2021` (or any
  route mounted under the wire surface) before the handler decides
  to reject. Memory pressure + bandwidth burn = cheap DoS against
  an exit node.
- **Proposed fix:**  Wrap `router_axum` with
  `.layer(DefaultBodyLimit::max(64 * 1024))` for control routes
  (`/session`, `/admin/preauth`) — 64 KB is plenty for the largest
  legitimate body. For `/ts2021`, enforce a max-read cap on the raw
  TLS read loop in `headscale-api/src/tailscale_wire/raw_tls.rs`.
- **Test:**  Integration test that POSTs 10 MB to `/session` and
  asserts 413 Payload Too Large.

### H-4 — Plaintext-key boot path remains accepted when `require_sealed_keys = false`

- **File:** `crates/octravpn-node/src/config.rs:180-189`
- **Category:** crypto / ops
- **Description:**  `require_sealed_keys` defaults to `false` for
  v1.1 back-compat. An operator who never reads the docs ships
  mainnet with plaintext wallet keys on disk. The threat-model
  acknowledges this (7.a, "Partially Mitigated") but the default
  is wrong for mainnet.
- **Impact:**  Any host compromise (filesystem read) hands the
  attacker the wallet/WG/receipt-signing keys. This is exactly the
  threat sealed-keys was meant to mitigate — and the back-compat
  default subverts the mitigation.
- **Proposed fix:**  Flip the default to `require_sealed_keys =
  true` for any binary built with `--cfg mainnet`. Print a
  bright-red stderr warning when the daemon starts with
  `require_sealed_keys = false` AND `chain_id != test`.
- **Test:**  Boot integration test that asserts the daemon refuses
  to start on a mainnet `chain_id` with a plaintext key file.
- **Lean coverage:** No formal proof — config-time check.

### H-5 — Equivocation detector for double-sign is unwired

- **File:** `crates/octravpn-node/src/control.rs:152-159`,
  `program/main-v3.aml` (slash_double_sign helper exists)
- **Category:** chain
- **Description:**  `slash_double_sign` is callable on chain, but no
  loop in the daemon actively scans for equivocation across forked
  binaries. Detection requires a third party to feed two
  conflicting receipts into the slasher. Today no such detector
  ships.
- **Impact:**  A malicious operator running two daemons against the
  same wallet can equivocate; the *first* victim is uncompensated
  because no automated detector dispatches the slash before the
  receipts are countersigned by their respective clients.
- **Proposed fix:**  Add a `receipt_oracle` task that subscribes to
  the on-chain `SettleClaimed` event stream and cross-references
  `(session_id, seq)` against the daemon's signed-receipt history.
  Any mismatch dispatches `slash_double_sign` automatically.
- **Test:**  Adversarial integration test that opens two daemons
  with the same wallet, settles different `bytes_used`, and
  asserts the operator's bond is burned by the slash.
- **Lean coverage:** Equivocation slashing is referenced in
  `program/main-v3.aml:382-418` (the `slash_double_sign` body) but
  no Lean theorem proves *liveness* of the slash path.

---

## MEDIUM — count: 7

### M-1 — DERP CDN cert SAN-only pin (no SPKI)

- **File:** `docker/devnet/tailscale-interop/run-interop.sh:166-175`
- **Category:** wire
- **Description:**  Threat-model row 4.c — re-issued cert from same
  CN passes the SAN match. Same root cause as H-1 but lower
  exploitability (DERP MITM only sees ciphertext).
- **Impact:**  Adversary who controls the CDN's CA can substitute a
  cert mid-session. WG inner layer is still safe; only relay
  metadata leaks.
- **Proposed fix:**  Move the SAN match to an SPKI match.
- **Test:**  Substitute a cert with same SAN but different SPKI,
  assert connection refused.
- **Lean coverage:** None.

### M-2 — Single-RPC submission; no multi-validator failover

- **File:** `crates/octravpn-core/src/rpc.rs:93-112`
- **Category:** chain
- **Description:**  `RpcClient` holds one `endpoint`. Threat-model
  3.a admits a single validator can censor a slash-of-itself tx.
- **Impact:**  A validator that knows it's about to be slashed
  censors the slash tx for one epoch, gives itself time to exit.
- **Proposed fix:**  `Vec<endpoint>`; round-robin; surface "all
  endpoints down" as a hard error to the operator. The retry path
  in `call()` already does exponential backoff — extend to
  multi-endpoint rotation.
- **Test:**  Integration test with two RPCs, one returning 500;
  assert the tx lands via the second.
- **Lean coverage:** None.

### M-3 — Onion layer uses fixed zero nonce

- **File:** `crates/octravpn-core/src/onion.rs:128, 172`
- **Category:** crypto
- **Description:**  `wrap_layer` / `peel_layer` use `Nonce::from_slice(&[0u8; 12])`.
  This is **safe today** because each layer derives a unique key
  from a fresh `EphemeralSecret::random_from_rng(OsRng)` — the
  shared secret is one-shot, so the (key, nonce) pair is unique
  per onion message. But the code reads as a footgun.
- **Impact:**  None today. If a future maintainer ever reuses an
  ephemeral, or switches to a `StaticSecret` for the wrap side,
  the zero-nonce becomes catastrophic.
- **Proposed fix:**  Add a clarifying comment block AND a debug-
  assertion that the eph secret is freshly generated per wrap.
  Better: derive a per-layer nonce from `HKDF(shared, "onion-nonce")`
  so the layer is robust under key-reuse mistakes.
- **Test:**  Property test: 1000 random wraps under the same target
  pubkey produce 1000 distinct ciphertexts (already passes by
  ephemeral randomness, but the test pins the invariant).
- **Lean coverage:** None — the onion module has no Lean spec yet.

### M-4 — obfs4 handshake has no replay cache

- **File:** `crates/octravpn-obfs4/src/handshake.rs:56-63`
  (docstring acknowledges this)
- **Category:** wire
- **Description:**  A replayed client handshake derives a session
  key the replayer cannot use (fresh server ephemeral) — confidentiality
  is intact. But the server pays a Curve25519 DH + HKDF + Poly1305 on
  every replay.
- **Impact:**  Cheap CPU-burn DoS. Attacker who captures one
  legitimate handshake can replay it indefinitely.
- **Proposed fix:**  Bounded LRU of recently-seen `(client_ephemeral)`
  values with a 60s TTL.
- **Test:**  Replay 1000 captures; assert the server's CPU
  fingerprint stays flat.
- **Lean coverage:** None.

### M-5 — Receipt journal compaction race on non-POSIX FS

- **File:** `crates/octravpn-core/src/receipt_journal.rs:88-108`
  (compaction commentary)
- **Category:** chain
- **Description:**  Compaction relies on `rename(2)` atomicity. On
  POSIX this is bulletproof; on Windows, NFS, or some cloud-native
  filesystems, `rename` may not be atomic. The on-disk seq-floor
  invariant could be lost mid-compaction, leading to a fresh boot
  re-signing at a lower seq.
- **Impact:**  On a non-POSIX filesystem, a crash mid-compaction
  could cause the operator to re-sign `(session_id, seq=K)` after
  having previously signed `(session_id, seq=K+ε)`. Slashable.
- **Proposed fix:**  Refuse to start when journal directory's
  filesystem is not in {ext4, xfs, btrfs, apfs, ufs, tmpfs}.
  Document this in `docs/operators/`.
- **Test:**  Integration test on a `fuse` mount that simulates
  non-atomic rename; assert the daemon refuses to boot.
- **Lean coverage:** `proofs/lean/OctraVPN_Rust/Lemmas.lean` covers
  monotonicity of the seq-floor but assumes atomic rename.

### M-6 — HFHE shadow blob unverified on chain (HFHE-2)

- **File:** `crates/octravpn-node/src/control.rs:142-154`
  (ShadowSigner attaches ciphertexts to receipts), `docs/audit/known-limitations.md`
- **Category:** chain
- **Description:**  The shadow blob (`encrypt_const(bytes_used)`,
  `encrypt_const(net)`) is attached to the proposed receipt but the
  chain stores it without integrity check. The swap-ready AML adds
  the check but is not deployed.
- **Impact:**  An operator can attach garbage as the shadow blob —
  it never decrypts to the real `bytes_used`. Confidentiality is
  preserved (because the real `bytes_used` is on the plaintext
  receipt), but the *purpose* of the shadow blob (privacy-preserving
  audit) is silently defeated.
- **Proposed fix:**  Land the AML check before mainnet. Until
  landed, document the gap loudly in `oct://` URLs that advertise
  HFHE-2.
- **Test:**  AML test that submits a tampered shadow blob and
  asserts rejection.
- **Lean coverage:** None — HFHE-2 is not formalized.

### M-7 — obfs4 `node_id` doubles as HMAC key

- **File:** `crates/octravpn-obfs4/src/handshake.rs:155, 222`
- **Category:** crypto
- **Description:**  `mac1 = HMAC(node_id, ...)`. The 20-byte
  `node_id` is the bridge's secret-distribution identifier — it
  serves both as a routing label *and* as a 160-bit HMAC key. No
  rotation primitive exists.
- **Impact:**  If `node_id` leaks (e.g. via a misconfigured bridge
  publishing it in plaintext), an attacker can forge probe-resistant
  handshakes against that bridge without knowing the identity
  secret. Probe-resistance is silently broken.
- **Proposed fix:**  Either (a) derive the HMAC key as
  `HKDF(node_id || identity_secret, "obfs4-mac1")` so the key is
  domain-separated, or (b) document `node_id` as confidential and
  add a `rotate_node_id` admin command.
- **Test:**  Test that a known `node_id` cannot forge `mac1`
  without the identity secret under the proposed fix.
- **Lean coverage:** None — obfs4 is not formalized in Lean.

---

## LOW — count: 6

### L-1 — `rand::random::<u64>()` in RPC retry jitter

- **File:** `crates/octravpn-core/src/rpc.rs:133`
- **Category:** crypto (defense-in-depth)
- **Description:**  `rand::random::<u64>() % 50` for backoff jitter.
  CSPRNG-backed (`thread_rng`), so cryptographically fine, but
  `rand::random` reads less obviously secure than explicit
  `OsRng.fill_bytes`. Audit reviewers should be able to spot RNG
  usage at a glance.
- **Impact:**  None today.
- **Proposed fix:**  Switch to `OsRng.next_u64() % 50` and document
  that all RNG goes through `OsRng` in this crate.
- **Test:**  Lint rule: `clippy::disallowed_method` for
  `rand::random`.

### L-2 — `unseal_one` heap residue

- **File:** `crates/octravpn-node/src/seal.rs:261-292`
- **Category:** crypto
- **Description:**  `unseal_one` zeroizes the `Vec<u8>` payload after
  `atomic_write`, but the `tempfile` crate's internal buffer may
  retain a copy of the plaintext until the `NamedTempFile` drops.
  Not a leak per se; the bytes are written to a tmpfs.
- **Impact:**  Negligible.
- **Proposed fix:**  Document or accept.

### L-3 — Knock `now_unix()` defaults to 0

- **File:** `crates/octravpn-mesh/src/knock.rs:80-85`,
  `headscale-api/src/tailscale_wire/knock.rs:202-207`
- **Category:** wire
- **Description:**  If `SystemTime::now().duration_since(UNIX_EPOCH)`
  ever returns `Err` (clock skew before epoch), `now_unix()`
  returns `0`. An attacker who controls the host clock can force
  knock-window 0 and replay a stale knock indefinitely.
- **Impact:**  Negligible — requires host clock compromise (which
  is out of scope per the threat-model).
- **Proposed fix:**  Return `Err(KnockError::ClockBroken)` instead
  of `0`, and have the middleware refuse all requests.

### L-4 — amnezia `copy_within` does not zero tail bytes

- **File:** `crates/octravpn-tun/src/amnezia.rs:409, 426`
- **Category:** wire
- **Description:**  `buf.copy_within(off..n, 0)` shifts the header
  in place but leaves the tail of `buf` (positions `n-off..n`)
  holding old bytes. The caller uses `new_len`, so the data is
  cipher-irrelevant. But a future change that hashes the full
  buffer would surface those bytes.
- **Impact:**  None today.
- **Proposed fix:**  Add `buf[new_len..n].fill(0)` after the shift.

### L-5 — Knock failures share rate limiter with all 404s

- **File:** `crates/octravpn-node/src/rate_limit.rs::classify`
- **Category:** wire
- **Description:**  Knock failures return 404 + canonical nginx
  body (good!). Rate limiting is per-route-class, not per-failure.
  A botnet sending bogus knocks burns the global default-class
  bucket but doesn't penalize the source IP further.
- **Impact:**  An attacker who passes the rate-limit can probe
  knock cookies at line rate. With 64-bit tags + 60s windows,
  brute force is 2^63 hashes/min — infeasible. Low.
- **Proposed fix:**  Add a `knock_failures_per_ip` counter and tar-
  pit after N failures.

### L-6 — `settle_blinding` accepts 1-byte input

- **File:** `program/main-v3.aml:556`
- **Category:** chain
- **Description:**  `require(len(settle_blinding) > 0, "blinding
  required")`. A 1-byte blind defeats the entropy of the earnings
  hash-chain.
- **Impact:**  Audit trail predictability for low-entropy
  attackers. Negligible for honest operators.
- **Proposed fix:**  `require(len(settle_blinding) >= 32, "blinding
  ≥ 32 bytes")`.
- **Test:**  AML test asserts rejection on a 16-byte blind.

---

## Cross-references to Lean theorems

| Finding | Lean theorem | Status |
|---------|-------------|--------|
| C-1 (dispute resolver) | — | NO formal proof — fuzz-only coverage |
| H-1 (SPKI pin) | — | NO formal proof — would need a `pin_verifier_correct` axiom |
| H-2 (counter wrap) | `proofs/lean/WireProtocol/BeNonce.lean:100-182` | proves monotonicity, NOT wrap-safety; axiom gap |
| H-3 (body limit) | — | NO formal proof — runtime middleware |
| H-4 (sealed keys default) | — | config-time check; out of Lean scope |
| H-5 (equivocation detector) | `program/main-v3.aml:382-418` | chain-side slash exists, liveness unproven |
| M-1 (DERP SPKI) | — | NO formal proof |
| M-2 (multi-RPC) | — | liveness property; out of Lean scope today |
| M-3 (onion zero nonce) | — | NO Lean spec for onion module |
| M-4 (replay cache) | — | NO formal proof |
| M-5 (rename atomicity) | `proofs/lean/OctraVPN_Rust/Lemmas.lean` | covers seq-floor monotonicity assuming atomic rename |
| M-6 (HFHE shadow) | — | HFHE-2 not formalized |
| M-7 (node_id reuse) | — | obfs4 not formalized in Lean |
| L-1..L-6 | — | housekeeping; not load-bearing |

## Out of scope

Lean proof verification (CI), dependency CVE scan (see
`dependency-audit.md`), `octra-foundry` chain runtime (only the
`sig`/`wallet_enc` consumers were inspected), `headscale-db` SQL
paths, side-channel timing, container/kernel surface.

## Veto recommendation

**If I had veto power, I would hold mainnet on C-1 only.**

C-1 is a stuck-funds bug with no recovery path. Every other finding
either:
- has a workaround the operator can deploy today (H-1: just don't
  trust portal URLs from untrusted sources; H-3: front a real reverse
  proxy with a body limit; H-4: set `require_sealed_keys = true`);
- requires an attacker capability outside the threat model (L-3:
  host clock; M-5: non-POSIX FS);
- is a defense-in-depth concern, not a present exploit (H-2 nonce
  wrap, M-3 zero nonce, M-4 replay cache, M-7 node_id reuse).

C-1, by contrast, is reachable by any party that pays one chain
tx fee. It locks funds permanently. It has no Lean coverage. The
fix (`settle_resolve` arbitration call) is a contract change that
mainnet cannot ship without.

The HIGH-severity items H-1 through H-5 should land within a release
cycle but are not deal-breakers individually. They share a common
theme: documentation overpromises mitigations the code does not yet
implement (H-1, H-4, H-5) or leaves a non-default-safe configuration
(H-4). Tightening defaults and aligning the threat-model with code
would substantially reduce the v3 audit surface.

## Reproduction

```
cd /Users/androolloyd/Development/octra
git checkout worktree-agent-a229e34852a17ea1d
grep -rn 'wrapping_add' crates/octravpn-obfs4/src/frame.rs
grep -rn 'spki\|SubjectPublicKeyInfo' crates/ --include='*.rs'   # empty
grep -n 'client_confirm_set\|settle_resolve' program/main-v3.aml
```
