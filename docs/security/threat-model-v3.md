# OctraVPN v3 threat model

Scope: the v3 chain-minimal flow (`program/main-v3.aml`) plus the
hardened control-plane HTTP surface introduced in the v3 release.
Supersedes `docs/v2-threat-model.md` for v3-shaped deployments; v1.1
and v2 deployments should continue to consult that document.

The model is intentionally focused. We enumerate the actors, the
assets they touch, an attack tree of credible misbehaviour, and the
mitigation that defends each branch (with file:line references). Each
row is labelled:

- **Mitigated** — the defense is in place and exercised by tests
  and/or a Lean theorem.
- **Partially Mitigated (with gap)** — the defense exists but a
  documented gap remains; the row lists the file:line of the residual
  surface so operators can monitor.
- **Out of Scope (operator responsibility)** — the asset is outside
  the daemon's trust boundary; the row records the assumption and
  defers to operator runbooks.

## Actors

| Actor | Capabilities | Trust |
|-------|--------------|-------|
| **Operator** | runs `octravpn-node`, holds wallet + receipt keys, configures `node.toml`, mints preauth keys | trusted in-scope; out-of-scope for host compromise |
| **Validator** | the Octra protocol validator the operator's wallet is bound to | trusted at the chain layer; misbehaviour is slashed via `slash_double_sign` |
| **Peer** | a remote OctraVPN node redeeming a preauth + carrying traffic | adversarial-tolerant; cannot forge a receipt the operator did not sign |
| **Client** | end-user driving `octravpn-client` against an `oct://` URL | adversarial-tolerant; can only learn what the operator chooses to expose via `/session/:id` and `/events` |
| **Attacker (external)** | unauthenticated network reach to the control plane | hostile; must be defeated by every public-facing surface |
| **Attacker (privileged)** | has stolen wallet or receipt key material | partial-defense: equivocation is detected and slashed, but pre-detection actions stand |

## Assets

| Asset | Location | Confidentiality | Integrity | Availability |
|-------|----------|-----------------|-----------|--------------|
| Chain state (registry, stake, anchors) | Octra chain | public | chain-enforced | chain-SLA |
| Audit log (per-day JSONL) | `${audit_dir}/audit-YYYY-MM-DD.jsonl`, HMAC key at `${audit_dir}/.audit.key` | low (no secrets) | HMAC-chained (`crates/octravpn-node/src/audit.rs:10-11`) | local disk |
| Preauth keys (in-memory + minted) | `PreauthMinter` in `crates/octravpn-node/src/control/state.rs:91` + `crates/octravpn-node/src/control/handlers/preauth.rs:64` | high (short-lived bearer tokens) | mint-only by operator | bounded-cap map |
| Session receipts (signed) | `ReceiptJournal` at `${control.receipt_journal_path}` default `./state/receipts.bin` (`crates/octravpn-node/src/config.rs:579`) | low | seq-floor durable across restart (`crates/octravpn-node/src/control/state.rs:86`) | local disk |
| Receipt-signing key | derived from `tunnel.wg_secret_path` via HKDF (`crates/octravpn-node/src/hub/boot.rs:64-72`) | high | filesystem ownership; sealed-keys mode at `crates/octravpn-node/src/config.rs:400` | host |
| Wallet (chain-signing) key | `chain.wallet_secret_path` | high | same sealed-keys mode | host |
| Treasury (operator earnings) | on-chain balance bound to wallet | public | wallet signature required to move | chain-SLA |

## Attack tree

Top-level adversary goal: **steal value from an operator, a client, or
the protocol**. Sub-goals follow.

### 1. Forge a receipt the operator did not sign

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 1.a Replay a receipt from a different program / chain / circle | **Mitigated** | `ReceiptContext` binds `(program_addr, chain_id, circle_id)` into every signed receipt (`crates/octravpn-core/src/receipt.rs:15-43`). Theorem: `proofs/lean/OctraVPN_Rust/Lemmas.lean:43` (`ReceiptContext.circleIdCanonical_length`). |
| 1.b Replay a receipt at an earlier `seq` after a daemon restart | **Mitigated** | `ReceiptJournal` consults a persistent seq-floor before signing (`crates/octravpn-node/src/control/state.rs:86, 226, 237, 245`). Atomic rename + fsync via tempfile (`tempfile` dev-dep). Disaster-recovery rebuild via `octravpn-node journal rebuild --from-audit` (`crates/octravpn-node/src/cli/journal.rs`). |
| 1.c Forge an ed25519 signature without the receipt key | **Mitigated** | curve25519-dalek + ed25519-dalek crates, no homebrew crypto. Receipt key is HKDF-derived (`crates/octravpn-node/src/hub/boot.rs:64-72`), zeroized on drop. |
| 1.d Trick the node into signing for a session it never announced | **Mitigated** | `/session/:id` is gated by the `sessions` map (`crates/octravpn-node/src/control/handlers/session.rs` + `crates/octravpn-node/src/control/state.rs:52`); only sessions that appeared in `POST /session` are signable. |

### 2. Double-spend / equivocation claim

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 2.a Operator signs two distinct receipts at the same `(session_id, seq)` | **Partially Mitigated (with gap)** | In-memory `sessions` map plus the on-disk `ReceiptJournal` make a *single-node* double-sign impossible. Gap: a forked operator running two binaries against the same secret can still equivocate; on-chain `slash_double_sign` detects it post-hoc (slash-payload builder lives in `crates/octravpn-node/src/v3_cli.rs:71-77`) but the *first* victim is uncompensated. Equivocation-detector loop is still TODO. |
| 2.b Client double-redeems a preauth key | **Mitigated** | `PreauthMinter` rejects a redeemed key on the second attempt; reusable keys are opt-in per mint (`crates/octravpn-node/src/control/handlers/preauth.rs:64-104`). |
| 2.c Replay a `settle_claim` call from an earlier epoch | **Mitigated** | v3 settlement uses a sha256 hash chain of `(prev_head || sha256(settle_blinding))` (`docs/v3-state-root-schema.md`, `crates/octravpn-core/src/v3_state_root.rs`); the chain rejects any claim whose chain-head does not match. |

### 3. Validator collusion

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 3.a Validator censors the operator's slash-of-its-own-misbehaviour | **Partially Mitigated (with gap)** | Slashing is a chain call; censorship at validator level is mitigated by the operator submitting to multiple validators. Gap: the daemon currently submits to one RPC (`crates/octravpn-core/src/rpc.rs:71-117`); multi-endpoint failover is on the security roadmap (`docs/security-roadmap.md`). |
| 3.b Validator MITMs the chain RPC | **Mitigated** | `[chain].pinned_root_paths` pins trust roots independent of the system CA store (`crates/octravpn-node/src/config.rs:368`, `crates/octravpn-core/src/rpc.rs:71-117`). Out-of-band CA compromise defeated. |
| 3.c Validator stalls the chain to delay slashing | **Out of Scope (operator responsibility)** | Chain liveness is the protocol's responsibility; operators rotate validators per the chain's own SLA. |

### 4. DERP MITM

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 4.a Rogue DERP server reads peer plaintext | **Mitigated** | Peer-to-peer noise tunnel terminates inside the WireGuard data plane (`crates/octravpn-node/src/tunnel.rs`); DERP only sees ciphertext. Theorem family: `proofs/lean/WireProtocol/BeNonce.lean:100-182` proves nonce uniqueness across the encrypted stream. |
| 4.b Rogue DERP server denies service | **Out of Scope (operator responsibility)** | DERP is a relay of last resort; the harness's interop sidecar (`docker/devnet/tailscale-interop/Dockerfile.derper`) is for testing. Production peers use the public Tailscale DERP fleet or operator-run relays per their own SLA. |
| 4.c Attacker substitutes the DERP cert mid-session | **Partially Mitigated (with gap)** | The peer rustls validator pins on SAN match (`docker/devnet/tailscale-interop/run-interop.sh:166-175`). Gap: the cert pin is *only* SAN-based, not SPKI-based; a re-issued cert from the same CN passes. Rotation runbook (`docs/operators/tls-rotation.md`) calls this out and points operators at SPKI-pin via `oct://` URLs for production. |

### 5. Control-plane hijack

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 5.a Brute-force `/admin/preauth` | **Mitigated** | Bearer-token gated; absent token returns 404 (`crates/octravpn-node/src/control/handlers/preauth.rs:64-104` + `crates/octravpn-node/src/control/router.rs:45`). Rate-limit at 60 rps / burst 120 per IP (`crates/octravpn-node/src/rate_limit.rs::classify`). |
| 5.b Flood `/session` to exhaust memory | **Mitigated** | `BoundedMap` caps total sessions (`crates/octravpn-node/src/control/state.rs:31` `CAP` const + `:253` instantiation); rate-limit caps mint rate (60 rps / burst 120). |
| 5.c Scrape `/metrics` to learn session counts | **Mitigated** | Bearer-token gated; returns 503 when unconfigured (`crates/octravpn-node/src/control/handlers/metrics.rs`). |
| 5.d Scrape `/events` SSE to learn session metadata | **Mitigated** | Bearer-token gated; returns 404 when unconfigured (`crates/octravpn-node/src/control/handlers/events.rs`). |
| 5.e Hammer arbitrary route to deny service | **Mitigated** | Per-IP, per-route-class token-bucket layer in `crates/octravpn-node/src/rate_limit.rs`; `/health` and `/metrics` bypass so liveness probes keep working. |
| 5.f Inject a forged `oct://` URL | **Mitigated** | The URL carries one or more sha256(SPKI) pins in a `?spki=<base64>[,<base64>...]` query parameter. The client extracts them via `octravpn_core::spki_verifier::SpkiPinVerifier::parse_pins_from_oct_url` and installs a `rustls::client::danger::ServerCertVerifier` that hashes the leaf cert's SubjectPublicKeyInfo and constant-time-compares to the pin set BEFORE any chain validation runs (`crates/octravpn-core/src/spki_verifier.rs`, wired in `crates/octravpn-client/src/portal/chain/fetch.rs::build_rpc_for_oct_url`). A compromised CA does not bypass the pin: the attacker also needs the leaf private key. Audit-1 H-1 closed. Residual gap: a phishing URL with an attacker-controlled fingerprint still routes the user to the attacker's exit — defence is end-user awareness + portal-side reputation, out of scope. |

### 6. Audit-log tamper

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 6.a Edit a historical audit JSONL line | **Mitigated** | Each line carries an HMAC chained to the previous line's HMAC (`crates/octravpn-node/src/audit.rs:10-11`). The HMAC key is persisted at mode-0600 alongside the log. Tamper detection: `octravpn-node audit verify` (`crates/octravpn-node/src/audit_cli.rs`). |
| 6.b Truncate the audit log | **Partially Mitigated (with gap)** | HMAC chain detects mid-file truncation. Gap: a full-day file deletion is detectable only by gap-in-filename heuristic (one file per UTC day); operators should ship the logs off-host on a rolling basis. Recommendation tracked in `docs/observability.md`. |
| 6.c Tamper while the daemon is offline | **Mitigated** | Same HMAC chain — the next boot re-opens the log and emits one entry; verifying from the previous entry's HMAC catches any intervening edit. |

### 7. Key compromise

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 7.a Read plaintext wallet/WG secret from disk | **Partially Mitigated (with gap)** | Sealed-keys mode wraps the secret with a passphrase from `OCTRAVPN_KEY_PASSPHRASE` (`crates/octravpn-node/src/config.rs:400`). Gap: when `require_sealed_keys = false` (the v1.1 default for back-compat), plaintext is accepted; operators must opt in explicitly. |
| 7.b Recover the receipt key from a memory dump | **Out of Scope (operator responsibility)** | We `Zeroize` on drop (`crates/octravpn-node/src/hub/identity.rs` + `crates/octravpn-node/src/hub/boot.rs`) but a live-process memory dump is host-level compromise; out of scope. |
| 7.c Use a stolen wallet to settle to attacker's address | **Mitigated** | v3 settle binds the destination to the on-chain wallet identity at `register_circle` time; settlement to a different address fails the AML check. |

### 8. v3 state-root forgery

| Branch | Status | Mitigation (file:line) |
|--------|--------|------------------------|
| 8.a Anchor a state-root that doesn't match the operator's circle JSON | **Mitigated** | Anchor is sha256 of the canonical JSON (`docs/v3-state-root-schema.md`); chain stores the 32-byte hash, clients fetch the JSON and verify. Theorem: `proofs/lean/WireProtocol/V3Canonical.lean:242` (`canonical_determinism`) + `:264` (`canonical_string_injective`). |
| 8.b Replay an old state-root after an `update_circle` | **Mitigated** | v3 settlement uses the chain-head hash chain (see 2.c); a stale anchor cannot resolve. |
| 8.c Withhold the state-root JSON from clients | **Partially Mitigated (with gap)** | The JSON lives circle-side; clients pin a list of fetch endpoints. Gap: if every published endpoint is taken offline, clients fail closed (no connection) rather than fall back — this is intentional for safety but is a DoS surface. Operators publish ≥2 endpoints in production. |

## Three highest-risk Partially Mitigated rows

1. **2.a** — operator-side equivocation across forked binaries. The
   on-chain slash works post-hoc but the first victim is uncompensated.
   Gap surface: slash payload-builder at
   `crates/octravpn-node/src/v3_cli.rs:71-77` (the call site exists but
   no equivocation-detector loop dispatches it).
2. **5.f** — phishing `oct://` URLs. **The claim of SPKI pinning is
   retracted** — `crates/octravpn-core/src/rpc.rs:71-117` is CA-bundle
   pinning only. Defense is end-user awareness + portal-side reputation,
   both out of scope here. Tracking: audit-1 H-1. Portal logic now in
   `crates/octravpn-client/src/portal/chain/{api,cache,decrypt,errors,fetch,mod}.rs`.
3. **4.c** — DERP cert SAN-only pin. A re-issued cert from the same
   CN passes the pin. Surface:
   `docker/devnet/tailscale-interop/run-interop.sh:166-175`.

## Out-of-scope assumptions

- Host OS, kernel, and filesystem are trusted (no LSM bypass, no
  privileged-container escape).
- Wallet passphrase is delivered out-of-band and not logged.
- Operator follows `docs/operators/tls-rotation.md` for cert lifecycle.
- Chain-level censorship is escalated through the chain's governance
  channel, not the daemon.

## Defense-in-depth surface

Each defense is exercised by one or more of the following:

- **Lean proofs** under `proofs/lean/`. Compile via `lake build`; the
  CI workflow `proofs.yml` enforces no broken sorry's. Theorems
  referenced in the attack tree above are load-bearing — a regression
  in their statement should be treated as a release-blocker.
- **Rust unit tests** colocated with the module (e.g.
  `crates/octravpn-node/src/rate_limit.rs::tests`,
  `crates/octravpn-core/src/receipt_journal/proptests.rs` plus the
  per-submodule tests under `crates/octravpn-core/src/receipt_journal/`).
- **Rust integration tests** under `crates/octravpn-node/tests/`:
  `tailscale_wire_integration.rs`, `raw_tls_integration.rs`,
  `v3_boot_integration.rs`.
- **End-to-end smoke** under `docker/devnet/` —
  `e2e-adversarial-v3.sh` exercises the v3 settle flow against a
  byzantine peer.

## Mitigation enforcement summary

The table below maps each defense category to the layer it runs in.
The point: most mitigations are enforced *below* the application
logic — at the chain, at rustls, at the audit log's HMAC chain — so
an application-level bug in `octravpn-node` cannot silently disable
them.

| Category | Enforcement layer | Bypass requires |
|----------|-------------------|-----------------|
| Receipt context binding | Signed bytes in every receipt | Forging an ed25519 signature |
| Receipt seq-floor | Atomic-rename journal write before sign | Tampering with the on-disk file outside the daemon |
| Rate limit | axum middleware before handler dispatch (`crates/octravpn-node/src/rate_limit.rs::rate_limit_layer`) | Crashing the daemon |
| Bearer-token gates | Inside the handler, constant-time compare (`crates/octravpn-core/src/bearer.rs`) | Knowing the token |
| TLS pin (chain RPC) | rustls trust-store (`crates/octravpn-core/src/rpc.rs:71-117`) | Replacing the pinned bundle on disk |
| Audit HMAC chain | Computed per-line, persisted at 0600 | Reading the key file |
| Sealed keys | AEAD over the secret, passphrase-derived | Knowing the passphrase |
| On-chain slash | Chain consensus | 51% attack on the chain |

## Operator hardening checklist

Pre-deploy:

- [ ] `[control].admin_token`, `events_token`, `metrics_token` all set to
      random ≥32-byte values.
- [ ] `[chain].require_sealed_keys = true` and `OCTRAVPN_KEY_PASSPHRASE`
      provisioned out-of-band.
- [ ] `[chain].pinned_root_paths` populated with the chain endpoint's
      current PEM bundle.
- [ ] `[control.rate_limit]` left at defaults OR explicitly tuned with
      per-class overrides under `[control.rate_limit.routes.*]`.
- [ ] Audit-log directory on a host-private path (NOT a bind-mount
      writable from a container the operator does not control).
- [ ] `scripts/operators/rotate-tls.sh` scheduled in cron / systemd-timer
      at the cadence documented in `docs/operators/tls-rotation.md`.

Post-deploy:

- [ ] `/health` returns 200; `/metrics` requires the bearer.
- [ ] `octravpn-node audit verify` passes from a fresh boot.
- [ ] `octravpn-node mesh mint-preauth --dry-run` succeeds (the CLI
      surface stays in sync with the HTTP surface).
- [ ] A test peer can complete a round-trip handshake and settle a
      receipt that the chain accepts.

## Revision history

- 2026-05-19 — initial v3 cut. Companion to `docs/v2-threat-model.md`
  (v2) and `docs/threat-model.md` (v1.1, deprecated).
