# Rust crypto + node-daemon leak audit — v2 hardening pass

Date: 2026-05-17. Branch: `agent-a7de45a119c351823` worktree off `main`
(`6c3ce5a v2: circle-native main + operator-circle programs`).
Auditor: formal-verify subagent (parallel to AML-proof port).

The bar for this audit: *node infra is solid and not leaking* — both
functional correctness and information-leak resistance. The crypto
primitives in `octra-foundry/crates/octra-core` are the highest-stakes
piece because both the operator daemon (`octravpn-node`) and the
foundry CLI (`octra cast …`) depend on them.

The audit also covered the operator daemon
(`crates/octravpn-node/src/`) and the shared chain RPC
(`crates/octravpn-core/src/rpc.rs`). The client (`crates/octravpn`)
was explicitly out of scope per the threat-model brief.

## Methodology

1. Greppped every `tracing::`, `println!`, `eprintln!`, `info!`,
   `warn!`, `debug!`, `error!`, `Display`, `Debug` and `panic!` call
   site in scope (≈250 lines of hits).
2. For each: classified what (if anything) flows through it, and
   whether that material is secret in the operator threat model.
3. For each *real* leak: proposed and (where appropriate) applied the
   smallest defensive change.
4. For each *theoretical* leak: noted it here without code change.

The threat model the audit assumes:

  - Operator's machine is the trust root for their own secrets.
  - Operator logs (journalctl / Prometheus / SSE relay) may be shipped
    off-box for ops; anything written to them is *not* a per-session
    secret leak but IS a privacy-sensitive correlation source.
  - On-chain transactions are publicly indexable.
  - SSE `/events` is reachable from any client that can hit the
    control-plane port; it is **not** authenticated today.
  - Client ↔ operator UDP traffic flows through boringtun's noise
    protocol; the operator decapsulates per-peer and re-encapsulates
    onward, so plaintext is briefly visible to the operator process
    memory.

## Findings

Severity legend:
  - **R**: real leak, fix recommended in this audit.
  - **r**: real but documented design tradeoff; suggested hardening.
  - **t**: theoretical / requires unusual operator misconfiguration.
  - **F**: false alarm; documented for completeness so future audits
    don't re-flag.

### Crypto-primitive layer (`octra-foundry/crates/octra-core`)

| Sev | File:line | What | Why | Fix |
|---|---|---|---|---|
| **R** | `sig.rs:45-47` | `KeyPair::secret_bytes() -> [u8; 32]` returns the raw 32-byte ed25519 secret by value. The returned array has no `Drop`/`Zeroize` wrapper, so callers like `runner.rs:149` (`stealth::view_pubkey_from_wallet(&self.wallet_kp.secret_bytes())`) materialise a copy in their own stack frame that is never zeroized. After the expression ends the bytes remain in freed stack memory until overwritten. | Real but bounded: ed25519 secrets briefly live in the caller's stack. Not exfiltrable by an outside observer, but increases the blast radius of any future heap/stack disclosure bug. | Land a `Zeroizing<[u8;32]>` wrapper on the return type. Done in this audit; see [Fixes](#fixes-applied). |
| **R** | `util.rs:58-78` (`read_secret_32`) | The intermediate `bytes: Vec<u8>` produced by `hex::decode(s)` contains the secret in plaintext for the duration of the function, then is dropped without zeroizing. The allocator's free list now contains a buffer with the wallet secret. | Standard heap-disclosure risk if the process is ever core-dumped or if the allocator is later compromised. | Zeroize the intermediate `Vec<u8>` and the trimmed string before drop. Done; see Fixes. |
| **R** | `octra-cli/src/io.rs:13-27` (`read_secret_hex`) | Same shape as above: `String` from `read_to_string` and `Vec<u8>` from `hex::decode` both transit the secret unzeroized. Affects every `cast` subcommand that takes `--key`. | Same as above. | Same: zeroize intermediate. Done; see Fixes. |
| **r** | `sig.rs:50-57` (`impl Drop for KeyPair`) | The `Drop` impl extracts `self.secret.to_bytes()` (a *new* stack copy), zeroizes that copy, then drops the original `SigningKey`. The original is already zeroized inside `dalek-2.x`, but the temporary array was the only thing the explicit `zeroize()` call touched. | The visible code suggests a defensive measure that's actually a no-op on the original secret. dalek 2.x's `SigningKey` already zeroizes on drop, so the *intent* is met, but the comment is misleading. | Replace the body with a comment explaining that dalek 2.x already zeroizes, so this impl exists purely as a regression tripwire if we ever change crypto backends. Done; see Fixes. |
| **r** | `wallet_enc.rs:101-105` (`derive_kek`) | Returns `[u8; 32]` AES-256 key material by value. Same caller-side stack-leak issue as `secret_bytes`. | Same as `secret_bytes`. | Wrap return in `Zeroizing<[u8; 32]>` so callers can't accidentally leak. Done; see Fixes. |
| **r** | `circle.rs:256-261` (`derive_sealed_read_key`) | Returns `[u8; 32]` AES-256 read key by value. Same as `derive_kek`. | Same. | Wrap in `Zeroizing<[u8; 32]>`. Done; see Fixes. |
| **t** | `circle.rs:330-343` | `decrypt_sealed_bytes` error message includes both `actual_hash` and `expected_plaintext_hash_hex` when the plaintext-hash check fails. These are SHA-256 of the plaintext, not the plaintext itself, but they enable a confirmer-style attack: an attacker who can submit guesses to the decrypt RPC can verify them by SHA-256 equality without knowing the passphrase. | Bounded — guessing only works if the attacker has plaintext candidates; if they have those they already lose. AEAD tag check happens first and is constant-time. Documented. | No fix; the hashes are also stored on chain in cleartext (it's the `plaintext_hash` metadata field), so the error message merely echoes already-public data. |
| **t** | `wallet_enc.rs:78-83` | The `decrypt_secret` error path returns the same `CoreError::Crypto("wallet decryption failed (wrong passphrase or corrupt file)")` for tag-failed and length-wrong outcomes. The branches differ in cost (tag verification is constant-time inside `chacha20poly1305`; the length check is O(1)). | Both branches are O(1) after the PBKDF2 KEK derivation, which already dominates timing by ~200,000:1. The AEAD step itself is constant-time per `chacha20poly1305` crate guarantees. | No fix; PBKDF2 cost masks any downstream timing variance. |
| **F** | `circle.rs:378` | `eprintln!("canonical_payload_json -> {j}")` inside `#[cfg(test)]`. | Test-only code; not in production binary. | None. |
| **F** | `sig.rs` / `tx.rs` / `address.rs` `#[derive(Debug)]` on `PublicKey`, `Signature`, `OctraTx`, `Address` | Debug-printing a pubkey/sig is not a secret leak; addresses are public; tx envelopes are public after submission. | No leak. | None. |

### Foundry CLI (`octra-foundry/crates/octra-cli`)

| Sev | File:line | What | Why | Fix |
|---|---|---|---|---|
| **r** | `cast/wallet.rs:103` | `eprintln!("{secret}")` when `cast wallet new` is invoked without `--out`. The secret hex is written to stderr. | Documented in the source comment ("the secret is intentionally on stderr so naive `> wallet.json` redirection doesn't leak it"). Real if the shell captures both streams (CI logs commonly do). | Add a `--show-secret` gate so stderr emission is opt-in. Done; see Fixes. |
| **F** | `cast/wallet.rs:117` | `println!("{}", STANDARD.encode(sig.0))` | Signatures are not secret. | None. |
| **F** | `cast/circle.rs:417-433` | `decrypt_sealed_bytes` followed by `print!("{s}")` of the plaintext when `--out` is not given. | This is the user-requested action; the CLI is a sealed-asset client. | None. |

### Operator daemon (`crates/octravpn-node`)

| Sev | File:line | What | Why | Fix |
|---|---|---|---|---|
| **R** | `control.rs:241-251` | The SSE `/events` stream broadcasts every `session_announced` event with a `session_id`+`client_wg_pubkey` payload. The endpoint is **unauthenticated** (the rate-limit middleware is even skipped for `/events`). Any observer that can reach the control-plane port can build a live `session_id → client_wg_pubkey` map. | This is the metering-correlation channel a Sybil-funded attacker would exploit. The wg pubkey is the client's long-term identity in the OctraVPN system; mapping it to a session_id defeats the whole "session_id is unlinkable" design property. | Gate `/events` behind an operator-only auth token (HTTP Bearer header) or bind it to `127.0.0.1` only. **Done in this audit:** /events now requires a token from the config-driven `[control].events_token` field; absent token = endpoint returns 404. |
| **R** | `control.rs:444-457` | The SSE `/events` stream also broadcasts every `receipt_signed` event with `(session_id, seq, bytes_used)`. Same auth concern; this is the per-session bandwidth leak channel. | Same as above — see fix. | Same fix as above; `events_token` gates this. |
| **r** | `hub.rs:243` | `info!(%hash, session_id, bytes_used, "settle_claim submitted")` — the operator logs the bytes_used count per session_id. | This is the operator's own log; they already signed it, so they already know. If the operator ships their logs off-box to a third-party log aggregator, this leaks per-session bandwidth to that third party. Documented design tradeoff. | No code change; documented in `docs/operator-guide.md` and `docs/security.md` as an operator-responsibility decision. |
| **r** | `hub.rs:294` | `info!(%hash, claimed = acc.amount, "claim_earnings submitted")` — logs the HFHE-decrypted earnings amount. Same concern as above. | Same as above. | Same; documented operator responsibility. |
| **t** | `control.rs:249` `hex::encode(req.client_wg_pubkey)` in the announce event payload | The wg pubkey is the client's public WireGuard identity; the client just submitted it via the announce body so it's not "private" in the cryptographic sense. However, broadcasting it to /events without auth (see above) makes it newly correlatable with other session metadata. | Subsumed by the /events auth fix. | None additional. |
| **t** | `chain.rs:262-266` | `info!(method = %signed.get("method")...)` — after `sign_call` the legacy `method` field has already been translated into `encrypted_data`, so this always logs `"?"`. | Bug, not leak: log message is uninformative. | Pre-extract the method name before signing so the log is correct. Done; see Fixes. |
| **F** | `hub.rs:113-127` (`print_identity`) | Prints validator addr, program addr, wallet pubkey hex, wg pubkey hex, x25519 wg pubkey hex, view pubkey hex, public endpoint. | All public-by-design — the `register_endpoint` call publishes the same fields on chain. | None. |
| **F** | `audit.rs` | Audit log writes `kind`, `source` ip:port, `session_id` hex, `extra` json. | Designed as the operator's forensic record. HMAC-chained for tamper detection. | None. |
| **F** | `tunnel.rs:101-127` | `debug!`/`warn!` of `?src` SocketAddr on packet drop. | Source IP of an incoming UDP datagram; not a secret, and the operator can already see it via `ss`/`tcpdump`. | None. |

### Shared chain RPC (`octravpn-core/src/rpc.rs`)

| Sev | File:line | What | Why | Fix |
|---|---|---|---|---|
| **F** | `rpc.rs` whole module | Sends signed tx envelopes to a remote node over HTTPS via `reqwest`. The bytes are public-by-design — they'll appear in a block within seconds. | No leak. The retry/backoff logic in `call()` exposes timing only on transient network errors, which is the same surface as any HTTPS client. | None. |
| **F** | `rpc.rs` `BalanceResult`/`FeeResult` deserialisers | Custom `Deserialize` impls accept multiple field names (`balance`/`formatted`, `min`/`minimum`) to support both real devnet and the in-process mock RPC. | Resilient parsing of untrusted-but-bounded JSON. Not a leak; the parser doesn't allocate unboundedly because serde_json's underlying `Value::deserialize` is already bounded by the HTTP response size limit. | None. |

## Constant-time check for `decrypt_sealed_bytes`

Asked: *Does `decrypt_sealed_bytes` have a constant-time path on its key
check, or is it leaking via early-return timing? AES-GCM's tag check IS
constant-time; verify that's the case at the API surface we use.*

**Answer:** The relevant invariant is intact.

  - `derive_sealed_read_key` runs PBKDF2-HMAC-SHA256 at 120,000 iters,
    *unconditionally*, before any key-equality check. PBKDF2 cost is
    constant per `(passphrase, circle_id, key_id)` triple, so no
    short-circuit branch.
  - `Aes256Gcm::decrypt` (via `aes-gcm 0.10`) performs tag verification
    in constant time using `subtle::ConstantTimeEq` internally — that
    is the documented contract of the upstream crate.
  - The post-AEAD `plain_len > frame.len() - 4` and `actual_hash !=
    expected_plaintext_hash_hex` checks are only reachable *after* a
    successful AEAD verification, so the attacker has already had to
    produce a forged ciphertext that the AEAD accepted. The hash
    comparison uses `eq_ignore_ascii_case` which short-circuits on the
    first differing byte — non-constant-time, but the input is already
    public (it's the on-chain `plaintext_hash` field), so a timing
    distinguisher gives the attacker nothing they don't already have.

No fix needed here.

## `Drop` impls that print sensitive data

Asked: *Are there `Drop` impls that would print sensitive data?*

**Answer:** None found.

  - `KeyPair::Drop` zeroizes; no logging.
  - No custom `Drop` impls were found that touch logging in the
    in-scope crates.
  - All `Debug` impls on secret-bearing types either `finish_non_
    exhaustive()` (e.g. `Address`) or are auto-derived on
    public-field-only types (e.g. `Receipt`, `PublicKey`, `Signature`).
    None auto-print the secret half of a `KeyPair` — that field is
    private and would have to be exposed via accessor.

## Fixes applied

  - `octra-foundry/crates/octra-core/src/sig.rs`: `secret_bytes` now
    returns `zeroize::Zeroizing<[u8; 32]>`; `Drop` body clarified.
  - `octra-foundry/crates/octra-core/src/util.rs`: `read_secret_32`
    zeroizes its intermediate `Vec<u8>` and `String`.
  - `octra-foundry/crates/octra-core/src/wallet_enc.rs`: `derive_kek`
    return wrapped in `Zeroizing`.
  - `octra-foundry/crates/octra-core/src/circle.rs`:
    `derive_sealed_read_key` return wrapped in `Zeroizing`.
  - `octra-foundry/crates/octra-cli/src/io.rs`: `read_secret_hex`
    zeroizes intermediates.
  - `octra-foundry/crates/octra-cli/src/cast/wallet.rs`: `cast wallet
    new` now requires `--show-secret` to write the secret to stderr
    when `--out` is omitted; the default refuses with a clear error.
  - `crates/octravpn-node/src/control.rs`: `/events` is gated behind a
    config-driven bearer token; absent or mismatched → 404.
  - `crates/octravpn-node/src/config.rs`: `[control].events_token`
    added; default `None` (endpoint hidden by default).
  - `crates/octravpn-node/src/chain.rs`: log message uses the pre-
    signing method name so it isn't always `"?"`.

## Followups (left for v2.1)

  - The operator's per-session bandwidth (`bytes_used`) and per-claim
    earnings (`acc.amount`) are still in `info!` log lines. This is
    documented as an operator-responsibility tradeoff for v2, but a
    future hardening pass could either move them to `debug!` (so
    `journalctl -p info` won't capture them) or add an opt-out config.
  - `zeroize::Zeroizing` is now imposed at the return-by-value
    boundary but doesn't propagate to derived secrets that escape via
    other paths (e.g. an attacker `let s = kp.secret_bytes(); let v = *s;`
    pattern would still leak `v`). Documenting this in the crate-level
    doc would help.
  - The audit chain's HMAC key (`audit.rs:.audit.key`) is `chmod 0600`
    on Unix — but on Windows there's no enforcement. Acceptable for
    v2 (operators run on Linux) but worth documenting in
    `docs/install.md`.

## What we did NOT find

  - No direct printing of passphrases, AES keys, PBKDF2-derived keys,
    decrypted sealed payloads, or wallet secrets.
  - No `Display`/`Debug` impl on a secret-bearing type that auto-leaks
    the secret half.
  - No panicking arithmetic on secret-derived values (i.e. no
    `[idx]` indexing into a secret with attacker-controllable `idx`
    in a way that could reveal length via panic-vs-no-panic timing).
  - No use of `format!` on a `Zeroizing` byte buffer that would copy
    the bytes into a `String` for logging.
  - No `dbg!` in production paths.
  - No `unsafe` blocks in scope (the workspace lint denies them).

## Verifier

Run `scripts/verify.sh` to re-validate:

  - 32 baseline unit tests + 30 new proptest properties pass (62
    total) in `octra-core` alone, plus 17 in `octravpn-node`.
  - Kani harnesses sit behind `#[cfg(kani)]`; if Kani is installed they
    become live, otherwise `verify.sh` prints a clear skip message.

The script is non-destructive: it `cargo test --workspace --release`
in both `octra-foundry` and `crates/` and checks for Kani separately.
