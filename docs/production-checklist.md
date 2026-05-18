# OctraVPN v1 Production Checklist

What's been done, what's left, and what blocks each gate. This is
the canonical "are we ready" document. Update as items move from
🟡 to 🟢.

## A. AML program (CORE)

| Item                                                                | Status |
| ------------------------------------------------------------------- | ------ |
| AML uses ONLY confirmed Octra host calls (`fhe_*`, runtime helpers) | 🟢      |
| Bond / unbond / finalize entrypoints                                | 🟢      |
| Governance slash entrypoint                                          | 🟢      |
| Single-hop session lifecycle (open / settle / no-show / sweep)      | 🟢      |
| HFHE-backed encrypted earnings + two-step claim                     | 🟢      |
| Program treasury (Tier 2 fee + slash burn share)                    | 🟢      |
| Mock-chain mirrors AML semantics faithfully                          | 🟢      |
| 54 test groups passing, clippy clean                                | 🟢      |
| OU snapshot up to date                                               | 🟢      |
| Verify confirmed primitive list with Octra core team                | 🟡      |
| Deploy compiled AML to Octra testnet                                | 🟡      |
| End-to-end test against real Octra testnet RPC                      | 🟡      |
| Independent third-party audit of `program/main.aml`                  | 🔴      |

## B. Formal verification

| Item                                                          | Status |
| ------------------------------------------------------------- | ------ |
| Lean state machine + entrypoints model the v1 AML             | 🟢      |
| Lean lemmas: treasury, refund, stake, slash, claim, register  | 🟢      |
| Lean proofs go through without `sorry`                        | 🟢      |
| TLA+ spec models v1 AML transitions + invariants              | 🟢      |
| TLA+ invariants: stake / slash / treasury / settle-or-refund  | 🟢      |
| TLC model-checks the spec in CI                               | 🟡      |
| Tamarin theory marked as v1.1+ target (pending verify_ed25519) | 🟢      |
| Kani harnesses for cryptographic primitives                   | 🟡      |
| Run TLC end-to-end on the updated spec                        | 🟡      |

## C. Client + node SDK

| Item                                                          | Status |
| ------------------------------------------------------------- | ------ |
| `octravpn-node` and `octravpn-client` binaries build           | 🟢      |
| `octravpn-node bond / unbond / finalize-unbond` subcommands    | 🔴      |
| `octravpn-node register` updated to v1 AML signature           | 🔴      |
| Drop `is_octra_validator` pre-check in favour of bond-status   | 🔴      |
| `octravpn slash-evidence verify | build` work (off-chain)      | 🟢      |
| `octravpn slash-evidence submit` calls `gov_slash_operator`    | 🔴      |
| Doctor flow checks bond status                                 | 🔴      |
| HFHE pubkey generation (placeholder OR real libpvac binding)   | 🔴      |
| Generate `initial_enc_zero` ciphertext                         | 🔴      |
| Update `discover.rs` to not expect receipt/view pubkey fields  | 🟡      |
| Two-step claim flow: AML transfer + native-tx stealth wrap     | 🔴      |

## D. Operator + user-facing docs

| Item                                                                | Status |
| ------------------------------------------------------------------- | ------ |
| `docs/whitepaper.md` updated to v1 model                            | 🟢      |
| `docs/economics.md` updated with v1 enforcement distinction         | 🟢      |
| `docs/security-roadmap.md` updated with §0 Octra-team asks          | 🟢      |
| `docs/value.md` (stakeholder value proposition)                      | 🟢      |
| `docs/aml-gap-analysis.md` (audit + rationale)                       | 🟢      |
| `docs/deployment-runbook.md` updated for bond + v1 health checks    | 🟢      |
| `docs/operator-guide.md` updated for bond + register flow           | 🟢      |
| `docs/validator-hardening.md` — review for stale receipt-pubkey refs | 🟡      |
| `docs/tailnet-user-guide.md` — review for v1 changes                 | 🟡      |
| `docs/threat-model.md` — review for v1 honest scope                  | 🟡      |
| `docs/security.md` — review for v1 honest scope                      | 🟡      |
| External-facing FAQ + getting-started for end-users                 | 🟡      |

## E. Octra-team engagement

Per `docs/security-roadmap.md §0`, these primitives close v1.1 gaps:

| Item                                            | Status |
| ----------------------------------------------- | ------ |
| Confirm host-call list with Octra core team     | 🟡      |
| Request `verify_ed25519(pk, msg, sig)` in AML    | 🟡      |
| Request `op_type="vpn_settle"` native extension | 🟡      |
| Request `verify_bulletproof(commit, proof)`     | 🟡      |
| Request `octra_isValidator(addr)` in AML         | 🟡      |

## F. Deployment infrastructure

| Item                                                              | Status |
| ----------------------------------------------------------------- | ------ |
| Reproducible builds for node + client binaries                    | 🟡      |
| Cosign-signed releases (Sigstore transparency log)                 | 🟡      |
| Multi-arch OCI images (linux amd64/arm64, macOS arm64)             | 🟡      |
| SBOM (CycloneDX) attached to each release                          | 🟡      |
| systemd hardening profile shipped + tested (see validator-hardening) | 🟢      |
| Prometheus + Grafana dashboards + alerting rules                  | 🟢      |
| Docker e2e harness (`docker/e2e.sh`, `docker/e2e-tailnet.sh`)     | 🟡 — needs v1 update |

## G. Operational + governance

| Item                                                              | Status |
| ----------------------------------------------------------------- | ------ |
| Owner-wallet ceremony for the program deploy                       | 🔴      |
| Bug-bounty program kickoff (Immunefi or HackerOne)                | 🔴      |
| Public roadmap + community channels                                | 🔴      |
| Incident-response oncall rotation                                  | 🔴      |
| Independent external audit (Trail of Bits / Spearbit / Zellic)    | 🔴      |
| Annual re-audit cadence                                            | 🔴      |

---

## Critical path to mainnet v1

Strict prerequisites for actually serving traffic on mainnet:

1. **AML compiles on real Octra.** Need to send `program/main.aml` to
   the Octra `compileAml` endpoint and verify zero errors. If it
   fails, we have unconfirmed host calls. (Sec §A row 9)
2. **Client/node SDK migration.** Update `register_endpoint` call,
   add `bond`/`unbond` subcommands, drop `is_octra_validator`
   pre-check, generate HFHE values. (Sec §C rows 2-9)
3. **End-to-end test against testnet.** Verify the entire lifecycle
   actually works against a real Octra node. (Sec §A row 11)
4. **Independent audit.** Pre-mainnet audit by an external firm.
   (Sec §G row 5)
5. **Owner-wallet ceremony.** Cold-storage multisig for the program
   deployer. (Sec §G row 1)
6. **Bug bounty live.** Programmatic incentive for external
   security researchers. (Sec §G row 2)

Without all six, mainnet is premature. With any subset, testnet
deploys are fine — and useful for items 3 + 4.

---

## H. v2 substrate gates

Applies to `[chain].protocol_version = "v2"` operators (v2 program
`oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7` on devnet). Tickets
cross-link to `docs/v2-threat-model.md`.

| Item | Ticket | Why |
| ---- | ------ | --- |
| `[control].events_token` set OR unset (404 default) | P0-1 | Without it, `/events` SSE broadcasts `(session_id → wg_pubkey)` + per-session `bytes_used` |
| `[chain].pinned_root_paths` = issuer chain for `rpc_url` | P0-2 | Defeats CA-compromise MITM (corporate proxy, rogue CA, MDM) |
| `[chain].require_sealed_keys = true` + `*.sealed` paths | P1-6 | Strict mode refuses plaintext on-disk; pair with `seal-keys` + `OCTRAVPN_KEY_PASSPHRASE` |
| `[chain].chain_id` set explicitly | P1-5 | Folded into receipt signing payload — devnet ↔ mainnet replay fails. Default `CHAIN_ID_DEVNET = 1 869 832 804` is a mainnet footgun |
| `[chain].sealed_passphrase` ≥ diceware-6 (rule of thumb) | P1-4 | **Not enforced today.** Diceware-6 (≈77 bits) for sealed-asset; ≥64 random bytes for `OCTRAVPN_KEY_PASSPHRASE`. PBKDF2-200k can't save a 30-bit passphrase |
| `[chain].circle_state_path` on durable backed-up storage | — | Loss = re-deploy circle, re-bond from scratch |
| `[control].receipt_journal_path` on durable backed-up storage | P1-8/9 | `(session → last_seq)` floor fsync'd pre-sign; loss = unknown-seq → can't safely sign. Critical state |
| `[pricing].price_per_mb_shared` + `_internal` set explicitly | — | Otherwise v1.1 `price_per_mb` is the only tariff |

### H.1 Pre-flight smoke

```sh
# 1. Strict-mode boot under sealed keys succeeds.
octravpn-node run --config /etc/octravpn/node.toml

# 2. /events 404s (or 401 with bad token).
curl -sS http://your.fqdn:51821/events

# 3. Chain sees the circle active + bonded.
octra cast call $PROG get_circle '["<circle>"]'

# 4. Kill -9 mid-session; restart; next signed seq strictly exceeds
#    the on-disk receipts.bin floor.
```

P1-5 / P1-6 / P1-8 / P1-9 are FIXED as of `d6b3930`; open items
(notably P0-2) tracked in `docs/v2-threat-model.md`.
