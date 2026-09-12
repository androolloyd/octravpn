# v5 sketch — from a VPN to a metered-resource mesh

> Working notes, 2026-09-12. What "v5" could be if OctraVPN's substrate is
> pointed at more than bandwidth: GPU rentals, inference routing, storage.
> Grounded in what the code and the chain actually do today; the speculative
> parts are labeled.

## 1. The observation that makes this cheap

OctraVPN is already a **metered-resource marketplace with one resource**. Strip the
WireGuard specifics and what remains is:

| Layer | What exists today | Resource-specific? |
|---|---|---|
| Supply | staked operators (circles, `min_circle_stake`), announce with `price_per_mb` + region | price vector is bytes-only |
| Demand | sessions with escrow (`open_session` is payable; `value >= max_pay`) | no |
| Metering | off-chain signed receipts, sha256 hash-chained, counter-signed | receipt carries `bytes_used` |
| Settlement | two-tx claim → confirm, or the v4 relay HTLC for unilateral settle; 50 bps protocol fee | **no** — `main-v4.aml:611`: *"sessions are class- and price-agnostic on chain; class/price live in the operator's signed off-chain receipt"* |
| Enforcement | disputes, slashing, sweeper, refund watcher, `RELAY_ARMED` mutex | no |
| Identity | sealed operator keys, canonical signer, ChainTxQueue | no |
| Transport | Tailscale-compatible mesh, DERP, exit selection by region/price | bytes-only today |

The chain layer needs **no change** to settle a GPU-second or an inference call. v5 is
overwhelmingly an off-chain change: the receipt schema, what an operator daemon can
*do*, and how a client picks who does it.

## 2. What the native rail turns out to be for

We characterized Octra's `circle_outbox_open` / `relay_claim` / `ingress_commit` as
"delivery attestation, no hashlock, no money" — correct, and it kept us on the AML HTLC
for payment. Read as a **job-assignment rail** it fits v5 exactly:

- `circle_outbox_open` — post an intent (a job: model, budget, SLO)
- `relay_claim` — a provider claims it; ed25519 over `circle|intent|relay|epoch|expiry`, with allowlist/quorum/topology policy owner-controlled (`epoch_exec.ml:1647-1691`)
- `ingress_commit` — chain-attested "delivered"
- and active quorum-ready claims **unlock scoped HFHE rights per `intent_id`** (`circle_cell_transition.ml:168-192`)

So assignment and delivery can be chain-attested natively while payment stays in our HTLC,
keyed by the same `intent_id`. That is the composition we already recommended for relays;
for compute it becomes the audit trail of *who ran what*.

## 3. The hard part, honestly: verifying compute

Metering bytes is symmetric — both sides count. Metering inference is not: the provider
can substitute a cheaper model, pad tokens, lie about GPU-seconds, or log the prompt.
Nothing in our substrate solves this; it only makes the *consequence* (slash) cheap.
Options, ranked by 2026 realism:

1. **Sampling + dispute + slash.** Re-run a fraction of jobs (deterministic seeds) on a
   second provider; mismatch → the existing dispute path → slash. Reuses everything we
   have. Cost: ~1.05–1.2× on sampled traffic. Covers substitution and padding; does
   **not** cover prompt logging.
2. **TEEs.** Attest the enclave running the model. This is Venice's path, and the
   independent audit of it (Bednár, 2026-08; Miller's registry) found the attested
   enclave was a *router with zero GPUs*, routes were mutable post-boot, GPU attestation
   proved silicon not software, and verification was not fail-closed. Doable, but the
   lesson is that the *measured* thing must be the inference host and the model hash —
   or it is marketing. Realistic as v5.1, not v5.0.
3. **HFHE.** Octra's headline primitive. Not for LLM inference (arithmetic circuits only)
   and `fhe_verify_*` is view-only so it can never gate settlement. Where it *does* fit:
   private **usage/billing data** — which is the v3 confidential-earnings design, now
   recoverable via `key_switch`. Keep it there.
4. **ZK inference.** Not at this scale in 2026.

v5.0 = (1) + stake + reputation from settled receipts. v5.1 = (2) done properly.

## 4. "Like an OpenRouter"

OpenRouter is a single API that routes to many model providers by price/latency. The
decentralized version has a choice of *who routes*:

- **client-side routing** — the client reads operator announces (price vector, region,
  models, stake, settled-receipt reputation) and picks. No trusted party. Fits the mesh
  exactly: exit-node selection *is* this already, for bytes.
- **gateway routing** — an operator runs a router that others pay through. Simpler,
  reintroduces a middleman and its logs.

Start client-side; a gateway can be one more operator class later. The router's inputs
are things we already publish or can (announce), plus one new signal: reputation
derived from on-chain settled sessions per `(operator, class)`.

## 5. Why this beats the incumbents on the one axis that matters

Venice's privacy is a policy promise in default mode and a router-attestation in TEE
mode; OpenRouter is a company that sees every request. Here the provider sees a **mesh
identity and an escrowed session**, never the client's IP, and the settlement happens
without a company in the middle. The VPN is not a feature bolted beside compute — it is
what makes the compute private. That is the product: **private pipes + private compute,
one client, one wallet, one session model.**

## 6. The economics, and the trap to avoid

- Stake per resource class (a GPU operator stakes more than a bytes relay).
- Price discovery stays in announces; generalize `price_per_mb` to a price vector
  `{bytes, gpu_sec, tokens_in, tokens_out, gb_hour}`.
- Keep the 50 bps fee and the escrow model. **Do not** copy the stake-for-capacity
  entitlement (Venice's DIEM): the independent analysis showed it prices as a ~50%
  discount-rate perpetual on an unsecured, upgradeable claim, injects no cash, and
  becomes a growing real liability as compute gets cheaper. Pay-per-session is already
  right; don't invent a token mechanic on top.

## 7. What kills it

- Supply bootstrapping: bytes relays are cheap to run; GPUs are not. Without a
  first cohort of operators with real hardware there is nothing to route to.
- Verification: if sampling proves too expensive or too gameable for a model class,
  that class needs TEEs before it can be sold honestly.
- Latency: an inference call through a relay hop. Direct paths (the mesh already
  prefers them) matter more here than for bulk bytes.
- Retention: `keep_epochs = 8192` (~23h). Compute disputes that need a receipt older
  than a day must anchor evidence off-chain (sealed asset) — the sealed-asset +
  anchor path we built for PVAC blobs is the right shape.
- Regulatory: "uncensored inference" is what drove Venice into underground forums.
  Operator policy (allowlists on the native rail) is the tool; the default matters.

## 8. The smallest credible v5.0

1. **Receipt schema v2** — `{class, quantity, unit_price, model_id?}` replacing
   `bytes_used`. Chain untouched. (~days)
2. **One new operator capability** — `job`: run a request against a local model
   endpoint, meter tokens in/out, sign the receipt. Announced with a price vector.
   (~1–2 weeks)
3. **Client-side router** — pick by class/price/region/reputation; open a session;
   stream the job over the mesh. (~1–2 weeks)
4. **Sampling verifier + dispute wiring** — re-run x% on a second operator, dispute on
   mismatch, reuse slash. (~1–2 weeks)
5. **Native outbox intents for assignment** — chain-attested who-served-what, keyed to
   the HTLC by `intent_id`. Already scoped as additive relay work. (~1–2 weeks)

What it proves: one client pays one GPU operator for one inference, privately over the
mesh, settled on chain, with substitution provably slashable. Roughly 6–8 weeks, most of
it off-chain, none of it needing a new AML deploy.

What it does not prove: confidential inference against a malicious operator. That is
v5.1 and it is a TEE project with its own audit.
