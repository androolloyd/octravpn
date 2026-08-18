# Building OctraVPN on Octra — what's working, and what's still genuinely open

*(Draft for the Octra forum / Discord / GitHub Discussions.)*

Hey Octra community 👋

We're building **OctraVPN** — an encrypted, Tailscale-style mesh VPN whose control plane and
payments settle on Octra. Operators stake OU to run exit/relay endpoints, sessions escrow their
cost, traffic flows over WireGuard, and settlement is two-tx with misbehaviour slashed in-AML.
Open source: `https://github.com/androolloyd/octravpn`.

**First, a thank-you that matters more than it sounds.** Publishing `lite_node` as full source
changed how we work. We had six long-standing "chain blockers" we were carrying as open
questions. Reading the node retired all six — and four of them turned out to be *our own bugs*,
not chain limitations. We'd been asking you about things we could have answered ourselves. The
list below is much shorter than the one we were about to post, and that is entirely down to the
source drop.

## What's working for us on devnet

- **The canonical tx signing preimage.** `transaction.ml:309-326`, cross-checked against the
  verifier at `tx_view.ml:1135-1148` and against `webcli/lib/tx_builder.hpp`. Every
  `invalid signature` (code 101) we ever hit was our own field-order/float-rendering drift. Ported
  it byte-for-byte; it works.
- **Circles execute.** Our "bytecode not found" was us calling `contract_call` — the wrong rail.
  Circle code lives under `["circles";id;"program"]` and runs via `circle_call`/`circle_view`.
- **Storage was never 4 KiB.** The VM cap is 4 MiB and reverts rather than truncating; 4096 is a
  read-side display slice with an explicit `truncated` flag, and `octra_contractStorage [.., "full"]`
  returns everything. Confirmed by writing 8,000 bytes and reading them back.
- **`fhe_load_pk` works** — and never didn't. We'd been probing it with *view* calls, which return
  a bare `execution reverted` and carry no reason. Probed as a live tx, the receipt says
  `fhe pubkey not available: <addr>`, which is the "no registered key" gate, not a capability gate.
  Three months of "the bridge is unwired" was a methodology error on our side.
- **The observability added since May is excellent.** `contract_receipt` giving
  `{success, events, effort, error}`, and `octra_transaction` returning `rejected` with our own
  `require()` reason verbatim, let us delete a pile of string-matched error heuristics.
- **`octra_pvacMigrationStatus`** telling us `migration_route = direct_key_switch` for our
  historical key answered a question we were about to ask. More RPCs that state the remedy rather
  than just the state, please — that one saved us a round trip entirely.
- **A private single-node network for CI.** Unsetting `OCTRA_CONSENSUS_MODE` gives Single mode with
  10s epochs and genesis minted across `OCTRA_VALIDATORS`. We now run a real node in Docker with
  deterministic pre-funded keys, and our AML executes under test against the real VM for the first
  time.

## What's still genuinely open

These are the ones we could not answer from source.

1. **Devnet binary provenance.** Is the running devnet exactly the published
   `source_commit`? Everything we verified against source presumes it, and we have no way to
   confirm the deployed binary matches the tree we read.

2. **Native relay payment — design intent.** `circle_outbox_open` / `relay_claim` /
   `ingress_commit` are, as we read them, delivery *attestation*: the only crypto check is an
   ed25519 signature over the claim subject, `fee_budget` is inert, and no value moves. We had
   assumed a paid-relay rail and built our own AML HTLC instead. **Is a value-bearing settlement
   layer planned for the outbox rail, or is attestation-only the long-term design?** This decides
   whether our HTLC eventually composes with something native or stays the rail permanently. It's
   our single most consequential open question.

3. **`fhe_verify_*` being view-only.** It can never gate a `settle_confirm`/`claim_earnings`
   mutation, which rules out confidential settlement as we'd designed it. Is that a deliberate
   permanent boundary, or a staging decision? We've moved to a sha256 hash chain either way; we'd
   just like to know whether to stop planning around it.

4. **`key_switch` for historical keys.** Our May-registered PVAC key reports
   `key_class = historical`, `canonical_binding = false`, `can_key_switch = true`,
   `reason = "encrypted balance is empty"`. Is `key_switch` itself epoch-gated, and is direct
   key_switch the intended path for an empty-balance historical key — or should we wait for the
   1,330,000 migration machinery?

5. **Sealed-asset write observability.** Receipts exist for deploy / `circle_save` / `program_save`.
   Is there any receipt or event for `CircleAssetPut`, or is polling the only auditor signal?

6. **Effort/gas activation.** Is OU metering beyond the current floors planned to activate on
   devnet? Our keeper daemons (claim/refund/sweep) assume near-zero-cost polling, and we'd rather
   redesign that economics now than discover it at activation.

7. **Mainnet RPC body cap.** Devnet's is 5,065,536 bytes. Does production match? Multi-MB PVAC
   pubkeys sit close enough to that line to matter.

## One piece of feedback

The mandatory epoch-gated release cadence is the right call for consensus safety, but it makes any
captured test fixture perishable — ours silently rotted between May and August. We've since wired
a canary that verifies the signed release JSON and alerts on `consensus_rules_id` changes. If
there's ever an "expected RPC response shapes for release N" artifact, or a changelog entry
flagging response-shape changes specifically, that'd save every downstream client the same
discovery.

Happy to share our devnet probe script — it settles eight chain-behaviour questions in one run and
might be useful to other teams building against devnet.

Thanks again for opening the node. It changed the shape of this project.
