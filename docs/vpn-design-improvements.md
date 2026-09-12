# Improving the VPN design — what this session exposed

> 2026-09-12. Not a roadmap for new products; a list of places where the *current*
> design is weaker than its substrate, found by running the real thing against a real
> node. Each item names the evidence, the fix, and what it costs. Grounded; the one
> speculative item is labeled.

## 1. The two planes never met — and the AML already has the join

**Evidence.** `v4-relay-e2e.sh` contains the string "tailscale" zero times: the money loop
rides the node's own boringtun tunnel and `POST /session/:id/receipt`. Meanwhile stock
`tailscale up` joins the mesh (interop exits 0) with no wallet, no session, no receipts.
So today a *paying* client must run our client, and the Tailscale-compatible mesh — the
thing that makes this a product anyone can use — is unmetered. That is the largest gap in
the design, and it is not a chain limitation.

**The join is already on chain.** `main-v4.aml` has `tailnet_treasury`,
`deposit_to_tailnet(tailnet_id)` (line 533) and `open_session_from_treasury(tailnet_id,
circle, max_pay)` (line 629). A tailnet **owner** can fund a treasury and sessions can be
opened from it *on a member's behalf*. That is the mechanism for stock clients:

1. A stock client joins the tailnet (works today).
2. When it is mapped to an exit node, the **control plane** opens a session from the
   tailnet treasury for that (member, exit) pair — the owner pays, the member has no wallet.
3. The exit meters the member's actual WireGuard peer counters (not a parallel tunnel),
   signs receipts against that session, and the existing HTLC settles.

**Cost.** Medium. The control plane already knows registrations and map assignments; it
needs a "session per (member, exit) mapping" lifecycle and a treasury-funded opener in the
node. Metering moves from the tunnel session tracker to per-peer WG counters. No new AML.

**What it changes.** The product becomes "an operator runs a tailnet, funds it, and
anyone with stock Tailscale can use it" — with settlement, disputes, and slashing intact.
This is the single improvement that turns two working halves into one product.

## 2. One settlement rail, not two

**Evidence.** Two-tx `settle_claim → settle_confirm` and the v4 relay HTLC both exist and
both are wired (`attestation.rs:421-459` still drives v1.1-style `settle_claim`). The v4
spec already says the HTLC is settlement-of-record; the source audit made it *permanent*
(the native rail has no hashlock and moves no money).

**Fix.** Flip `[control.relay]` / `[v3.relay]` default-on once Step 9's proofs land, then
retire the two-tx driver from the node. Fewer keepers, fewer invariants, one thing to audit.
Cost: small, mostly deletion — after the proofs.

## 3. Registration and identity must survive a restart — DONE 2026-09-12

**Evidence.** `WireStateBuilder::build` hardcodes `registration_store: None`
(`wire_state.rs:105`) and `hub/spawn.rs` builds `MachineRegistry::new()` inline: a node
restart wipes node identity and tailnet IPs. A shakeout tolerates it; an operator paging
at 3am does not.

**Done.** `PersistentMachineAdmin` over `<wire state dir>/machines.sqlite`, hydrated at boot, in
both the Hub and `mesh serve`. Proven by `run-interop.sh` with `INTEROP_RESTART=1`: the restarted
control plane logs `hydrated … nodes=2`, peers keep their IPs, ping succeeds with no re-`up`.

## 4. Enforce the policy we already anchor

**Evidence.** An empty PolicyStore falls back to `allow_all_packet_filter`
(`hub/spawn.rs:191`, `cli/mesh.rs:357`). The tailnet's `members_root` / `policy.json` are
anchored on chain and sealed in the owner's circle — and not enforced on the wire.

**Fix.** Render the anchored policy into the PacketFilter the map response already carries.
Membership becomes a chain fact the mesh obeys, not a config file. Cost: medium; the
headscale-rs policy machinery exists, it needs the chain-backed source.

## 5. Chain-attested exit assignment, for free

**Evidence.** The native outbox rail (`circle_outbox_open` / `relay_claim` /
`ingress_commit`) is delivery *attestation* with owner-controlled allowlists
(`epoch_exec.ml:1647-1691`). We correctly declined to use it for money.

**Fix.** Use it for what it is: when an exit is assigned a session, open an intent; the
exit claims it; delivery commits. Auditors get *who served what* on chain, keyed to the
HTLC by `intent_id`, and operators get chain-enforced relay allowlists. Cost: the additive
work already scoped for relays. Not required for v1; high value for disputes.

## 6. Retention shapes the audit design

**Evidence.** `keep_epochs = 8192` ≈ 22.75h; a 26-day-old receipt is
`112 receipt not found`. The operator audit CLI (P0 #4) does not exist yet.

**Fix.** Make the off-chain evidence path first-class: the receipt journal and vault are
the durable record; the chain anchors settlement hashes. The audit CLI diffs journal vs
chain *within* the window and anchors anything older as a sealed asset (the PVAC-blob
indirection, reused). Cost: this is P0 #4 done right rather than done twice.

## 7. Stop reading the storage envelope — everywhere

**Evidence.** The session-admission verifier scraped it and returned 401 in production on
sequence 12 (fixed today). Two legacy scrapes remain (`chain.rs read_endpoint_record`,
client `discover_v2`), and the map-key scheme changed under us.

**Fix.** A lint-level rule: `contract_call` results are `result` only; storage goes through
`octra_contractStorage`. Retire the two legacy readers with the v1.1/v2 paths. Cost: small.

## 8. Commit to one DERP — DONE 2026-09-12: native Rust DERP, Go derper deleted

**Evidence.** Interop passes with a vendored Go `derper` sidecar; the native Rust DERP
(3,013 lines) has never been run against a real client.

**Done.** `mesh serve --serve-derp` serves the Rust DERP on `/derp` of the HTTPS listener with a
self DERP map (`tsi-mesh-control:443`, same cert the peers trust). The interop harness passes
on it (exit 0: preauth, `tailscale up`, convergence, ping) and `Dockerfile.derper`,
`derp-map.json` and the derp-certs step are gone.

## 9. Keepers should follow epochs, not poll — DONE 2026-09-12 (node keepers)

**Evidence.** Claimer, sweeper, and refund watcher poll views on timers; effort metering
beyond floors may activate (open question to the core team). Retention is per-epoch;
`octra_epochTags` and the new gRPC `Epoch` read exist.

**Done for the node keepers.** The relay claimer and sweeper read `current_epoch()` each timer
tick and scan only when it advanced; a failed epoch read scans anyway rather than stalling.
`ClaimerBackend` gained `current_epoch()`. The client's refund replay runs at client start
(`runner.rs`), not on a timer, so there was nothing to gate there.

## 10. Finish hidden-exit before calling it private *(the speculative one)*

**Evidence.** The onion path seals with nonce=0 and `build_onion` has no production caller
(memory: onion zero-nonce landmine). Circle-resident hidden-exit v2 is designed, not wired.
Today's privacy claim is "the exit sees a mesh identity" — true and valuable, but not
onion privacy.

**Fix.** Per-packet nonces first, then wire the relay hop through the same session/receipt
model (relays are just metered peers). This is the largest item and the only one that
changes the threat model; sequence it after 1–4.

---

**Order that pays off soonest:** 7 (already half done) → 3 → 1 → 2 → 4 → 9 → 6 → 8 → 5 → 10.
Items 1–4 are the ones that make the current VPN a product a stranger can pay for; 5–9
make it operable; 10 makes it private in the strong sense.
