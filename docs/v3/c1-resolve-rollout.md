# v3.2 — `settle_resolve` rollout runbook (C-1 fix)

> Audit reference: `docs/audit/2026-05-20-deep-security-audit.md` §C-1
> ("settle_confirm dispute is a permanent stuck-funds state").
> Sibling AML: `program/main-v3-c1-fix.aml`. Companion proofs:
> `proofs/lean/OctraVPN_V3/Invariants.lean` (`settle_resolve_*`).

## Why this fix matters

In `program/main-v3.aml:549-601` (the deployed v3 contract), when
the opener and operator disagree on `bytes_used`, `settle_confirm`
takes the dispute path: it writes `client_confirm_set = 1`, emits
`SettleDispute`, and returns `false`. The session stays
`SESSION_OPEN` forever — there is no follow-up entrypoint to:

  1. transition the session out of OPEN,
  2. release the deposit,
  3. arbitrate the discrepancy.

`claim_no_show` (line 603) requires `operator_claim_set == 0`, so
it cannot rescue a disputed session either. The result: ANY pair
of parties that disagree on a single byte-count can permanently
lock the session deposit, the protocol fee, and the operator's
earnings — for the cost of one chain tx.

The deep-security audit veto-blocked mainnet on this finding alone.

## The fix (v3.2)

`program/main-v3-c1-fix.aml` is a **sibling AML** — a new program
deployed at a new address. It is NOT a hot-patch of the existing
v3 contract. The shape mirrors the swap-ready-hfhe branch pattern:
the audit finding is fixed in a forward-compatible v3.2 program,
and we run a coordinated cohort migration from v3.1 to v3.2.

The contract change adds:

  - `SESSION_DISPUTED = 3` session status (new terminal-pending).
  - `session_dispute_deadline: map[int]int` recording the in-grace
    resolution window.
  - `dispute_grace_epochs` governance param (default 7; bounded
    `1 ≤ x ≤ session_grace_epochs * 2`).
  - Two new entrypoints:
    - `settle_resolve(session_id, accepted_bytes_used, blinding)`
      — either party picks one of the two recorded claims; the
      losing side is half-slashed (4500 bps on default
      `slash_burn_bps = 9000`).
    - `claim_disputed_no_show(session_id)` — any third party may
      auto-resolve after the grace window expires; defaults to
      the CLIENT's claim with no slash. A small sweep bounty
      pays the third party for the bookkeeping tx.

`settle_confirm` is modified to flip the session to
`SESSION_DISPUTED` (instead of leaving it `SESSION_OPEN`) when the
claims disagree.

## Why 7 epochs?

Octra devnet runs ~10-minute slots, ~6 slots/epoch — roughly 1
wall-clock hour per epoch. Seven epochs ≈ **7 hours**:

  - Long enough that an on-call operator can wake up, see a
    `SettleDispute` event in their dashboard, dig out a signed
    receipt, and call `settle_resolve` with their preferred
    accepted value. (4 hours of sleep + 1 hour of paging slack +
    2 hours of investigation.)
  - Short enough that a chronically-unresponsive operator (sloppy
    deployment, dead daemon) does not strand a client's deposit
    for days. After 7 hours the client (or any third party with
    spare gas) calls `claim_disputed_no_show` and the deposit
    flows back to the tailnet treasury with no operator earnings.
  - Well below `session_grace_epochs * sweep_grace_multiplier`
    (the permissionless sweep window for OPEN sessions) so the
    dispute resolution NEVER races a permissionless sweep — the
    two timelines are disjoint by construction.

Mainnet block-time may differ (target ~12s per slot). With
`set_params`, the chain owner can re-tune to maintain the ~7-hour
wall-clock window — e.g. `dispute_grace_epochs = 21` if mainnet
epoch is 20 minutes. The proof gap is in `set_params`; the contract
enforces the `1 ≤ x ≤ session_grace_epochs * 2` band so a clueless
owner cannot accidentally set a zero grace window.

## Slash rate justification

`slash_burn_bps / 2` — half of the double-sign slash. The
rationale:

  - `slash_double_sign` (the existing slash entrypoint) requires
    TWO signed receipts at distinct `bytes_used` for the same
    `(session_id, seq)`. That is a cryptographically-provable
    equivocation: an honest operator could not generate it.
  - A dispute is fundamentally ambiguous: both sides have a
    signed (off-chain) receipt; we just don't know whose
    arithmetic is right, and neither party has produced two
    signed receipts. The slash penalty should therefore be
    proportionally lower.
  - Half (4500 bps on the default 9000) is the smallest "round"
    fraction that still bites — it is enough that an operator
    who routinely loses disputes (i.e. is regularly lying about
    `bytes_used`) bleeds bond, but it does not catastrophically
    burn the bond on a single ambiguous dispute.

The chosen losing side is the one whose claimed value was NOT
picked. The winning party absorbs the resolver tx-fee, which is
already a small disincentive against frivolous disputes.

For the client side (no bond), the half-slash is taken off the
deposit itself — `slash_burn_bps / 2` bps of the deposit goes to
the program treasury rather than back to the tailnet. The
operator's earnings credit is unaffected; only the refund flow
is diverted.

## Cohort + monitoring during rollout

This is a NEW program address. Operators have to:

  1. Bond on the v3.2 program (`register_circle` + bond value).
  2. Tailnet owners create a fresh tailnet on v3.2
     (`create_tailnet`).
  3. Tailnet members re-onboard against the new tailnet anchor
     (publish a new `oct://` URL with the v3.2 program addr).

We roll out in three cohorts to avoid a flag day:

  - **Cohort A** (week 1, devnet only): the operator team's own
    nodes. Run both v3 and v3.2 in parallel; verify the dispute
    drill in `program/test/main-v3-c1-fix-test.am` passes end-
    to-end on devnet. Monitor `SettleDispute`,
    `SettleResolved`, and `DisputeNoShowResolved` event volumes;
    confirm `session_dispute_deadline` is set + cleared as
    expected.
  - **Cohort B** (week 2, devnet + canary mainnet): one or two
    third-party operators opt in. Old tailnets stay on v3; new
    ones are created on v3.2. Watch for: bond drainage from
    dispute slashes (should be ~0 if both parties are honest),
    grace-window expirations leading to `claim_disputed_no_show`
    (a healthy signal of the fallback path working).
  - **Cohort C** (week 3+): general migration. Tailnets retire
    on v3 (`retire_tailnet`) and recreate on v3.2. Treasuries
    migrate via `withdraw_tailnet_treasury` followed by a fresh
    `create_tailnet`. Operators bond on v3.2 and let their v3
    bonds finalise out naturally (no equivocation, no slash).

The cohort timeline mirrors `docs/v3/hfhe-swap-rollout.md` — refer
to that document for the canonical migration phasing and the
treasury-migration checklist. The HFHE rollout pattern is the
proven template; this is a smaller swap (one new entrypoint, no
cryptographic upgrade), so the cohort A → B → C cadence can be
compressed proportionally.

## Treasury migration

Treasury safety is THE delicate step. On v3:

  - Each tailnet treasury holds OctRaw the chain owns on behalf of
    the tailnet owner. The owner can only withdraw via
    `withdraw_tailnet_treasury` (gated on `retired = true`).
  - Pending session deposits are NOT in the tailnet treasury;
    they are escrowed in the session record. Migrate AFTER all
    sessions are SETTLED or REFUNDED — do not migrate with
    pending OPEN sessions, or the v3 tailnet owner will retire a
    tailnet that owes the operator earnings.

Operator earnings on v3 stay in `circle_earnings_total` until
`claim_earnings` is called. Operators MUST drain their v3
earnings before retiring the v3 circle, or those earnings are
stranded (slashed-state earnings are also unreachable).

The sequence per tailnet:

  1. Owner stops opening new sessions on v3.
  2. Wait for all OPEN sessions to settle (or call
     `sweep_expired_session` on anything past the extended grace).
  3. Owner calls `claim_earnings` on operator circles.
  4. Owner calls `retire_tailnet(tid)` on v3.
  5. Owner calls `withdraw_tailnet_treasury(tid, full_balance)` on
     v3 — pays to a wallet controlled by the same owner.
  6. Owner calls `create_tailnet(value=full_balance, members_root)`
     on v3.2 — creates a new tid on v3.2.
  7. Owner republishes the tailnet's `oct://` portal URL with the
     v3.2 program addr (clients pick up the new addr on next
     refresh).

## Monitoring during rollout

Key metrics to watch (per program-addr):

  - `SettleDispute` event rate — baseline expected ~0 on a
    healthy network; spikes indicate an operator with broken
    accounting OR a client with broken accounting. Cross-reference
    by `circle` and `opener`.
  - `SettleResolved` events — slash amount distribution. A
    bimodal "always 0 / always max" distribution flags a stuck
    helper or a misconfigured `dispute_grace_epochs`.
  - `DisputeNoShowResolved` events — every one of these is a sign
    of an unresponsive operator. Page the operator if it's an
    in-house circle.
  - `session_dispute_deadline` aggregate: count of disputed
    sessions with a deadline in the future. Should be small (<10
    in steady state on devnet); if it grows monotonically, the
    resolve path is broken.

## Rust client work (follow-up)

This v3.2 change is AML-only. The Rust client work to surface the
new entrypoints is a separate, non-blocking PR:

  - `octravpn-node v3 settle-resolve <session-id> <bytes>` — calls
    `settle_resolve` with the operator's preferred accepted value.
  - `octravpn-node v3 dispute-no-show <session-id>` — calls
    `claim_disputed_no_show` as a third-party sweeper.
  - The settler loop (`crates/octravpn-client/src/settler.rs`) needs
    to react to `SettleDispute` events with a configurable
    auto-resolve policy ("always accept my own value", "always
    accept counterparty's value", "page operator and wait").

The AML deployment can land first; the Rust client gets the new
subcommands in the follow-up. While the client is in flight, the
sweep path (`claim_disputed_no_show`) is reachable via any AML
RPC tool — the deposit is not actually stuck even during the
gap, just slower to recover.

## Verification checklist before flipping cohort

  - [ ] `program/main-v3-c1-fix.aml` deployed at a new program addr
        on devnet.
  - [ ] All 16+ scenarios in `program/test/main-v3-c1-fix-test.am`
        pass on devnet.
  - [ ] `proofs/lean/OctraVPN_V3/Invariants.lean` builds clean
        with the 4 new `settle_resolve_*` theorems.
  - [ ] Monitoring dashboards updated to track `SettleDispute`,
        `SettleResolved`, `DisputeNoShowResolved` event streams.
  - [ ] Operator runbook (this doc) circulated to cohort A.
  - [ ] HFHE-swap rollout (`docs/v3/hfhe-swap-rollout.md`) is NOT
        active simultaneously — coordinate on `swap-ready-hfhe`
        and `swap-ready-c1-fix` cohort calendars so no operator
        re-registers twice in one week.
