----------------------------- MODULE RelaySettlement -----------------------------
(*****************************************************************************)
(* Protocol-level state-machine spec for the v4 relay-settlement money loop  *)
(* (`program/main-v4.aml`: arm_relay / relay_claim / relay_refund /          *)
(* relay_sweep) and the three off-chain autonomous actors that drive it      *)
(* (Step 6 claimer, Step 8a refund watcher, Step 8b sweeper).                *)
(*                                                                           *)
(* It machine-checks the safety argument that was previously only stated on  *)
(* paper: a relay session's escrow is drained AT MOST ONCE, and the operator *)
(* claim and the funder refund/sweep are NEVER both applied (claim-XOR-      *)
(* refund), and the two actors' off-chain submission windows do not overlap  *)
(* (the I3 quiet zone).                                                       *)
(*                                                                           *)
(* Why in-flight txs, not atomic transitions: the interesting case is a      *)
(* claim SUBMITTED inside its window (epoch + Kc <= D) whose tx only CONFIRMS *)
(* after the epoch has advanced past the deadline. The on-chain guard is     *)
(* re-checked at confirm time, so such a claim REVERTS -- and a refund can    *)
(* then drain the escrow, with no double-settle. Modeling submit / confirm / *)
(* revert as separate steps, with Tick interleaved, exercises exactly that    *)
(* race. The single on-chain invariant that makes it safe is that every      *)
(* terminal transition requires status = ARMED and flips it, so the second   *)
(* attempt always fails.                                                      *)
(*                                                                           *)
(* Abstraction: one session, starting already ARMED (open+arm elided); a     *)
(* single global epoch clock; value is the whole Deposit (fee/net/bounty     *)
(* splits are irrelevant to the drained-at-most-once property). Sweep sets    *)
(* the same terminal (funder-returned) state as refund, so it counts on the  *)
(* refund side of the XOR.                                                    *)
(*                                                                           *)
(* Invariants checked (see .cfg):                                            *)
(*   TypeOK                                                                   *)
(*   NoDoubleSettle    -- claim and refund/sweep never both applied           *)
(*   DrainAtMostOnce   -- at most one terminal on-chain transition            *)
(*   Conservation      -- payout = Deposit iff terminal, else 0               *)
(*   OnChainWindowsXOR -- claim and refund on-chain guards are disjoint        *)
(*   QuietZone         -- claimer and refund-watcher submit windows disjoint   *)
(*****************************************************************************)

EXTENDS Naturals

CONSTANTS
    Deposit,     \* escrowed deposit, >= 1
    D,           \* the relay deadline epoch (arm_relay set it)
    SweepGrace,  \* extra epochs past D before relay_sweep is on-chain-valid
    Kc,          \* operator claimer off-chain margin (submit while epoch + Kc <= D)
    Kr,          \* funder refund off-chain margin  (submit while epoch >= D + Kr)
    Ks,          \* keeper sweep off-chain margin    (submit while epoch >= D + SweepGrace + Ks)
    MaxEpoch     \* clock bound so TLC's state space is finite

VARIABLES
    status,         \* "ARMED" | "CLAIMED" | "REFUNDED"
    epoch,          \* current chain epoch, 0..MaxEpoch
    payout,         \* value moved out of escrow so far (0 or Deposit)
    claimed,        \* TRUE once relay_claim applied  (operator paid)
    refunded,       \* TRUE once relay_refund/relay_sweep applied (funder returned)
    terminalCount,  \* number of terminal on-chain transitions applied
    claimPending,   \* an operator claim tx is in flight (submitted, unconfirmed)
    refundPending,  \* a funder refund tx is in flight
    sweepPending    \* a keeper sweep tx is in flight

vars == << status, epoch, payout, claimed, refunded, terminalCount,
           claimPending, refundPending, sweepPending >>

Init ==
    /\ status = "ARMED"
    /\ epoch = 0
    /\ payout = 0
    /\ claimed = FALSE
    /\ refunded = FALSE
    /\ terminalCount = 0
    /\ claimPending = FALSE
    /\ refundPending = FALSE
    /\ sweepPending = FALSE

(* --- On-chain guards the AML relay_* entrypoints enforce at confirm time. *)
ClaimOnChainOK  == status = "ARMED" /\ epoch < D
RefundOnChainOK == status = "ARMED" /\ epoch >= D
SweepOnChainOK  == status = "ARMED" /\ epoch >= D + SweepGrace

(* --- Off-chain gates the autonomous actors apply when SUBMITTING a tx. *)
ClaimSubmitOK  == status = "ARMED" /\ epoch + Kc <= D            /\ ~claimPending
RefundSubmitOK == status = "ARMED" /\ epoch >= D + Kr            /\ ~refundPending
SweepSubmitOK  == status = "ARMED" /\ epoch >= D + SweepGrace + Ks /\ ~sweepPending

Tick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ UNCHANGED << status, payout, claimed, refunded, terminalCount,
                    claimPending, refundPending, sweepPending >>

ClaimSubmit ==
    /\ ClaimSubmitOK
    /\ claimPending' = TRUE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    refundPending, sweepPending >>

ClaimConfirm ==   \* the in-flight claim mines; guard re-checked NOW
    /\ claimPending
    /\ ClaimOnChainOK
    /\ status' = "CLAIMED"
    /\ claimed' = TRUE
    /\ payout' = Deposit
    /\ terminalCount' = terminalCount + 1
    /\ claimPending' = FALSE
    /\ UNCHANGED << epoch, refunded, refundPending, sweepPending >>

ClaimRevert ==    \* the in-flight claim mines but the guard fails -> reverts
    /\ claimPending
    /\ ~ClaimOnChainOK
    /\ claimPending' = FALSE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    refundPending, sweepPending >>

RefundSubmit ==
    /\ RefundSubmitOK
    /\ refundPending' = TRUE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    claimPending, sweepPending >>

RefundConfirm ==
    /\ refundPending
    /\ RefundOnChainOK
    /\ status' = "REFUNDED"
    /\ refunded' = TRUE
    /\ payout' = Deposit
    /\ terminalCount' = terminalCount + 1
    /\ refundPending' = FALSE
    /\ UNCHANGED << epoch, claimed, claimPending, sweepPending >>

RefundRevert ==
    /\ refundPending
    /\ ~RefundOnChainOK
    /\ refundPending' = FALSE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    claimPending, sweepPending >>

SweepSubmit ==
    /\ SweepSubmitOK
    /\ sweepPending' = TRUE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    claimPending, refundPending >>

SweepConfirm ==   \* sweep also returns the deposit to the funder
    /\ sweepPending
    /\ SweepOnChainOK
    /\ status' = "REFUNDED"
    /\ refunded' = TRUE
    /\ payout' = Deposit
    /\ terminalCount' = terminalCount + 1
    /\ sweepPending' = FALSE
    /\ UNCHANGED << epoch, claimed, claimPending, refundPending >>

SweepRevert ==
    /\ sweepPending
    /\ ~SweepOnChainOK
    /\ sweepPending' = FALSE
    /\ UNCHANGED << status, epoch, payout, claimed, refunded, terminalCount,
                    claimPending, refundPending >>

Next ==
    \/ Tick
    \/ ClaimSubmit  \/ ClaimConfirm  \/ ClaimRevert
    \/ RefundSubmit \/ RefundConfirm \/ RefundRevert
    \/ SweepSubmit  \/ SweepConfirm  \/ SweepRevert

Spec == Init /\ [][Next]_vars

(*************************** Invariants ***************************)

TypeOK ==
    /\ status \in {"ARMED", "CLAIMED", "REFUNDED"}
    /\ epoch \in 0..MaxEpoch
    /\ payout \in {0, Deposit}
    /\ claimed \in BOOLEAN
    /\ refunded \in BOOLEAN
    /\ terminalCount \in 0..3
    /\ claimPending \in BOOLEAN
    /\ refundPending \in BOOLEAN
    /\ sweepPending \in BOOLEAN

\* Money-safety: the operator claim (operator paid) and the funder refund/sweep
\* (funder returned) are NEVER both applied. This is the claim-XOR-refund
\* guarantee -- the escrow is never drained to both parties.
NoDoubleSettle == ~(claimed /\ refunded)

\* The escrow is drained by at most one terminal on-chain transition.
DrainAtMostOnce == terminalCount <= 1

\* Value conservation: escrow paid out exactly when (and only when) terminal.
Conservation == (status \in {"CLAIMED", "REFUNDED"}) <=> (payout = Deposit)

\* The on-chain guards for claim (epoch < D) and refund (epoch >= D) are disjoint
\* at every reachable state -- the hard on-chain XOR at the deadline boundary.
OnChainWindowsXOR == ~(ClaimOnChainOK /\ RefundOnChainOK)

\* I3 quiet zone: the operator's claim-submit window and the funder's
\* refund-submit window never overlap. Holds iff Kc + Kr > 0 (positive margins);
\* a config with Kc = Kr = 0 makes this FALSE at epoch = D (see RelaySettlement.cfg).
QuietZone == ~(ClaimSubmitOK /\ RefundSubmitOK)

=============================================================================
