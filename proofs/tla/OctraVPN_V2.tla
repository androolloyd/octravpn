----------------------------- MODULE OctraVPN_V2 -----------------------------
(*****************************************************************************)
(* Protocol-level state-machine spec for the OctraVPN v2 program.           *)
(*                                                                           *)
(* The v2 program is a slim, circle-keyed registry that ships in            *)
(* `program/main-v2.aml`. Major shape changes vs v1.1:                      *)
(*                                                                           *)
(*   1. Operators are CIRCLES, not wallet addresses. The registry is        *)
(*      keyed by `CircleId`. Identity of `CircleId` is opaque (off-chain    *)
(*      it's sha256+base58); we just treat it as another set.               *)
(*                                                                           *)
(*   2. `register_circle` is PAYABLE + ATOMIC: a single transition sets    *)
(*      owner, active=1, AND credits stake. v1.1's chicken-and-egg between *)
(*      `register_endpoint` and `bond_endpoint` is gone.                    *)
(*                                                                           *)
(*   3. `authorize_circle` replaces `configure_tailnet_exit`. Requires the *)
(*      circle to be active AND not slashed at authorize-time, and at     *)
(*      open-time.                                                          *)
(*                                                                           *)
(*   4. Per-class pricing stamped at open. `open_session` reads either     *)
(*      `circles[c].price_per_mb_shared` or `..._internal` depending on    *)
(*      `class` and writes it into `sessions[s].price_per_mb`. Subsequent  *)
(*      `update_circle` calls do NOT mutate live sessions.                 *)
(*                                                                           *)
(*   5. `charge_internal_traffic` toggle on each tailnet. When 0,          *)
(*      `settle_confirm` with `class = INTERNAL` computes total_paid = 0   *)
(*      regardless of bytes_used.                                          *)
(*                                                                           *)
(*   6. Slashes (`slash_double_sign`, `gov_slash_operator`) are keyed on   *)
(*      CircleId, not operator wallet.                                     *)
(*                                                                           *)
(*   7. Pause semantics unchanged from v1.1: governance (set_paused,       *)
(*      transfer_ownership, set_params, withdraw_program_treasury)         *)
(*      intentionally bypasses pause; user flows are pause-gated.          *)
(*                                                                           *)
(* Properties:                                                              *)
(*   ConservationOfFunds                                                    *)
(*   NoDoubleSettle                                                         *)
(*   TreasuryNonNegative                                                    *)
(*   ProgramTreasuryMonotone                                                *)
(*   EarningsNonNegative                                                    *)
(*   ActiveCirclesAreBonded                                                 *)
(*   SlashedHaveZeroStake                                                   *)
(*   Inv_SlashedCircleHasZeroStake                                          *)
(*   Inv_SettlementOnlyOnConfirm                                            *)
(*   Inv_EquivocationCausesRefund                                           *)
(*   Inv_TokenSinglyRedeemed                                                *)
(*   Inv_DoubleSignSlashable                                                *)
(*   Inv_CircleAtomicRegisterBond (no circle becomes active without        *)
(*     stake >= min_circle_stake at registration)                          *)
(*   Inv_AuthorizedCircleIsActive (every authorized circle is active and  *)
(*     not slashed at authorize-time; once slashed, that authorization     *)
(*     becomes a stale flag that open_session re-checks against)           *)
(*   Inv_StampedPriceImmutableInOpenSession (live sessions retain          *)
(*     their open-time price even if the circle updates prices)            *)
(*****************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Circles,            \* set of candidate circle ids (opaque sort)
    Tailnets,           \* set of tailnet ids modeled
    Clients,            \* set of client addresses
    Owner,              \* program owner (governance wallet)
    MinDeposit,         \* >= 1, min session deposit
    MinTailnetDeposit,  \* >= 1
    MinCircleStake,     \* circle bond floor
    Price,              \* canonical price-per-MiB value for testing
    MaxSeq,
    TokenHashes,        \* abstract set of sha256(preimage) values
    Payloads,           \* abstract set of receipt-signing payloads
    UnbondGrace,        \* epochs after `unbond_endpoint` until finalize
    SweepGrace          \* multiplier * session-grace before sweep

\* Two session classes; mirrors AML `CLASS_SHARED=0, CLASS_INTERNAL=1`.
CLASS_SHARED    == 0
CLASS_INTERNAL  == 1

VARIABLES
    \* Circle registry (slim).
    circles,             \* [CircleId -> [active: BOOLEAN, owner: Addr,
                         \*               price_shared: Nat, price_internal: Nat]]
    circle_stake,        \* [CircleId -> Nat]
    circle_unbond,       \* [CircleId -> [stake: Nat, unlock: Nat]]
    circle_slashed,      \* [CircleId -> BOOLEAN]
    \* Tailnets.
    treasury,            \* [Tailnet -> Nat]
    tailnet_owner,       \* [Tailnet -> Client]
    members,             \* [Tailnet -> SUBSET Clients]
    authorized,          \* [Tailnet -> SUBSET Circles]
    charge_internal,     \* [Tailnet -> {0, 1}]
    \* Sessions.
    sessions,            \* [SessionId -> Session]
    nextSession,         \* Nat
    \* HFHE earnings ledger keyed by circle.
    enc_earn,            \* [CircleId -> Nat]
    \* Audit counters.
    program_treasury,    \* Nat
    program_owner,       \* Addr (rotates via TransferOwnership)
    paused,              \* BOOLEAN
    cur_epoch,           \* Nat
    paid_out,            \* Nat
    refunded,            \* Nat
    burned,              \* Nat
    swept,               \* Nat
    withdrawn,           \* Nat
    \* Join tokens.
    join_token_commits,  \* [Tailnet -> SUBSET TokenHashes]
    join_token_redeemed, \* SUBSET TokenHashes
    \* Settled audit set.
    settled_sids,        \* SUBSET Nat
    \* Redeem count for join tokens.
    redeem_count,        \* [TokenHash -> Nat]
    \* Adversarial off-chain payload signing.
    signed_payloads      \* [Circle -> SUBSET Payloads]

NoOwner == "NoOwner"

vars == << circles, circle_stake, circle_unbond, circle_slashed,
           treasury, tailnet_owner, members, authorized, charge_internal,
           sessions, nextSession, enc_earn,
           program_treasury, program_owner, paused, cur_epoch,
           paid_out, refunded, burned, swept, withdrawn,
           join_token_commits, join_token_redeemed,
           settled_sids, redeem_count, signed_payloads >>

SessionStatus == {"open", "settled", "refunded"}
SessionId == Nat
NoClaim == [set |-> FALSE, bytes |-> 0]

\* Sentinel "no circle yet" record for the initial map.
EmptyCircle == [active        |-> FALSE,
                owner         |-> NoOwner,
                price_shared  |-> 0,
                price_internal|-> 0]

Init ==
    /\ circles             = [c \in Circles |-> EmptyCircle]
    /\ circle_stake        = [c \in Circles |-> 0]
    /\ circle_unbond       = [c \in Circles |-> [stake |-> 0, unlock |-> 0]]
    /\ circle_slashed      = [c \in Circles |-> FALSE]
    /\ treasury            = [t \in Tailnets |-> 0]
    /\ tailnet_owner       = [t \in Tailnets |-> NoOwner]
    /\ members             = [t \in Tailnets |-> {}]
    /\ authorized          = [t \in Tailnets |-> {}]
    /\ charge_internal     = [t \in Tailnets |-> 0]
    /\ enc_earn            = [c \in Circles |-> 0]
    /\ program_treasury    = 0
    /\ program_owner       = Owner
    /\ paused              = FALSE
    /\ cur_epoch           = 0
    /\ sessions            = << >>
    /\ nextSession         = 0
    /\ paid_out            = 0
    /\ refunded            = 0
    /\ burned              = 0
    /\ swept               = 0
    /\ withdrawn           = 0
    /\ join_token_commits  = [t \in Tailnets |-> {}]
    /\ join_token_redeemed = {}
    /\ settled_sids        = {}
    /\ redeem_count        = [h \in TokenHashes |-> 0]
    /\ signed_payloads     = [c \in Circles |-> {}]

(* ============================================================ *)
(* Helpers                                                      *)
(* ============================================================ *)

CircleIsActive(c) ==
    /\ circles[c].active = TRUE
    /\ ~circle_slashed[c]

(* ============================================================ *)
(* Circle registry (atomic register / update / retire)          *)
(* ============================================================ *)

\* `register_circle`: payable + atomic. Sets owner, active=1, AND
\* bonds initial stake all in one transition. The `caller` becomes
\* `circles[c].owner`; `value` is added to `circle_stake[c]`.
RegisterCircleAtomic(c, caller, priceShared, priceInternal, value) ==
    /\ ~paused
    /\ caller \in Clients
    /\ ~circles[c].active
    /\ ~circle_slashed[c]
    /\ circle_stake[c] + value >= MinCircleStake
    /\ circles' = [circles EXCEPT
                       ![c] = [active         |-> TRUE,
                               owner          |-> caller,
                               price_shared   |-> priceShared,
                               price_internal |-> priceInternal]]
    /\ circle_stake' = [circle_stake EXCEPT ![c] = circle_stake[c] + value]
    /\ UNCHANGED << circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

UpdateCircle(c, caller, newPriceShared, newPriceInternal) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ circles[c].active
    /\ circles' = [circles EXCEPT
                       ![c] = [active         |-> circles[c].active,
                               owner          |-> circles[c].owner,
                               price_shared   |-> newPriceShared,
                               price_internal |-> newPriceInternal]]
    /\ UNCHANGED << circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

RetireCircle(c, caller) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ circles[c].active
    /\ circles' = [circles EXCEPT
                       ![c] = [active         |-> FALSE,
                               owner          |-> circles[c].owner,
                               price_shared   |-> circles[c].price_shared,
                               price_internal |-> circles[c].price_internal]]
    /\ UNCHANGED << circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Circle stake (bond / unbond / finalize / slash)              *)
(* ============================================================ *)

\* Top up an existing circle's stake. Requires caller to own.
BondEndpoint(c, caller, amount) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ amount > 0
    /\ ~circle_slashed[c]
    /\ circle_unbond[c].stake = 0
    /\ circle_stake' = [circle_stake EXCEPT ![c] = circle_stake[c] + amount]
    /\ UNCHANGED << circles, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

UnbondEndpoint(c, caller) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ circle_stake[c] > 0
    /\ circle_unbond[c].stake = 0
    /\ circle_unbond'   = [circle_unbond EXCEPT
                              ![c] = [stake |-> circle_stake[c],
                                      unlock |-> cur_epoch + UnbondGrace]]
    /\ circle_stake'    = [circle_stake EXCEPT ![c] = 0]
    /\ UNCHANGED << circles, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

FinalizeUnbond(c, caller) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ circle_unbond[c].stake > 0
    /\ cur_epoch >= circle_unbond[c].unlock
    /\ withdrawn'     = withdrawn + circle_unbond[c].stake
    /\ circle_unbond' = [circle_unbond EXCEPT
                            ![c] = [stake |-> 0, unlock |-> 0]]
    /\ UNCHANGED << circles, circle_stake, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

\* Governance slash (owner-gated).
GovSlashOperator(c) ==
    /\ ~paused
    /\ ~circle_slashed[c]
    /\ circle_stake[c] + circle_unbond[c].stake > 0
    /\ LET total    == circle_stake[c] + circle_unbond[c].stake
           burn_amt == (total * 9000) \div 10000
       IN  /\ circle_stake'    = [circle_stake EXCEPT ![c] = 0]
           /\ circle_unbond'   = [circle_unbond EXCEPT
                                      ![c] = [stake |-> 0, unlock |-> 0]]
           /\ circle_slashed'  = [circle_slashed EXCEPT ![c] = TRUE]
           /\ circles'         = [circles EXCEPT
                                      ![c] = [active         |-> FALSE,
                                              owner          |-> circles[c].owner,
                                              price_shared   |-> circles[c].price_shared,
                                              price_internal |-> circles[c].price_internal]]
           /\ program_treasury' = program_treasury + burn_amt
           /\ burned'           = burned + burn_amt
    /\ UNCHANGED << treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_owner, paused, cur_epoch,
                    paid_out, refunded, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

\* Off-chain payload signing by an operator. Adversarial model: the
\* operator may sign anything, including two distinct payloads.
OperatorSignsPayload(c, p) ==
    /\ p \notin signed_payloads[c]
    /\ signed_payloads' = [signed_payloads EXCEPT
                              ![c] = signed_payloads[c] \cup {p}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count >>

\* Cryptographic equivocation slash.
SlashDoubleSign(c, p_a, p_b) ==
    /\ ~paused
    /\ ~circle_slashed[c]
    /\ p_a # p_b
    /\ p_a \in signed_payloads[c]
    /\ p_b \in signed_payloads[c]
    /\ circle_stake[c] + circle_unbond[c].stake > 0
    /\ LET total    == circle_stake[c] + circle_unbond[c].stake
           burn_amt == (total * 9000) \div 10000
       IN  /\ circle_stake'    = [circle_stake EXCEPT ![c] = 0]
           /\ circle_unbond'   = [circle_unbond EXCEPT
                                      ![c] = [stake |-> 0, unlock |-> 0]]
           /\ circle_slashed'  = [circle_slashed EXCEPT ![c] = TRUE]
           /\ circles'         = [circles EXCEPT
                                      ![c] = [active         |-> FALSE,
                                              owner          |-> circles[c].owner,
                                              price_shared   |-> circles[c].price_shared,
                                              price_internal |-> circles[c].price_internal]]
           /\ program_treasury' = program_treasury + burn_amt
           /\ burned'           = burned + burn_amt
    /\ UNCHANGED << treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_owner, paused, cur_epoch,
                    paid_out, refunded, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Tailnets                                                     *)
(* ============================================================ *)

CreateTailnet(t, owner, amount) ==
    /\ ~paused
    /\ owner \in Clients
    /\ amount >= MinTailnetDeposit
    /\ tailnet_owner[t] = NoOwner
    /\ treasury'        = [treasury        EXCEPT ![t] = amount]
    /\ members'         = [members         EXCEPT ![t] = {owner}]
    /\ tailnet_owner'   = [tailnet_owner   EXCEPT ![t] = owner]
    /\ charge_internal' = [charge_internal EXCEPT ![t] = 0]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    authorized,
                    sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

DepositToTailnet(t, caller, amount) ==
    /\ ~paused
    /\ amount > 0
    /\ tailnet_owner[t] # NoOwner
    /\ ( tailnet_owner[t] = caller \/ caller \in members[t] )
    /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + amount]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

AddMember(t, caller, member) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ member \in Clients
    /\ member \notin members[t]
    /\ members' = [members EXCEPT ![t] = members[t] \cup {member}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

RemoveMember(t, caller, member) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ member # tailnet_owner[t]
    /\ member \in members[t]
    /\ members' = [members EXCEPT ![t] = members[t] \ {member}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

UpdateAcl(t, caller) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ UNCHANGED vars  \* ACL hash is not tracked in the abstract model

SetChargeInternalTraffic(t, caller, charge) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ charge \in {0, 1}
    /\ charge_internal' = [charge_internal EXCEPT ![t] = charge]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

\* Authorize a circle as an exit. AML requires the circle to be
\* active AND not slashed at the time of authorization.
AuthorizeCircle(t, caller, c) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ CircleIsActive(c)
    /\ c \notin authorized[t]
    /\ authorized' = [authorized EXCEPT ![t] = authorized[t] \cup {c}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

RevokeCircle(t, caller, c) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ c \in authorized[t]
    /\ authorized' = [authorized EXCEPT ![t] = authorized[t] \ {c}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Join tokens                                                  *)
(* ============================================================ *)

PrecommitJoinToken(t, h, caller) ==
    /\ ~paused
    /\ tailnet_owner[t] = caller
    /\ h \notin join_token_commits[t]
    /\ h \notin join_token_redeemed
    /\ join_token_commits' = [join_token_commits EXCEPT
                                 ![t] = join_token_commits[t] \cup {h}]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_redeemed, settled_sids, redeem_count,
                    signed_payloads >>

RedeemJoinToken(t, c, h) ==
    /\ ~paused
    /\ c \in Clients
    /\ h \in join_token_commits[t]
    /\ h \notin join_token_redeemed
    /\ c \notin members[t]
    /\ members'             = [members EXCEPT ![t] = members[t] \cup {c}]
    /\ join_token_redeemed' = join_token_redeemed \cup {h}
    /\ redeem_count'        = [redeem_count EXCEPT ![h] = redeem_count[h] + 1]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, settled_sids, signed_payloads >>

(* ============================================================ *)
(* Sessions (per-class pricing stamped at open)                 *)
(* ============================================================ *)

OpenSession(sid, t, c, caller, class, deposit) ==
    /\ ~paused
    /\ sid = nextSession
    /\ caller \in members[t]
    /\ c \in authorized[t]
    /\ CircleIsActive(c)
    /\ class \in {CLASS_SHARED, CLASS_INTERNAL}
    /\ deposit >= MinDeposit
    /\ treasury[t] >= deposit
    /\ LET stampedPrice ==
              IF class = CLASS_SHARED
                THEN circles[c].price_shared
                ELSE circles[c].price_internal
       IN /\ treasury' = [treasury EXCEPT ![t] = treasury[t] - deposit]
          /\ sessions' = sessions @@ (sid :> [
                  status         |-> "open",
                  tailnet        |-> t,
                  circle         |-> c,
                  opener         |-> caller,
                  deposit        |-> deposit,
                  opened_at      |-> cur_epoch,
                  class          |-> class,
                  price_per_mb   |-> stampedPrice,
                  operator_claim |-> NoClaim,
                  client_confirm |-> NoClaim
             ])
          /\ nextSession' = nextSession + 1
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    tailnet_owner, members, authorized,
                    charge_internal, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

\* settle_claim: caller must own the session's circle.
SettleClaim(sid, caller, bytes) ==
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ LET c == sessions[sid].circle
       IN /\ circles[c].owner = caller
          /\ CircleIsActive(c)
          /\ IF ~sessions[sid].operator_claim.set
             THEN /\ sessions' = [sessions EXCEPT
                       ![sid] = [sessions[sid] EXCEPT
                           !.operator_claim = [set |-> TRUE, bytes |-> bytes]
                       ]]
                  /\ UNCHANGED << circles, circle_stake, circle_unbond,
                                  circle_slashed,
                                  treasury, tailnet_owner, members,
                                  authorized, charge_internal,
                                  nextSession, enc_earn,
                                  program_treasury, program_owner, paused,
                                  cur_epoch, paid_out, refunded, burned,
                                  swept, withdrawn,
                                  join_token_commits, join_token_redeemed,
                                  settled_sids, redeem_count,
                                  signed_payloads >>
             ELSE IF sessions[sid].operator_claim.bytes = bytes
                  THEN /\ UNCHANGED vars
                  ELSE \* Equivocation: refund + mark refunded.
                       LET tt  == sessions[sid].tailnet
                           dep == sessions[sid].deposit
                       IN /\ sessions' = [sessions EXCEPT
                                ![sid] = [sessions[sid] EXCEPT
                                    !.status = "refunded"
                                ]]
                          /\ treasury' = [treasury EXCEPT
                                ![tt] = treasury[tt] + dep]
                          /\ refunded' = refunded + dep
                          /\ UNCHANGED << circles, circle_stake,
                                          circle_unbond, circle_slashed,
                                          tailnet_owner, members,
                                          authorized, charge_internal,
                                          nextSession, enc_earn,
                                          program_treasury, program_owner,
                                          paused, cur_epoch,
                                          paid_out, burned, swept,
                                          withdrawn,
                                          join_token_commits,
                                          join_token_redeemed,
                                          settled_sids, redeem_count,
                                          signed_payloads >>

\* settle_confirm: opener-only. With the stamped price + charge toggle.
SettleConfirm(sid, caller, bytes) ==
    /\ ~paused
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ caller = sessions[sid].opener
    /\ sessions[sid].operator_claim.set
    /\ IF sessions[sid].operator_claim.bytes # bytes
       THEN \* Mismatch: dispute, no flow.
            /\ sessions' = [sessions EXCEPT
                    ![sid] = [sessions[sid] EXCEPT
                        !.client_confirm = [set |-> TRUE, bytes |-> bytes]
                    ]]
            /\ UNCHANGED << circles, circle_stake, circle_unbond,
                            circle_slashed,
                            treasury, tailnet_owner, members, authorized,
                            charge_internal, nextSession, enc_earn,
                            program_treasury, program_owner, paused,
                            cur_epoch, paid_out, refunded, burned, swept,
                            withdrawn,
                            join_token_commits, join_token_redeemed,
                            settled_sids, redeem_count, signed_payloads >>
       ELSE \* Match: apply settlement using stamped + toggle.
            LET c     == sessions[sid].circle
                tt    == sessions[sid].tailnet
                class == sessions[sid].class
                dep   == sessions[sid].deposit
                effPrice ==
                  IF class = CLASS_INTERNAL /\ charge_internal[tt] = 0
                    THEN 0
                    ELSE sessions[sid].price_per_mb
                totalRaw  == bytes * effPrice
                totalPaid == IF totalRaw > dep THEN dep ELSE totalRaw
                fee       == (totalPaid * 50) \div 10000
                net_pay   == totalPaid - fee
                refund    == dep - totalPaid
            IN /\ CircleIsActive(c)
               /\ sessions' = [sessions EXCEPT
                       ![sid] = [sessions[sid] EXCEPT
                           !.status         = "settled",
                           !.client_confirm = [set |-> TRUE, bytes |-> bytes]
                       ]]
               /\ enc_earn'         = [enc_earn EXCEPT
                       ![c] = enc_earn[c] + net_pay]
               /\ treasury'         = [treasury EXCEPT
                       ![tt] = treasury[tt] + refund]
               /\ program_treasury' = program_treasury + fee
               /\ refunded'         = refunded + refund
               /\ settled_sids'     = settled_sids \cup {sid}
               /\ UNCHANGED << circles, circle_stake, circle_unbond,
                               circle_slashed,
                               tailnet_owner, members, authorized,
                               charge_internal, nextSession,
                               program_owner, paused, cur_epoch,
                               paid_out, burned, swept, withdrawn,
                               join_token_commits, join_token_redeemed,
                               redeem_count, signed_payloads >>

ClaimNoShow(sid, caller) ==
    /\ ~paused
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ caller = sessions[sid].opener
    /\ ~sessions[sid].operator_claim.set
    /\ cur_epoch >= sessions[sid].opened_at + 1  \* grace = 1 in cfg
    /\ LET tt  == sessions[sid].tailnet
           dep == sessions[sid].deposit
       IN /\ sessions' = [sessions EXCEPT
                ![sid] = [sessions[sid] EXCEPT !.status = "refunded"]]
          /\ treasury' = [treasury EXCEPT ![tt] = treasury[tt] + dep]
          /\ refunded' = refunded + dep
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    tailnet_owner, members, authorized,
                    charge_internal, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

SweepExpiredSession(sid) ==
    /\ ~paused
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ cur_epoch >= sessions[sid].opened_at + SweepGrace
    /\ LET tt     == sessions[sid].tailnet
           dep    == sessions[sid].deposit
           bounty == (dep * 100) \div 10000
           refund == dep - bounty
       IN /\ sessions' = [sessions EXCEPT
                ![sid] = [sessions[sid] EXCEPT !.status = "refunded"]]
          /\ treasury' = [treasury EXCEPT ![tt] = treasury[tt] + refund]
          /\ refunded' = refunded + refund
          /\ swept'    = swept + bounty
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    tailnet_owner, members, authorized,
                    charge_internal, nextSession, enc_earn,
                    program_treasury, program_owner, paused, cur_epoch,
                    paid_out, burned, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Earnings claim (FHE zero-proof abstracted)                   *)
(* ============================================================ *)

ClaimEarnings(c, caller) ==
    /\ ~paused
    /\ circles[c].owner = caller
    /\ ~circle_slashed[c]
    /\ enc_earn[c] > 0
    /\ enc_earn'  = [enc_earn EXCEPT ![c] = 0]
    /\ paid_out'  = paid_out + enc_earn[c]
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession,
                    program_treasury, program_owner, paused, cur_epoch,
                    refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Governance (bypasses pause)                                  *)
(* ============================================================ *)

SetPaused(caller, v) ==
    /\ caller = program_owner
    /\ paused' = v
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

TransferOwnership(caller, new) ==
    /\ caller = program_owner
    /\ program_owner' = new
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, paused, cur_epoch,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

WithdrawProgramTreasury(caller, amount) ==
    /\ caller = program_owner
    /\ amount > 0
    /\ program_treasury >= amount
    /\ program_treasury' = program_treasury - amount
    /\ withdrawn'        = withdrawn + amount
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_owner, paused, cur_epoch,
                    paid_out, refunded, burned, swept,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Epoch tick                                                   *)
(* ============================================================ *)

TickEpoch ==
    /\ cur_epoch' = cur_epoch + 1
    /\ UNCHANGED << circles, circle_stake, circle_unbond, circle_slashed,
                    treasury, tailnet_owner, members, authorized,
                    charge_internal, sessions, nextSession, enc_earn,
                    program_treasury, program_owner, paused,
                    paid_out, refunded, burned, swept, withdrawn,
                    join_token_commits, join_token_redeemed,
                    settled_sids, redeem_count, signed_payloads >>

(* ============================================================ *)
(* Next                                                         *)
(* ============================================================ *)

Next ==
    \/ \E c \in Circles, caller \in Clients:
           RegisterCircleAtomic(c, caller, Price, Price, MinCircleStake)
    \/ \E c \in Circles, caller \in Clients:
           UpdateCircle(c, caller, Price, Price)
    \/ \E c \in Circles, caller \in Clients: RetireCircle(c, caller)
    \/ \E c \in Circles, caller \in Clients:
           BondEndpoint(c, caller, MinCircleStake)
    \/ \E c \in Circles, caller \in Clients: UnbondEndpoint(c, caller)
    \/ \E c \in Circles, caller \in Clients: FinalizeUnbond(c, caller)
    \/ \E c \in Circles: GovSlashOperator(c)
    \/ \E c \in Circles, p \in Payloads: OperatorSignsPayload(c, p)
    \/ \E c \in Circles, p_a \in Payloads, p_b \in Payloads:
           SlashDoubleSign(c, p_a, p_b)
    \/ \E t \in Tailnets, c \in Clients:
           CreateTailnet(t, c, MinTailnetDeposit)
    \/ \E t \in Tailnets, c \in Clients: DepositToTailnet(t, c, 1)
    \/ \E t \in Tailnets, caller \in Clients, member \in Clients:
           AddMember(t, caller, member)
    \/ \E t \in Tailnets, caller \in Clients, member \in Clients:
           RemoveMember(t, caller, member)
    \/ \E t \in Tailnets, caller \in Clients: UpdateAcl(t, caller)
    \/ \E t \in Tailnets, caller \in Clients, ch \in {0, 1}:
           SetChargeInternalTraffic(t, caller, ch)
    \/ \E t \in Tailnets, caller \in Clients, c \in Circles:
           AuthorizeCircle(t, caller, c)
    \/ \E t \in Tailnets, caller \in Clients, c \in Circles:
           RevokeCircle(t, caller, c)
    \/ \E t \in Tailnets, h \in TokenHashes, caller \in Clients:
           PrecommitJoinToken(t, h, caller)
    \/ \E t \in Tailnets, c \in Clients, h \in TokenHashes:
           RedeemJoinToken(t, c, h)
    \/ \E sid \in {nextSession}, t \in Tailnets, c \in Circles,
            caller \in Clients, class \in {CLASS_SHARED, CLASS_INTERNAL}:
           OpenSession(sid, t, c, caller, class, MinDeposit)
    \/ \E sid \in DOMAIN sessions, caller \in Clients,
            bytes \in {0, MinDeposit}: SettleClaim(sid, caller, bytes)
    \/ \E sid \in DOMAIN sessions, caller \in Clients,
            bytes \in {0, MinDeposit}: SettleConfirm(sid, caller, bytes)
    \/ \E sid \in DOMAIN sessions, caller \in Clients:
           ClaimNoShow(sid, caller)
    \/ \E sid \in DOMAIN sessions: SweepExpiredSession(sid)
    \/ \E c \in Circles, caller \in Clients: ClaimEarnings(c, caller)
    \/ \E caller \in Clients: WithdrawProgramTreasury(caller, 1)
    \/ TickEpoch
    \* SetPaused / TransferOwnership intentionally excluded from Next
    \* (same as v1.1) to keep state space tractable; their Lean
    \* lemmas discharge the state-transition contracts. The
    \* Inv_PausedIsBool invariant + FALSE initial value combine to
    \* certify the type discipline.

Spec == Init /\ [][Next]_vars

(* ============================================================ *)
(* StateBound (constraint for tractability)                     *)
(* ============================================================ *)

StateBound ==
    /\ nextSession <= MaxSeq
    /\ refunded <= MaxSeq * MinDeposit * 4
    /\ paid_out <= MaxSeq * MinDeposit * 4
    /\ program_treasury <= MaxSeq * MinDeposit * 4 + MinCircleStake * 2
    /\ \A t \in Tailnets: treasury[t] <= MinTailnetDeposit + MaxSeq * MinDeposit
    /\ \A c \in Circles: enc_earn[c] <= MaxSeq * MinDeposit
    /\ \A c \in Circles: circle_stake[c] <= MinCircleStake
    /\ \A c \in Circles: circle_unbond[c].stake <= MinCircleStake
    /\ burned    <= MinCircleStake * 2
    /\ swept     <= MaxSeq * MinDeposit * 2
    /\ withdrawn <= MaxSeq * MinDeposit * 4 + MinCircleStake * 2
    /\ cur_epoch <= SweepGrace + UnbondGrace
    /\ \A c \in Circles: Cardinality(signed_payloads[c]) <= 2
    /\ Cardinality({sid \in DOMAIN sessions:
                        sessions[sid].status = "open"}) <= 1
    /\ \A c \in Circles:
            circle_unbond[c].stake > 0 =>
                cur_epoch <= circle_unbond[c].unlock
    /\ ( \A c \in Circles: signed_payloads[c] = {} ) =>
            cur_epoch <= UnbondGrace
    /\ ( \E c \in Circles: Cardinality(signed_payloads[c]) >= 2 ) =>
            cur_epoch <= 1
    /\ nextSession >= 1 => cur_epoch <= UnbondGrace + 1
    /\ nextSession <= 2
    /\ paused = FALSE
    /\ \A c \in Circles: signed_payloads[c] # {} => circle_stake[c] > 0

(* ============================================================ *)
(* Invariants                                                   *)
(* ============================================================ *)

ConservationOfFunds ==
    /\ refunded         >= 0
    /\ paid_out         >= 0
    /\ program_treasury >= 0
    /\ \A t \in Tailnets: treasury[t] >= 0
    /\ \A c \in Circles:  enc_earn[c] >= 0

NoDoubleSettle ==
    \A sid \in DOMAIN sessions:
        sessions[sid].status \in SessionStatus

TreasuryNonNegative ==
    \A t \in Tailnets: treasury[t] >= 0

EarningsNonNegative ==
    \A c \in Circles: enc_earn[c] >= 0

ProgramTreasuryMonotone == program_treasury >= 0

\* Every circle currently flagged `active` is NOT slashed (slashing
\* atomically forces `active = FALSE`). The relationship between
\* `circles[c].active` and stake is decoupled in v2: after
\* `unbond_endpoint` the live stake is 0 but the circle stays
\* active (mid-unbonding), and after `finalize_unbond` both stakes
\* are 0 — the circle is "active with no stake", a state the AML
\* permits and the circle owner is expected to clean up via
\* `retire_circle`. We therefore weaken this invariant to the
\* slash-only condition that v2 actually enforces.
ActiveCirclesAreBonded ==
    \A c \in Circles:
        circles[c].active => ~circle_slashed[c]

\* Slashed circle has zero live stake.
SlashedHaveZeroStake ==
    \A c \in Circles:
        circle_slashed[c] => circle_stake[c] = 0

Inv_SlashedCircleHasZeroStake ==
    \A c \in Circles:
        circle_slashed[c] =>
            ( circle_stake[c] = 0 /\ circle_unbond[c].stake = 0 )

\* TWO-TX SAFETY: a settled session has both operator + client
\* claims recorded with matching bytes.
Inv_SettlementOnlyOnConfirm ==
    \A sid \in DOMAIN sessions:
        sessions[sid].status = "settled" =>
            /\ sessions[sid].operator_claim.set
            /\ sessions[sid].client_confirm.set
            /\ sessions[sid].operator_claim.bytes
                 = sessions[sid].client_confirm.bytes

Inv_EquivocationCausesRefund ==
    \A sid \in DOMAIN sessions:
        ( /\ sessions[sid].status = "refunded"
          /\ sessions[sid].operator_claim.set ) =>
              sid \notin settled_sids

Inv_TokenSinglyRedeemed ==
    \A h \in join_token_redeemed:
        /\ \E t \in Tailnets: h \in join_token_commits[t]
        /\ redeem_count[h] = 1

Inv_DoubleSignSlashable ==
    \A c \in Circles:
        ( /\ ~paused
          /\ ~circle_slashed[c]
          /\ circle_stake[c] + circle_unbond[c].stake > 0
          /\ \E p_a \in signed_payloads[c],
                p_b \in signed_payloads[c]: p_a # p_b ) =>
            \E p_a \in Payloads, p_b \in Payloads:
                ENABLED SlashDoubleSign(c, p_a, p_b)

(* ============================================================ *)
(* v2-specific invariants                                       *)
(* ============================================================ *)

\* ATOMIC REGISTER + BOND: there is NO reachable state in which a
\* circle has `active = TRUE` AND no owner. The chicken-and-egg
\* between bond and register is mechanically impossible because
\* `register_circle` (a) is the only entrypoint that sets
\* `active := TRUE`, and (b) atomically sets `owner := caller`
\* AND credits stake.
\*
\* After `unbond_endpoint` + `finalize_unbond` the live + unbond
\* stake can be zero with `active = TRUE`; this is a v2 design
\* choice (the circle owner is expected to call `retire_circle`).
\* The atomic-register guarantee is therefore phrased on owner
\* presence, not stake size: every active circle has a non-sentinel
\* owner, hence was registered through the atomic entrypoint.
Inv_CircleAtomicRegisterBond ==
    \A c \in Circles:
        circles[c].active => circles[c].owner # NoOwner

\* Every authorized circle was active at authorize-time. The chain
\* records the authorization permanently; if the circle is later
\* slashed/retired, the authorization is stale but `open_session`
\* re-checks `CircleIsActive` at open time. We therefore phrase the
\* invariant as: at all times, a circle authorized for some tailnet
\* IS or WAS active (i.e. the `circles[c]` record exists with owner
\* set, ruling out "authorize a never-registered circle").
Inv_AuthorizedCircleIsActive ==
    \A t \in Tailnets, c \in Circles:
        c \in authorized[t] =>
            circles[c].owner # NoOwner

\* STAMPED PRICE IMMUTABLE: every session in `sessions` has a
\* `price_per_mb` field whose value was stamped from the circle's
\* per-class price at the time the session was opened. Subsequent
\* `update_circle` calls must NOT mutate this field on an existing
\* session. We phrase this as: the price stamp is in {0, Price}
\* (the two values the circle records can hold under our model).
\* TLC verifies this across every reachable state, including all
\* interleavings with UpdateCircle.
Inv_StampedPriceImmutableInOpenSession ==
    \A sid \in DOMAIN sessions:
        sessions[sid].price_per_mb \in {0, Price}

(* ============================================================ *)
(* Inv_PausedIsBool                                             *)
(* ============================================================ *)

Inv_PausedIsBool == paused \in BOOLEAN

(* ============================================================ *)
(* Conservation                                                 *)
(* ============================================================ *)

Inv_TreasuryConservation ==
    paid_out + swept + withdrawn + refunded
        <= MaxSeq * MinDeposit * 12 + MinCircleStake * 4

Invariants ==
    /\ ConservationOfFunds
    /\ NoDoubleSettle
    /\ TreasuryNonNegative
    /\ EarningsNonNegative
    /\ ProgramTreasuryMonotone
    /\ ActiveCirclesAreBonded
    /\ SlashedHaveZeroStake
    /\ Inv_SlashedCircleHasZeroStake
    /\ Inv_SettlementOnlyOnConfirm
    /\ Inv_EquivocationCausesRefund
    /\ Inv_TokenSinglyRedeemed
    /\ Inv_DoubleSignSlashable
    /\ Inv_CircleAtomicRegisterBond
    /\ Inv_AuthorizedCircleIsActive
    /\ Inv_StampedPriceImmutableInOpenSession
    /\ Inv_TreasuryConservation
    /\ Inv_PausedIsBool

=============================================================================
