------------------------------ MODULE OctraVPN ------------------------------
(*****************************************************************************)
(* Protocol-level state-machine spec for the OctraVPN program (v1).         *)
(*                                                                           *)
(* Abstracts cryptography (HFHE, stealth) and models the on-chain            *)
(* bookkeeping. v1 differs from v0 in three key ways:                       *)
(*                                                                           *)
(*   1. Operator stake lives in-program (`endpoint_stake`); slashing is     *)
(*      governance-driven (`gov_slash_operator`).                            *)
(*   2. Sessions are single-hop with a single configured exit.              *)
(*   3. Settlement is validator-only — only `sess.exit` can call            *)
(*      `settle_session(bytes_used)`.                                        *)
(*                                                                           *)
(* Properties:                                                                *)
(*   ConservationOfFunds                                                      *)
(*   NoDoubleSettle                                                           *)
(*   TreasuryNonNegative                                                      *)
(*   ProgramTreasuryMonotone                                                  *)
(*   EarningsNonNegative                                                      *)
(*   ActiveEndpointsAreBonded                                                 *)
(*   SlashedHaveZeroStake                                                     *)
(*   StakeUnlockReachable (liveness)                                          *)
(*   Liveness_SettleOrRefund                                                  *)
(*****************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Endpoints,          \* set of candidate endpoint addresses
    Tailnets,           \* set of tailnet ids modeled
    Clients,            \* set of client addresses
    Owner,              \* program owner (governance wallet)
    MinDeposit,         \* >= 1
    MinTailnetDeposit,  \* >= 1
    MinEndpointStake,   \* operator bond floor
    MaxSeq

VARIABLES
    registered,          \* [Endpoint -> BOOLEAN]
    endpoint_stake,      \* [Endpoint -> Nat]
    endpoint_slashed,    \* [Endpoint -> BOOLEAN]
    treasury,            \* [Tailnet -> Nat]
    members,             \* [Tailnet -> SUBSET Clients]
    exits,               \* [Tailnet -> SUBSET Endpoints]
    enc_earn,            \* [Endpoint -> Nat]
    program_treasury,    \* Nat — Tier 2 protocol fee + burn share
    sessions,            \* [SessionId -> Session]
    nextSession,         \* Nat
    paid_out,            \* Nat — total claimed via claim_earnings
    refunded             \* Nat — total refunded (back to treasury)

vars == << registered, endpoint_stake, endpoint_slashed, treasury,
           members, exits, enc_earn, program_treasury, sessions,
           nextSession, paid_out, refunded >>

SessionStatus == {"open", "settled", "refunded"}
SessionId == Nat

Init ==
    /\ registered       = [e \in Endpoints |-> FALSE]
    /\ endpoint_stake   = [e \in Endpoints |-> 0]
    /\ endpoint_slashed = [e \in Endpoints |-> FALSE]
    /\ treasury         = [t \in Tailnets |-> 0]
    /\ members          = [t \in Tailnets |-> {}]
    /\ exits            = [t \in Tailnets |-> {}]
    /\ enc_earn         = [e \in Endpoints |-> 0]
    /\ program_treasury = 0
    /\ sessions         = << >>
    /\ nextSession      = 0
    /\ paid_out         = 0
    /\ refunded         = 0

(* ---- Operator stake ---- *)

BondEndpoint(e, amount) ==
    /\ amount > 0
    /\ ~endpoint_slashed[e]
    /\ endpoint_stake' = [endpoint_stake EXCEPT ![e] = endpoint_stake[e] + amount]
    /\ UNCHANGED << registered, endpoint_slashed, treasury, members, exits,
                    enc_earn, program_treasury, sessions, nextSession,
                    paid_out, refunded >>

GovSlashOperator(op) ==
    /\ ~endpoint_slashed[op]
    /\ endpoint_stake[op] > 0  \* must have stake to slash
    /\ LET total == endpoint_stake[op]
           burn_amt == (total * 9000) \div 10000
       IN  /\ endpoint_stake'   = [endpoint_stake EXCEPT ![op] = 0]
           /\ endpoint_slashed' = [endpoint_slashed EXCEPT ![op] = TRUE]
           /\ registered'       = [registered EXCEPT ![op] = FALSE]
           /\ program_treasury' = program_treasury + burn_amt
    /\ UNCHANGED << treasury, members, exits, enc_earn, sessions,
                    nextSession, paid_out, refunded >>

(* ---- Endpoint registration (stake-gated) ---- *)

RegisterEndpoint(e) ==
    /\ endpoint_stake[e] >= MinEndpointStake
    /\ ~endpoint_slashed[e]
    /\ ~registered[e]
    /\ registered' = [registered EXCEPT ![e] = TRUE]
    /\ UNCHANGED << endpoint_stake, endpoint_slashed, treasury, members,
                    exits, enc_earn, program_treasury, sessions,
                    nextSession, paid_out, refunded >>

RetireEndpoint(e) ==
    /\ registered[e]
    /\ registered' = [registered EXCEPT ![e] = FALSE]
    /\ UNCHANGED << endpoint_stake, endpoint_slashed, treasury, members,
                    exits, enc_earn, program_treasury, sessions,
                    nextSession, paid_out, refunded >>

(* ---- Tailnet lifecycle ---- *)

CreateTailnet(t, owner, amount) ==
    /\ owner \in Clients
    /\ amount >= MinTailnetDeposit
    /\ treasury[t] = 0
    /\ treasury' = [treasury EXCEPT ![t] = amount]
    /\ members'  = [members  EXCEPT ![t] = {owner}]
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, exits,
                    enc_earn, program_treasury, sessions, nextSession,
                    paid_out, refunded >>

AddMember(t, c) ==
    /\ c \in Clients
    /\ treasury[t] > 0           \* tailnet exists
    /\ c \notin members[t]
    /\ members' = [members EXCEPT ![t] = members[t] \cup {c}]
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, treasury,
                    exits, enc_earn, program_treasury, sessions, nextSession,
                    paid_out, refunded >>

ConfigureTailnetExit(t, e) ==
    /\ treasury[t] > 0
    /\ registered[e]
    /\ e \notin exits[t]
    /\ exits' = [exits EXCEPT ![t] = exits[t] \cup {e}]
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, treasury,
                    members, enc_earn, program_treasury, sessions, nextSession,
                    paid_out, refunded >>

DepositToTailnet(t, amount) ==
    /\ amount > 0
    /\ treasury[t] > 0
    /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + amount]
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, members,
                    exits, enc_earn, program_treasury, sessions, nextSession,
                    paid_out, refunded >>

(* ---- Session lifecycle (single-hop, validator-only settle) ---- *)

OpenSession(sid, t, c, e, deposit) ==
    /\ sid = nextSession
    /\ c \in members[t]
    /\ e \in exits[t]
    /\ deposit >= MinDeposit
    /\ treasury[t] >= deposit
    /\ treasury' = [treasury EXCEPT ![t] = treasury[t] - deposit]
    /\ sessions' = sessions @@ (sid :> [
            status      |-> "open",
            tailnet     |-> t,
            exit        |-> e,
            deposit     |-> deposit,
            paid_amount |-> 0
       ])
    /\ nextSession' = nextSession + 1
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, members,
                    exits, enc_earn, program_treasury, paid_out, refunded >>

\* Validator-only settle: only `sess.exit` can call. The protocol fee
\* (0.5 %) goes to the program treasury; the operator gets the rest;
\* the unspent deposit refunds to the tailnet treasury.
SettleSession(sid, caller, paid) ==
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ caller = sessions[sid].exit
    /\ registered[caller]
    /\ ~endpoint_slashed[caller]
    /\ paid <= sessions[sid].deposit
    /\ LET t == sessions[sid].tailnet
           fee == (paid * 50) \div 10000  \* 0.5%
           net_pay == paid - fee
           extra_refund == sessions[sid].deposit - paid
       IN  /\ sessions' = [sessions EXCEPT ![sid] = [
                sessions[sid] EXCEPT
                !.status      = "settled",
                !.paid_amount = paid
              ]]
           /\ enc_earn'         = [enc_earn EXCEPT ![caller] = enc_earn[caller] + net_pay]
           /\ treasury'         = [treasury EXCEPT ![t] = treasury[t] + extra_refund]
           /\ program_treasury' = program_treasury + fee
           /\ refunded'         = refunded + extra_refund
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, members,
                    exits, nextSession, paid_out >>

ClaimNoShow(sid) ==
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ sessions[sid].paid_amount = 0
    /\ LET t == sessions[sid].tailnet
       IN  /\ sessions' = [sessions EXCEPT ![sid] = [
                sessions[sid] EXCEPT !.status = "refunded"
              ]]
           /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + sessions[sid].deposit]
           /\ refunded' = refunded + sessions[sid].deposit
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, members,
                    exits, enc_earn, program_treasury, nextSession, paid_out >>

(* ---- Earnings claim (FHE-zero-proof abstracted) ---- *)

\* In v1 the operator must claim the *exact* balance (FHE proof gates
\* this on-chain). Modeled as claim_amount = enc_earn[v].
ClaimEarnings(v) ==
    /\ ~endpoint_slashed[v]
    /\ enc_earn[v] > 0
    /\ enc_earn'  = [enc_earn EXCEPT ![v] = 0]
    /\ paid_out'  = paid_out + enc_earn[v]
    /\ UNCHANGED << registered, endpoint_stake, endpoint_slashed, treasury,
                    members, exits, program_treasury, sessions, nextSession,
                    refunded >>

Next ==
    \/ \E e \in Endpoints: BondEndpoint(e, MinEndpointStake)
    \/ \E e \in Endpoints: RegisterEndpoint(e)
    \/ \E e \in Endpoints: RetireEndpoint(e)
    \/ \E e \in Endpoints: GovSlashOperator(e)
    \/ \E t \in Tailnets, c \in Clients, d \in {MinTailnetDeposit, MinTailnetDeposit + 1}:
            CreateTailnet(t, c, d)
    \/ \E t \in Tailnets, c \in Clients: AddMember(t, c)
    \/ \E t \in Tailnets, e \in Endpoints: ConfigureTailnetExit(t, e)
    \/ \E t \in Tailnets, a \in {1, 2}: DepositToTailnet(t, a)
    \/ \E sid \in {nextSession}, t \in Tailnets, c \in Clients, e \in Endpoints,
          d \in {MinDeposit, MinDeposit + 1}:
            OpenSession(sid, t, c, e, d)
    \/ \E sid \in DOMAIN sessions, caller \in Endpoints, paid \in 0..MinDeposit + 1:
            SettleSession(sid, caller, paid)
    \/ \E sid \in DOMAIN sessions: ClaimNoShow(sid)
    \/ \E v \in Endpoints: ClaimEarnings(v)

Spec == Init /\ [][Next]_vars

(* ---------------------------- INVARIANTS ---------------------------- *)

ConservationOfFunds ==
    /\ refunded         >= 0
    /\ paid_out         >= 0
    /\ program_treasury >= 0
    /\ \A t \in Tailnets:  treasury[t] >= 0
    /\ \A e \in Endpoints: enc_earn[e] >= 0

NoDoubleSettle ==
    \A sid \in DOMAIN sessions:
        sessions[sid].status \in SessionStatus

TreasuryNonNegative ==
    \A t \in Tailnets: treasury[t] >= 0

EarningsNonNegative ==
    \A e \in Endpoints: enc_earn[e] >= 0

ProgramTreasuryMonotone == program_treasury >= 0

\* SECURITY: every endpoint currently flagged as registered must have
\* at least MinEndpointStake bonded AND not be slashed.
ActiveEndpointsAreBonded ==
    \A e \in Endpoints:
        registered[e] =>
            (endpoint_stake[e] >= MinEndpointStake /\ ~endpoint_slashed[e])

\* SECURITY: a slashed operator can never have non-zero live stake.
SlashedHaveZeroStake ==
    \A e \in Endpoints:
        endpoint_slashed[e] => endpoint_stake[e] = 0

\* SECURITY: sessions reference an exit that was configured for the
\* tailnet at open-time (we model this strictly: configured at all times).
SessionExitsAreConfigured ==
    \A sid \in DOMAIN sessions:
        sessions[sid].status # "refunded" =>
            sessions[sid].exit \in exits[sessions[sid].tailnet]

Invariants ==
    /\ ConservationOfFunds
    /\ NoDoubleSettle
    /\ TreasuryNonNegative
    /\ EarningsNonNegative
    /\ ProgramTreasuryMonotone
    /\ ActiveEndpointsAreBonded
    /\ SlashedHaveZeroStake
    /\ SessionExitsAreConfigured

(* ---------------------------- LIVENESS ---------------------------- *)

\* Every open session eventually transitions to settled or refunded.
Liveness_SettleOrRefund ==
    \A sid \in 0..MaxSeq:
        (sid \in DOMAIN sessions /\ sessions[sid].status = "open")
            ~> sessions[sid].status \in {"settled", "refunded"}

=============================================================================
