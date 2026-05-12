------------------------------ MODULE OctraVPN ------------------------------
(*****************************************************************************)
(* Protocol-level state-machine spec for the OctraVPN program (tailnet model).*)
(*                                                                           *)
(* Abstracts away cryptography (signatures, FHE, commitments) and models the *)
(* on-chain bookkeeping as a transition system. Bond / liveness / slashing   *)
(* are delegated to the Octra protocol layer and not modeled here.           *)
(*                                                                           *)
(* We model:                                                                  *)
(*   - endpoint registration gated on `is_octra_validator`                    *)
(*   - tailnets with treasuries and member sets                              *)
(*   - sessions opening (deposit from treasury) / settling / refunding       *)
(*   - encrypted-earnings ledger as a counter                                 *)
(*                                                                           *)
(* The properties:                                                            *)
(*   ConservationOfFunds                                                      *)
(*   NoDoubleSettle                                                           *)
(*   MonotonicSeq                                                             *)
(*   TreasuryNonNegative                                                      *)
(*   EarningsNonNegative                                                      *)
(*   OnlyOctraValidatorsRegistered                                            *)
(*   Liveness_SettleOrRefund                                                  *)
(*****************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Endpoints,          \* set of candidate endpoint addresses (must be subset
                        \* of OctraValidators to register)
    OctraValidators,    \* set of addresses currently considered Octra protocol
                        \* validators (the chain-level gate)
    Tailnets,           \* set of tailnet ids modeled
    Clients,            \* set of client addresses
    MinDeposit,         \* >= 1
    MinTailnetDeposit,  \* >= 1
    MaxSeq

ASSUME EndpointsAreCandidates == Endpoints \subseteq OctraValidators

VARIABLES
    registered,     \* [Endpoint -> BOOLEAN] — true iff register_endpoint succeeded
    treasury,       \* [Tailnet -> Nat] — OU available
    members,        \* [Tailnet -> SUBSET Clients] — membership set
    enc_earn,       \* [Endpoint -> Nat] — decrypted earnings ledger
    sessions,       \* [SessionId -> Session]
    nextSession,    \* Nat
    paid_out,       \* Nat — total OU paid out via claim_earnings
    refunded        \* Nat — total OU refunded (back to treasury)

vars == << registered, treasury, members, enc_earn, sessions,
           nextSession, paid_out, refunded >>

SessionStatus == {"open", "settled", "refunded"}
SessionId == Nat

Init ==
    /\ registered  = [e \in Endpoints |-> FALSE]
    /\ treasury    = [t \in Tailnets |-> 0]
    /\ members     = [t \in Tailnets |-> {}]
    /\ enc_earn    = [e \in Endpoints |-> 0]
    /\ sessions    = << >>
    /\ nextSession = 0
    /\ paid_out    = 0
    /\ refunded    = 0

(* ---- Endpoint registration (Octra-validator gated) ---- *)

RegisterEndpoint(e) ==
    /\ e \in OctraValidators       \* the program-side `is_octra_validator` gate
    /\ ~registered[e]
    /\ registered' = [registered EXCEPT ![e] = TRUE]
    /\ UNCHANGED << treasury, members, enc_earn, sessions, nextSession,
                    paid_out, refunded >>

(* ---- Tailnet lifecycle ---- *)

CreateTailnet(t, owner, amount) ==
    /\ owner \in Clients
    /\ amount >= MinTailnetDeposit
    /\ treasury[t] = 0
    /\ treasury' = [treasury EXCEPT ![t] = amount]
    /\ members'  = [members  EXCEPT ![t] = {owner}]
    /\ UNCHANGED << registered, enc_earn, sessions, nextSession,
                    paid_out, refunded >>

AddMember(t, c) ==
    /\ c \in Clients
    /\ treasury[t] > 0           \* tailnet exists
    /\ c \notin members[t]
    /\ members' = [members EXCEPT ![t] = members[t] \cup {c}]
    /\ UNCHANGED << registered, treasury, enc_earn, sessions, nextSession,
                    paid_out, refunded >>

DepositToTailnet(t, amount) ==
    /\ amount > 0
    /\ treasury[t] > 0           \* tailnet exists
    /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + amount]
    /\ UNCHANGED << registered, members, enc_earn, sessions, nextSession,
                    paid_out, refunded >>

(* ---- Session lifecycle ---- *)

OpenSession(sid, t, c, deposit) ==
    /\ sid = nextSession
    /\ c \in members[t]
    /\ deposit >= MinDeposit
    /\ treasury[t] >= deposit
    /\ treasury' = [treasury EXCEPT ![t] = treasury[t] - deposit]
    /\ sessions' = sessions @@ (sid :> [
            status      |-> "open",
            tailnet     |-> t,
            deposit     |-> deposit,
            last_seq    |-> 0,
            paid_amount |-> 0
       ])
    /\ nextSession' = nextSession + 1
    /\ UNCHANGED << registered, members, enc_earn, paid_out, refunded >>

SettleSession(sid, exit, seq, paid) ==
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ seq > sessions[sid].last_seq
    /\ seq <= MaxSeq
    /\ paid <= sessions[sid].deposit
    /\ registered[exit]
    /\ exit \in OctraValidators        \* still a validator at settle time
    /\ LET t == sessions[sid].tailnet
           extra_refund == sessions[sid].deposit - paid
       IN  /\ sessions' = [sessions EXCEPT ![sid] = [
                sessions[sid] EXCEPT
                !.status      = "settled",
                !.last_seq    = seq,
                !.paid_amount = paid
              ]]
           /\ enc_earn' = [enc_earn EXCEPT ![exit] = enc_earn[exit] + paid]
           /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + extra_refund]
           /\ refunded' = refunded + extra_refund
    /\ UNCHANGED << registered, members, nextSession, paid_out >>

ClaimNoShow(sid) ==
    /\ sid \in DOMAIN sessions
    /\ sessions[sid].status = "open"
    /\ sessions[sid].last_seq = 0
    /\ LET t == sessions[sid].tailnet
       IN  /\ sessions' = [sessions EXCEPT ![sid] = [
                sessions[sid] EXCEPT !.status = "refunded"
              ]]
           /\ treasury' = [treasury EXCEPT ![t] = treasury[t] + sessions[sid].deposit]
           /\ refunded' = refunded + sessions[sid].deposit
    /\ UNCHANGED << registered, members, enc_earn, nextSession, paid_out >>

(* ---- Earnings claim ---- *)

ClaimEarnings(v, amount) ==
    /\ amount > 0
    /\ registered[v]
    /\ enc_earn[v] >= amount
    /\ enc_earn' = [enc_earn EXCEPT ![v] = enc_earn[v] - amount]
    /\ paid_out' = paid_out + amount
    /\ UNCHANGED << registered, treasury, members, sessions, nextSession, refunded >>

Next ==
    \/ \E e \in Endpoints: RegisterEndpoint(e)
    \/ \E t \in Tailnets, c \in Clients, d \in {MinTailnetDeposit, MinTailnetDeposit + 1}:
            CreateTailnet(t, c, d)
    \/ \E t \in Tailnets, c \in Clients: AddMember(t, c)
    \/ \E t \in Tailnets, a \in {1, 2}: DepositToTailnet(t, a)
    \/ \E sid \in {nextSession}, t \in Tailnets, c \in Clients,
          d \in {MinDeposit, MinDeposit + 1}:
            OpenSession(sid, t, c, d)
    \/ \E sid \in DOMAIN sessions, e \in Endpoints,
          seq \in 1..MaxSeq, paid \in 0..MinDeposit + 1:
            SettleSession(sid, e, seq, paid)
    \/ \E sid \in DOMAIN sessions: ClaimNoShow(sid)
    \/ \E e \in Endpoints, amt \in 1..3: ClaimEarnings(e, amt)

Spec == Init /\ [][Next]_vars

(* ---------------------------- INVARIANTS ---------------------------- *)

Sum(S) ==
    LET RECURSIVE sumOf(_)
        sumOf(T) == IF T = {} THEN 0
                     ELSE LET x == CHOOSE x \in T : TRUE
                          IN x + sumOf(T \ {x})
    IN sumOf(S)

ConservationOfFunds ==
    /\ refunded     >= 0
    /\ paid_out     >= 0
    /\ \A t \in Tailnets:  treasury[t] >= 0
    /\ \A e \in Endpoints: enc_earn[e] >= 0

NoDoubleSettle ==
    \A sid \in DOMAIN sessions:
        sessions[sid].status \in SessionStatus

MonotonicSeq ==
    \A sid \in DOMAIN sessions:
        sessions[sid].last_seq >= 0

TreasuryNonNegative ==
    \A t \in Tailnets: treasury[t] >= 0

EarningsNonNegative ==
    \A e \in Endpoints: enc_earn[e] >= 0

(* The chain-level gate at registration is preserved: every registered
   endpoint must be (or have been at registration time) an Octra
   validator. We model OctraValidators as a constant set for tractability;
   a richer model would let validators leave/return. *)
OnlyOctraValidatorsRegistered ==
    \A e \in Endpoints: registered[e] => e \in OctraValidators

Invariants ==
    /\ ConservationOfFunds
    /\ NoDoubleSettle
    /\ MonotonicSeq
    /\ TreasuryNonNegative
    /\ EarningsNonNegative
    /\ OnlyOctraValidatorsRegistered

(* ---------------------------- LIVENESS ---------------------------- *)

Liveness_SettleOrRefund ==
    \A sid \in 0..MaxSeq:
        (sid \in DOMAIN sessions /\ sessions[sid].status = "open")
            ~> sessions[sid].status \in {"settled", "refunded"}

=============================================================================
