/-!
# State of the OctraVPN program — Lean 4 model (tailnet edition).

Endpoints (paid relays/exits) carry no bond inside this program — bond
and liveness are delegated to the Octra protocol layer, modeled as the
external predicate `isOctraValidator`. Tailnets are member groups with
shared treasuries that fund sessions.
-/

namespace OctraVPN

abbrev Addr := Nat
abbrev Bytes := List UInt8
abbrev Epoch := Nat
abbrev OctRaw := Nat

inductive SessionStatus where
  | open      : SessionStatus
  | settled   : SessionStatus
  | refunded  : SessionStatus
  deriving Repr, DecidableEq

/-- On-chain endpoint record under `endpoints[addr]`. -/
structure EndpointRecord where
  active           : Bool
  endpoint         : String
  region           : String
  pricePerMb       : Nat
  registeredAt     : Epoch
  reputation       : Int
  deriving Repr

def EndpointRecord.empty : EndpointRecord :=
  { active := false, endpoint := "", region := "",
    pricePerMb := 0, registeredAt := 0, reputation := 0 }

/-- On-chain tailnet record under `tailnets[id]`. -/
structure Tailnet where
  owner       : Addr
  treasury    : OctRaw
  members     : List Addr
  exits       : List Addr
  createdAt   : Epoch
  deriving Repr

def Tailnet.empty : Tailnet :=
  { owner := 0, treasury := 0, members := [], exits := [], createdAt := 0 }

/-- A session record. -/
structure Session where
  tailnetId       : Bytes
  deposit         : OctRaw
  openedAt        : Epoch
  receiptSeq      : Nat
  status          : SessionStatus
  /-- Hops are a list of (endpoint address, split bps) pairs. -/
  route           : List (Addr × Nat)
  /-- Plaintext "view" of bytes paid for, for proof purposes only. -/
  paidBytes       : Nat
  deriving Repr

abbrev Map (α : Type) (β : Type) := α → β

def Map.update {α} {β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : Map α β :=
  fun x => if x = k then v else m x

structure Params where
  minSessionDeposit    : OctRaw
  minTailnetDeposit    : OctRaw
  sessionGraceEpochs   : Nat
  sweepGraceMultiplier : Nat
  sweepBountyBps       : Nat
  deriving Repr

structure ProgramState where
  /-- External oracle: is `addr` currently an Octra protocol validator?
      The program's `register_endpoint` gate checks this. -/
  isOctraValidator : Addr → Bool
  endpoints        : Map Addr EndpointRecord
  tailnets         : Map Bytes Tailnet
  sessions         : Map Bytes (Option Session)
  encEarn          : Map Addr Nat
  burned           : OctRaw
  params           : Params
  currentEpoch     : Epoch

end OctraVPN
