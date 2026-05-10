/-!
# State of the OctraVPN program — Lean 4 model.
-/

namespace OctraVPN

abbrev Addr := Nat
abbrev Bytes := List UInt8
abbrev Epoch := Nat
abbrev Bond := Nat
abbrev OctRaw := Nat

/-- An on-chain validator record, as stored under `validators[addr]`. -/
structure ValidatorRecord where
  bond              : Bond
  endpoint          : String
  region            : String
  pricePerMb        : Nat
  registeredAt      : Epoch
  lastAttestEpoch   : Epoch
  unbondRequest     : Option Epoch
  jailedAt          : Option Epoch
  reputation        : Int
  deriving Repr

def ValidatorRecord.empty : ValidatorRecord :=
  { bond := 0, endpoint := "", region := "",
    pricePerMb := 0, registeredAt := 0,
    lastAttestEpoch := 0, unbondRequest := none,
    jailedAt := none, reputation := 0 }

/-- A session record. We track only fields relevant to the proofs. -/
structure Session where
  deposit          : OctRaw
  openedAt         : Epoch
  receiptSeq       : Nat
  status           : SessionStatus
  /-- Hops are a list of (validator address, split bps) pairs. We omit
      Pedersen blinds in the model since they're cryptographic detail. -/
  route            : List (Addr × Nat)
  /-- Plaintext "view" of the FHE-encrypted bytes paid for. The real
      program never stores this; the proof needs it to argue earnings. -/
  paidBytes        : Nat
  deriving Repr

inductive SessionStatus where
  | open      : SessionStatus
  | settled   : SessionStatus
  | refunded  : SessionStatus
  | slashed   : SessionStatus
  deriving Repr, DecidableEq

abbrev Map (α : Type) (β : Type) := α → β

def Map.update {α} {β} [DecidableEq α]
    (m : Map α β) (k : α) (v : β) : Map α β :=
  fun x => if x = k then v else m x

structure Params where
  minBond              : Bond
  minSessionDeposit    : OctRaw
  attestGraceEpochs    : Nat
  sessionGraceEpochs   : Nat
  unbondEpochs         : Nat
  slashBountyBps       : Nat
  slashBurnBps         : Nat
  slashTreasuryBps     : Nat
  deriving Repr

structure ProgramState where
  validators   : Map Addr ValidatorRecord
  sessions     : Map Bytes (Option Session)
  encEarn      : Map Addr Nat       -- decrypted view; in chain it's a ciphertext
  treasury     : OctRaw
  burned       : OctRaw
  params       : Params
  currentEpoch : Epoch

end OctraVPN
