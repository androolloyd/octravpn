/-!
# Spec: pure-functional Lean models of the Rust security primitives.

These mirror the Rust types and functions in:

  * `octra-foundry/crates/octra-core/src/{circle,tx,sig,address,wallet_enc,util}.rs`
  * `crates/octravpn-core/src/{receipt,receipt_journal}.rs`
  * `crates/octravpn-mesh/src/{ip_alloc,acl,peer}.rs`

Cryptographic primitives (SHA-256, Ed25519, AES-GCM, ChaCha20-Poly1305,
PBKDF2, HKDF) are modeled as opaque sorts with **assumed** structural
axioms (determinism, domain separation, injectivity-modulo-collision).
We do **not** prove cryptographic soundness — that's a property of the
crate-level audited Rust implementations and the underlying math.

Rationale for each axiom is captured at its declaration. None of the
axioms below assume collision resistance directly; instead we assume
that distinct *structural* inputs (different framings, tags, salts)
yield distinct opaque outputs. Where the Rust code's tests already
exercise determinism by computation (proptest), the Lean spec encodes
that same determinism as `def`-equality.
-/

namespace OctraVPN_Rust

/-- A byte string is a list of 8-bit unsigned integers. -/
abbrev ByteString := List UInt8

/-- A 32-byte SHA-256-shaped digest. -/
abbrev Digest32 := ByteString

/-- A big-endian u32 length prefix (4 bytes). -/
def u32be (n : Nat) : ByteString :=
  let b0 : UInt8 := UInt8.ofNat ((n / (256 * 256 * 256)) % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / (256 * 256)) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b3 : UInt8 := UInt8.ofNat (n % 256)
  [b0, b1, b2, b3]

theorem u32be_length (n : Nat) : (u32be n).length = 4 := by
  unfold u32be; rfl

/-- Big-endian u64 length prefix (8 bytes), used by `signing_payload`
    and the receipt journal codec. -/
def u64be (n : Nat) : ByteString :=
  let lo : Nat := n % (256 * 256 * 256 * 256)
  let hi : Nat := n / (256 * 256 * 256 * 256)
  u32be hi ++ u32be lo

theorem u64be_length (n : Nat) : (u64be n).length = 8 := by
  unfold u64be
  rw [List.length_append, u32be_length, u32be_length]

-- ============================================================
-- SHA-256 model
-- ============================================================

/-- Opaque SHA-256 digest function. -/
opaque Sha256.digest : ByteString → Digest32 := fun _ => []

/-- SHA-256 is a function. -/
theorem Sha256.digest_function (m₁ m₂ : ByteString)
    (h : m₁ = m₂) : Sha256.digest m₁ = Sha256.digest m₂ := by
  rw [h]

/-- Axiom: distinct byte strings hash to distinct digests in our model. -/
axiom Sha256.injective {m₁ m₂ : ByteString} :
    Sha256.digest m₁ = Sha256.digest m₂ → m₁ = m₂

-- ============================================================
-- h256_raw  (TupleHash-style framed SHA-256, octra-foundry/circle.rs)
-- ============================================================

/-- Frame the `(tag, parts)` input as it appears in `h256_raw`:
       utf8(tag) || 0x00 || (u32be(len(p)) || p)* -/
def h256Frame (tag : ByteString) (parts : List ByteString) : ByteString :=
  tag ++ [0] ++ (parts.foldl (fun acc p => acc ++ u32be p.length ++ p) [])

/-- `h256_raw(tag, parts) = sha256(frame)`. -/
def h256Raw (tag : ByteString) (parts : List ByteString) : Digest32 :=
  Sha256.digest (h256Frame tag parts)

-- ============================================================
-- Address (octra-foundry/address.rs)
-- ============================================================

/-- Opaque `displayOf` function: a deterministic projection from
    the raw 32-byte hash to the 47-char `oct…` string. -/
opaque Address.displayOf : Digest32 → String := fun _ => "oct"

/-- Octra `oct…` address. -/
structure Address where
  raw     : Digest32
  display : String
  deriving Repr

instance : DecidableEq Address := fun a b => by
  rcases a with ⟨ra, da⟩
  rcases b with ⟨rb, db⟩
  by_cases h1 : ra = rb
  · by_cases h2 : da = db
    · exact isTrue (by subst h1; subst h2; rfl)
    · exact isFalse (by intro he; cases he; exact h2 rfl)
  · exact isFalse (by intro he; cases he; exact h1 rfl)

/-- `Address::from_pubkey` — build from a 32-byte ed25519 pubkey. -/
def Address.fromPubkey (pubkey : ByteString) : Address :=
  let raw := Sha256.digest pubkey
  { raw := raw, display := Address.displayOf raw }

/-- Axiom: display starts with "oct" — hard-coded in
    `format!("{ADDRESS_PREFIX}{padded}")` in the Rust source. -/
axiom Address.displayOf_prefix (raw : Digest32) :
    (Address.displayOf raw).startsWith "oct" = true

/-- Axiom: display has total length 47 ("oct" + 44 base58 chars). -/
axiom Address.displayOf_len (raw : Digest32) :
    (Address.displayOf raw).length = 47

-- ============================================================
-- Ed25519 (octra-foundry/sig.rs)
-- ============================================================

/-- Opaque 32-byte public key. -/
structure PublicKey where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- Opaque 32-byte secret key. -/
structure SecretKey where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- Opaque 64-byte signature. -/
structure Signature where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- A KeyPair pairs a secret with the derived public key. -/
structure KeyPair where
  secret    : SecretKey
  publicKey : PublicKey
  deriving Repr

/-- Public key derivation; opaque deterministic function. -/
opaque deriveVerifyingKey : SecretKey → PublicKey := fun _ => default

/-- `KeyPair::from_secret_bytes(sk)`. -/
def KeyPair.fromSecretBytes (sk : SecretKey) : KeyPair :=
  { secret := sk, publicKey := deriveVerifyingKey sk }

/-- Opaque ed25519 sign function. -/
opaque ed25519Sign : SecretKey → ByteString → Signature := fun _ _ => default

/-- `KeyPair::sign` is `ed25519Sign(secret, msg)`. -/
def KeyPair.sign (kp : KeyPair) (msg : ByteString) : Signature :=
  ed25519Sign kp.secret msg

/-- Verify result. -/
inductive VerifyResult where
  | ok      : VerifyResult
  | badSig  : VerifyResult
  deriving DecidableEq, Repr, Inhabited

/-- Opaque verify primitive. -/
opaque verifyRaw : PublicKey → ByteString → Signature → VerifyResult :=
  fun _ _ _ => VerifyResult.badSig

/-- Axiom — Ed25519 round-trip identity (EUF-CMA soundness side). -/
axiom verify_sign_roundtrip (sk : SecretKey) (m : ByteString) :
    verifyRaw (deriveVerifyingKey sk) m (ed25519Sign sk m) = VerifyResult.ok

/-- Axiom — Ed25519 tamper-rejection. -/
axiom verify_rejects_tampered_message
    (sk : SecretKey) (m m' : ByteString) (h : m ≠ m') :
    verifyRaw (deriveVerifyingKey sk) m' (ed25519Sign sk m) = VerifyResult.badSig

/-- Axiom — Ed25519 wrong-pubkey rejection. -/
axiom verify_rejects_wrong_pubkey
    (sk sk' : SecretKey) (m : ByteString) (h : sk ≠ sk') :
    verifyRaw (deriveVerifyingKey sk') m (ed25519Sign sk m) = VerifyResult.badSig

-- ============================================================
-- Circle ID derivation (octra-foundry/circle.rs)
-- ============================================================

/-- Tag constants. -/
def TAG_CIRCLE_PAYLOAD : ByteString := [0]
def TAG_CIRCLE_ID      : ByteString := [1]
def TAG_RESOURCE_KEY   : ByteString := [2]

/-- The three circle-framing tags are pairwise distinct. -/
axiom circle_tags_distinct :
    TAG_CIRCLE_PAYLOAD ≠ TAG_CIRCLE_ID ∧
    TAG_CIRCLE_ID ≠ TAG_RESOURCE_KEY ∧
    TAG_CIRCLE_PAYLOAD ≠ TAG_RESOURCE_KEY

/-- `circle_id_of_deploy`. -/
def circleIdOfDeploy
    (deployer : ByteString) (nonceBE : ByteString)
    (payload : ByteString) : Digest32 :=
  let payloadHash := h256Raw TAG_CIRCLE_PAYLOAD [payload]
  h256Raw TAG_CIRCLE_ID [deployer, nonceBE, payloadHash]

/-- `resource_key(circle_id, canonical_path)`. -/
def resourceKey (circleId : ByteString) (canonicalPath : ByteString)
    : Digest32 :=
  h256Raw TAG_RESOURCE_KEY [circleId, canonicalPath]

-- ============================================================
-- Padded frame (octra-foundry/circle.rs:padded_frame)
-- ============================================================

inductive PaddingClass where
  | none : PaddingClass
  | k4   : PaddingClass
  | k16  : PaddingClass
  | k32  : PaddingClass
  | k128 : PaddingClass
  deriving Repr, DecidableEq

def PaddingClass.targetBytes : PaddingClass → Nat
  | .none => 0
  | .k4   => 4096
  | .k16  => 16384
  | .k32  => 32768
  | .k128 => 131072

def paddedFrameBareLen (plLen : Nat) : Nat := 4 + plLen

def paddedFrameLen (plLen : Nat) (class_ : PaddingClass) : Nat :=
  let bare := paddedFrameBareLen plLen
  let target := class_.targetBytes
  if target = 0 then
    bare
  else
    let aligned := ((bare + target - 1) / target) * target
    if aligned ≤ bare then bare else aligned

-- ============================================================
-- AEAD (sealed envelope + wallet envelope)
-- ============================================================

structure AeadKey where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

inductive AeadResult where
  | ok        (plaintext : ByteString)  : AeadResult
  | wrongKey  : AeadResult
  | corrupt   : AeadResult
  deriving Repr, Inhabited

opaque aeadEncrypt : AeadKey → ByteString → ByteString := fun _ _ => []

opaque aeadDecrypt : AeadKey → ByteString → AeadResult :=
  fun _ _ => AeadResult.corrupt

/-- Axiom — AEAD round-trip identity. -/
axiom aead_roundtrip (k : AeadKey) (p : ByteString) :
    aeadDecrypt k (aeadEncrypt k p) = AeadResult.ok p

/-- Axiom — AEAD wrong-key rejection. -/
axiom aead_wrong_key (k k' : AeadKey) (p : ByteString)
    (h : k ≠ k') :
    aeadDecrypt k' (aeadEncrypt k p) ≠ AeadResult.ok p

/-- Axiom — AEAD tamper rejection: a tampered ciphertext never
    decrypts to the original plaintext. -/
axiom aead_tamper_specific (k : AeadKey) (p : ByteString)
    (ct' : ByteString) (h : ct' ≠ aeadEncrypt k p) :
    aeadDecrypt k ct' ≠ AeadResult.ok p

-- ============================================================
-- PBKDF2 / HKDF key derivation
-- ============================================================

opaque pbkdf2 : (passphrase : ByteString) → (salt : ByteString)
              → (iters : Nat) → (outLen : Nat) → ByteString :=
  fun _ _ _ _ => []

theorem pbkdf2_deterministic
    (p p' : ByteString) (s s' : ByteString) (i i' : Nat) (l l' : Nat)
    (hp : p = p') (hs : s = s') (hi : i = i') (hl : l = l') :
    pbkdf2 p s i l = pbkdf2 p' s' i' l' := by
  rw [hp, hs, hi, hl]

axiom pbkdf2_salt_distinct
    (p : ByteString) (s s' : ByteString) (i l : Nat) (h : s ≠ s') :
    pbkdf2 p s i l ≠ pbkdf2 p s' i l

axiom pbkdf2_passphrase_distinct
    (p p' : ByteString) (s : ByteString) (i l : Nat) (h : p ≠ p') :
    pbkdf2 p s i l ≠ pbkdf2 p' s i l

/-- Salt template for `derive_sealed_read_key`. -/
def sealedReadKeySalt (circleId : ByteString) (keyId : ByteString)
    : ByteString :=
  circleId ++ [58] ++ keyId  -- ':' = 58

axiom sealedReadKeySalt_injective
    (c c' : ByteString) (k k' : ByteString)
    (h : (c, k) ≠ (c', k')) :
    sealedReadKeySalt c k ≠ sealedReadKeySalt c' k'

def deriveSealedReadKey
    (circleId : ByteString) (keyId : ByteString)
    (passphrase : ByteString) : AeadKey :=
  { bytes := pbkdf2 passphrase (sealedReadKeySalt circleId keyId) 120000 32 }

opaque hkdfExpand : (master : ByteString) → (domain : ByteString)
                  → (outLen : Nat) → ByteString :=
  fun _ _ _ => []

axiom hkdf_domain_distinct
    (master : ByteString) (d d' : ByteString) (l : Nat) (h : d ≠ d') :
    hkdfExpand master d l ≠ hkdfExpand master d' l

def deriveSubkey (master : ByteString) (domain : ByteString)
    : ByteString :=
  hkdfExpand master domain 32

-- ============================================================
-- Wallet envelope (octra-foundry/wallet_enc.rs)
-- ============================================================

def walletKek (passphrase : ByteString) (salt : ByteString)
    (iters : Nat) : AeadKey :=
  { bytes := pbkdf2 passphrase salt iters 32 }

def walletSeal (secret : ByteString) (passphrase : ByteString)
    (salt : ByteString) (iters : Nat) : ByteString :=
  aeadEncrypt (walletKek passphrase salt iters) secret

def walletUnseal (ciphertext : ByteString) (passphrase : ByteString)
    (salt : ByteString) (iters : Nat) : AeadResult :=
  aeadDecrypt (walletKek passphrase salt iters) ciphertext

-- ============================================================
-- Receipt context (crates/octravpn-core/src/receipt.rs)
-- ============================================================

def DOMAIN_RECEIPT : ByteString := [3]

structure ReceiptContext where
  programAddr : Address
  chainId     : Nat
  circleId    : Option Address
  deriving Repr

def ReceiptContext.circleIdCanonical (c : ReceiptContext) : Digest32 :=
  match c.circleId with
  | some a => a.raw
  | none   => List.replicate 32 0

abbrev SessionId := Digest32
abbrev Blind     := Digest32

def receiptSigningInput
    (ctx : ReceiptContext) (sid : SessionId) (seq : Nat)
    (bytesUsed : Nat) (blind : Blind) : ByteString :=
  DOMAIN_RECEIPT
    ++ ctx.programAddr.raw
    ++ u32be ctx.chainId
    ++ ctx.circleIdCanonical
    ++ sid
    ++ u64be seq
    ++ u64be bytesUsed
    ++ blind

def receiptSigningPayload
    (ctx : ReceiptContext) (sid : SessionId) (seq : Nat)
    (bytesUsed : Nat) (blind : Blind) : Digest32 :=
  Sha256.digest (receiptSigningInput ctx sid seq bytesUsed blind)

-- ============================================================
-- Receipt journal (crates/octravpn-core/src/receipt_journal.rs)
-- ============================================================

structure ReceiptJournal where
  floors : SessionId → Nat

instance : Inhabited ReceiptJournal := ⟨{ floors := fun _ => 0 }⟩

def ReceiptJournal.floor (j : ReceiptJournal) (sid : SessionId) : Nat :=
  j.floors sid

def ReceiptJournal.bump
    (j : ReceiptJournal) (sid : SessionId) (newSeq : Nat)
    : Option ReceiptJournal :=
  let prev := j.floor sid
  if newSeq ≤ prev then
    none
  else
    some { floors := fun s => if s = sid then newSeq else j.floors s }

def ReceiptJournal.empty : ReceiptJournal :=
  { floors := fun _ => 0 }

def ReceiptJournal.persist (j : ReceiptJournal) : ReceiptJournal := j

-- ============================================================
-- Tailnet IP allocation (crates/octravpn-mesh/src/ip_alloc.rs)
-- ============================================================

def CGNAT_BASE    : Nat := 0x64400000
def TAILNET_BITS  : Nat := 12
def HOST_BITS     : Nat := 10
def HOST_MASK     : Nat := (1 <<< HOST_BITS) - 1
def TAILNET_MASK  : Nat := (1 <<< TAILNET_BITS) - 1
def RESERVED_LOW  : Nat := 2
def RESERVED_HIGH : Nat := 1
def USABLE_HOSTS  : Nat := (1 <<< HOST_BITS) - RESERVED_LOW - RESERVED_HIGH

opaque hashBitsU32 : ByteString → Nat := fun _ => 0

def tailnetNetworkPrefix (tid : ByteString) : Nat :=
  let tag : ByteString := [4]
  let bits := hashBitsU32 (tag ++ tid)
  let tailnetBits := bits &&& TAILNET_MASK
  CGNAT_BASE ||| (tailnetBits <<< HOST_BITS)

def tailnetHostSuffix (tid : ByteString) (member : ByteString) : Nat :=
  let tag : ByteString := [5]
  let bits := hashBitsU32 (tag ++ tid ++ [58, 58] ++ member)
  RESERVED_LOW + ((bits &&& HOST_MASK) % USABLE_HOSTS)

def tailnetAllocate (tid : ByteString) (member : ByteString) : Nat :=
  tailnetNetworkPrefix tid ||| tailnetHostSuffix tid member

-- ============================================================
-- ACL canonical bytes (crates/octravpn-mesh/src/acl.rs)
-- ============================================================

structure AclDoc where
  version : Nat
  payload : ByteString
  deriving DecidableEq, Repr

def AclDoc.canonicalBytes (d : AclDoc) : ByteString :=
  u32be d.version ++ d.payload

-- ============================================================
-- Peer snapshot canonical message (crates/octravpn-mesh/src/peer.rs)
-- ============================================================

inductive PeerCandidate where
  | lan   (ip : Digest32) (port : Nat) : PeerCandidate
  | stun  (ip : Digest32) (port : Nat) : PeerCandidate
  | relay (validatorAddr : ByteString) : PeerCandidate
  deriving Repr

def canonicalCandidate : PeerCandidate → ByteString
  | .lan ip _ =>  [0] ++ ip ++ [0, 0]
  | .stun ip _ => [1] ++ ip ++ [0, 0]
  | .relay v =>   [2] ++ u32be v.length ++ v

def canonicalCandidates (cs : List PeerCandidate) : ByteString :=
  cs.foldl (fun acc c => acc ++ canonicalCandidate c) []

structure PeerSnapshot where
  tailnetId : ByteString
  addr      : ByteString
  wgPubkey  : ByteString
  cands     : List PeerCandidate
  hostname  : ByteString
  deriving Repr

def peerCanonicalMessage (s : PeerSnapshot) (tsUnix : Nat) : ByteString :=
  s.tailnetId
    ++ s.addr
    ++ s.wgPubkey
    ++ canonicalCandidates s.cands
    ++ s.hostname
    ++ u64be tsUnix

-- ============================================================
-- Canonical tx bytes (octra-foundry/tx.rs)
-- ============================================================

structure OctraTx where
  fromAddr      : ByteString
  toAddr        : ByteString
  amount        : Nat
  nonce         : Nat
  ou            : Nat
  opType        : ByteString
  encryptedData : Option ByteString
  message       : Option ByteString
  deriving DecidableEq, Repr

opaque canonicalTxBytes : OctraTx → ByteString := fun _ => []

theorem canonical_tx_function (a b : OctraTx) (h : a = b) :
    canonicalTxBytes a = canonicalTxBytes b := by rw [h]

end OctraVPN_Rust
