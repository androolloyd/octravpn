/-!
# HMAC token (portal confirm tokens) — Lean spec & proofs.

Mirrors `PortalState::token_for` and `PortalState::token_valid` in
`crates/octravpn-client/src/portal/routes.rs` (lines 148-164):

```rust
pub(crate) fn token_for(&self, circle_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_ref())
        .expect("HMAC accepts any 32B key");
    mac.update(circle_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn token_valid(&self, circle_id: &str, supplied_hex: &str) -> bool {
    let Ok(supplied) = hex::decode(supplied_hex) else { return false };
    let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_ref())
        .expect("HMAC accepts any 32B key");
    mac.update(circle_id.as_bytes());
    mac.verify_slice(&supplied).is_ok()
}
```

The HMAC-SHA256 primitive is modeled opaquely (same strategy as
`OctraVPN_Rust/Spec.lean`'s SHA-256 / AEAD axioms). We prove the
composition layer: that `token_for` is deterministic, that
`token_valid` matches iff the supplied bytes equal the MAC, and that
distinct circle IDs produce distinct tokens (under a standard
PRF-collision-resistance axiom).

We do **not** prove HMAC-SHA256's PRF security — that's the standard
cryptographic assumption (HMAC is a PRF when the underlying hash's
compression function is a PRF; see RFC 2104 §6). Like the AEAD axioms
in `OctraVPN_Rust`, we encode it as a Lean axiom and rely on the
audited `hmac` crate for the implementation.

The constant-time-equality property in `token_valid` (via
`mac.verify_slice(&supplied).is_ok()` which uses
`subtle::ConstantTimeEq`) is a SIDE-CHANNEL property, not a functional
one: the boolean output is the same `supplied == expected` predicate
either way. We prove the functional equivalence here.
-/

namespace OctraVPN.WireProtocol.HmacToken

abbrev ByteString := List UInt8

/-- An opaque HMAC-SHA256 32-byte secret. -/
structure HmacSecret where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- An opaque 32-byte HMAC-SHA256 MAC tag. -/
structure HmacTag where
  bytes : ByteString
  deriving DecidableEq, Repr, Inhabited

/-- Opaque HMAC-SHA256: `HMAC(secret, message)`. -/
opaque hmacSha256 : HmacSecret → ByteString → HmacTag :=
  fun _ _ => default

/-- Hex-encode a tag to a lowercase string of length `2 * bytes.length`.
    Mirrors `hex::encode` from the Rust source. We treat this as an
    opaque injective function — the actual hex digit-by-digit
    implementation is straightforward but irrelevant to the
    correctness story; what matters is `hex::encode` is a bijection
    on byte strings, and `hex::decode ∘ hex::encode = id`. -/
opaque hexEncode : HmacTag → String := fun _ => ""

/-- Hex-decode. Returns `none` for non-hex strings; `some bytes` on
    success. -/
opaque hexDecode : String → Option HmacTag := fun _ => none

/-- Axiom — hex encode/decode round-trip. -/
axiom hex_roundtrip (t : HmacTag) : hexDecode (hexEncode t) = some t

/-- Axiom — `hexEncode` is injective. (Equivalent to the round-trip
    above plus `Option.some.inj`.) -/
axiom hexEncode_injective {t t' : HmacTag} (h : hexEncode t = hexEncode t') :
    t = t'

/-- A circle ID is just an opaque string (we don't model its
    parse-side validation). -/
abbrev CircleId := String

/-- The portal HMAC state — just the secret. The other portal state
    (allow_set, unseal_cache) is in `PortalCache.lean`. -/
structure PortalHmac where
  secret : HmacSecret
  deriving Repr, Inhabited

/-- Convert a circle-id string to its UTF-8 bytes. We treat this as
    opaque and injective (Lean's `String` is UTF-8 internally; the
    Rust `as_bytes()` call is the byte view). -/
opaque circleIdBytes : CircleId → ByteString := fun _ => []

axiom circleIdBytes_injective {c c' : CircleId}
    (h : circleIdBytes c = circleIdBytes c') : c = c'

/-- Build the approval token for a circle ID. Returns the hex string. -/
def PortalHmac.tokenFor (p : PortalHmac) (c : CircleId) : String :=
  hexEncode (hmacSha256 p.secret (circleIdBytes c))

/-- Verify a supplied hex string against the canonical token for a
    circle id. Constant-time at the byte level in Rust; pure boolean
    equality semantically. -/
def PortalHmac.tokenValid (p : PortalHmac) (c : CircleId) (suppliedHex : String) : Bool :=
  match hexDecode suppliedHex with
  | none => false
  | some supplied => decide (supplied = hmacSha256 p.secret (circleIdBytes c))

-- ============================================================
-- §1  determinism
-- ============================================================

/-- `token_for` is deterministic in its inputs. -/
theorem token_for_deterministic (p : PortalHmac) (c : CircleId) :
    p.tokenFor c = p.tokenFor c := rfl

/-- Equal inputs produce equal tokens (a function!). -/
theorem token_for_function (p p' : PortalHmac) (c c' : CircleId)
    (hp : p = p') (hc : c = c') :
    p.tokenFor c = p'.tokenFor c' := by
  rw [hp, hc]

-- ============================================================
-- §2  HMAC collision-resistance axioms (composition layer)
-- ============================================================

/-- Axiom — HMAC is a function. (Standard: equal key + equal message
    ⇒ equal tag.) -/
theorem hmac_function (k k' : HmacSecret) (m m' : ByteString)
    (hk : k = k') (hm : m = m') :
    hmacSha256 k m = hmacSha256 k' m' := by
  rw [hk, hm]

/-- Axiom — HMAC distinct messages produce distinct tags (under the
    PRF assumption + the standard birthday bound; we treat this as
    structural collision-resistance for the composition layer).

    This is the same modeling strategy as `Sha256.injective` in
    `OctraVPN_Rust/Spec.lean`; we are NOT proving PRF security, just
    structural distinctness for proof composition. -/
axiom hmac_distinct_messages
    (k : HmacSecret) (m m' : ByteString) (h : m ≠ m') :
    hmacSha256 k m ≠ hmacSha256 k m'

-- ============================================================
-- §3  Distinct circles → distinct tokens
-- ============================================================

/-- **Distinct circles → distinct tokens.** Two different circle IDs
    produce different approval tokens (under the HMAC PRF assumption).
    This is the per-circle isolation property the portal's
    `confirm_interstitial` flow relies on. -/
theorem token_for_distinct_circles
    (p : PortalHmac) (c c' : CircleId) (h : c ≠ c') :
    p.tokenFor c ≠ p.tokenFor c' := by
  intro heq
  unfold PortalHmac.tokenFor at heq
  have htag : hmacSha256 p.secret (circleIdBytes c) =
              hmacSha256 p.secret (circleIdBytes c') := hexEncode_injective heq
  -- If circleIdBytes c = circleIdBytes c' we contradict h via injectivity;
  -- else HMAC distinctness gives a contradiction.
  by_cases hb : circleIdBytes c = circleIdBytes c'
  · exact h (circleIdBytes_injective hb)
  · exact hmac_distinct_messages p.secret (circleIdBytes c) (circleIdBytes c') hb htag

-- ============================================================
-- §4  token_valid iff supplied = canonical
-- ============================================================

/-- **`token_valid` matches iff supplied bytes decode to the
    canonical MAC tag.** This is the functional spec of the
    constant-time check; the side-channel (constant-time) property
    is a runtime property of the `subtle::ConstantTimeEq` crate and
    is out of scope for deductive proof. -/
theorem token_valid_iff_match
    (p : PortalHmac) (c : CircleId) (supplied : String) :
    p.tokenValid c supplied = true ↔
    hexDecode supplied = some (hmacSha256 p.secret (circleIdBytes c)) := by
  unfold PortalHmac.tokenValid
  constructor
  · intro hb
    cases hd : hexDecode supplied with
    | none =>
        rw [hd] at hb
        simp at hb
    | some t =>
        rw [hd] at hb
        simp at hb
        rw [hb]
  · intro hd
    rw [hd]
    simp

/-- **`token_valid (token_for c)` always returns true** (round-trip
    soundness). -/
theorem token_valid_self
    (p : PortalHmac) (c : CircleId) :
    p.tokenValid c (p.tokenFor c) = true := by
  unfold PortalHmac.tokenValid PortalHmac.tokenFor
  rw [hex_roundtrip]
  simp

/-- **`token_valid` rejects mismatched circle IDs** (under HMAC
    distinctness). If `c ≠ c'`, the token for `c` does not validate
    against `c'`. -/
theorem token_valid_cross_circle_rejected
    (p : PortalHmac) (c c' : CircleId) (h : c ≠ c') :
    p.tokenValid c' (p.tokenFor c) = false := by
  unfold PortalHmac.tokenValid PortalHmac.tokenFor
  rw [hex_roundtrip]
  simp
  -- Need to show hmacSha256 p.secret (circleIdBytes c)
  --             ≠ hmacSha256 p.secret (circleIdBytes c').
  by_cases hb : circleIdBytes c = circleIdBytes c'
  · exact absurd (circleIdBytes_injective hb) h
  · exact hmac_distinct_messages p.secret (circleIdBytes c) (circleIdBytes c') hb

-- ============================================================
-- §5  Concrete-value anchor
-- ============================================================

/-- Concrete anchor: a token round-trips against itself. -/
example
    (p : PortalHmac) (c : CircleId) :
    p.tokenValid c (p.tokenFor c) = true :=
  token_valid_self p c

end OctraVPN.WireProtocol.HmacToken
